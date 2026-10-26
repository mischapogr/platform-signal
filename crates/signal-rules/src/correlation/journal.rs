//! Opaque journal composition. No historical artifact becomes a fresh authority.
use super::*;
use crate::state_journal::{Config as JournalConfig, Journal, Output, Record};

impl Binding {
    pub fn journal_config(&self) -> JournalConfig {
        binding::BindingView::authentication(self).journal_config()
    }
}
impl d14::RuntimeBinding {
    pub fn journal_config(&self) -> JournalConfig {
        binding::BindingView::runtime(self).journal_config()
    }
}
pub enum Action<'a> {
    Admit {
        stream: Uuid,
        position: u64,
        event: &'a SignalEvent,
    },
    Seal,
}
#[derive(Debug)]
pub enum Applied {
    Admission(Admission),
    Sealed(Seal),
    History,
    Generation,
}
pub struct Prepared {
    pub(super) record: Record,
    pub(super) previous: Option<Record>,
    pub(super) config: JournalConfig,
    pub(super) original: RuleContext,
    pub(super) authority: RuleContext,
    pub(super) history_authority: Option<RuleContext>,
    pub(super) source: Option<(Journal, Record)>,
    pub(super) applied: Applied,
}
impl Prepared {
    pub fn record(&self) -> &Record {
        &self.record
    }
    pub fn applied(&self) -> &Applied {
        &self.applied
    }
    pub async fn commit(&self, journal: &Journal) -> Result<Record, Error> {
        if journal.config() != &self.config {
            return Err(Error::Conflict);
        }
        check(&self.original)?;
        check(&self.authority)?;
        if let Some(h) = &self.history_authority {
            check(h)?;
        }
        let mut operation = self.original.clone();
        operation.deadline = operation.deadline.min(self.authority.deadline);
        if let Some(h) = &self.history_authority {
            operation.deadline = operation.deadline.min(h.deadline);
        }
        let execute = async {
            if let Some((source, expected)) = &self.source
                && source
                    .load(operation.clone())
                    .await
                    .map_err(|_| Error::Journal)?
                    .as_ref()
                    != Some(expected)
            {
                return Err(Error::Conflict);
            }
            if journal
                .load(operation.clone())
                .await
                .map_err(|_| Error::Journal)?
                != self.previous
            {
                return Err(Error::Conflict);
            }
            journal
                .commit(
                    self.previous.as_ref().map_or(0, |r| r.revision),
                    self.record.clone(),
                    operation,
                )
                .await
                .map_err(|_| Error::Journal)
        };
        tokio::select! {biased;
            _=self.authority.cancellation.cancelled()=>Err(Error::Cancelled),
            _=async {match &self.history_authority{Some(h)=>h.cancellation.cancelled().await,None=>std::future::pending().await}}=>Err(Error::Cancelled),
            result=execute=>result,
        }
    }
    pub async fn reconcile(
        &self,
        journal: &Journal,
        context: RuleContext,
    ) -> Result<Record, Error> {
        if journal.config() != &self.config {
            return Err(Error::Conflict);
        }
        let actual = journal.load(context).await.map_err(|_| Error::Journal)?;
        if actual.as_ref() != Some(&self.record) {
            return Err(Error::Conflict);
        }
        Ok(self.record.clone())
    }
}
/// Validate an actual committed record without renewing its historical authority.
/// A fresh read budget may expose original pending/published effects only.
pub fn recover(binding: &Binding, record: &Record, context: &RuleContext) -> Result<State, Error> {
    check(context)?;
    if record.schema_version != 1
        || record.revision == 0
        || record.revision > i64::MAX as u64
        || record.checkpoint > i64::MAX as u64
        || record.outbox.len() > binding.config.max_episodes
    {
        return Err(Error::Conflict);
    }
    let state = State::decode(binding, &record.state, context)?;
    let mut seen = BTreeSet::new();
    for o in &record.outbox {
        check(context)?;
        if o.schema_version != 1
            || !seen.insert(o.id)
            || !state
                .effects
                .iter()
                .any(|e| e.id == o.id && e.bytes == o.bytes)
        {
            return Err(Error::Conflict);
        }
    }
    codec::encode(record, binding.journal_config().max_record_bytes, context)?;
    Ok(state)
}
/// Prepare one serial source action or a watermark seal. Full predecessor bytes
/// are rechecked against the real destination, then revision CAS closes races.
pub fn prepare(
    binding: &Binding,
    previous: Option<&Record>,
    checkpoint: u64,
    action: Action<'_>,
    epoch: &Epoch,
    context: &RuleContext,
) -> Result<Prepared, Error> {
    prepare_checked(binding, previous, checkpoint, action, epoch, None, context)
}
#[allow(clippy::too_many_arguments)]
pub fn prepare_checked(
    binding: &Binding,
    previous: Option<&Record>,
    checkpoint: u64,
    action: Action<'_>,
    epoch: &Epoch,
    lookup: Option<&history::Lookup<'_>>,
    context: &RuleContext,
) -> Result<Prepared, Error> {
    epoch.valid(binding, context)?;
    if checkpoint > i64::MAX as u64 || previous.is_some_and(|p| checkpoint < p.checkpoint) {
        return Err(Error::Conflict);
    }
    if previous.is_some_and(|p| !p.outbox.is_empty()) {
        return Err(Error::Pending);
    }
    let old_checkpoint = previous.map_or(0, |r| r.checkpoint);
    match &action {
        Action::Seal if checkpoint != old_checkpoint => return Err(Error::Conflict),
        Action::Admit { .. } if old_checkpoint.checked_add(1) != Some(checkpoint) => {
            return Err(Error::Conflict);
        }
        _ => (),
    }
    let mut state = previous
        .map(|r| recover(binding, r, context))
        .transpose()?
        .unwrap_or_else(|| State::new(binding));
    let old_count = state.episodes.len();
    let applied = match action {
        Action::Admit {
            stream,
            position,
            event,
        } => {
            let admission =
                state.admit_checked(binding, stream, position, event, epoch, lookup, context)?;
            if admission != Admission::Duplicate
                && previous.is_some_and(|p| checkpoint <= p.checkpoint)
            {
                return Err(Error::Conflict);
            }
            Applied::Admission(admission)
        }
        Action::Seal => Applied::Sealed(state.seal(binding, epoch, context)?),
    };
    let outbox = state.effects[old_count..]
        .iter()
        .map(|e| {
            Ok(Output {
                schema_version: 1,
                id: e.id,
                bytes: e.bytes.clone(),
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let revision = previous.map_or(Ok(1), |p| {
        p.revision
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(Error::Capacity)
    })?;
    let record = Record {
        schema_version: 1,
        revision,
        checkpoint,
        state: state.encode(binding, context)?,
        outbox,
    };
    codec::encode(&record, binding.journal_config().max_record_bytes, context)?;
    epoch.valid(binding, context)?;
    Ok(Prepared {
        record,
        previous: previous.cloned(),
        config: binding.journal_config(),
        original: context.clone(),
        authority: epoch.context.clone(),
        history_authority: lookup.map(|l| l.authority_context().clone()),
        source: None,
        applied,
    })
}
