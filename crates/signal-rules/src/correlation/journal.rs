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
    pub(super) runtime_contexts: Vec<RuleContext>,
    pub(super) source: Option<(Journal, Record)>,
    pub(super) applied: Applied,
}
// At most three extra contexts: action input, decision proof and decision input.
// Poll them together so cancellation of any original token interrupts journal I/O.
async fn runtime_cancelled(contexts: &[RuleContext]) {
    let mut pending = contexts
        .iter()
        .map(|c| Box::pin(c.cancellation.cancelled()))
        .collect::<Vec<_>>();
    std::future::poll_fn(move |cx| {
        for future in &mut pending {
            if std::future::Future::poll(future.as_mut(), cx).is_ready() {
                return std::task::Poll::Ready(());
            }
        }
        std::task::Poll::Pending
    })
    .await
}
impl Prepared {
    pub fn record(&self) -> &Record {
        &self.record
    }
    pub fn applied(&self) -> &Applied {
        &self.applied
    }
    /// A cancellation/error after physical mutation starts is uncertain. Reconcile
    /// exact prepared bytes before acknowledging or retrying the source action.
    pub async fn commit(&self, journal: &Journal) -> Result<Record, Error> {
        if journal.config() != &self.config {
            return Err(Error::Conflict);
        }
        check(&self.original)?;
        check(&self.authority)?;
        if let Some(h) = &self.history_authority {
            check(h)?;
        }
        if self.runtime_contexts.len() > 3 {
            return Err(Error::Conflict);
        }
        for context in &self.runtime_contexts {
            check(context)?;
        }
        let mut operation = self.original.clone();
        operation.deadline = operation.deadline.min(self.authority.deadline);
        if let Some(h) = &self.history_authority {
            operation.deadline = operation.deadline.min(h.deadline);
        }
        for context in &self.runtime_contexts {
            operation.deadline = operation.deadline.min(context.deadline);
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
            _=runtime_cancelled(&self.runtime_contexts)=>Err(Error::Cancelled),
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
    recover_with(
        &binding::BindingView::authentication(binding),
        record,
        context,
    )
}
pub(super) fn recover_with(
    binding: &binding::BindingView<'_>,
    record: &Record,
    context: &RuleContext,
) -> Result<State, Error> {
    check(context)?;
    if record.schema_version != 1
        || record.revision == 0
        || record.revision > i64::MAX as u64
        || record.checkpoint > i64::MAX as u64
        || record.outbox.len() > binding.config.max_episodes
    {
        return Err(Error::Conflict);
    }
    let state = State::decode_with(binding, &record.state, context)?;
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
    let action = match action {
        Action::Admit {
            stream,
            position,
            event,
        } => SelectedAction::Admit {
            stream,
            position,
            event,
            input_context: None,
            decision: None,
        },
        Action::Seal => SelectedAction::Seal,
    };
    prepare_with(
        &binding::BindingView::authentication(binding),
        previous,
        checkpoint,
        action,
        epoch,
        lookup,
        context,
    )
}

/// Runtime actions retain typed input and first-admission policy lifetimes. A
/// replacement decision on a duplicate is unused and cannot change old facts.
pub enum RuntimeAction<'a> {
    Admit {
        input: &'a d14::Input,
        position: u64,
        decision: Option<&'a d14::CurrentDecision>,
    },
    Seal,
}
pub fn recover_runtime(
    binding: &d14::RuntimeBinding,
    record: &Record,
    context: &RuleContext,
) -> Result<d14::RuntimeState, Error> {
    Ok(d14::RuntimeState::from_inner(recover_with(
        &binding::BindingView::runtime(binding),
        record,
        context,
    )?))
}
pub fn prepare_runtime(
    binding: &d14::RuntimeBinding,
    previous: Option<&Record>,
    checkpoint: u64,
    action: RuntimeAction<'_>,
    epoch: &d14::RuntimeEpoch,
    context: &RuleContext,
) -> Result<Prepared, Error> {
    prepare_runtime_checked(binding, previous, checkpoint, action, epoch, None, context)
}
#[allow(clippy::too_many_arguments)]
pub fn prepare_runtime_checked(
    binding: &d14::RuntimeBinding,
    previous: Option<&Record>,
    checkpoint: u64,
    action: RuntimeAction<'_>,
    epoch: &d14::RuntimeEpoch,
    lookup: Option<&history::Lookup<'_>>,
    context: &RuleContext,
) -> Result<Prepared, Error> {
    let action = match action {
        RuntimeAction::Admit {
            input,
            position,
            decision,
        } => {
            input.valid_for(binding, context)?;
            SelectedAction::Admit {
                stream: input.stream(),
                position,
                event: input.event(),
                input_context: Some(input.original_context()),
                decision,
            }
        }
        RuntimeAction::Seal => SelectedAction::Seal,
    };
    prepare_with(
        &binding::BindingView::runtime(binding),
        previous,
        checkpoint,
        action,
        &epoch.inner,
        lookup,
        context,
    )
}
enum SelectedAction<'a> {
    Admit {
        stream: Uuid,
        position: u64,
        event: &'a SignalEvent,
        input_context: Option<&'a RuleContext>,
        decision: Option<&'a d14::CurrentDecision>,
    },
    Seal,
}
#[allow(clippy::too_many_arguments)]
fn prepare_with(
    binding: &binding::BindingView<'_>,
    previous: Option<&Record>,
    checkpoint: u64,
    action: SelectedAction<'_>,
    epoch: &Epoch,
    lookup: Option<&history::Lookup<'_>>,
    context: &RuleContext,
) -> Result<Prepared, Error> {
    epoch.valid_with(binding, context)?;
    if checkpoint > i64::MAX as u64 || previous.is_some_and(|p| checkpoint < p.checkpoint) {
        return Err(Error::Conflict);
    }
    if previous.is_some_and(|p| !p.outbox.is_empty()) {
        return Err(Error::Pending);
    }
    let old_checkpoint = previous.map_or(0, |r| r.checkpoint);
    match &action {
        SelectedAction::Seal if checkpoint != old_checkpoint => return Err(Error::Conflict),
        SelectedAction::Admit { .. } if old_checkpoint.checked_add(1) != Some(checkpoint) => {
            return Err(Error::Conflict);
        }
        _ => (),
    }
    let mut state = previous
        .map(|r| recover_with(binding, r, context))
        .transpose()?
        .unwrap_or_else(|| State::new_with(binding));
    let old_count = state.episodes.len();
    let mut runtime_contexts = Vec::new();
    let applied = match action {
        SelectedAction::Admit {
            stream,
            position,
            event,
            input_context,
            decision,
        } => {
            let admission = state.admit_selected_with(
                binding,
                stream,
                position,
                event,
                epoch,
                lookup,
                decision,
                input_context,
                context,
            )?;
            if let Some(original) = input_context {
                runtime_contexts.push(original.clone());
            }
            if admission != Admission::Duplicate
                && let Some(decision) = decision
            {
                runtime_contexts.extend(decision.original_contexts().into_iter().cloned());
            }
            if admission != Admission::Duplicate
                && previous.is_some_and(|p| checkpoint <= p.checkpoint)
            {
                return Err(Error::Conflict);
            }
            Applied::Admission(admission)
        }
        SelectedAction::Seal => Applied::Sealed(state.seal_with(binding, epoch, context)?),
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
        state: state.encode_with(binding, context)?,
        outbox,
    };
    codec::encode(&record, binding.journal_config().max_record_bytes, context)?;
    if let Some(lookup) = lookup {
        lookup.valid(binding, context)?;
    }
    epoch.valid_with(binding, context)?;
    for c in &runtime_contexts {
        check(c)?;
    }
    check(context)?;
    Ok(Prepared {
        record,
        previous: previous.cloned(),
        config: binding.journal_config(),
        original: context.clone(),
        authority: epoch.context.clone(),
        history_authority: lookup.map(|l| l.authority_context().clone()),
        runtime_contexts,
        source: None,
        applied,
    })
}
