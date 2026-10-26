//! Deterministic runtime episodes from historical typed observations/proofs.
use super::state::{RuntimeEpisode, historical_watermark};
use super::*;

pub(in crate::correlation) fn time(o: &Observation) -> DateTime<Utc> {
    o.runtime.as_ref().map_or(o.event.timestamp, |r| r.time())
}
pub(in crate::correlation) fn candidate(o: &Observation) -> bool {
    o.runtime.as_ref().is_some_and(|r| {
        matches!(
            r.projection.operation,
            Operation::Connect {
                result: 0,
                error: false,
                ..
            } | Operation::Gap { .. }
        )
    })
}
fn input(b: &RuntimeBinding, o: &Observation, c: &RuleContext) -> Result<Input, Error> {
    Input::new(b, o.verification.stream, &o.event, c)
}
fn bounds(o: &Observation) -> Result<(DateTime<Utc>, DateTime<Utc>), Error> {
    let r = o.runtime.as_ref().ok_or(Error::Conflict)?;
    Ok(match r.projection.operation.interval() {
        Some(i) => (
            DateTime::from_timestamp_nanos(i.entry_ns as i64),
            DateTime::from_timestamp_nanos(i.exit_ns as i64),
        ),
        None => (o.event.timestamp, o.event.timestamp),
    })
}
fn scope(o: &Observation) -> Contributor {
    Contributor {
        stream: o.verification.stream,
        source_binding: o.verification.source_binding,
        source_type: o.event.source.source_type.clone(),
        source_name: o.event.source.name.clone(),
        account: o.event.resource.as_ref().and_then(|r| r.account_id.clone()),
        resource: o.event.resource.as_ref().map(|r| r.id.clone()),
    }
}
fn definite_capture(o: &Observation) -> bool {
    o.verification
        .runtime
        .as_ref()
        .is_some_and(|p| p.execution_continuity && p.clock_continuity)
}
#[allow(clippy::too_many_arguments)]
pub(in crate::correlation) fn episode(
    b: &RuntimeBinding,
    observations: &[Observation],
    index: usize,
    watermark: DateTime<Utc>,
    proofs: &[VerificationEvidence],
    policies: &[PolicyCoverageEvidence],
    degraded: Option<DateTime<Utc>>,
    c: &RuleContext,
) -> Result<Episode, Error> {
    check(c)?;
    let anchor = observations.get(index).ok_or(Error::Conflict)?;
    if !candidate(anchor) || historical_watermark(b, proofs, policies, c)? != watermark {
        return Err(Error::Conflict);
    }
    for p in proofs {
        if observations
            .iter()
            .any(|o| o.verification.stream == p.stream && o.source_position > p.position)
        {
            return Err(Error::Conflict);
        }
    }
    let (entry, end) = bounds(anchor)?;
    if end > watermark {
        return Err(Error::Conflict);
    }
    let lower = entry
        .checked_sub_signed(TimeDelta::milliseconds(b.config.correlation_ms))
        .ok_or(Error::Invalid)?;
    let expired = watermark.signed_duration_since(end) > TimeDelta::milliseconds(b.config.ttl_ms);
    let a = input(b, anchor, c)?;
    let ar = anchor.runtime.as_ref().ok_or(Error::Conflict)?;
    let is_gap = matches!(a.operation(), Operation::Gap { .. });
    let mut gap = is_gap || expired || d11::late(anchor) || degraded.is_some_and(|t| entry <= t);
    gap |= proofs
        .iter()
        .any(|p| !p.complete || p.coverage_from > lower || p.frontier < end);
    gap |= policies
        .iter()
        .any(|p| !p.complete() || p.coverage_from() > lower || p.frontier() < end);
    if !is_gap && ar.decision.is_none() {
        gap = true;
    }
    let mut relevant = observations
        .iter()
        .filter(|o| bounds(o).is_ok_and(|(start, stop)| stop >= lower && start <= end))
        .collect::<Vec<_>>();
    relevant.sort_by(|a, b| {
        time(a)
            .cmp(&time(b))
            .then_with(|| a.native.cmp(&b.native))
            .then_with(|| a.event.id.cmp(&b.event.id))
    });
    let mut matches = Vec::new();
    let mut decisions = Vec::new();
    let mut contributors = Vec::new();
    for o in &relevant {
        check(c)?;
        let r = o.runtime.as_ref().ok_or(Error::Conflict)?;
        gap |= !o.verification.complete;
        let i = input(b, o, c)?;
        let contributor = scope(o);
        if !contributors.contains(&contributor) {
            contributors.push(contributor);
        }
        if let Some(d) = &r.decision {
            d.validate_historical(b, &i, c)?;
            decisions.push(d.clone());
        }
        if matches!(i.operation(), Operation::Gap { .. }) {
            gap = true;
        }
        if i.process() != a.process() || i.operation().role() != Some(Role::Asset) {
            continue;
        }
        // Only positive regular-file reads require an asset decision. EOF,
        // failed reads and socket reads are supported negative observations.
        if let Some(asset) = &r.decision {
            if let Some(destination) = &ar.decision {
                match relation(b, &i, asset, &a, destination, c)? {
                    Relation::Match
                        if !d11::late(o)
                            && !expired
                            && !d11::late(anchor)
                            && definite_capture(o)
                            && definite_capture(anchor) =>
                    {
                        matches.push(*o)
                    }
                    Relation::Uncertain => gap = true,
                    Relation::Match => gap = true,
                    _ => (),
                }
            }
        } else {
            gap = true;
        }
        gap |= d11::late(o);
    }
    // Visit newest definite read first; uncertainty must not hide a definite pair.
    matches.sort_by(|a, b| {
        time(a)
            .cmp(&time(b))
            .then_with(|| a.native.cmp(&b.native))
            .then_with(|| a.event.id.cmp(&b.event.id))
    });
    let chosen = matches.last().copied();
    let status = if chosen.is_some() {
        Status::Match
    } else if gap {
        Status::Indeterminate
    } else {
        Status::NoMatch
    };
    let mut selected = Vec::new();
    if let Some(o) = chosen {
        selected.push(o);
    }
    selected.push(anchor);
    for o in &selected {
        let contributor = scope(o);
        if !contributors.contains(&contributor) {
            contributors.push(contributor);
        }
    }
    for s in &b.config.sources {
        let contributor = Contributor {
            stream: s.stream,
            source_binding: s.binding,
            source_type: s.source_type.clone(),
            source_name: Some(s.source_name.clone()),
            account: None,
            resource: None,
        };
        if !contributors.contains(&contributor) {
            contributors.push(contributor);
        }
    }
    for p in &b.config.policy_authorities {
        let contributor = Contributor {
            stream: p.id,
            source_binding: p.binding,
            source_type: p.source_type.clone(),
            source_name: Some(p.source_name.clone()),
            account: p.account.clone(),
            resource: p.resource.clone(),
        };
        if !contributors.contains(&contributor) {
            contributors.push(contributor);
        }
    }
    let selected_native = selected.iter().map(|o| &o.native).collect::<Vec<_>>();
    let commitment = hash(
        b"PLATFORM::SIGNAL/correlation/D14-episode/v2\0",
        &codec::encode(
            &(
                "SIG-D14",
                &b.config.revision,
                b.config.partition,
                b.digest,
                selected_native,
            ),
            16384,
            c,
        )?,
    );
    let id = Uuid::new_v5(&Uuid::from_bytes(*b"SIGNAL-CORREL001"), &commitment);
    let event_ids = selected.iter().map(|o| o.event.id).collect::<Vec<_>>();
    let finding = if status == Status::Match {
        let f = Finding {
            schema_version: 1,
            id: Uuid::new_v5(&id, b"finding/v1"),
            rule_id: "SIG-D14".into(),
            created_at: end,
            severity: b.config.severity,
            title: b.config.title.clone(),
            event_ids: event_ids.clone(),
            attributes: serde_json::Map::from_iter([(
                "correlation".into(),
                serde_json::json!({"episode_id":id,"rule_revision":b.config.revision,"policy_sha256":b.digest,"coverage_gap":gap,"claim":"investigative_candidate"}),
            )]),
        };
        f.validate().map_err(|_| Error::Invalid)?;
        Some(f)
    } else {
        None
    };
    let e = Episode {
        schema_version: 2,
        id,
        rule_id: "SIG-D14".into(),
        rule_revision: b.config.revision.clone(),
        policy_sha256: b.digest,
        anchor: end,
        success_native: anchor.native.clone(),
        sealed_watermark: watermark,
        observation_count: observations.len(),
        coverage_degraded_through: degraded,
        status,
        coverage_gap: gap,
        reasons: if expired {
            vec!["expired_operation_history".into()]
        } else if gap {
            vec!["incomplete_runtime_policy_or_interval_history".into()]
        } else {
            vec![]
        },
        event_ids,
        originals: selected.iter().map(|o| o.event.clone()).collect(),
        contributors,
        verification: proofs.to_vec(),
        finding,
        runtime: Some(RuntimeEpisode {
            policy_coverage: policies.to_vec(),
            decisions,
        }),
    };
    codec::encode(&e, 65536, c)?;
    Ok(e)
}
