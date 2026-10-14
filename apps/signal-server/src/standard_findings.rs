//! First-occurrence reconciliation for the bounded Standard WINDOW batch.
use signal_control::{ControlError, FindingInput};
use signal_findings::ScopedFinding;

pub(super) struct Batch {
    pub scoped: Vec<(u64, ScopedFinding)>,
    pub legacy: Vec<FindingInput>,
    pub candidates: Vec<FindingInput>,
}

pub(super) fn reconcile(
    mut derived: Vec<(u64, ScopedFinding)>,
    legacy: Vec<FindingInput>,
) -> Result<Batch, ControlError> {
    let mut candidates = std::collections::BTreeMap::new();
    let mut distinct = Vec::with_capacity(derived.len());
    for (sequence, finding) in derived {
        let bytes = serde_json::to_vec(finding.finding()).map_err(|_| ControlError::Invalid)?;
        match candidates.entry(finding.finding().id) {
            std::collections::btree_map::Entry::Occupied(old) => {
                if old.get() != &bytes {
                    return Err(ControlError::Conflict);
                }
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(bytes);
                distinct.push((sequence, finding));
            }
        }
    }
    derived = distinct;
    let mut distinct = Vec::with_capacity(legacy.len());
    for finding in legacy {
        match candidates.entry(finding.id) {
            std::collections::btree_map::Entry::Occupied(mut old) => {
                let mut original: signal_findings::Finding =
                    serde_json::from_slice(old.get()).map_err(|_| ControlError::Corrupt)?;
                original.attributes.remove("signal.scope.v1");
                let repeated: signal_findings::Finding =
                    serde_json::from_slice(&finding.bytes).map_err(|_| ControlError::Corrupt)?;
                if original != repeated {
                    return Err(ControlError::Conflict);
                }
                // An older unscoped occurrence in this batch wins
                // over a later authenticated retry of the same ID.
                if derived
                    .iter()
                    .any(|(_, scoped)| scoped.finding().id == finding.id)
                {
                    derived.retain(|(_, scoped)| scoped.finding().id != finding.id);
                    old.insert(finding.bytes.clone());
                    distinct.push(finding);
                }
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(finding.bytes.clone());
                distinct.push(finding);
            }
        }
    }
    let legacy = distinct;
    let candidates = candidates
        .into_iter()
        .map(|(id, bytes)| signal_control::FindingInput { id, bytes })
        .collect::<Vec<_>>();
    Ok(Batch {
        scoped: derived,
        legacy,
        candidates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_event::SignalEvent;
    use signal_findings::{DerivedFinding, DetectionSeverity, Finding};
    use uuid::Uuid;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn event(id: u128) -> Result<SignalEvent> {
        Ok(serde_json::from_value(serde_json::json!({
            "schema_version":1,"id":Uuid::from_u128(id),
            "timestamp":"2026-10-15T00:00:00Z","observed_at":"2026-10-15T00:00:00Z",
            "source":{"type":"fixture"},"severity":"info","message":"fixture",
            "attributes":{},"tags":[]
        }))?)
    }
    fn base(event: &SignalEvent, title: &str) -> Result<Finding> {
        Ok(Finding::for_event(
            "fixture-rule",
            event,
            DetectionSeverity::High,
            title,
        )?)
    }
    fn scoped(event: &SignalEvent, title: &str, generation: u128) -> Result<ScopedFinding> {
        Ok(
            DerivedFinding::from_event(base(event, title)?, event, true)?
                .into_scoped(Uuid::from_u128(generation))?,
        )
    }
    fn legacy(event: &SignalEvent, title: &str, pretty: bool) -> Result<FindingInput> {
        let finding = base(event, title)?;
        let bytes = if pretty {
            serde_json::to_vec_pretty(&finding)?
        } else {
            serde_json::to_vec(&finding)?
        };
        Ok(FindingInput {
            id: finding.id,
            bytes,
        })
    }

    #[test]
    fn scoped_retry_keeps_first_sequence_and_exact_payload() -> Result {
        let event = event(1)?;
        let first = scoped(&event, "Fixture", 2)?;
        let original = serde_json::to_vec(first.finding())?;
        let batch = reconcile(
            vec![(7, first), (11, scoped(&event, "Fixture", 2)?)],
            vec![],
        )?;
        assert_eq!(batch.scoped.len(), 1);
        assert_eq!(batch.scoped[0].0, 7);
        assert_eq!(serde_json::to_vec(batch.scoped[0].1.finding())?, original);
        assert!(batch.legacy.is_empty());
        assert_eq!(batch.candidates.len(), 1);
        assert_eq!(batch.candidates[0].bytes, original);
        Ok(())
    }

    #[test]
    fn unknown_scope_wins_retry_and_keeps_original_wire_bytes() -> Result {
        let event = event(1)?;
        let first = legacy(&event, "Fixture", true)?;
        let expected = first.clone();
        let batch = reconcile(
            vec![(11, scoped(&event, "Fixture", 2)?)],
            vec![first, legacy(&event, "Fixture", false)?],
        )?;
        assert!(batch.scoped.is_empty());
        assert_eq!(batch.legacy, vec![expected.clone()]);
        assert_eq!(batch.candidates, vec![expected]);
        let finding: Finding = serde_json::from_slice(&batch.legacy[0].bytes)?;
        assert!(!finding.attributes.contains_key("signal.scope.v1"));
        Ok(())
    }

    #[test]
    fn repeated_unknown_scope_keeps_first_encoding_and_distinct_rows() -> Result {
        let first_event = event(1)?;
        let second_event = event(2)?;
        let first = legacy(&first_event, "Fixture", true)?;
        let second = legacy(&second_event, "Fixture", false)?;
        let batch = reconcile(
            vec![],
            vec![
                first.clone(),
                legacy(&first_event, "Fixture", false)?,
                second.clone(),
            ],
        )?;
        assert!(batch.scoped.is_empty());
        assert_eq!(batch.legacy, vec![first.clone(), second.clone()]);
        assert_eq!(batch.candidates.len(), 2);
        assert!(batch.candidates.contains(&first));
        assert!(batch.candidates.contains(&second));
        Ok(())
    }

    #[test]
    fn same_id_changed_body_refuses_scoped_and_unknown_retries() -> Result {
        let event = event(1)?;
        assert!(matches!(
            reconcile(
                vec![
                    (7, scoped(&event, "Original", 2)?),
                    (11, scoped(&event, "Changed", 2)?)
                ],
                vec![]
            ),
            Err(ControlError::Conflict)
        ));
        assert!(matches!(
            reconcile(
                vec![],
                vec![
                    legacy(&event, "Original", true)?,
                    legacy(&event, "Changed", false)?
                ]
            ),
            Err(ControlError::Conflict)
        ));
        assert!(matches!(
            reconcile(
                vec![(11, scoped(&event, "Changed", 2)?)],
                vec![legacy(&event, "Original", true)?]
            ),
            Err(ControlError::Conflict)
        ));
        Ok(())
    }

    #[test]
    fn same_id_changed_generation_or_canonical_scope_refuses_retry() -> Result {
        let original = event(1)?;
        assert!(matches!(
            reconcile(
                vec![
                    (7, scoped(&original, "Fixture", 2)?),
                    (11, scoped(&original, "Fixture", 3)?)
                ],
                vec![]
            ),
            Err(ControlError::Conflict)
        ));
        let mut changed = original.clone();
        changed
            .attributes
            .insert("account_id".into(), serde_json::json!("other-fixture"));
        // Source facts enter the canonical binding, even when the base finding is identical.
        changed.source = serde_json::from_value(serde_json::json!({"type":"other-fixture"}))?;
        assert!(matches!(
            reconcile(
                vec![
                    (7, scoped(&original, "Fixture", 2)?),
                    (11, scoped(&changed, "Fixture", 2)?)
                ],
                vec![]
            ),
            Err(ControlError::Conflict)
        ));
        Ok(())
    }

    #[test]
    fn malformed_duplicate_wire_bytes_refuse_whole_batch() -> Result {
        let event = event(1)?;
        let mut malformed = legacy(&event, "Fixture", false)?;
        malformed.bytes = b"{".to_vec();
        assert!(matches!(
            reconcile(vec![(11, scoped(&event, "Fixture", 2)?)], vec![malformed]),
            Err(ControlError::Corrupt)
        ));
        Ok(())
    }
}
