use super::*;
use chrono::Datelike;

/// Ephemeral input from a trusted source adapter. Construction checks bounds,
/// not provider identity, handle freshness or permission. Never serialize/log.
pub struct SourceDelivery {
    attempt: Uuid,
    delivery: String,
    handle: String,
}
impl SourceDelivery {
    pub fn new(attempt: Uuid, delivery: String, handle: String) -> Result<Self, ReceiptError> {
        if attempt.is_nil() || !bounded(&delivery, 128) || !bounded(&handle, 16 * 1024) {
            return Err(ReceiptError::Ack);
        }
        Ok(Self {
            attempt,
            delivery,
            handle,
        })
    }
}
fn bounded(s: &str, cap: usize) -> bool {
    !s.is_empty() && s.len() <= cap && !s.chars().any(char::is_control)
}
/// Returned only after durable intent publication. Its handle is in memory only.
/// The source adapter must use its authenticated transport; a ticket alone does
/// not attest current source permission. Owner transfer invalidates the ticket.
pub struct SourceAckTicket {
    receipt: [u8; 32],
    owner: Uuid,
    generation: u64,
    delivery: SourceDelivery,
}
impl SourceAckTicket {
    pub fn handle(&self) -> &str {
        &self.delivery.handle
    }
}
/// Narrow response-shape verification from an authenticated AWS JSON adapter.
/// Success does not prove deletion with a stale handle or exclude redelivery.
pub struct SourceAckOutcome(bool);
impl SourceAckOutcome {
    pub fn from_sqs_json_response(status: u16, body: &[u8]) -> Self {
        Self(status == 200 && body.is_empty())
    }
    pub fn uncertain() -> Self {
        Self(false)
    }
}
pub enum ReceiptAckUpdate {
    /// Calling this explicitly opts into the binding's process-local assurance.
    BeginProcessLocal {
        delivery: SourceDelivery,
        observed_at: String,
    },
    Finish {
        ticket: SourceAckTicket,
        outcome: SourceAckOutcome,
        observed_at: String,
    },
    /// Lost tickets/results must not be reconstructed from persisted IDs/handles.
    RecoverUncertain { observed_at: String },
}
pub enum ReceiptAckCommit {
    Intent {
        ticket: SourceAckTicket,
        progress: ReceiptProgress,
    },
    Settled(ReceiptProgress),
}
impl ReceiptAckUpdate {
    pub(super) fn validate_bounds(&self) -> Result<(), ReceiptError> {
        let observed = match self {
            Self::BeginProcessLocal { observed_at, .. }
            | Self::Finish { observed_at, .. }
            | Self::RecoverUncertain { observed_at } => observed_at,
        };
        if observed.len() != 30 {
            return Err(ReceiptError::Ack);
        }
        format::time(&Value::String(observed.clone()))?;
        Ok(())
    }
}
/// Validate frozen ACK shape during every reopen, including ACK-only controls.
pub(super) fn validate(value: &Value, r: &StoredReceipt) -> Result<(), ReceiptError> {
    let a = &value["ack"];
    if a.as_object().is_none_or(|a| a.len() != 4)
        || !["state", "attempt_id", "delivery_id", "observed_at"]
            .iter()
            .all(|k| a.get(k).is_some())
    {
        return Err(ReceiptError::Ack);
    }
    if a["state"] == "not_requested" {
        if !a["attempt_id"].is_null() || !a["delivery_id"].is_null() || !a["observed_at"].is_null()
        {
            return Err(ReceiptError::Ack);
        }
    } else {
        if !matches!(
            a["state"].as_str(),
            Some("intent" | "uncertain" | "confirmed")
        ) {
            return Err(ReceiptError::Ack);
        }
        format::uuid(&a["attempt_id"])?;
        if a["delivery_id"].as_str().is_none_or(|s| !bounded(s, 128))
            || format::time(&a["observed_at"])? < format::time(&r.metadata["prepared_at"])?
        {
            return Err(ReceiptError::Ack);
        }
        eligible(r)?;
        if r.metadata["binding"]["ack_requires_m2"] == true
            && value["verified_prefix"].as_u64() != Some(r.info.prepared_count as u64)
        {
            return Err(ReceiptError::Ack);
        }
        if a["state"] == "intent" {
            intent_budget(r, &a["observed_at"])?;
        }
    }
    Ok(())
}
fn eligible(r: &StoredReceipt) -> Result<(), ReceiptError> {
    if r.metadata["binding"]["custody_mode"] != "process_local"
        || r.metadata["object_disposition"] != "prepared"
        || r.info.prepared_count == 0
        || r.metadata["records"].as_array().is_none_or(|records| {
            records.iter().any(|r| {
                !matches!(
                    r["disposition"].as_str(),
                    Some("emit" | "emit_indeterminate")
                )
            })
        })
    {
        return Err(ReceiptError::Ack);
    }
    Ok(())
}
fn intent_budget(r: &StoredReceipt, observed: &Value) -> Result<(), ReceiptError> {
    let at = format::time(observed)?;
    let retention = &r.metadata["retention"];
    let budget = retention["recovery_budget_seconds"]
        .as_i64()
        .ok_or(ReceiptError::Ack)?;
    let end = at
        .checked_add_signed(chrono::Duration::seconds(budget))
        .ok_or(ReceiptError::Ack)?;
    if end.year() > 9999
        || end > format::time(&retention["retain_until"])?
        || end > format::time(&retention["source_replay_until"])?
    {
        return Err(ReceiptError::Ack);
    }
    Ok(())
}
pub(super) fn replacement(
    replay: &ReceiptReplay,
    update: ReceiptAckUpdate,
    owner: Uuid,
    generation: u64,
) -> Result<(ReceiptProgress, Option<SourceAckTicket>), ReceiptError> {
    eligible(&replay.receipt)?;
    let old = &replay.progress;
    let (observed_at, delivery, state) = match update {
        ReceiptAckUpdate::BeginProcessLocal {
            delivery,
            observed_at,
        } => {
            if old.value["ack"]["state"] == "intent"
                || old.value["ack"]["attempt_id"] == delivery.attempt.to_string()
                || (replay.receipt.metadata["binding"]["ack_requires_m2"] == true
                    && replay.remaining() != 0)
            {
                return Err(ReceiptError::Ack);
            }
            intent_budget(&replay.receipt, &Value::String(observed_at.clone()))?;
            (observed_at, Some(delivery), "intent")
        }
        ReceiptAckUpdate::Finish {
            ticket,
            outcome,
            observed_at,
        } => {
            if ticket.receipt != replay.receipt.info.checksum
                || ticket.owner != owner
                || ticket.generation != generation
                || old.value["ack"]["state"] != "intent"
                || old.value["ack"]["attempt_id"] != ticket.delivery.attempt.to_string()
                || old.value["ack"]["delivery_id"] != ticket.delivery.delivery
            {
                return Err(ReceiptError::Ack);
            }
            (
                observed_at,
                None,
                if outcome.0 { "confirmed" } else { "uncertain" },
            )
        }
        ReceiptAckUpdate::RecoverUncertain { observed_at } => {
            if old.value["ack"]["state"] != "intent" {
                return Err(ReceiptError::Ack);
            }
            (observed_at, None, "uncertain")
        }
    };
    let at = format::time(&Value::String(observed_at.clone()))?;
    if at < format::time(&replay.receipt.metadata["prepared_at"])?
        || (!old.value["ack"]["observed_at"].is_null()
            && at < format::time(&old.value["ack"]["observed_at"])?)
    {
        return Err(ReceiptError::Ack);
    }
    let mut p = old.value.clone();
    p["revision"] = old
        .revision()
        .checked_add(1)
        .ok_or(ReceiptError::Ack)?
        .into();
    p["previous_sha256"] = format::hex(&old.checksum()).into();
    p["attempt"] =
        serde_json::json!({"kind":"none","start":0,"count":0,"accepted":0,"response_sha256":null});
    p["ack"]["state"] = state.into();
    p["ack"]["observed_at"] = observed_at.into();
    if let Some(d) = &delivery {
        p["ack"]["attempt_id"] = d.attempt.to_string().into();
        p["ack"]["delivery_id"] = d.delivery.clone().into();
    }
    let next = progress::decode(progress::encode(&p)?, &replay.receipt, owner, generation)?;
    let ticket = delivery.map(|delivery| SourceAckTicket {
        receipt: replay.receipt.info.checksum,
        owner,
        generation,
        delivery,
    });
    Ok((next, ticket))
}
