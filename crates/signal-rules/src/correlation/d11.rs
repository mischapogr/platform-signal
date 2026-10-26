use super::*;

pub(super) fn observation(
    source: &Source,
    event: &SignalEvent,
    proof: &VerificationEvidence,
    context: &RuleContext,
) -> Result<Observation, Error> {
    let bytes = codec::canonical(event, context)?;
    if event.source.source_type != source.source_type
        || event.source.name.as_deref() != Some(&source.source_name)
    {
        return Err(Error::Unverified);
    }
    let mut content = serde_json::to_value(event).map_err(|_| Error::Invalid)?;
    let object = content.as_object_mut().ok_or(Error::Invalid)?;
    object.remove("id");
    object.remove("observed_at");
    let content_sha256 = hash(
        b"PLATFORM::SIGNAL/correlation/native-content/v1\0",
        &codec::encode(&content, 65536, context)?,
    );
    let authentication = event.attributes.get("authentication");
    let text = |name: &str| {
        authentication
            .and_then(|a| a.get(name))
            .and_then(|v| v.as_str())
            .filter(|v| identity(v))
            .map(str::to_owned)
    };
    let profile = event
        .attributes
        .get("evidence")
        .and_then(|v| v.get("profile"))
        .and_then(|v| v.as_str())
        == Some("host-auth-json-v1");
    let key = match (
        text("identity_authority"),
        text("principal_id"),
        text("target_id"),
    ) {
        (Some(authority), Some(principal), Some(target))
            if authority == source.identity_authority =>
        {
            Some(Key {
                authority,
                principal,
                target,
            })
        }
        _ => None,
    };
    let success = match text("outcome").as_deref() {
        Some("success") if source.successes => Some(true),
        Some("failure") if source.failures => Some(false),
        _ => None,
    };
    let native = event.attributes.get("producer").and_then(|producer| {
        let boot = producer.get("boot_id")?.as_str()?.to_owned();
        if !identity(&boot) {
            return None;
        }
        Some(NativeId {
            stream: source.stream,
            boot,
            sequence: producer.get("sequence")?.as_u64()?,
        })
    });
    Ok(Observation {
        event: event.clone(),
        canonical_sha256: hash(b"PLATFORM::SIGNAL/correlation/input/v1\0", &bytes),
        native,
        content_sha256,
        key: if profile
            && text("session_id").is_some()
            && text("method").is_some_and(|m| {
                matches!(
                    m.as_str(),
                    "password" | "public_key" | "mfa" | "token" | "federated" | "other"
                )
            }) {
            key
        } else {
            None
        },
        success,
        verification: proof.clone(),
        admission_watermark: None,
        source_position: 0,
    })
}
pub(super) fn historical_proof(b: &Binding, p: &VerificationEvidence) -> Result<(), Error> {
    let s = b
        .config
        .sources
        .iter()
        .find(|s| s.stream == p.stream)
        .ok_or(Error::Conflict)?;
    if p.runtime.is_some()
        || p.source_binding != s.binding
        || p.source_config_revision != s.config_revision
        || p.authority_keys_sha256 != b.config.authority_keys_sha256
        || !identity(&p.verification_reference)
        || p.verified_at > p.assessed_at
        || p.assessed_at >= p.verified_until
        || p.coverage_from > p.frontier
        || p.frontier > p.assessed_at
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
pub(super) fn late(o: &Observation) -> bool {
    o.admission_watermark
        .is_some_and(|w| o.event.timestamp <= w)
}
pub(super) fn usable(o: &Observation) -> bool {
    o.native.is_some() && o.key.is_some() && o.success.is_some()
}
fn contributor(o: &Observation) -> Contributor {
    Contributor {
        stream: o.verification.stream,
        source_binding: o.verification.source_binding,
        source_type: o.event.source.source_type.clone(),
        source_name: o.event.source.name.clone(),
        account: o.event.resource.as_ref().and_then(|r| r.account_id.clone()),
        resource: o.event.resource.as_ref().map(|r| r.id.clone()),
    }
}
pub(super) fn episode(
    b: &Binding,
    observations: &[Observation],
    success_index: usize,
    watermark: DateTime<Utc>,
    proofs: &[VerificationEvidence],
    degraded_through: Option<DateTime<Utc>>,
    context: &RuleContext,
) -> Result<Episode, Error> {
    check(context)?;
    let success = observations.get(success_index).ok_or(Error::Conflict)?;
    let cfg = &b.config;
    let lower = success
        .event
        .timestamp
        .checked_sub_signed(TimeDelta::milliseconds(cfg.correlation_ms + cfg.window_ms))
        .ok_or(Error::Invalid)?;
    let expired = watermark.signed_duration_since(success.event.timestamp)
        > TimeDelta::milliseconds(cfg.ttl_ms);
    for proof in proofs {
        if observations
            .iter()
            .any(|o| o.verification.stream == proof.stream && o.source_position > proof.position)
        {
            return Err(Error::Conflict);
        }
    }
    let mut gap = expired
        || late(success)
        || !usable(success)
        || degraded_through.is_some_and(|t| success.event.timestamp <= t);
    let key = success.key.as_ref();
    if success.event.timestamp > watermark || proofs.len() > cfg.sources.len() {
        return Err(Error::Conflict);
    }
    let mut proof_streams = BTreeSet::new();
    for proof in proofs {
        if !proof_streams.insert(proof.stream) {
            return Err(Error::Conflict);
        }
    }
    for source in &cfg.sources {
        let proof = proofs
            .iter()
            .find(|p| p.stream == source.stream)
            .ok_or(Error::Conflict)?;
        let frontier = proof
            .frontier
            .checked_sub_signed(TimeDelta::milliseconds(cfg.lateness_ms))
            .ok_or(Error::Invalid)?;
        if watermark > frontier {
            return Err(Error::Conflict);
        }
    }

    for source in &cfg.sources {
        if key.is_some_and(|k| k.authority != source.identity_authority) {
            continue;
        }
        let p = proofs.iter().find(|p| p.stream == source.stream);
        gap |= p.is_none_or(|p| {
            !p.complete || p.coverage_from > lower || p.frontier < success.event.timestamp
        });
    }
    gap |= observations.iter().any(|o| {
        let relevant = o.event.timestamp >= lower && o.event.timestamp <= success.event.timestamp;
        let dropped = o
            .event
            .attributes
            .get("producer")
            .and_then(|p| p.get("dropped_events"))
            .and_then(|v| v.as_u64())
            .is_none_or(|n| n > 0);
        relevant && (!usable(o) || late(o) || dropped) && (o.key.as_ref() == key || o.key.is_none())
    });
    let mut failures: Vec<&Observation> = observations
        .iter()
        .filter(|o| {
            usable(o)
                && !late(o)
                && o.success == Some(false)
                && o.key.as_ref() == key
                && o.event.timestamp < success.event.timestamp
                && o.event.timestamp >= lower
        })
        .collect();
    failures.sort_by(|a, b| {
        a.event
            .timestamp
            .cmp(&b.event.timestamp)
            .then_with(|| a.native.cmp(&b.native))
    });
    let mut chosen = Vec::new();
    if usable(success) && !late(success) && !expired {
        for anchor in failures.iter().rev() {
            check(context)?;
            if success
                .event
                .timestamp
                .signed_duration_since(anchor.event.timestamp)
                > TimeDelta::milliseconds(cfg.correlation_ms)
            {
                break;
            }
            let start = anchor
                .event
                .timestamp
                .checked_sub_signed(TimeDelta::milliseconds(cfg.window_ms))
                .ok_or(Error::Invalid)?;
            let eligible: Vec<&Observation> = failures
                .iter()
                .copied()
                .filter(|o| {
                    o.event.timestamp >= start && o.event.timestamp <= anchor.event.timestamp
                })
                .collect();
            if eligible.len() >= cfg.threshold {
                chosen = eligible[eligible.len() - cfg.threshold..].to_vec();
                break;
            }
        }
    }
    gap |= observations.iter().any(|o| {
        usable(o)
            && o.success == Some(false)
            && o.key.as_ref() == key
            && o.event.timestamp == success.event.timestamp
    });
    let status = if !chosen.is_empty() {
        Status::Match
    } else if gap {
        Status::Indeterminate
    } else {
        Status::NoMatch
    };
    let mut selected = chosen.clone();
    selected.push(success);
    let native_ids: Vec<_> = selected.iter().map(|o| o.native.as_ref()).collect();
    let identity_fields = (
        "SIG-D11",
        &cfg.revision,
        cfg.partition,
        b.digest,
        key,
        success.native.as_ref(),
        &native_ids,
        if success.native.is_none() {
            Some(success.canonical_sha256)
        } else {
            None
        },
    );
    let episode_hash = hash(
        b"PLATFORM::SIGNAL/correlation/D11-episode/v1\0",
        &codec::encode(&identity_fields, 16384, context)?,
    );
    let id = Uuid::new_v5(&Uuid::from_bytes(*b"SIGNAL-CORREL001"), &episode_hash);
    let event_ids = selected.iter().map(|o| o.event.id).collect::<Vec<_>>();
    let mut contributors = Vec::new();
    for o in &selected {
        let c = contributor(o);
        if !contributors.contains(&c) {
            contributors.push(c);
        }
    }
    // Every configured proof contributes to the partition's minimum watermark.
    // Retain and authorize them all, even when only some carry selected events.
    let retained_proofs = proofs.to_vec();
    for proof in &retained_proofs {
        let source = b
            .config
            .sources
            .iter()
            .find(|s| s.stream == proof.stream)
            .ok_or(Error::Conflict)?;
        let scope = Contributor {
            stream: source.stream,
            source_binding: source.binding,
            source_type: source.source_type.clone(),
            source_name: Some(source.source_name.clone()),
            account: None,
            resource: None,
        };
        if !contributors.contains(&scope) {
            contributors.push(scope);
        }
    }
    let reasons = if expired {
        vec!["expired_history".into()]
    } else if !usable(success) {
        vec!["missing_native_identity_or_authentication_fields".into()]
    } else if gap {
        vec!["incomplete_lookback_or_late_or_dropped_input".into()]
    } else {
        vec![]
    };
    let finding = if status == Status::Match {
        let f = Finding {
            schema_version: 1,
            id: Uuid::new_v5(&id, b"finding/v1"),
            rule_id: "SIG-D11".into(),
            created_at: success.event.timestamp,
            severity: cfg.severity,
            title: cfg.title.clone(),
            event_ids: event_ids.clone(),
            attributes: serde_json::Map::from_iter([(
                "correlation".into(),
                serde_json::json!({"episode_id":id,"rule_revision":cfg.revision,"policy_sha256":b.digest,"coverage_gap":gap,"claim":"investigative_candidate"}),
            )]),
        };
        f.validate().map_err(|_| Error::Invalid)?;
        Some(f)
    } else {
        None
    };
    let out = Episode {
        schema_version: 1,
        id,
        rule_id: "SIG-D11".into(),
        rule_revision: cfg.revision.clone(),
        policy_sha256: b.digest,
        anchor: success.event.timestamp,
        success_native: success.native.clone(),
        sealed_watermark: watermark,
        observation_count: observations.len(),
        coverage_degraded_through: degraded_through,
        status,
        coverage_gap: gap,
        reasons,
        event_ids,
        originals: selected.iter().map(|o| o.event.clone()).collect(),
        contributors,
        verification: retained_proofs,
        finding,
    };
    codec::encode(&out, 65536, context)?;
    Ok(out)
}
