use super::*;
use flate2::{Compression, write::GzEncoder};
use std::io::Write;
fn gzip(raw: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut g = GzEncoder::new(Vec::new(), Compression::fast());
    g.write_all(raw)?;
    g.finish()
}
fn plan(count: usize) -> Result<ReceiptPreparation, Box<dyn std::error::Error>> {
    let f = fixture()?;
    let m = &f["receipt_vectors"][0]["metadata"];
    let o = &m["original"];
    let t = &m["retention"];
    let text = |v: &Value| v.as_str().map(str::to_owned).ok_or("text");
    Ok(ReceiptPreparation {
        receipt_id: format::uuid(&m["receipt_id"])?,
        binding: ReceiptBinding::from_json(&format::canonical(&m["binding"], 65536)?)?,
        original: OriginalCapture {
            bucket: text(&o["bucket"])?,
            key: text(&o["key"])?,
            version_id: text(&o["version_id"])?,
            etag: o["etag"].as_str().map(str::to_owned),
            captured_at: format::time(&o["captured_at"])?,
            discovery_sha256: format::hash(&o["discovery_sha256"])?,
            delivery_id: text(&o["delivery_id"])?,
        },
        prepared_at: format::time(&m["prepared_at"])?,
        normalizer_sha256: format::hash(&m["normalizer_sha256"])?,
        retention: ReceiptRetention {
            retain_until: format::time(&t["retain_until"])?,
            source_replay_until: format::time(&t["source_replay_until"])?,
            recovery_budget_seconds: t["recovery_budget_seconds"].as_u64().ok_or("seconds")? as u32,
        },
        event_ids: (0..count)
            .map(|i| Uuid::from_u128(0x20000000000040008000000000000001 + i as u128))
            .collect(),
    })
}
fn original() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let f = fixture()?;
    unhex(
        f["receipt_vectors"][0]["original_hex"]
            .as_str()
            .ok_or("hex")?,
    )
}
#[test]
fn actual_fixture_object_preparation_is_repeatable_and_every_native_span_is_bound() -> TestResult {
    let original = original()?;
    let bytes = prepare_receipt(&original, plan(3)?, &ctx())?;
    assert_eq!(prepare_receipt(&original, plan(3)?, &ctx())?, bytes);
    let r = format::decode(bytes, &ctx())?;
    assert_eq!(r.original_bytes(), original);
    assert_eq!(r.info.prepared_count, 2);
    let object = crate::cloudtrail::read_object(&original, &ctx())?;
    let fixture = fixture()?;
    let expected = &fixture["receipt_vectors"][0]["metadata"];
    assert_eq!(r.metadata["binding"], expected["binding"]);
    assert_eq!(r.metadata["original"], expected["original"]);
    assert_eq!(r.metadata["records"].as_array().ok_or("records")?.len(), 3);
    for i in 0..3 {
        let raw = object.record(i).ok_or("record")?;
        let record = &r.metadata["records"][i];
        assert_eq!(record["sha256"], format::hex(&Sha256::digest(raw)));
        assert_eq!(record["start"], object.span(i).ok_or("span")?.start);
        assert_eq!(record["length"], raw.len());
        assert_eq!(
            record["native_event_id"],
            expected["records"][i]["native_event_id"]
        );
        if i < 2 {
            let e: Value = serde_json::from_slice(r.prepared_bytes(i).ok_or("event")?)?;
            assert_eq!(e["id"], plan(3)?.event_ids[i].to_string());
            assert_eq!(
                e["observed_at"]
                    .as_str()
                    .ok_or("observed")?
                    .parse::<chrono::DateTime<chrono::Utc>>()?,
                format::time(&r.metadata["prepared_at"])?
            );
            assert_eq!(
                e["attributes"]["evidence_ref"],
                format!("receipt://{}/record/{i}", r.info.id)
            );
        } else {
            assert_eq!(record["disposition"], "quarantine_record");
            assert!(record["prepared_id"].is_null());
        }
    }
    Ok(())
}
#[test]
fn malformed_compression_late_json_foreign_and_empty_objects_yield_original_only_quarantine()
-> TestResult {
    for (raw, reason) in [
        (b"bad gzip".to_vec(), "invalid_compression"),
        (
            gzip(b"{\"Records\":[{}, {\"x\":1,\"x\":2}]}")?,
            "invalid_object_json",
        ),
        (gzip(b"{\"Message\":\"foreign\"}")?, "unsupported_object"),
        (gzip(b"{\"Records\":[]}")?, "empty_records"),
        (gzip(b"{\"Records\":[{},]} ")?, "invalid_object_json"),
    ] {
        let r = format::decode(prepare_receipt(&raw, plan(3)?, &ctx())?, &ctx())?;
        assert_eq!(r.original_bytes(), raw);
        assert_eq!(r.info.prepared_count, 0);
        assert_eq!(r.metadata["object_disposition"], "quarantine_object");
        assert_eq!(r.metadata["object_reasons"], json!([reason]));
        assert_eq!(r.metadata["records"], json!([]));
    }
    Ok(())
}
#[test]
fn wrong_counts_ids_capture_namespace_version_and_times_fail_before_receipt_exposure() -> TestResult
{
    let raw = original()?;
    for key in [
        "count",
        "nil",
        "duplicate",
        "receipt",
        "namespace",
        "version",
        "capture",
        "horizon",
        "budget",
        "normalizer_time",
    ] {
        let mut p = plan(3)?;
        match key {
            "count" => {
                p.event_ids.pop();
            }
            "nil" => p.event_ids[0] = Uuid::nil(),
            "duplicate" => p.event_ids[1] = p.event_ids[0],
            "receipt" => p.receipt_id = Uuid::nil(),
            "namespace" => p.original.key = "foreign/unauthorized".into(),
            "version" => p.original.version_id = "null".into(),
            "capture" => p.original.captured_at = p.prepared_at + chrono::Duration::seconds(1),
            "horizon" => p.retention.retain_until = p.prepared_at,
            "budget" => p.retention.recovery_budget_seconds = 0,
            _ => {
                p.prepared_at =
                    chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 10000, 1, 1, 0, 0, 0)
                        .single()
                        .ok_or("calendar")?
            }
        }
        assert!(prepare_receipt(&raw, p, &ctx()).is_err(), "{key}");
    }
    assert!(prepare_receipt(&vec![0; 8 * 1024 * 1024 + 1], plan(0)?, &ctx()).is_err());
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let c = ExtensionContext::new(cancellation, Duration::from_secs(5))?;
    assert!(matches!(
        prepare_receipt(&raw, plan(3)?, &c),
        Err(PreparationError::Receipt(ReceiptError::Cancelled))
    ));
    Ok(())
}
#[tokio::test]
async fn prepared_publish_reopen_and_quarantine_ack_denial_preserve_exact_bytes() -> TestResult {
    for poison in [false, true] {
        let d = root()?;
        let raw = if poison {
            b"invalid compressed capture".to_vec()
        } else {
            original()?
        };
        let p = plan(3)?;
        let binding = p.binding.clone();
        let bytes = prepare_receipt(&raw, p, &ctx())?;
        let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
        s.publish(bytes.clone(), binding.clone(), ctx()).await?;
        let r = s.replay(binding.clone(), ctx()).await?.ok_or("r")?;
        let grant = ReceiptRecoveryGrant::from_trusted_checkpoint(
            binding.clone(),
            r.progress.checksum(),
            "trusted-independent-current".into(),
        )?;
        assert!(matches!(
            s.acknowledge(
                binding.clone(),
                r.progress,
                grant,
                ReceiptAckUpdate::BeginProcessLocal {
                    delivery: SourceDelivery::new(
                        Uuid::new_v4(),
                        "delivery".into(),
                        "handle".into()
                    )?,
                    observed_at: "2026-10-07T12:00:02.000000000Z".into()
                },
                ctx()
            )
            .await,
            Err(ReceiptError::Ack)
        ));
        s.close(ctx()).await?;
        let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
        let r = s.replay(binding, ctx()).await?.ok_or("r")?;
        assert_eq!(r.receipt.bytes, bytes);
        assert_eq!(r.receipt.original_bytes(), raw);
        s.close(ctx()).await?;
    }
    Ok(())
}

#[test]
fn event_observation_precision_and_offsets_match_instants_without_rewriting() -> TestResult {
    let raw = original()?;
    for at in [
        "2026-10-07T12:00:01.000000000Z",
        "2026-10-07T12:00:01.123456000Z",
        "2026-10-07T12:00:01.123456789Z",
    ] {
        let mut p = plan(3)?;
        p.prepared_at = format::time(&at.into())?;
        let wire = prepare_receipt(&raw, p, &ctx())?;
        let r = format::decode(wire.clone(), &ctx())?;
        let e: Value = serde_json::from_slice(r.prepared_bytes(0).ok_or("event")?)?;
        assert_eq!(
            e["observed_at"]
                .as_str()
                .ok_or("at")?
                .parse::<chrono::DateTime<chrono::Utc>>()?,
            format::time(&r.metadata["prepared_at"])?
        );
    }
    let same = changed_event(|e| e["observed_at"] = "2026-10-07T14:00:01+02:00".into())?;
    assert!(format::decode(same, &ctx()).is_ok());
    let different = changed_event(|e| e["observed_at"] = "2026-10-07T12:00:01.000000001Z".into())?;
    assert!(format::decode(different, &ctx()).is_err());
    Ok(())
}
#[test]
fn complete_object_record_count_and_byte_limits_quarantine_available_original() -> TestResult {
    for input in [
        format!("{{\"Records\":[\"{}\"]}}", "x".repeat(256 * 1024)),
        format!("{{\"Records\":[{}]}}", vec!["{}"; 1025].join(",")),
    ] {
        let raw = gzip(input.as_bytes())?;
        let r = format::decode(prepare_receipt(&raw, plan(0)?, &ctx())?, &ctx())?;
        assert_eq!(r.info.prepared_count, 0);
        assert_eq!(r.original_bytes(), raw);
        assert_eq!(
            r.metadata["object_reasons"],
            json!(["object_limits_exceeded"])
        );
    }
    Ok(())
}

#[test]
fn aggregate_prepared_payload_limit_discards_all_emission_frames() -> TestResult {
    let captured = original()?;
    let object = crate::cloudtrail::read_object(&captured, &ctx())?;
    let mut native: Value = serde_json::from_slice(object.record(0).ok_or("record")?)?;
    native["sourceIPAddress"] = "x".repeat(60 * 1024).into();
    let raw = gzip(&serde_json::to_vec(&json!({"Records": vec![native; 280]}))?)?;
    let context = ExtensionContext::new(CancellationToken::new(), Duration::from_secs(30))?;
    let r = format::decode(prepare_receipt(&raw, plan(280)?, &context)?, &context)?;
    assert_eq!(r.original_bytes(), raw);
    assert_eq!(r.info.prepared_count, 0);
    assert_eq!(r.metadata["object_disposition"], "quarantine_object");
    assert_eq!(
        r.metadata["object_reasons"],
        json!(["object_limits_exceeded"])
    );
    assert_eq!(r.metadata["records"], json!([]));
    Ok(())
}
