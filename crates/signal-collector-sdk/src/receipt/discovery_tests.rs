use super::*;

fn binding() -> Result<ReceiptBinding, Box<dyn std::error::Error>> {
    Ok(vector("prepared")?.1)
}
pub(super) fn record() -> Value {
    json!({"eventVersion":"2.1","eventSource":"aws:s3","eventName":"ObjectCreated:Put",
        "s3":{"bucket":{"name":"fixture-source-evidence","ownerIdentity":{"principalId":"canonical-retail-not-account"}},
            "object":{"key":"AWSLogs%2Ffixture%2Fcaf%C3%A9+%2B+%25.json.gz","versionId":"fixture-version-001","size":393,"eTag":"opaque-not-a-sha256"}}})
}
fn discover(records: Vec<Value>) -> Result<ObjectDiscovery, DiscoveryError> {
    let bytes =
        serde_json::to_vec(&json!({"Records":records})).map_err(|_| DiscoveryError::Malformed)?;
    let binding = binding().map_err(|_| DiscoveryError::Scope)?;
    discover_object(&bytes, &binding, &ctx())
}

#[test]
fn direct_notification_identity_hash_and_exact_once_form_decoding() -> TestResult {
    let body = serde_json::to_vec(&json!({"Records":[record()]}))?;
    let b = binding()?;
    let d = discover_object(&body, &b, &ctx())?;
    assert_eq!(d.bucket(), "fixture-source-evidence");
    assert_eq!(d.key(), "AWSLogs/fixture/café + %.json.gz");
    assert_eq!(d.version_id(), "fixture-version-001");
    assert_eq!(d.etag(), Some("opaque-not-a-sha256"));
    assert_eq!(d.declared_size(), Some(393));
    assert_eq!(d.sha256(), <[u8; 32]>::from(Sha256::digest(&body)));
    assert_eq!(d.binding(), &b);
    let mut r = record();
    r["s3"]["object"]["key"] = "AWSLogs%2Ffixture%2F%252E%252E%252Fobj%2B.gz".into();
    assert_eq!(discover(vec![r])?.key(), "AWSLogs/fixture/%2E%2E%2Fobj+.gz");
    Ok(())
}

#[test]
fn version_minor_additions_and_four_created_kinds_are_supported() -> TestResult {
    for version in ["2.1", "2.2", "2.6", "2.10", "02.01"] {
        for kind in ["Put", "Post", "Copy", "CompleteMultipartUpload"] {
            let mut r = record();
            r["eventVersion"] = version.into();
            r["eventName"] = format!("ObjectCreated:{kind}").into();
            r["additive"] = json!({"url":"https://untrusted.invalid/never-fetch"});
            r["s3"]["object"]["size"] = u64::MAX.into();
            assert!(discover(vec![r]).is_ok());
        }
    }
    for version in [
        "2.0",
        "3.1",
        "1.6",
        "2",
        "2.1.0",
        "2.+1",
        "2.99999999999",
        "2.x",
    ] {
        let mut r = record();
        r["eventVersion"] = version.into();
        assert!(
            matches!(discover(vec![r]), Err(DiscoveryError::Unsupported)),
            "{version}"
        );
    }
    for kind in [
        "ObjectRemoved:Delete",
        "ObjectRestore:Completed",
        "s3:ObjectCreated:Put",
    ] {
        let mut r = record();
        r["eventName"] = kind.into();
        assert!(matches!(
            discover(vec![r]),
            Err(DiscoveryError::Unsupported)
        ));
    }
    Ok(())
}

#[test]
fn every_reference_validates_before_multi_reference_hold() -> TestResult {
    assert!(matches!(
        discover(vec![record(); 2]),
        Err(DiscoveryError::MultipleReferences)
    ));
    assert!(matches!(
        discover(vec![record(); 16]),
        Err(DiscoveryError::MultipleReferences)
    ));
    assert!(matches!(
        discover(vec![record(); 17]),
        Err(DiscoveryError::Limit)
    ));
    let mut records = vec![record(); 16];
    records[15]["s3"]["object"]["versionId"] = Value::Null;
    assert!(matches!(
        discover(records),
        Err(DiscoveryError::VersionRequired)
    ));
    assert!(matches!(
        discover(vec![record(), json!({})]),
        Err(DiscoveryError::Malformed)
    ));
    Ok(())
}

#[test]
fn unsupported_wrappers_test_empty_and_malformed_inputs_never_complete() -> TestResult {
    for body in [
        b"{\"Type\":\"Notification\",\"Message\":\"{\\\"Records\\\":[]}\"}".as_slice(),
        b"{\"Event\":\"s3:TestEvent\"}",
        b"{\"Records\":[]}",
        b"{\"detail\":{\"Records\":[]}}",
        b"{\"Records\":{}}",
    ] {
        assert!(matches!(
            discover_object(body, &binding()?, &ctx()),
            Err(DiscoveryError::Unsupported)
        ));
    }
    for body in [
        b"[]".as_slice(),
        b"",
        b"{\"Records\":[],\"Records\":[]}",
        b"{\"x\":1,\"\\u0078\":2}",
        b"{\"x\":1e999}",
        b"{\"x\":\"\xff\"}",
    ] {
        assert!(matches!(
            discover_object(body, &binding()?, &ctx()),
            Err(DiscoveryError::Malformed)
        ));
    }
    Ok(())
}

#[test]
fn scope_version_and_invalid_typed_fields_hold_source_responsibility() -> TestResult {
    for key in ["bucket", "prefix", "double_encoded_prefix"] {
        let mut r = record();
        match key {
            "bucket" => r["s3"]["bucket"]["name"] = "other-bucket".into(),
            "prefix" => r["s3"]["object"]["key"] = "AWSLogs%2Ffixture-other%2Fobj".into(),
            _ => r["s3"]["object"]["key"] = "AWSLogs%252Ffixture%252Fobj".into(),
        }
        assert!(matches!(discover(vec![r]), Err(DiscoveryError::Scope)));
    }
    for version in [
        json!(null),
        json!(""),
        json!("null"),
        json!(123),
        json!("x".repeat(1025)),
    ] {
        let mut r = record();
        r["s3"]["object"]["versionId"] = version;
        assert!(matches!(
            discover(vec![r]),
            Err(DiscoveryError::VersionRequired)
        ));
    }
    for key in [
        "AWSLogs/fixture/%",
        "AWSLogs/fixture/%GG",
        "AWSLogs/fixture/%FF",
    ] {
        let mut r = record();
        r["s3"]["object"]["key"] = key.into();
        assert!(matches!(discover(vec![r]), Err(DiscoveryError::Malformed)));
    }
    for size in [json!(-1), json!(1.5), json!("393"), json!(null)] {
        let mut r = record();
        r["s3"]["object"]["size"] = size;
        assert!(matches!(discover(vec![r]), Err(DiscoveryError::Malformed)));
    }
    Ok(())
}

#[test]
fn discovery_caps_keys_depth_nodes_and_actual_body_bytes() -> TestResult {
    let mut r = record();
    let suffix = "x".repeat(1024 - "AWSLogs/fixture/".len());
    r["s3"]["object"]["key"] = format!("AWSLogs/fixture/{suffix}").into();
    assert_eq!(discover(vec![r.clone()])?.key().len(), 1024);
    r["s3"]["object"]["key"] = format!("AWSLogs/fixture/{suffix}x").into();
    assert!(matches!(discover(vec![r]), Err(DiscoveryError::Limit)));
    let mut body = serde_json::to_vec(&json!({"Records":[record()]}))?;
    body.resize(MAX_DISCOVERY_BYTES, b' ');
    assert!(discover_object(&body, &binding()?, &ctx()).is_ok());
    body.push(b' ');
    assert!(matches!(
        discover_object(&body, &binding()?, &ctx()),
        Err(DiscoveryError::Limit)
    ));
    let mut r = record();
    r["additive"] = json!(vec![Value::Null; 17000]);
    assert!(matches!(discover(vec![r]), Err(DiscoveryError::Malformed)));
    let mut r = record();
    let mut deep = json!(null);
    for _ in 0..17 {
        deep = json!([deep]);
    }
    r["additive"] = deep;
    assert!(matches!(discover(vec![r]), Err(DiscoveryError::Malformed)));
    Ok(())
}

#[test]
fn cancel_deadline_and_bounded_diagnostics_before_discovery() -> TestResult {
    let token = CancellationToken::new();
    token.cancel();
    let context = ExtensionContext::new(token, Duration::from_secs(5))?;
    assert!(matches!(
        discover_object(b"secret", &binding()?, &context),
        Err(DiscoveryError::Operation(ReceiptError::Cancelled))
    ));
    let context = ExtensionContext::new(CancellationToken::new(), Duration::from_nanos(1))?;
    std::thread::sleep(Duration::from_millis(1));
    assert!(matches!(
        discover_object(b"secret", &binding()?, &context),
        Err(DiscoveryError::Operation(ReceiptError::Timeout))
    ));
    let error = discover_object(b"secret", &binding()?, &ctx())
        .err()
        .ok_or("error")?;
    assert!(!format!("{error:?} {error}").contains("secret"));
    Ok(())
}
