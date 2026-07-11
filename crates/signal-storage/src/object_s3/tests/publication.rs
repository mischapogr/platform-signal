//! Finite native HTTP/S3 wire fixture, not disk durability or real AWS proof.
use super::*;
use crate::{
    StoredEvent,
    object_io::SmallOwnerConfig,
    object_publication::{ObjectPublisher, PublicationConfig},
};
use object_store::{ObjectStore, ObjectStoreExt};
use signal_event::IngestEvent;
use std::sync::atomic::{AtomicU8, Ordering};
use tempfile::TempDir;
use uuid::Uuid;

#[derive(Default, Debug)]
struct Stats {
    requests: usize,
    conditional_puts: usize,
    pinned_gets: usize,
    lists: usize,
    conditional_deletes: usize,
    removed_keys: Vec<String>,
    remaining_keys: Vec<String>,
}
struct NativeEndpoint {
    url: String,
    // 1 denied; 2 reply lost after effect; 3 replaced before delete;
    // 4 hidden current key with an older still-readable version; 5 GET denied.
    fault: Arc<AtomicU8>,
    delete_stage: Arc<AtomicU8>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<JoinHandle<std::result::Result<Stats, String>>>,
}
impl Drop for NativeEndpoint {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl NativeEndpoint {
    async fn start() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let fault = Arc::new(AtomicU8::new(0));
        let selected_fault = fault.clone();
        let delete_stage = Arc::new(AtomicU8::new(0));
        let observed_stage = delete_stage.clone();
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(15), async move {
                let mut objects: BTreeMap<String, (Vec<u8>, String, String)> = BTreeMap::new();
                let mut stats = Stats::default();
                let mut stored_bytes = 0usize;
                loop {
                    let accepted = tokio::select! {
                        _ = &mut stopped => {
                            stats.remaining_keys = objects.keys().cloned().collect();
                            return Ok(stats);
                        },
                        accepted = listener.accept() => accepted,
                    };
                    let (mut socket, _) = accepted.map_err(|e| e.to_string())?;
                    let wire = read_wire(&mut socket).await?;
                    if !wire.target.starts_with('/') { return Err("fixture requires origin-form".into()); }
                    stats.requests += 1;
                    if stats.requests > 128 { return Err("fixture request budget exhausted".into()); }
                    let uri = Url::parse(&format!("http://fixture{}", wire.target)).map_err(|e| e.to_string())?;
                    let key = unescape(uri.path().strip_prefix("/synthetic-query-fixture").ok_or("fixture bucket")?.trim_start_matches('/'))?;
                    let mut query: BTreeMap<String, String> = uri.query_pairs().map(|(k,v)| (k.into_owned(),v.into_owned())).collect();
                    let mode = selected_fault.load(Ordering::Acquire);
                    let response = if query.remove("list-type").as_deref() == Some("2") {
                        if wire.method != "GET" { return Err("fixture list method".into()); }
                        stats.lists += 1;
                        let prefix = query.get("prefix").map_or("", String::as_str);
                        let mut xml = "<ListBucketResult><Name>synthetic-query-fixture</Name><IsTruncated>false</IsTruncated>".to_owned();
                        for (key, (body, etag, _)) in objects.iter().filter(|(key,_)| key.starts_with(prefix)) {
                            if mode == 4 && key.contains("/data/") && key.contains("/hour=19/") { continue; }
                            // Keys are strictly decoded publisher-generated UUID/date/hour names.
                            if key.contains(['<', '>', '&']) { return Err("fixture XML key".into()); }
                            xml.push_str(&format!("<Contents><Key>{key}</Key><LastModified>2026-07-10T19:30:00Z</LastModified><ETag>{etag}</ETag><Size>{}</Size></Contents>",body.len()));
                        }
                        xml.push_str("</ListBucketResult>");
                        reply(200,"Content-Type: application/xml\r\n",xml.as_bytes())
                    } else if wire.method == "PUT" {
                        if wire.headers.get("if-none-match").map(String::as_str) != Some("*") { return Err("fixture non-conditional write".into()); }
                        stats.conditional_puts += 1;
                        if objects.contains_key(&key) {
                            reply(412, "", b"<Error><Code>PreconditionFailed</Code></Error>")
                        } else {
                            if objects.len() >= 16 || wire.body.len() > (8*1024*1024usize).saturating_sub(stored_bytes) { return Err("fixture object budget exhausted".into()); }
                            let etag = format!("\"{}\"", crate::object_manifest::sha256(&wire.body).iter().map(|b|format!("{b:02x}")).collect::<String>());
                            let version = format!("synthetic-v{}", stats.conditional_puts);
                            let headers = headers(&etag,&version);
                            stored_bytes += wire.body.len();
                            objects.insert(key,(wire.body,etag,version));
                            reply(200,&headers,b"")
                        }
                    } else if wire.method == "DELETE" {
                        if !key.starts_with("query/") || !key.contains("/data/") || !key.ends_with(".parquet") || !wire.body.is_empty() || query.len()!=1 || !query.contains_key("versionId") || wire.headers.contains_key("x-amz-bypass-governance-retention") || wire.headers.contains_key("x-amz-mfa") { return Err("fixture unsafe delete".into()); }
                        stats.conditional_deletes += 1;
                        if mode == 6 {
                            observed_stage.store(1,Ordering::Release);
                            let until = tokio::time::Instant::now()+Duration::from_secs(3);
                            while selected_fault.load(Ordering::Acquire)==6 && tokio::time::Instant::now()<until { tokio::time::sleep(Duration::from_millis(5)).await; }
                            reply(403,"",b"<Error><Code>AccessDenied</Code></Error>")
                        } else if mode == 1 { reply(403,"",b"<Error><Code>AccessDenied</Code></Error>") }
                        else {
                            if mode == 3 && let Some((_,etag,version)) = objects.get_mut(&key) {
                                *etag = "\"replaced-etag\"".into();
                                *version = "replacement-version".into();
                            }
                            match objects.get(&key) {
                                Some((_,etag,version)) if query.get("versionId")==Some(version) && wire.headers.get("if-match")==Some(etag) => {
                                    let (body,_,version) = objects.remove(&key).ok_or("fixture remove")?;
                                    stored_bytes -= body.len();
                                    stats.removed_keys.push(key);
                                    if mode == 7 {
                                        observed_stage.store(2,Ordering::Release);
                                        let until = tokio::time::Instant::now()+Duration::from_secs(3);
                                        while selected_fault.load(Ordering::Acquire)==7 && tokio::time::Instant::now()<until { tokio::time::sleep(Duration::from_millis(5)).await; }
                                        socket.shutdown().await.map_err(|e|e.to_string())?;
                                        continue;
                                    }
                                    if mode == 2 {
                                        selected_fault.store(0,Ordering::Release);
                                        socket.shutdown().await.map_err(|e|e.to_string())?;
                                        continue;
                                    }
                                    reply(204,&format!("x-amz-version-id: {version}\r\n"),b"")
                                }
                                _ => reply(412,"",b"<Error><Code>PreconditionFailed</Code></Error>"),
                            }
                        }
                    } else if wire.method == "GET" {
                        if mode == 5 && key.contains("/data/") && key.contains("/hour=19/") {
                            let response = reply(403,"",b"<Error><Code>AccessDenied</Code></Error>");
                            socket.write_all(&response).await.map_err(|e|e.to_string())?;
                            socket.shutdown().await.map_err(|e|e.to_string())?;
                            continue;
                        }
                        match objects.get(&key) {
                            None => reply(404,"", b"<Error><Code>NoSuchKey</Code></Error>"),
                            Some((body,etag,version)) => {
                                if query.get("versionId").is_some_and(|pin|pin != version) || wire.headers.get("if-match").is_some_and(|guard|guard != etag) {
                                    reply(412,"", b"<Error><Code>PreconditionFailed</Code></Error>")
                                } else {
                                    if query.get("versionId") == Some(version) { stats.pinned_gets += 1; }
                                    reply(200,&headers(etag,version),body)
                                }
                            }
                        }
                    } else { return Err("fixture unsupported method".into()); };
                    socket.write_all(&response).await.map_err(|e|e.to_string())?;
                    socket.shutdown().await.map_err(|e|e.to_string())?;
                }
            }).await.map_err(|_| "native fixture total deadline".to_owned())?.inspect_err(|e| eprintln!("native fixture refused: {e}"))
        });
        Ok(Self {
            url,
            fault,
            delete_stage,
            stop: Some(stop),
            task: Some(task),
        })
    }
    async fn finish(&mut self) -> Result<Stats> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let result = self.task.as_mut().ok_or("fixture task")?.await;
        self.task.take();
        Ok(result?.map_err(std::io::Error::other)?)
    }
}
fn headers(etag: &str, version: &str) -> String {
    format!(
        "ETag: {etag}\r\nx-amz-version-id: {version}\r\nLast-Modified: Fri, 10 Jul 2026 19:30:00 GMT\r\n"
    )
}
fn unescape(path: &str) -> std::result::Result<String, String> {
    if path.len() > 1024 {
        return Err("fixture key full".into());
    }
    let mut bytes = Vec::with_capacity(path.len());
    let mut input = path.as_bytes().iter().copied();
    while let Some(byte) = input.next() {
        bytes.push(if byte == b'%' {
            let first = input.next().ok_or("fixture escape")?;
            let second = input.next().ok_or("fixture escape")?;
            let first = (first as char).to_digit(16).ok_or("fixture escape")?;
            let second = (second as char).to_digit(16).ok_or("fixture escape")?;
            (first * 16 + second) as u8
        } else {
            byte
        });
    }
    String::from_utf8(bytes).map_err(|_| "fixture key UTF8".into())
}
async fn writer(endpoint: &str, owner: &SmallOwnerConfig) -> Result<ObjectPublisher> {
    let (store, _) = build(&config(endpoint), &credentials())?;
    let io = ObjectIo::open_small_remote(
        owner,
        Arc::new(store),
        tokio::runtime::Handle::current(),
        ObjectIoLimits::default(),
        context(),
    )
    .await?;
    Ok(ObjectPublisher::new(
        io,
        tokio::runtime::Handle::current(),
        PublicationConfig::default(),
    )?)
}
#[tokio::test]
async fn native_versionless_list_supports_second_commit_reopen_and_exact_replay() -> Result {
    let mut endpoint = NativeEndpoint::start().await?;
    let directory = TempDir::new()?;
    let owner = SmallOwnerConfig {
        directory: directory.path().to_path_buf(),
        stream_id: Uuid::new_v4(),
        backend_id: Uuid::new_v4(),
    };
    let mut rows = Vec::new();
    for (i, timestamp) in ["2026-07-10T19:30:00Z", "2026-07-10T20:30:00Z"]
        .into_iter()
        .enumerate()
    {
        let input: IngestEvent = serde_json::from_value(
            serde_json::json!({"timestamp":timestamp,"source":{"type":"synthetic"},"message":"native query fixture"}),
        )?;
        rows.push(StoredEvent {
            sequence: 7 + i as u64 * 2,
            event: input.normalize(chrono::Utc::now())?,
        });
    }
    let first = writer(&endpoint.url, &owner).await?;
    assert_eq!(first.append(&rows[..1], context()).await?.last_sequence, 7);
    assert_eq!(first.append(&rows[1..], context()).await?.last_sequence, 9);
    let snapshot = first.snapshot(context()).await?;
    assert_eq!(snapshot.manifests().len(), 2);
    assert!(snapshot.manifests().iter().all(|manifest| {
        manifest.reference.object.version.is_some()
            && manifest
                .manifest
                .files
                .iter()
                .all(|file| file.object.version.is_some())
    }));
    drop(snapshot);
    first.shutdown(context()).await?;
    drop(first);
    let reopened = writer(&endpoint.url, &owner).await?;
    let replay = reopened.append(&rows[..1], context()).await?;
    assert_eq!(
        (replay.last_sequence, replay.new_count, replay.replay_count),
        (7, 0, 1)
    );
    assert_eq!(reopened.metrics().high_water, 9);
    reopened.shutdown(context()).await?;
    let stats = endpoint.finish().await?;
    assert_eq!(stats.conditional_puts, 4);
    assert!(stats.lists >= 4 && stats.pinned_gets >= 8, "{stats:?}");
    Ok(())
}

fn retention_policy() -> crate::object_retention::RetentionPolicy {
    crate::object_retention::RetentionPolicy {
        schema_version: 1,
        raw_seconds: None,
        query_seconds: 3600,
        index_seconds: None,
        replay_seconds: 1800,
        evidence_reference_seconds: 7200,
        reader_seconds: 600,
        orphan_grace_seconds: 1800,
    }
}
fn checkpoint(owner: &SmallOwnerConfig) -> crate::object_retirement::RetirementCheckpoint {
    crate::object_retirement::RetirementCheckpoint {
        stream_id: owner.stream_id,
        checkpoint: 9,
    }
}
async fn reclaiming_writer(endpoint: &str, owner: &SmallOwnerConfig) -> Result<ObjectPublisher> {
    let (store, _) = build(&config(endpoint), &credentials())?;
    let (reclaimer, _) =
        build_retired_version_reclaimer(&config(endpoint), &credentials(), owner.stream_id)?;
    let io = ObjectIo::open_small_reclaiming(
        owner,
        Arc::new(store),
        reclaimer,
        tokio::runtime::Handle::current(),
        ObjectIoLimits::default(),
        context(),
    )
    .await?;
    Ok(ObjectPublisher::new(
        io,
        tokio::runtime::Handle::current(),
        PublicationConfig::default(),
    )?)
}
async fn retired_fixture(
    endpoint: &str,
    owner: &SmallOwnerConfig,
) -> Result<(ObjectPublisher, Vec<StoredEvent>, String, String)> {
    let writer = reclaiming_writer(endpoint, owner).await?;
    let mut rows = Vec::new();
    for (i, timestamp) in ["2026-07-10T19:30:00Z", "2026-07-10T20:30:00Z"]
        .into_iter()
        .enumerate()
    {
        let input: IngestEvent = serde_json::from_value(
            serde_json::json!({"timestamp":timestamp,"source":{"type":"synthetic"},"message":"retired native query fixture"}),
        )?;
        rows.push(StoredEvent {
            sequence: 7 + i as u64 * 2,
            event: input.normalize(chrono::Utc::now())?,
        });
    }
    writer.append(&rows[..1], context()).await?;
    writer.append(&rows[1..], context()).await?;
    let snapshot = writer.snapshot(context()).await?;
    let retired = snapshot.manifests()[0].manifest.files[0].object.key.clone();
    let live = snapshot.manifests()[1].manifest.files[0].object.key.clone();
    assert!(matches!(
        writer
            .reclaim_retired_query_data(checkpoint(owner), context())
            .await,
        Err(crate::StorageError::Busy)
    ));
    drop(snapshot);
    assert_eq!(
        writer
            .retire_query_prefix(
                &retention_policy(),
                checkpoint(owner),
                chrono::DateTime::parse_from_rfc3339("2026-07-10T21:00:00Z")?
                    .with_timezone(&chrono::Utc),
                context()
            )
            .await?,
        7
    );
    Ok((writer, rows, retired, live))
}
fn controls(owner: &SmallOwnerConfig) -> Result<BTreeMap<String, Vec<u8>>> {
    [
        "binding.json",
        "genesis.json",
        "head.json",
        "retirement.json",
    ]
    .into_iter()
    .filter(|name| owner.directory.join(name).exists())
    .map(|name| Ok((name.into(), std::fs::read(owner.directory.join(name))?)))
    .collect()
}
#[tokio::test]
async fn native_reclamation_exact_absence_reopen_and_hidden_pinned_version() -> Result {
    for hidden in [false, true] {
        let mut endpoint = NativeEndpoint::start().await?;
        let directory = TempDir::new()?;
        let owner = SmallOwnerConfig {
            directory: directory.path().to_path_buf(),
            stream_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
        };
        let (writer, rows, retired, live) = retired_fixture(&endpoint.url, &owner).await?;
        let before = controls(&owner)?;
        // Protected originals and unknown-age query orphans cannot be selected.
        let (store, _) = build(&config(&endpoint.url), &credentials())?;
        let raw = "protected/raw/synthetic-original";
        let orphan = crate::object_manifest::data_key(
            owner.stream_id,
            "2026-07-10",
            18,
            crate::object_manifest::sha256(b"unknown-age-orphan"),
        );
        {
            let ctx = context();
            let _scope = RequestScope::enter(&ctx)?;
            store
                .put_opts(
                    &object_store::path::Path::from(raw),
                    b"protected-original".to_vec().into(),
                    object_store::PutMode::Create.into(),
                )
                .await?;
            store
                .put_opts(
                    &object_store::path::Path::from(orphan.clone()),
                    b"unknown-age-orphan".to_vec().into(),
                    object_store::PutMode::Create.into(),
                )
                .await?;
        }
        drop(writer.snapshot(context()).await?);
        let before_bytes = writer.storage_metrics().disk_bytes;
        if hidden {
            endpoint.fault.store(4, Ordering::Release);
        }
        let report = writer
            .reclaim_retired_query_data(checkpoint(&owner), context())
            .await?;
        assert_eq!(
            (
                report.acknowledged_versions,
                report.observed_absent_versions
            ),
            (1, 0)
        );
        assert!(report.acknowledged_bytes > 0);
        let repeated = writer
            .reclaim_retired_query_data(checkpoint(&owner), context())
            .await?;
        assert_eq!(
            (
                repeated.acknowledged_versions,
                repeated.observed_absent_versions
            ),
            (0, 1)
        );
        assert_eq!(repeated.observed_absent_bytes, report.acknowledged_bytes);
        assert_eq!(controls(&owner)?, before);
        assert_eq!(writer.metrics().high_water, 9);
        assert_eq!(
            writer.storage_metrics().disk_bytes,
            before_bytes - report.acknowledged_bytes
        );
        assert!(matches!(
            writer.append(&rows[..1], context()).await,
            Err(crate::StorageError::InvalidBatch)
        ));
        writer.shutdown(context()).await?;
        drop(writer);
        let reopened = reclaiming_writer(&endpoint.url, &owner).await?;
        let snapshot = reopened.snapshot(context()).await?;
        assert_eq!(snapshot.retired_through(), 7);
        assert_eq!(snapshot.manifests().len(), 2);
        assert_eq!(snapshot.orphans().len(), 1);
        drop(snapshot);
        assert_eq!(reopened.metrics().high_water, 9);
        {
            let ctx = context();
            let _scope = RequestScope::enter(&ctx)?;
            assert_eq!(
                store
                    .get(&object_store::path::Path::from(raw))
                    .await?
                    .bytes()
                    .await?
                    .as_ref(),
                b"protected-original"
            );
            assert_eq!(
                store
                    .get(&object_store::path::Path::from(orphan.clone()))
                    .await?
                    .bytes()
                    .await?
                    .as_ref(),
                b"unknown-age-orphan"
            );
        }
        reopened.shutdown(context()).await?;
        drop(reopened);
        let stats = endpoint.finish().await?;
        assert_eq!(stats.conditional_deletes, 1, "{stats:?}");
        assert_eq!(stats.removed_keys, vec![retired]);
        assert!(stats.remaining_keys.contains(&live));
        assert!(
            stats.remaining_keys.contains(&raw.into()) && stats.remaining_keys.contains(&orphan)
        );
        assert_eq!(stats.remaining_keys.len(), 5);
    }
    Ok(())
}
#[tokio::test]
async fn native_reclamation_denied_replaced_and_lost_reply_recover_conservatively() -> Result {
    for fault in [1, 2, 3, 5] {
        let mut endpoint = NativeEndpoint::start().await?;
        let directory = TempDir::new()?;
        let owner = SmallOwnerConfig {
            directory: directory.path().to_path_buf(),
            stream_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
        };
        let (writer, _, retired, live) = retired_fixture(&endpoint.url, &owner).await?;
        let before = controls(&owner)?;
        let cancelled = context();
        cancelled.cancellation.cancel();
        assert!(matches!(
            writer
                .reclaim_retired_query_data(checkpoint(&owner), cancelled)
                .await,
            Err(crate::StorageError::Cancelled)
        ));
        let mut stale = checkpoint(&owner);
        stale.checkpoint = 6;
        assert!(
            writer
                .reclaim_retired_query_data(stale, context())
                .await
                .is_err()
        );
        endpoint.fault.store(fault, Ordering::Release);
        assert!(
            writer
                .reclaim_retired_query_data(checkpoint(&owner), context())
                .await
                .is_err()
        );
        assert_eq!(controls(&owner)?, before);
        assert_eq!(writer.metrics().depth, 0);
        assert_eq!(writer.metrics().high_water, 9);
        endpoint.fault.store(0, Ordering::Release);
        // Lost reply means effect is unknown, never acknowledged. Exact GET on
        // retry observes absence; replacement instead remains corrupt/held.
        if fault == 3 {
            assert!(
                writer
                    .reclaim_retired_query_data(checkpoint(&owner), context())
                    .await
                    .is_err()
            );
        } else {
            let retry = writer
                .reclaim_retired_query_data(checkpoint(&owner), context())
                .await?;
            assert_eq!(
                (retry.acknowledged_versions, retry.observed_absent_versions),
                if fault == 2 { (0, 1) } else { (1, 0) }
            );
        }
        assert_eq!(controls(&owner)?, before);
        writer.shutdown(context()).await?;
        drop(writer);
        let stats = endpoint.finish().await?;
        assert!(stats.remaining_keys.contains(&live));
        if fault == 3 {
            assert!(stats.removed_keys.is_empty() && stats.remaining_keys.contains(&retired));
        } else {
            assert_eq!(stats.removed_keys, vec![retired]);
        }
        assert_eq!(stats.conditional_deletes, if fault == 1 { 2 } else { 1 });
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "actual process-loss helper invoked by owned parent"]
async fn native_reclamation_process_helper() -> Result {
    let owner = SmallOwnerConfig {
        directory: std::env::var("SIGNAL_TEST_RECLAIM_CONTROL")?.into(),
        stream_id: Uuid::parse_str(&std::env::var("SIGNAL_TEST_RECLAIM_STREAM")?)?,
        backend_id: Uuid::parse_str(&std::env::var("SIGNAL_TEST_RECLAIM_BACKEND")?)?,
    };
    let writer = reclaiming_writer(&std::env::var("SIGNAL_TEST_RECLAIM_ENDPOINT")?, &owner).await?;
    writer
        .reclaim_retired_query_data(checkpoint(&owner), context())
        .await?;
    Err("helper unexpectedly completed before process loss".into())
}
#[cfg(unix)]
#[tokio::test]
async fn native_reclamation_actual_sigkill_before_and_after_effect_replays_exactly() -> Result {
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Child, Command, Stdio},
    };
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for fault in [6, 7] {
        let mut endpoint = NativeEndpoint::start().await?;
        let directory = TempDir::new()?;
        let owner = SmallOwnerConfig {
            directory: directory.path().to_path_buf(),
            stream_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
        };
        let (writer, _, retired, live) = retired_fixture(&endpoint.url, &owner).await?;
        let before = controls(&owner)?;
        writer.shutdown(context()).await?;
        drop(writer);
        endpoint.fault.store(fault, Ordering::Release);
        let mut child = OwnedChild(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "object_s3::tests::publication::native_reclamation_process_helper",
                    "--ignored",
                    "--nocapture",
                ])
                .env("SIGNAL_TEST_RECLAIM_CONTROL", &owner.directory)
                .env("SIGNAL_TEST_RECLAIM_STREAM", owner.stream_id.to_string())
                .env("SIGNAL_TEST_RECLAIM_BACKEND", owner.backend_id.to_string())
                .env("SIGNAL_TEST_RECLAIM_ENDPOINT", &endpoint.url)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        let until = tokio::time::Instant::now() + Duration::from_secs(3);
        while endpoint.delete_stage.load(Ordering::Acquire) == 0 {
            if child.0.try_wait()?.is_some() || tokio::time::Instant::now() >= until {
                return Err("native reclaim process witness unavailable".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            endpoint.delete_stage.load(Ordering::Acquire),
            if fault == 6 { 1 } else { 2 }
        );
        child.0.kill()?;
        assert_eq!(child.0.wait()?.signal(), Some(9));
        endpoint.fault.store(0, Ordering::Release);
        assert_eq!(controls(&owner)?, before);
        let reopened = reclaiming_writer(&endpoint.url, &owner).await?;
        let report = reopened
            .reclaim_retired_query_data(checkpoint(&owner), context())
            .await?;
        assert_eq!(
            (
                report.acknowledged_versions,
                report.observed_absent_versions
            ),
            if fault == 6 { (1, 0) } else { (0, 1) }
        );
        assert_eq!(reopened.retired_through(), 7);
        assert_eq!(reopened.metrics().high_water, 9);
        assert_eq!(controls(&owner)?, before);
        reopened.shutdown(context()).await?;
        drop(reopened);
        let stats = endpoint.finish().await?;
        assert_eq!(stats.removed_keys, vec![retired]);
        assert!(stats.remaining_keys.contains(&live));
        assert_eq!(stats.conditional_deletes, if fault == 6 { 2 } else { 1 });
    }
    Ok(())
}
