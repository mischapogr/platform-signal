//! Finite native HTTP/S3 wire fixture, not disk durability or real AWS proof.
use super::*;
use crate::{
    StoredEvent,
    object_io::SmallOwnerConfig,
    object_publication::{ObjectPublisher, PublicationConfig},
};
use signal_event::IngestEvent;
use tempfile::TempDir;
use uuid::Uuid;

#[derive(Default, Debug)]
struct Stats {
    requests: usize,
    conditional_puts: usize,
    pinned_gets: usize,
    lists: usize,
}
struct NativeEndpoint {
    url: String,
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
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(15), async move {
                let mut objects: BTreeMap<String, (Vec<u8>, String, String)> = BTreeMap::new();
                let mut stats = Stats::default();
                let mut stored_bytes = 0usize;
                loop {
                    let accepted = tokio::select! {
                        _ = &mut stopped => return Ok(stats),
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
                    let response = if query.remove("list-type").as_deref() == Some("2") {
                        if wire.method != "GET" { return Err("fixture list method".into()); }
                        stats.lists += 1;
                        let prefix = query.get("prefix").map_or("", String::as_str);
                        let mut xml = "<ListBucketResult><Name>synthetic-query-fixture</Name><IsTruncated>false</IsTruncated>".to_owned();
                        for (key, (body, etag, _)) in objects.iter().filter(|(key,_)| key.starts_with(prefix)) {
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
                            let version = format!("synthetic-v{}", objects.len()+1);
                            let headers = headers(&etag,&version);
                            stored_bytes += wire.body.len();
                            objects.insert(key,(wire.body,etag,version));
                            reply(200,&headers,b"")
                        }
                    } else if wire.method == "GET" {
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
