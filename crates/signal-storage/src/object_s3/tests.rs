use super::*;
use crate::object_io::{ObjectIo, ObjectIoError, ObjectIoLimits};
use std::{collections::BTreeMap, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
mod publication;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Debug)]
struct Wire {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
struct Endpoint {
    url: String,
    task: Option<JoinHandle<std::result::Result<Vec<Wire>, String>>>,
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl Endpoint {
    async fn start(replies: Vec<Vec<u8>>) -> Result<Self> {
        Self::start_at("127.0.0.1:0", replies).await
    }
    async fn start_at(address: &str, replies: Vec<Vec<u8>>) -> Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let url = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut wires = Vec::new();
                for reply in replies {
                    let (mut socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
                    wires.push(read_wire(&mut socket).await?);
                    let _ = socket.write_all(&reply).await;
                    let _ = socket.shutdown().await;
                }
                Ok(wires)
            })
            .await
            .map_err(|_| "fixture total deadline".to_owned())?
        });
        Ok(Self {
            url,
            task: Some(task),
        })
    }
    async fn finish(&mut self) -> Result<Vec<Wire>> {
        let result = self.task.as_mut().ok_or("fixture task missing")?.await;
        self.task.take();
        Ok(result?.map_err(std::io::Error::other)?)
    }
}
async fn read_wire(socket: &mut TcpStream) -> std::result::Result<Wire, String> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= HEADER_BYTES {
            return Err("fixture request headers full".into());
        }
        header.push(socket.read_u8().await.map_err(|e| e.to_string())?);
    }
    let text = std::str::from_utf8(&header).map_err(|e| e.to_string())?;
    let mut lines = text.split("\r\n");
    let mut start = lines.next().ok_or("fixture start")?.split_whitespace();
    let method = start.next().ok_or("fixture method")?.to_owned();
    let target = start.next().ok_or("fixture target")?.to_owned();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|s| {
            s.split_once(':')
                .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        })
        .collect();
    let bytes = headers
        .get("content-length")
        .map_or(Ok(0), |s| s.parse::<usize>())
        .map_err(|e| e.to_string())?;
    if bytes > 8 * 1024 * 1024 {
        return Err("fixture request body full".into());
    }
    let mut body = vec![0; bytes];
    socket
        .read_exact(&mut body)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Wire {
        method,
        target,
        headers,
        body,
    })
}
fn context() -> OperationContext {
    OperationContext::new(Duration::from_secs(3))
}
fn credentials() -> S3Credentials {
    S3Credentials {
        access_key: "AKIDSYNTHETICQUERYFIXTURE".into(),
        secret_key: "synthetic-query-secret-never-use-in-aws".into(),
        session_token: Some("synthetic-query-token-never-log".into()),
    }
}
fn config(endpoint: &str) -> S3Config {
    S3Config {
        endpoint: endpoint.into(),
        region: "eu-central-1".into(),
        bucket: "synthetic-query-fixture".into(),
        max_object_bytes: 1024 * 1024,
        allow_loopback_http: true,
    }
}
fn io(endpoint: &str) -> Result<(ObjectIo, S3HttpObserver)> {
    let (store, observer) = build(&config(endpoint), &credentials())?;
    Ok((
        ObjectIo::remote(
            Arc::new(store),
            tokio::runtime::Handle::current(),
            ObjectIoLimits {
                bytes: 1024 * 1024,
                ..Default::default()
            },
        )?,
        observer,
    ))
}
fn reply(status: u16, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
fn object_headers() -> &'static str {
    "ETag: \"synthetic-query-v1\"\r\nx-amz-version-id: query-v1\r\nLast-Modified: Fri, 10 Jul 2026 19:30:00 GMT\r\n"
}
#[test]
fn explicit_endpoint_credentials_and_loopback_configuration_are_bounded() -> Result {
    let valid = config("http://127.0.0.1:12345");
    let secret = credentials();
    assert!(!format!("{secret:?}").contains(&secret.access_key));
    let (store, _) = build(&valid, &secret)?;
    for rendered in [format!("{store:?}"), format!("{:?}", store.credentials())] {
        assert!(!rendered.contains(&secret.access_key));
        assert!(!rendered.contains(&secret.secret_key));
        assert!(!rendered.contains(secret.session_token.as_deref().ok_or("token")?));
    }
    for endpoint in [
        "http://localhost:12345",
        "http://192.0.2.1:12345",
        "ftp://127.0.0.1",
        "https://user:password@example.invalid",
        "https://example.invalid/extra",
        "https://example.invalid/?token=sensitive",
    ] {
        assert!(matches!(
            build(&config(endpoint), &secret),
            Err(S3Error::Config)
        ));
    }
    let mut no_http = valid.clone();
    no_http.allow_loopback_http = false;
    assert!(matches!(build(&no_http, &secret), Err(S3Error::Config)));
    let mut oversize = valid;
    oversize.max_object_bytes = 1024 * 1024 * 1024 + 1;
    assert!(matches!(build(&oversize, &secret), Err(S3Error::Config)));
    Ok(())
}
#[tokio::test]
async fn literal_ipv6_endpoint_uses_ip_not_bracketed_dns_name() -> Result {
    let mut endpoint =
        Endpoint::start_at("[::1]:0", vec![reply(200, object_headers(), b"ipv6")]).await?;
    let (io, _) = io(&endpoint.url)?;
    let reference = crate::object_manifest::QueryObjectRef {
        key: "query/synthetic/data/ipv6.parquet".into(),
        bytes: 4,
        version: Some("query-v1".into()),
        etag: Some("\"synthetic-query-v1\"".into()),
        sha256: crate::object_manifest::sha256(b"ipv6"),
    };
    drop(io.read_exact(&reference, context()).await?);
    assert_eq!(endpoint.finish().await?.len(), 1);
    io.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn direct_backend_call_without_physical_scope_is_counted_and_denied() -> Result {
    use object_store::ObjectStoreExt;
    let (store, observer) = build(&config("http://127.0.0.1:1"), &credentials())?;
    assert!(
        store
            .head(&object_store::path::Path::from("query/no-scope"))
            .await
            .is_err()
    );
    assert_eq!(observer.metrics().depth, 0);
    assert_eq!(observer.metrics().requests, 0);
    assert_eq!(observer.metrics().rejected, 1);
    Ok(())
}
#[tokio::test]
async fn native_conditional_create_and_pinned_get_keep_wire_binding() -> Result {
    let mut endpoint = Endpoint::start(vec![
        reply(200, object_headers(), b""),
        reply(200, object_headers(), b"exact-query-object"),
    ])
    .await?;
    let (io, observer) = io(&endpoint.url)?;
    let key = "query/synthetic/data/date=2026-07-10/hour=19/fixture.parquet";
    let reference = io.create(key, b"exact-query-object", context()).await?;
    assert_eq!(reference.version.as_deref(), Some("query-v1"));
    let read = io.read_exact(&reference, context()).await?;
    assert_eq!(read.bytes(), b"exact-query-object");
    drop(read);
    let wires = endpoint.finish().await?;
    assert_eq!(wires.len(), 2);
    assert_eq!(
        wires[0].headers.get("if-none-match").map(String::as_str),
        Some("*")
    );
    assert_eq!(wires[0].body, b"exact-query-object");
    assert!(wires[1].target.contains("versionId=query-v1"));
    assert_eq!(
        wires[1].headers.get("if-match").map(String::as_str),
        reference.etag.as_deref()
    );
    for wire in &wires {
        assert!(wire.target.starts_with("/synthetic-query-fixture/"));
        assert_eq!(
            wire.headers.get("host").map(String::as_str),
            Url::parse(&endpoint.url)?.authority().into()
        );
        assert!(
            wire.headers
                .get("authorization")
                .is_some_and(|v| v.starts_with("AWS4-HMAC-SHA256 "))
        );
        assert_eq!(
            wire.headers.get("x-amz-security-token").map(String::as_str),
            Some("synthetic-query-token-never-log")
        );
        assert_eq!(
            wire.headers.get("connection").map(String::as_str),
            Some("close")
        );
    }
    assert_eq!(observer.metrics().depth, 0);
    assert_eq!(observer.metrics().requests, 2);
    io.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn list_pagination_is_bounded_and_preserves_continuation() -> Result {
    let key = "query/synthetic/data/a.parquet";
    let first = format!(
        "<ListBucketResult><Name>synthetic-query-fixture</Name><IsTruncated>true</IsTruncated><NextContinuationToken>next-page</NextContinuationToken><Contents><Key>{key}</Key><LastModified>2026-07-10T19:30:00Z</LastModified><ETag>\"listed-v1\"</ETag><Size>5</Size></Contents></ListBucketResult>"
    );
    let second = "<ListBucketResult><Name>synthetic-query-fixture</Name><IsTruncated>false</IsTruncated></ListBucketResult>";
    let mut endpoint = Endpoint::start(vec![
        reply(200, "Content-Type: application/xml\r\n", first.as_bytes()),
        reply(200, "Content-Type: application/xml\r\n", second.as_bytes()),
    ])
    .await?;
    let (io, observer) = io(&endpoint.url)?;
    let inventory = io.inventory("query/synthetic", context()).await?;
    assert_eq!(inventory.entries().len(), 1);
    assert_eq!(inventory.entries()[0].key, key);
    assert_eq!(inventory.entries()[0].sha256, [0; 32]);
    drop(inventory);
    let wires = endpoint.finish().await?;
    assert!(wires[1].target.contains("continuation-token=next-page"));
    assert_eq!(observer.metrics().requests, 2);
    io.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn oversized_xml_headers_chunked_body_and_malformed_success_fail_closed() -> Result {
    let excessive_xml = vec![b'x'; CONTROL_BYTES + 1];
    let long_header = format!("x-injected: {}\r\n", "a".repeat(HEADER_BYTES + 1));
    let mut chunked =
        b"HTTP/1.1 200 Fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    for _ in 0..33 {
        chunked.extend_from_slice(b"2000\r\n");
        chunked.extend_from_slice(&[b'x'; 8192]);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    for response in [
        reply(200, "", &excessive_xml),
        reply(200, &long_header, b""),
        chunked,
        reply(200, "", b"<malformed"),
    ] {
        let mut endpoint = Endpoint::start(vec![response]).await?;
        let (io, observer) = io(&endpoint.url)?;
        assert!(io.inventory("query/synthetic", context()).await.is_err());
        assert_eq!(observer.metrics().depth, 0);
        assert_eq!(io.metrics().depth, 0);
        endpoint.finish().await?;
        io.shutdown(context()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn denial_throttling_redirect_and_version_mismatch_never_fallback() -> Result {
    for status in [403, 429, 307] {
        let body = b"<Error><Code>AccessDenied</Code><Message>synthetic denial</Message></Error>";
        let mut endpoint = Endpoint::start(vec![reply(
            status,
            "Location: http://192.0.2.1/not-allowed\r\n",
            body,
        )])
        .await?;
        let (io, observer) = io(&endpoint.url)?;
        assert!(
            io.discover("query/synthetic/data/a.parquet", context())
                .await
                .is_err()
        );
        assert_eq!(observer.metrics().requests, 1);
        assert_eq!(endpoint.finish().await?.len(), 1);
        io.shutdown(context()).await?;
    }
    let mut endpoint = Endpoint::start(vec![reply(200, object_headers(), b""), reply(200, "ETag: \"synthetic-query-v1\"\r\nx-amz-version-id: wrong-version\r\nLast-Modified: Fri, 10 Jul 2026 19:30:00 GMT\r\n", b"exact-query-object")]).await?;
    let (io, _) = io(&endpoint.url)?;
    let reference = io
        .create(
            "query/synthetic/data/a.parquet",
            b"exact-query-object",
            context(),
        )
        .await?;
    assert_eq!(
        io.read_exact(&reference, context()).await.err(),
        Some(ObjectIoError::Condition)
    );
    assert_eq!(endpoint.finish().await?.len(), 2);
    io.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn cancellation_closes_owned_connection_before_releasing_physical_slot() -> Result {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let (entered, observed) = tokio::sync::oneshot::channel();
    let fixture = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
            read_wire(&mut socket).await?;
            let _ = entered.send(());
            let mut one = [0];
            let read = socket.read(&mut one).await.map_err(|e| e.to_string())?;
            if read != 0 {
                return Err("cancelled client sent unexpected bytes".into());
            }
            Ok::<_, String>(())
        })
        .await
        .map_err(|_| "fixture disconnect deadline".to_owned())?
    });
    let (io, observer) = io(&url)?;
    let io = Arc::new(io);
    let front = io.clone();
    let context = context();
    let cancelled = context.cancellation.clone();
    let request = tokio::spawn(async move {
        front
            .discover("query/synthetic/data/a.parquet", context)
            .await
    });
    observed.await?;
    assert_eq!(observer.metrics().depth, 1);
    cancelled.cancel();
    assert_eq!(request.await?.err(), Some(ObjectIoError::Cancelled));
    fixture.await?.map_err(std::io::Error::other)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while io.metrics().depth != 0 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(observer.metrics().depth, 0);
    assert_eq!(observer.metrics().rejected, 1);
    io.shutdown(self::context()).await?;
    Ok(())
}
