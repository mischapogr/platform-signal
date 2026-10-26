//! Explicitly invoked owned local-kind API qualification; no ambient credentials.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use signal_collector_sdk::{
    ExtensionContext,
    kubernetes_context::{
        Kind, Limits, Profile,
        client::{AccessToken, Collector, Error, TokenProvider},
    },
};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    origin: String,
    cluster: String,
    namespace: String,
    node: String,
    token_file: PathBuf,
    cluster_token_file: PathBuf,
    ca_file: PathBuf,
    output: PathBuf,
}
struct Tokens(String);
#[async_trait]
impl TokenProvider for Tokens {
    async fn token(&self, _: &ExtensionContext) -> Result<AccessToken, Error> {
        AccessToken::new(self.0.clone())
    }
}
fn read(path: &Path, max: u64) -> Vec<u8> {
    let mut v = Vec::new();
    fs::File::open(path)
        .unwrap()
        .take(max + 1)
        .read_to_end(&mut v)
        .unwrap();
    assert!(v.len() as u64 <= max);
    v
}
fn ctx() -> ExtensionContext {
    ExtensionContext::new(CancellationToken::new(), Duration::from_secs(25)).unwrap()
}
fn save(dir: &Path, name: &str, value: Value) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(format!("{name}.tmp")))
        .unwrap();
    f.write_all(&serde_json::to_vec(&value).unwrap()).unwrap();
    f.sync_all().unwrap();
    fs::rename(dir.join(format!("{name}.tmp")), dir.join(name)).unwrap();
}
fn collector(c: &Config, kind: Kind, namespace: Option<&str>, node: Option<&str>) -> Collector {
    let ca = read(&c.ca_file, 64 * 1024);
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&ca) {
        roots.add(cert.unwrap()).unwrap();
    }
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Collector::new(
        &c.origin,
        Profile::new(&c.cluster, kind, namespace, node, Limits::default()).unwrap(),
        tls,
        Sha256::digest(&ca).into(),
    )
    .unwrap()
}
fn object<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    v["collection"]["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["name"] == name)
}
#[tokio::test]
#[ignore = "requires exclusively owned local kind and private credential config"]
async fn owned_kind_scoped_api_and_metadata_churn() {
    let config =
        std::env::var_os("SIGNAL_K8S_CONTEXT_CONFIG").expect("owned configuration required");
    let c: Config = serde_json::from_slice(&read(Path::new(&config), 16384)).unwrap();
    let tokens = Tokens(
        String::from_utf8(read(&c.token_file, 4096))
            .unwrap_or_else(|_| panic!("owned token encoding invalid"))
            .trim()
            .into(),
    );
    let cluster_tokens = Tokens(
        String::from_utf8(read(&c.cluster_token_file, 4096))
            .unwrap_or_else(|_| panic!("owned token encoding invalid"))
            .trim()
            .into(),
    );
    let mut inventories = Vec::new();
    for kind in [
        Kind::Pod,
        Kind::Role,
        Kind::RoleBinding,
        Kind::Node,
        Kind::Namespace,
        Kind::ClusterRole,
        Kind::ClusterRoleBinding,
    ] {
        let namespaced = matches!(kind, Kind::Pod | Kind::Role | Kind::RoleBinding);
        let mut api = collector(&c, kind, namespaced.then_some(c.namespace.as_str()), None);
        api.list(if namespaced { &tokens } else { &cluster_tokens }, &ctx())
            .await
            .unwrap_or_else(|e| panic!("native {} list refused: {e}", kind.name()));
        let v = serde_json::to_value(api.snapshot()).unwrap();
        assert_eq!(v["collection"]["authoritative"], true);
        assert!(!v["collection"]["objects"].as_array().unwrap().is_empty());
        inventories.push(v);
    }
    for (kind, namespace) in [
        (Kind::Pod, Some("context-denied")),
        (Kind::Node, None),
        (Kind::ClusterRole, None),
    ] {
        let mut denied = collector(&c, kind, namespace, None);
        assert!(matches!(
            denied.list(&tokens, &ctx()).await,
            Err(Error::Permission)
        ));
        assert!(!denied.snapshot().collection.authoritative);
    }
    let mut invalid = collector(&c, Kind::Pod, Some(&c.namespace), None);
    assert!(matches!(
        invalid
            .list(&Tokens("invalid-owned-fixture-token".into()), &ctx())
            .await,
        Err(Error::Permission)
    ));
    let mut filtered = collector(&c, Kind::Pod, Some(&c.namespace), Some(&c.node));
    filtered.list(&tokens, &ctx()).await.unwrap();
    assert_eq!(filtered.snapshot().collection.objects.len(), 1);
    let mut pods = collector(&c, Kind::Pod, Some(&c.namespace), None);
    pods.list(&tokens, &ctx()).await.unwrap();
    let initial = serde_json::to_value(pods.snapshot()).unwrap();
    let old_uid = object(&initial, "sample-a").unwrap()["uid"].clone();
    save(&c.output, "pod-ready.json", json!({"ready":true}));
    let mut watch = pods.watch(&tokens, &ctx()).await.unwrap();
    loop {
        assert!(watch.next_frame().await.unwrap());
        let v = serde_json::to_value(watch.snapshot()).unwrap();
        if object(&v, "sample-a").is_some_and(|o| o["labels"]["revision"] == "changed") {
            save(&c.output, "pod-modified.json", v);
            break;
        }
    }
    loop {
        assert!(watch.next_frame().await.unwrap());
        let v = serde_json::to_value(watch.snapshot()).unwrap();
        if object(&v, "sample-a").is_none() {
            save(&c.output, "pod-deleted.json", v);
            break;
        }
    }
    loop {
        assert!(watch.next_frame().await.unwrap());
        let v = serde_json::to_value(watch.snapshot()).unwrap();
        if object(&v, "sample-a").is_some_and(|o| o["uid"] != old_uid) {
            save(&c.output, "pod-recreated.json", v);
            break;
        }
    }
    drop(watch);
    assert!(!pods.snapshot().collection.authoritative);
    pods.list(&tokens, &ctx()).await.unwrap();
    assert!(pods.snapshot().collection.authoritative);
    for (kind, ready, done, name) in [
        (
            Kind::Role,
            "role-ready.json",
            "role-modified.json",
            "workload-role",
        ),
        (
            Kind::RoleBinding,
            "binding-ready.json",
            "binding-modified.json",
            "workload-binding",
        ),
    ] {
        let mut api = collector(&c, kind, Some(&c.namespace), None);
        api.list(&tokens, &ctx()).await.unwrap();
        let old = serde_json::to_value(api.snapshot()).unwrap();
        let revision = object(&old, name).unwrap()["resource_version"].clone();
        save(&c.output, ready, json!({"ready":true}));
        let mut stream = api.watch(&tokens, &ctx()).await.unwrap();
        loop {
            assert!(stream.next_frame().await.unwrap());
            let v = serde_json::to_value(stream.snapshot()).unwrap();
            if object(&v, name).is_some_and(|o| o["resource_version"] != revision) {
                save(&c.output, done, v);
                break;
            }
        }
        drop(stream);
        assert!(!api.snapshot().collection.authoritative);
    }
    save(&c.output, "revoke-ready.json", json!({"ready":true}));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !c.output.join("revoked.json").exists() {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(matches!(
        pods.list(&tokens, &ctx()).await,
        Err(Error::Permission)
    ));
    let historical = serde_json::to_value(pods.snapshot()).unwrap();
    assert_eq!(historical["collection"]["authoritative"], false);
    assert!(object(&historical, "sample-a").is_some());
    save(
        &c.output,
        "report.json",
        json!({"schema_version":1,"status":"passed","inventories":inventories,"revoked_inventory":historical,"checks":{"seven_kinds":true,"namespace_denied":true,"cluster_denied":true,"invalid_token":true,"node_filter":true,"pod_modify_delete_recreate":true,"role_churn":true,"binding_churn":true,"drop_invalidates":true,"relist":true,"revocation_retains_history_without_authority":true}}),
    );
}
