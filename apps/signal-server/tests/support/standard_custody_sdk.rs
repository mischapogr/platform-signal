use super::Result;
use signal_collector_sdk::{ExtensionContext, object_custody::ObjectCustodyClient};
use signal_protocol::object_custody::Description;
use std::{fs, path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;
pub(super) async fn qualify() -> Result {
    let root = PathBuf::from(std::env::var("SIGNAL_STANDARD_ROOT")?);
    let mode = std::env::var("SIGNAL_STANDARD_CUSTODY_MODE")?;
    let bytes = fs::read(root.join("custody-description.json"))?;
    assert!(bytes.len() <= 4096);
    let description: Description = serde_json::from_slice(&bytes)?;
    let original = root.join("producer-original");
    assert_eq!(fs::read(&original)?, b"body");
    let material = fs::read(std::env::var("SIGNAL_STANDARD_CUSTODY_TLS")?)?;
    let tls = signal_collector_sdk::transport::tls::from_private_json(&material)?;
    let client = ObjectCustodyClient::new(
        &std::env::var("SIGNAL_STANDARD_CUSTODY_ENDPOINT")?,
        if mode == "deny" {
            "global"
        } else {
            "custodian"
        },
        Duration::from_secs(1),
        Some(tls),
        false,
    )?;
    let ctx = ExtensionContext::new(CancellationToken::new(), Duration::from_secs(5))?;
    let result = client.confirm(&description, &ctx).await;
    match mode.as_str() {
        "deny" | "offline" => {
            assert!(result.is_err());
            assert_eq!(fs::read(&original)?, b"body");
        }
        "confirm" | "release" => {
            let permit = result?;
            let confirmation = permit.checked_confirmation()?;
            assert_eq!(confirmation.description, description);
            let label = std::env::var("SIGNAL_STANDARD_CUSTODY_LABEL")?;
            assert!(matches!(label.as_str(), "first" | "restart-fresh"));
            fs::write(
                root.join(format!("custody-{label}.json")),
                serde_json::to_vec(confirmation)?,
            )?;
            if mode == "release" {
                permit.checked_confirmation()?;
                fs::remove_file(&original)?;
            }
        }
        _ => return Err("owned fixture mode".into()),
    }
    eprintln!("phase: actual-Standard-mounted-custody-SDK-mTLS-original-retention-qualified");
    Ok(())
}
