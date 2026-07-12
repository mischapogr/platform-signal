//! Bounded local certificate fixture shared by outbound transport regressions.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde_json::json;
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn openssl(root: &Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Reap(
        Command::new("openssl")
            .args(args)
            .current_dir(root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait()? {
            if !status.success() {
                return Err("synthetic TLS generation failed".into());
            }
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err("synthetic TLS generation deadline".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
pub(crate) fn pki(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for ca in ["original", "foreign"] {
        openssl(
            root,
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-keyout",
                &format!("{ca}.key"),
                "-out",
                &format!("{ca}.pem"),
                "-days",
                "1",
                "-subj",
                &format!("/CN=synthetic-{ca}"),
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        )?;
    }
    for (name, ca, usage, serial) in [
        ("server", "original", "serverAuth", "10"),
        ("client", "original", "clientAuth", "11"),
        ("foreign-client", "foreign", "clientAuth", "12"),
    ] {
        openssl(
            root,
            &[
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
                "-subj",
                &format!("/CN=synthetic-{name}"),
            ],
        )?;
        fs::write(
            root.join(format!("{name}.ext")),
            format!(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={usage}\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n"
            ),
        )?;
        openssl(
            root,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                &format!("{ca}.pem"),
                "-CAkey",
                &format!("{ca}.key"),
                "-set_serial",
                serial,
                "-days",
                "1",
                "-extfile",
                &format!("{name}.ext"),
                "-out",
                &format!("{name}.pem"),
            ],
        )?;
    }
    Ok(())
}
pub(crate) fn material(
    root: &Path,
    identity: &str,
    trust: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cert = CertificateDer::from_pem_file(root.join(format!("{identity}.pem")))?;
    let key = PrivateKeyDer::from_pem_file(root.join(format!("{identity}.key")))?;
    let ca = CertificateDer::from_pem_file(root.join(format!("{trust}.pem")))?;
    let wire = serde_json::to_vec(&json!({"schema_version":1,
        "certificate_chain_der_base64":[STANDARD.encode(cert.as_ref())],
        "private_key_der_base64":STANDARD.encode(key.secret_der()),
        "peer_roots_der_base64":[STANDARD.encode(ca.as_ref())]}))?;
    Ok(wire)
}
pub(crate) fn client_config(
    root: &Path,
    identity: &str,
    trust: &str,
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error>> {
    Ok(crate::transport::tls::from_private_json(&material(
        root, identity, trust,
    )?)?)
}
