//! TLS setup: self-signed certificate generation, SHA-256 fingerprint, and a client-side
//! certificate verifier that pins the server's leaf certificate by fingerprint (so no CA,
//! domain, or Let's Encrypt is needed — the client trusts exactly one server cert).

use std::path::Path;
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::ServerSettings;

/// Hostname presented in the TLS handshake. Pinning ignores it, so it's a fixed placeholder.
pub const TLS_SERVER_NAME: &str = "porthole";

/// Build a TLS acceptor for the server, loading the cert/key from disk or generating a
/// self-signed pair on first run. Returns the acceptor and the cert's fingerprint string.
pub fn server_acceptor(settings: &ServerSettings) -> Result<(TlsAcceptor, String)> {
    let (certs, key) = load_or_generate(&settings.cert_path, &settings.key_path)?;
    let fingerprint = fingerprint_str(certs[0].as_ref());

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building server TLS config")?;

    Ok((TlsAcceptor::from(Arc::new(config)), fingerprint))
}

/// Build a TLS connector for the client that pins `fingerprint` (sha256:HEX).
pub fn client_connector(fingerprint: &str) -> Result<TlsConnector> {
    let pin = parse_fingerprint(fingerprint)?;
    let provider = rustls::crypto::ring::default_provider();
    let verifier = Arc::new(PinnedVerifier {
        pin,
        algs: provider.signature_verification_algorithms,
    });

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Owned [`ServerName`] for the client handshake (the verifier ignores it).
pub fn pinned_server_name() -> ServerName<'static> {
    ServerName::try_from(TLS_SERVER_NAME).expect("static server name is valid")
}

// ---------------------------------------------------------------------------
// Cert load / generate
// ---------------------------------------------------------------------------

fn load_or_generate(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    if cert_path.exists() && key_path.exists() {
        return load_pem(cert_path, key_path);
    }
    generate(cert_path, key_path)
}

fn load_pem(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_bytes =
        std::fs::read(cert_path).with_context(|| format!("reading {}", cert_path.display()))?;
    let certs = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certs in {}", cert_path.display()))?;
    ensure!(
        !certs.is_empty(),
        "no certificates in {}",
        cert_path.display()
    );

    let key_bytes =
        std::fs::read(key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .with_context(|| format!("parsing key in {}", key_path.display()))?
        .with_context(|| format!("no private key in {}", key_path.display()))?;

    Ok((certs, key))
}

fn generate(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certified = rcgen::generate_simple_self_signed(vec![TLS_SERVER_NAME.to_string()])
        .context("generating self-signed certificate")?;

    std::fs::write(cert_path, certified.cert.pem())
        .with_context(|| format!("writing {}", cert_path.display()))?;
    std::fs::write(key_path, certified.key_pair.serialize_pem())
        .with_context(|| format!("writing {}", key_path.display()))?;
    restrict_key_perms(key_path);

    let cert_der = certified.cert.der().clone();
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    Ok((vec![cert_der], key_der))
}

#[cfg(unix)]
fn restrict_key_perms(key_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_key_perms(_key_path: &Path) {}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/// `sha256:HEX` over the leaf certificate DER.
pub fn fingerprint_str(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    let mut hex = String::with_capacity(7 + 64);
    hex.push_str("sha256:");
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

fn parse_fingerprint(s: &str) -> Result<[u8; 32]> {
    let hex = s.trim().strip_prefix("sha256:").unwrap_or(s.trim());
    ensure!(
        hex.len() == 64,
        "fingerprint must be 64 hex chars (got {})",
        hex.len()
    );
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .context("invalid hex digit in fingerprint")?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Pinning verifier
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // Pin the leaf cert only; chain/SAN/hostname are intentionally ignored.
        let digest = Sha256::digest(end_entity.as_ref());
        if digest.as_slice() == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "server certificate fingerprint does not match the pinned value".into(),
            ))
        }
    }

    // Delegate signature checks to the crypto provider — NEVER stub these to Ok, or a
    // forged handshake from anyone holding a cert with the pinned fingerprint's public key
    // would be accepted.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_roundtrip() {
        let der = b"some certificate bytes";
        let fp = fingerprint_str(der);
        assert!(fp.starts_with("sha256:"));
        let parsed = parse_fingerprint(&fp).unwrap();
        assert_eq!(&parsed[..], &Sha256::digest(der)[..]);
    }

    #[test]
    fn fingerprint_parse_rejects_bad() {
        assert!(parse_fingerprint("sha256:xyz").is_err());
        assert!(parse_fingerprint("deadbeef").is_err());
    }

    #[test]
    fn generate_then_load_is_stable() {
        let dir = std::env::temp_dir().join(format!("porthole-tls-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("c.crt");
        let key = dir.join("c.key");
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);

        let (certs1, _k1) = load_or_generate(&cert, &key).unwrap();
        let fp1 = fingerprint_str(certs1[0].as_ref());
        // Second call loads from disk; fingerprint must be identical (stable pinning).
        let (certs2, _k2) = load_or_generate(&cert, &key).unwrap();
        let fp2 = fingerprint_str(certs2[0].as_ref());
        assert_eq!(fp1, fp2);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
