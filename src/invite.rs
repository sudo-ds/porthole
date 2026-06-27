//! Connection code: bundles everything a client needs — server address, pinned certificate
//! fingerprint, and shared secret — into one opaque, pasteable string so a non-technical
//! user never has to deal with certs/fingerprints/config by hand.

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

const PREFIX: &str = "porthole1_";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub secret: String,
}

impl ConnectionInfo {
    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Encode to a `porthole1_…` connection code.
pub fn encode(info: &ConnectionInfo) -> String {
    let json = serde_json::to_vec(info).expect("ConnectionInfo serializes");
    format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
}

/// Decode a `porthole1_…` connection code.
pub fn decode(code: &str) -> Result<ConnectionInfo> {
    let b64 = code
        .trim()
        .strip_prefix(PREFIX)
        .context("that doesn't look like a porthole connection code")?;
    let json = URL_SAFE_NO_PAD
        .decode(b64.as_bytes())
        .context("connection code is corrupted")?;
    serde_json::from_slice(&json).context("connection code has invalid contents")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ConnectionInfo {
        ConnectionInfo {
            host: "10xdev.sk".into(),
            port: 7835,
            fingerprint: "sha256:abc123".into(),
            secret: "s3cr3t".into(),
        }
    }

    #[test]
    fn roundtrip() {
        let info = sample();
        let code = encode(&info);
        assert!(code.starts_with(PREFIX));
        assert_eq!(decode(&code).unwrap(), info);
    }

    #[test]
    fn trims_whitespace() {
        let code = format!("  {}\n", encode(&sample()));
        assert_eq!(decode(&code).unwrap(), sample());
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode("hello").is_err());
        assert!(decode("porthole1_!!!notbase64!!!").is_err());
        assert!(decode("porthole1_").is_err());
    }
}
