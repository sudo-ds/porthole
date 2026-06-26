//! Bearer-token authentication. The token travels inside the TLS channel; we compare it
//! in constant time so a mismatch can't be timed.

use subtle::ConstantTimeEq;

/// Constant-time compare of the provided token against the expected secret.
pub fn verify_token(expected: &str, provided: &str) -> bool {
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_match_rejects_mismatch() {
        assert!(verify_token("hunter2", "hunter2"));
        assert!(!verify_token("hunter2", "hunter3"));
        assert!(!verify_token("hunter2", "hunter2x"));
        assert!(!verify_token("hunter2", ""));
    }
}
