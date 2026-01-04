//! CTF Flag Generation
//!
//! HMAC-SHA1 based flag generation for unique, verifiable flags.

use crate::crypto::hmac;

/// Flag generator using HMAC-SHA1
pub struct FlagGenerator {
    /// Secret key for HMAC
    secret: Vec<u8>,
    /// Flag prefix (e.g., "CTF{", "flag{")
    prefix: String,
    /// Flag suffix (e.g., "}")
    suffix: String,
}

impl FlagGenerator {
    /// Create new flag generator with secret
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            prefix: "flag{".to_string(),
            suffix: "}".to_string(),
        }
    }

    /// Set flag prefix
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = prefix.to_string();
        self
    }

    /// Set flag suffix
    pub fn with_suffix(mut self, suffix: &str) -> Self {
        self.suffix = suffix.to_string();
        self
    }

    /// Generate flag for challenge name
    pub fn generate(&self, challenge_name: &str) -> String {
        let hmac_result = hmac::hmac_sha1(&self.secret, challenge_name.as_bytes());
        let hex = hex_encode(&hmac_result);
        format!("{}{}{}", self.prefix, hex, self.suffix)
    }

    /// Generate shortened flag (first 16 chars of HMAC)
    pub fn generate_short(&self, challenge_name: &str) -> String {
        let hmac_result = hmac::hmac_sha1(&self.secret, challenge_name.as_bytes());
        let hex = hex_encode(&hmac_result);
        format!("{}{}{}", self.prefix, &hex[..16], self.suffix)
    }
}

/// Flag verifier for constant-time comparison
pub struct FlagVerifier {
    /// Secret keys (supports rotation)
    secrets: Vec<Vec<u8>>,
    /// Flag prefix
    prefix: String,
    /// Flag suffix
    suffix: String,
}

impl FlagVerifier {
    /// Create new verifier with single secret
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secrets: vec![secret.to_vec()],
            prefix: "flag{".to_string(),
            suffix: "}".to_string(),
        }
    }

    /// Add additional secret for rotation
    pub fn add_secret(mut self, secret: &[u8]) -> Self {
        self.secrets.push(secret.to_vec());
        self
    }

    /// Set flag prefix
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = prefix.to_string();
        self
    }

    /// Set flag suffix
    pub fn with_suffix(mut self, suffix: &str) -> Self {
        self.suffix = suffix.to_string();
        self
    }

    /// Verify submitted flag against challenge name
    pub fn verify(&self, challenge_name: &str, submitted_flag: &str) -> bool {
        // Extract hash from submitted flag
        let submitted_hash =
            if submitted_flag.starts_with(&self.prefix) && submitted_flag.ends_with(&self.suffix) {
                &submitted_flag[self.prefix.len()..submitted_flag.len() - self.suffix.len()]
            } else {
                submitted_flag
            };

        // Try all secrets (for key rotation)
        for secret in &self.secrets {
            let expected_hmac = hmac::hmac_sha1(secret, challenge_name.as_bytes());
            let expected_hex = hex_encode(&expected_hmac);

            // Constant-time comparison
            if constant_time_eq(submitted_hash.as_bytes(), expected_hex.as_bytes()) {
                return true;
            }

            // Also check short version
            if constant_time_eq(submitted_hash.as_bytes(), expected_hex[..16].as_bytes()) {
                return true;
            }
        }

        false
    }
}

/// Constant-time byte comparison (prevents timing attacks)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Hex encode bytes
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX_CHARS[(byte >> 4) as usize] as char);
        result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_generation() {
        let gen = FlagGenerator::new(b"secret_key");
        let flag = gen.generate("web-challenge-1");

        assert!(flag.starts_with("flag{"));
        assert!(flag.ends_with("}"));
        assert_eq!(flag.len(), 5 + 40 + 1); // prefix + 40 hex chars + suffix
    }

    #[test]
    fn test_flag_generation_short() {
        let gen = FlagGenerator::new(b"secret_key");
        let flag = gen.generate_short("web-challenge-1");

        assert!(flag.starts_with("flag{"));
        assert!(flag.ends_with("}"));
        assert_eq!(flag.len(), 5 + 16 + 1); // prefix + 16 hex chars + suffix
    }

    #[test]
    fn test_flag_verification() {
        let gen = FlagGenerator::new(b"secret_key");
        let verifier = FlagVerifier::new(b"secret_key");

        let flag = gen.generate("web-challenge-1");
        assert!(verifier.verify("web-challenge-1", &flag));
        assert!(!verifier.verify("wrong-challenge", &flag));
    }

    #[test]
    fn test_flag_verification_short() {
        let gen = FlagGenerator::new(b"secret_key");
        let verifier = FlagVerifier::new(b"secret_key");

        let flag = gen.generate_short("web-challenge-1");
        assert!(verifier.verify("web-challenge-1", &flag));
    }

    #[test]
    fn test_custom_prefix() {
        let gen = FlagGenerator::new(b"secret")
            .with_prefix("CTF{")
            .with_suffix("}");
        let flag = gen.generate("challenge");

        assert!(flag.starts_with("CTF{"));
        assert!(flag.ends_with("}"));
    }

    #[test]
    fn test_key_rotation() {
        let gen_old = FlagGenerator::new(b"old_secret");
        let gen_new = FlagGenerator::new(b"new_secret");

        let verifier = FlagVerifier::new(b"new_secret").add_secret(b"old_secret");

        let old_flag = gen_old.generate("challenge");
        let new_flag = gen_new.generate("challenge");

        // Both should verify
        assert!(verifier.verify("challenge", &old_flag));
        assert!(verifier.verify("challenge", &new_flag));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
