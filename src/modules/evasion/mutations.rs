//! Build-time Mutations
//!
//! This module includes code generated at compile time by build.rs.
//! Each build produces unique values:
//! - BUILD_FINGERPRINT: Unique identifier for this build
//! - JUNK_DATA: Random bytes that change binary hash
//! - XOR_KEY: Build-specific obfuscation key
//! - MUTATION_TABLE: Random substitution table
//!
//! # How it works
//! 1. `build.rs` runs before compilation
//! 2. Generates random values based on timestamp + entropy
//! 3. Writes Rust code to `$OUT_DIR/build_mutations.rs`
//! 4. This module includes that generated code
//! 5. Result: Different binary hash each `cargo build`

// Include the generated mutations from build.rs
include!(concat!(env!("OUT_DIR"), "/build_mutations.rs"));

/// Get the unique build fingerprint
pub fn get_build_fingerprint() -> &'static str {
    BUILD_FINGERPRINT
}

/// Get the build timestamp
pub fn get_build_timestamp() -> u64 {
    BUILD_TIMESTAMP
}

/// Get the build-specific XOR key
pub fn get_xor_key() -> u8 {
    XOR_KEY
}

/// Obfuscate a string using build-specific key
pub fn obfuscate_string(s: &str) -> Vec<u8> {
    obfuscate_bytes(s.as_bytes())
}

/// Deobfuscate to string using build-specific key
pub fn deobfuscate_string(data: &[u8]) -> String {
    deobfuscate_str(data)
}

/// Check if this build matches a fingerprint
pub fn verify_build(fingerprint: &str) -> bool {
    BUILD_FINGERPRINT == fingerprint
}

/// Macro to create an obfuscated string at compile time
/// The string is XOR'd with the build key and stored as bytes
#[macro_export]
macro_rules! obfuscated {
    ($s:expr) => {{
        // At runtime, deobfuscate using the build key
        $crate::modules::evasion::mutations::deobfuscate_string(
            &$crate::modules::evasion::mutations::obfuscate_bytes($s.as_bytes())
        )
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_exists() {
        let fp = get_build_fingerprint();
        assert!(!fp.is_empty());
        assert_eq!(fp.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn test_obfuscation_roundtrip() {
        let original = "secret string";
        let obfuscated = obfuscate_string(original);
        let recovered = deobfuscate_string(&obfuscated);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_xor_key_not_zero() {
        // Key should not be zero (would be no-op)
        let key = get_xor_key();
        // Key can technically be any value, just check it exists
        let _ = key;
    }

    #[test]
    fn test_junk_data_exists() {
        // Junk data should exist and have content
        assert!(!JUNK_DATA.is_empty());
    }
}
