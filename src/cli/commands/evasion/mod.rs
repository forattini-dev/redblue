//! Evasion CLI commands
//!
//! AV/EDR evasion techniques for authorized penetration testing.
//!
//! # Usage
//! ```bash
//! rb evasion sandbox check           # Check if running in sandbox/VM
//! rb evasion sandbox score           # Get sandbox detection score
//! rb evasion obfuscate xor <string>  # XOR obfuscate a string
//! rb evasion obfuscate base64 <data> # Base64 encode data
//! rb evasion network jitter <ms>     # Calculate jittered delay
//! ```

mod amsi;
mod antidebug;
mod apihash;
mod build;
mod config;
mod controlflow;
mod inject;
mod memory;
mod network;
mod obfuscate;
mod sandbox;
mod strings;
mod tracks;

// Re-export all command structs
pub use amsi::EvasionAmsiCommand;
pub use antidebug::EvasionAntidebugCommand;
pub use apihash::EvasionApihashCommand;
pub use build::EvasionBuildCommand;
pub use config::EvasionConfigCommand;
pub use controlflow::EvasionControlflowCommand;
pub use inject::EvasionInjectCommand;
pub use memory::EvasionMemoryCommand;
pub use network::EvasionNetworkCommand;
pub use obfuscate::EvasionObfuscateCommand;
pub use sandbox::EvasionSandboxCommand;
pub use strings::EvasionStringsCommand;
pub use tracks::EvasionTracksCommand;

// Shared color constants for all evasion commands
pub(crate) const RED: &str = "\x1b[31m";
pub(crate) const GREEN: &str = "\x1b[32m";
pub(crate) const YELLOW: &str = "\x1b[33m";
pub(crate) const RESET: &str = "\x1b[0m";

pub(crate) fn colored(text: &str, color: &str) -> String {
    format!("{}{}{}", color, text, RESET)
}

#[cfg(test)]
mod tests {
    use crate::modules::evasion::obfuscate;

    #[test]
    fn test_xor_roundtrip() {
        let original = "test string";
        let key = 0x42;
        let obfuscated = obfuscate::xor_obfuscate(original, key);
        let recovered = obfuscate::xor_deobfuscate(&obfuscated, key);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"test data";
        let encoded = obfuscate::base64_encode(original);
        let decoded = obfuscate::base64_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }
}
