//! TLS Fingerprinting
//!
//! JA3 and JA3S fingerprint calculation for TLS traffic analysis.

mod ja3;

pub use ja3::{Ja3Fingerprint, Ja3sFingerprint, TlsFingerprinter};
