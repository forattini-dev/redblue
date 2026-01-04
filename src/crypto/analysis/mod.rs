//! Cryptographic Analysis Module
//!
//! Tools for analyzing encoded/encrypted data to identify algorithms and patterns.

mod auto_detect;
mod cyclic;
mod entropy;
mod frequency;
mod hash_id;

pub use auto_detect::AutoDetector;
pub use cyclic::{CyclicGenerator, CyclicOffsetResult, Endianness};
pub use entropy::{EntropyAnalyzer, EntropyClassification, EntropyRegion, EntropyResult};
pub use frequency::FrequencyAnalyzer;
pub use hash_id::HashIdentifier;
