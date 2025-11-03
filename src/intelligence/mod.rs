pub mod banner_analysis;
pub mod behavior_patterns;
/// Intelligence Gathering Module
///
/// This module implements advanced fingerprinting and metadata extraction
/// techniques that go beyond basic protocol functionality. We analyze:
///
/// - Timing behaviors (timeout patterns, response delays)
/// - Banner variations and version strings
/// - Protocol implementation quirks
/// - Error message patterns
/// - Default configurations
/// - Behavioral fingerprinting
///
/// The goal is to extract maximum intelligence from every network interaction.
pub mod os_fingerprint;
pub mod service_detection;
pub mod timing_analysis;
