/// Intelligence Gathering Module
///
/// This module implements advanced fingerprinting and metadata extraction
/// techniques that go beyond basic protocol functionality. We analyze:
///
/// - Connection metadata (timing, TCP options, IP stack fingerprinting)
/// - TLS handshake details (ciphers, extensions, cert chain analysis)
/// - HTTP intelligence (headers, cookies, security posture)
/// - Infrastructure inference (CDN, WAF, load balancer, cloud provider)
/// - Timing behaviors (timeout patterns, response delays)
/// - Banner variations and version strings
/// - Protocol implementation quirks
/// - Error message patterns
/// - Default configurations
/// - Behavioral fingerprinting
///
/// The goal is to extract maximum intelligence from every network interaction.

#[path = "banner-analysis.rs"]
pub mod banner_analysis;

#[path = "behavior-patterns.rs"]
pub mod behavior_patterns;

#[path = "connection-intel.rs"]
pub mod connection_intel;

#[path = "os-fingerprint.rs"]
pub mod os_fingerprint;

#[path = "service-detection.rs"]
pub mod service_detection;

#[path = "timing-analysis.rs"]
pub mod timing_analysis;
