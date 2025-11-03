/// Web application security testing modules
///
/// This module provides comprehensive web security testing capabilities:
/// - HTTP header analysis
/// - Directory/file fuzzing (ffuf-style)
/// - Web crawling and endpoint discovery
/// - Technology fingerprinting (whatweb-style)
/// - Vulnerability scanning (nikto-style)
/// - CMS-specific scanning with Strategy Pattern
///
/// All implementations are from scratch with ZERO external dependencies.
pub mod crawler;
pub mod fingerprint; // NEW: HTTP fingerprinting & tech detection
pub mod fingerprinter;
pub mod fuzzer;
pub mod headers;
pub mod linkfinder;
#[path = "scanner-strategy.rs"]
pub mod scanner_strategy;
pub mod strategies;
#[path = "vuln-scanner.rs"]
pub mod vuln_scanner;

// Re-export commonly used types
pub use fingerprinter::WebFingerprinter;
pub use fuzzer::DirectoryFuzzer;
pub use scanner_strategy::{ScanStrategy, UnifiedScanResult, UnifiedWebScanner};
pub use strategies::{
    DirectusScanResult, DirectusScanner, DrupalScanResult, DrupalScanner, GhostScanResult,
    GhostScanner, JoomlaScanResult, JoomlaScanner, StrapiScanResult, StrapiScanner, WPScanResult,
    WPScanner,
};
pub use vuln_scanner::{ScanResult as VulnScanResult, WebScanner};
