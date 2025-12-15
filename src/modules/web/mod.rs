/// Web application security testing modules
///
/// This module provides comprehensive web security testing capabilities:
/// - HTTP header analysis
/// - Directory/file fuzzing (ffuf-style)
/// - Web crawling and endpoint discovery
/// - Technology fingerprinting (whatweb-style)
/// - Vulnerability scanning (nikto-style)
/// - CMS-specific scanning with Strategy Pattern
/// - Advanced CMS security testing (wpscan/droopescan style)
/// - HTML DOM parsing and CSS selectors (Cheerio-like)
/// - Built-in extractors (links, images, meta, forms, tables)
/// - Rule-based web scraping with config support
///
/// All implementations are from scratch with ZERO external dependencies.
pub mod cms; // Advanced CMS security testing (wpscan, droopescan replacement)
pub mod crawler;
pub mod dom; // HTML DOM parser with CSS selectors
pub mod extractors; // Built-in extractors for common web data
pub mod fingerprint; // HTTP fingerprinting & tech detection
pub mod fingerprinter;
pub mod fuzzer;
pub mod headers;
pub mod linkfinder;
#[path = "scanner-strategy.rs"]
pub mod scanner_strategy;
pub mod scraper; // Rule-based web scraping
pub mod strategies;
#[path = "vuln-scanner.rs"]
pub mod vuln_scanner;

// Re-export commonly used types
pub use cms::{CmsDetector, CmsScanConfig, CmsScanResult, CmsScanner, CmsType};
pub use crawler::{CrawlResult, CrawledPage, CrawlerConfig, WebCrawler};
pub use fingerprinter::WebFingerprinter;
pub use fuzzer::{
    DirFuzzResult, DirFuzzStats, DirectoryFuzzer, FuzzResult, FuzzTarget, FuzzerConfig, HttpMethod,
    ProgressBar, WebFuzzer, WordlistManager, Wordlists,
};
pub use scanner_strategy::{ScanStrategy, UnifiedScanResult, UnifiedWebScanner};
pub use scraper::{ExtractType, ExtractedValue, ScrapeConfig, ScrapeResult, ScrapeRule, Scraper};
pub use strategies::{
    DirectusScanResult, DirectusScanner, DrupalScanResult, DrupalScanner, GhostScanResult,
    GhostScanner, JoomlaScanResult, JoomlaScanner, StrapiScanResult, StrapiScanner, WPScanResult,
    WPScanner,
};
pub use vuln_scanner::{ScanResult as VulnScanResult, WebScanner};
