/// Web application security testing modules
///
/// This module provides comprehensive web security testing capabilities:
/// - HTTP header analysis
/// - Directory/file fuzzing (ffuf-style)
/// - Web crawling and endpoint discovery
/// - Technology fingerprinting (whatweb-style)
/// - Vulnerability scanning (nikto-style)
/// - SQL injection testing (sqlmap-style)
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
pub mod fingerprinter; // HTTP fingerprinting, tech & WAF detection
pub mod fuzzer;
pub mod git_exposed; // Exposed .git directory scanner (git-scanner style)
pub mod headers;
pub mod linkfinder;
pub mod nosqli; // NoSQL injection testing (MongoDB, Redis, Elasticsearch)
pub mod recursive; // Recursive content discovery (link extraction, queue, scanner)
#[path = "scanner-strategy.rs"]
pub mod scanner_strategy;
pub mod scraper; // Rule-based web scraping
pub mod sqli; // SQL injection testing (sqlmap-style)
pub mod strategies;
#[path = "vuln-scanner.rs"]
pub mod vuln_scanner;

// Re-export commonly used types
pub use cms::{CmsDetector, CmsScanConfig, CmsScanResult, CmsScanner, CmsType};
pub use crawler::{CrawlResult, CrawledPage, CrawlerConfig, WebCrawler};
pub use fingerprinter::WebFingerprinter;
pub use fuzzer::{FuzzResult, FuzzTarget, FuzzerConfig, HttpMethod, WebFuzzer, WordlistManager};
pub use scanner_strategy::{ScanStrategy, UnifiedScanResult, UnifiedWebScanner};
pub use scraper::{ExtractType, ExtractedValue, ScrapeConfig, ScrapeResult, ScrapeRule, Scraper};
pub use strategies::{
    DirectusScanResult, DirectusScanner, DrupalScanResult, DrupalScanner, GhostScanResult,
    GhostScanner, JoomlaScanResult, JoomlaScanner, StrapiScanResult, StrapiScanner, WPScanResult,
    WPScanner,
};
pub use vuln_scanner::{ScanResult as VulnScanResult, WebScanner};

// SQL injection testing
pub use sqli::{
    payloads::{Dbms, RiskLevel, SqliPayload, SqliTechnique},
    tamper::{TamperScript, TAMPER_SCRIPTS},
    techniques::{DetectionConfig, DetectionResult, InjectionPoint},
    ScanConfig as SqliScanConfig, ScanResult as SqliScanResult, SqliScanner,
};

// NoSQL injection testing
pub use nosqli::{
    payloads::{NoSqlDb, NoSqlPayload, NoSqlTechnique, RiskLevel as NoSqlRiskLevel},
    techniques::{
        DetectionConfig as NoSqlDetectionConfig, DetectionResult as NoSqlDetectionResult,
        InjectionPoint as NoSqlInjectionPoint,
    },
    AuthBypassScanner, JsonBodyScanner, NoSqliScanner, ScanConfig as NoSqlScanConfig,
    ScanResult as NoSqlScanResult,
};

// Recursive content discovery
pub use recursive::{
    DiscoveredResource, DiscoverySource, ExtractedLink, LinkExtractor, LinkSource, QueuedUrl,
    RecursionQueue, RecursiveScanConfig, RecursiveScanner, ScannerState,
};
