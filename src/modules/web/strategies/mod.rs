/// CMS/Framework-specific scanning strategies
///
/// Each strategy implements specialized scanning for a specific CMS or framework:
/// - WordPress: Plugin/theme enumeration, user enumeration, vulnerability checks
/// - Drupal: Module detection, version fingerprinting, security audits
/// - Joomla: Component/extension enumeration, configuration issues
/// - Strapi: Headless CMS API testing, authentication checks
/// - Ghost: Blog platform scanning, API discovery
/// - Directus: Headless CMS security testing
///
/// The scanner_strategy.rs orchestrator auto-detects the CMS and applies
/// the appropriate strategy using the Strategy Pattern.
pub mod directus;
pub mod drupal;
pub mod ghost;
pub mod joomla;
pub mod strapi;
pub mod wordpress;

// Re-export for convenience
pub use directus::{DirectusScanResult, DirectusScanner};
pub use drupal::{DrupalScanResult, DrupalScanner};
pub use ghost::{GhostScanResult, GhostScanner};
pub use joomla::{JoomlaScanResult, JoomlaScanner};
pub use strapi::{StrapiScanResult, StrapiScanner};
pub use wordpress::{WPScanResult, WPScanner};
