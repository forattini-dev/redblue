#![allow(dead_code)]

/// Unified web scanner with auto-detection strategy pattern
///
/// Replaces the need for separate commands (scan, vuln-scan, wpscan, etc.)
/// Auto-detects the CMS/framework and applies the best scanning strategy
///
/// NO external dependencies - pure Rust implementation
use crate::modules::network::scanner::ScanProgress;
use crate::modules::web::fingerprinter::WebFingerprinter;
use crate::modules::web::strategies::{
    DirectusScanResult, DirectusScanner, DrupalScanResult, DrupalScanner, GhostScanResult,
    GhostScanner, JoomlaScanResult, JoomlaScanner, StrapiScanResult, StrapiScanner, WPScanResult,
    WPScanner,
};
use crate::modules::web::vuln_scanner::{ScanResult as VulnScanResult, WebScanner};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanStrategy {
    AutoDetect,
    WordPress,
    Drupal,
    Joomla,
    Strapi,
    Ghost,
    Directus,
    Laravel,
    Django,
    Generic,
}

impl ScanStrategy {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "auto" | "auto-detect" => Ok(ScanStrategy::AutoDetect),
            "wordpress" | "wp" => Ok(ScanStrategy::WordPress),
            "drupal" => Ok(ScanStrategy::Drupal),
            "joomla" => Ok(ScanStrategy::Joomla),
            "strapi" => Ok(ScanStrategy::Strapi),
            "ghost" => Ok(ScanStrategy::Ghost),
            "directus" => Ok(ScanStrategy::Directus),
            "laravel" => Ok(ScanStrategy::Laravel),
            "django" => Ok(ScanStrategy::Django),
            "generic" | "standard" => Ok(ScanStrategy::Generic),
            _ => Err(format!(
                "Unknown strategy: '{}'. Valid options: auto, wordpress, drupal, joomla, strapi, ghost, directus, laravel, django, generic",
                s
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub enum UnifiedScanResult {
    WordPress(WPScanResult),
    Drupal(DrupalScanResult),
    Joomla(JoomlaScanResult),
    Strapi(StrapiScanResult),
    Ghost(GhostScanResult),
    Directus(DirectusScanResult),
    Generic(VulnScanResult),
    NotDetected(VulnScanResult),
}

pub struct UnifiedWebScanner {
    fingerprinter: WebFingerprinter,
    vuln_scanner: WebScanner,
    wp_scanner: WPScanner,
    drupal_scanner: DrupalScanner,
    joomla_scanner: JoomlaScanner,
    strapi_scanner: StrapiScanner,
    ghost_scanner: GhostScanner,
    directus_scanner: DirectusScanner,
}

impl UnifiedWebScanner {
    pub fn new() -> Self {
        Self {
            fingerprinter: WebFingerprinter::new(),
            vuln_scanner: WebScanner::new(),
            wp_scanner: WPScanner::new(),
            drupal_scanner: DrupalScanner::new(),
            joomla_scanner: JoomlaScanner::new(),
            strapi_scanner: StrapiScanner::new(),
            ghost_scanner: GhostScanner::new(),
            directus_scanner: DirectusScanner::new(),
        }
    }

    /// Main unified scan entry point
    pub fn scan(&self, url: &str, strategy: ScanStrategy) -> Result<UnifiedScanResult, String> {
        let effective_strategy = match strategy {
            ScanStrategy::AutoDetect => self.detect_strategy(url)?,
            other => other,
        };
        self.scan_with_strategy_with_progress(url, effective_strategy, None)
    }

    pub fn scan_with_progress(
        &self,
        url: &str,
        strategy: ScanStrategy,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<UnifiedScanResult, String> {
        let effective_strategy = match strategy {
            ScanStrategy::AutoDetect => self.detect_strategy(url)?,
            other => other,
        };
        self.scan_with_strategy_with_progress(url, effective_strategy, progress)
    }

    pub fn detect_strategy_for(&self, url: &str) -> Result<ScanStrategy, String> {
        self.detect_strategy(url)
    }

    pub fn scan_with_strategy(
        &self,
        url: &str,
        strategy: ScanStrategy,
    ) -> Result<UnifiedScanResult, String> {
        self.scan_with_strategy_with_progress(url, strategy, None)
    }

    pub fn scan_with_strategy_with_progress(
        &self,
        url: &str,
        strategy: ScanStrategy,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<UnifiedScanResult, String> {
        match strategy {
            ScanStrategy::WordPress => self.scan_wordpress_with_progress(url, progress),
            ScanStrategy::Drupal => self.scan_drupal_with_progress(url, progress),
            ScanStrategy::Joomla => self.scan_joomla_with_progress(url, progress),
            ScanStrategy::Strapi => self.scan_strapi_with_progress(url, progress),
            ScanStrategy::Ghost => self.scan_ghost_with_progress(url, progress),
            ScanStrategy::Directus => self.scan_directus_with_progress(url, progress),
            ScanStrategy::Laravel => self.scan_generic_with_progress(url, progress), // TODO: Implement Laravel-specific scanner
            ScanStrategy::Django => self.scan_generic_with_progress(url, progress), // TODO: Implement Django-specific scanner
            ScanStrategy::Generic => self.scan_generic_with_progress(url, progress),
            ScanStrategy::AutoDetect => self.scan_generic_with_progress(url, progress),
        }
    }

    /// Auto-detect the best scanning strategy based on fingerprinting
    fn detect_strategy(&self, url: &str) -> Result<ScanStrategy, String> {
        let fingerprint = self.fingerprinter.fingerprint(url)?;

        // Check detected technologies and select appropriate scanner
        for tech in &fingerprint.technologies {
            let tech_lower = tech.name.to_lowercase();

            // Traditional CMSs (have dedicated scanners)
            if tech_lower.contains("wordpress") {
                return Ok(ScanStrategy::WordPress);
            }
            if tech_lower.contains("drupal") {
                return Ok(ScanStrategy::Drupal);
            }
            if tech_lower.contains("joomla") {
                return Ok(ScanStrategy::Joomla);
            }

            // Modern Headless CMSs (using generic scanner for now)
            if tech_lower.contains("strapi") {
                return Ok(ScanStrategy::Strapi);
            }
            if tech_lower.contains("ghost") {
                return Ok(ScanStrategy::Ghost);
            }
            if tech_lower.contains("directus") {
                return Ok(ScanStrategy::Directus);
            }

            // Frameworks (using generic scanner for now)
            if tech_lower.contains("laravel") {
                return Ok(ScanStrategy::Laravel);
            }
            if tech_lower.contains("django") {
                return Ok(ScanStrategy::Django);
            }
        }

        // Default to generic scan
        Ok(ScanStrategy::Generic)
    }

    /// Scan WordPress site
    fn scan_wordpress(&self, url: &str) -> Result<UnifiedScanResult, String> {
        self.scan_wordpress_with_progress(url, None)
    }

    fn scan_wordpress_with_progress(
        &self,
        url: &str,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<UnifiedScanResult, String> {
        let result = self.wp_scanner.scan_with_progress(url, progress)?;
        Ok(UnifiedScanResult::WordPress(result))
    }

    /// Scan Drupal site (placeholder - to be implemented)
    fn scan_drupal(&self, url: &str) -> Result<UnifiedScanResult, String> {
        self.scan_drupal_with_progress(url, None)
    }

    fn scan_drupal_with_progress(
        &self,
        url: &str,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<UnifiedScanResult, String> {
        let result = self.drupal_scanner.scan_with_progress(url, progress)?;
        Ok(UnifiedScanResult::Drupal(result))
    }

    /// Scan Joomla site (placeholder - to be implemented)
    fn scan_joomla(&self, url: &str) -> Result<UnifiedScanResult, String> {
        self.scan_joomla_with_progress(url, None)
    }

    fn scan_joomla_with_progress(
        &self,
        url: &str,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<UnifiedScanResult, String> {
        let result = self.joomla_scanner.scan_with_progress(url, progress)?;
        Ok(UnifiedScanResult::Joomla(result))
    }

    /// Scan Strapi site
    fn scan_strapi(&self, url: &str) -> Result<UnifiedScanResult, String> {
        self.scan_strapi_with_progress(url, None)
    }

    fn scan_strapi_with_progress(
        &self,
        url: &str,
        _progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<UnifiedScanResult, String> {
        let result = self.strapi_scanner.scan(url)?;
        Ok(UnifiedScanResult::Strapi(result))
    }

    /// Scan Ghost site
    fn scan_ghost(&self, url: &str) -> Result<UnifiedScanResult, String> {
        self.scan_ghost_with_progress(url, None)
    }

    fn scan_ghost_with_progress(
        &self,
        url: &str,
        _progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<UnifiedScanResult, String> {
        let result = self.ghost_scanner.scan(url)?;
        Ok(UnifiedScanResult::Ghost(result))
    }

    /// Scan Directus site
    fn scan_directus(&self, url: &str) -> Result<UnifiedScanResult, String> {
        self.scan_directus_with_progress(url, None)
    }

    fn scan_directus_with_progress(
        &self,
        url: &str,
        _progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<UnifiedScanResult, String> {
        let result = self.directus_scanner.scan(url)?;
        Ok(UnifiedScanResult::Directus(result))
    }

    /// Generic vulnerability scan
    fn scan_generic(&self, url: &str) -> Result<UnifiedScanResult, String> {
        self.scan_generic_with_progress(url, None)
    }

    fn scan_generic_with_progress(
        &self,
        url: &str,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<UnifiedScanResult, String> {
        let result = self.vuln_scanner.scan_active_with_progress(url, progress)?;
        Ok(UnifiedScanResult::Generic(result))
    }
}

impl Default for UnifiedWebScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strategy_from_str() {
        assert_eq!(
            ScanStrategy::from_str("auto").unwrap(),
            ScanStrategy::AutoDetect
        );
        assert_eq!(
            ScanStrategy::from_str("wordpress").unwrap(),
            ScanStrategy::WordPress
        );
        assert_eq!(
            ScanStrategy::from_str("wp").unwrap(),
            ScanStrategy::WordPress
        );
        assert!(ScanStrategy::from_str("invalid").is_err());
    }
}
