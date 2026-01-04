//! MITRE ATT&CK Coverage Analysis
//!
//! Analyzes detection coverage against MITRE ATT&CK techniques and identifies gaps.
//!
//! ## Features
//!
//! - **Coverage Calculation**: Percentage of techniques covered by data sources
//! - **Gap Analysis**: Identify techniques with no detection capability
//! - **Tactic Coverage**: Coverage breakdown by kill chain phase
//! - **Platform Coverage**: Coverage by target platform (Windows, Linux, etc.)
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use redblue::modules::recon::mitre::{CoverageAnalyzer, MitreClient};
//!
//! let mut client = MitreClient::new();
//! let data = client.fetch()?;
//! let analyzer = CoverageAnalyzer::new(data);
//!
//! // Define available data sources
//! analyzer.add_data_source("Process Creation");
//! analyzer.add_data_source("Network Traffic");
//!
//! // Generate coverage report
//! let report = analyzer.analyze();
//! println!("Overall coverage: {:.1}%", report.overall_coverage);
//! ```

use super::types::{AttackData, Technique};
use std::collections::{HashMap, HashSet};

/// Coverage analyzer for MITRE ATT&CK techniques
pub struct CoverageAnalyzer<'a> {
    /// Reference to ATT&CK data
    attack_data: &'a AttackData,
    /// Available data sources for detection
    data_sources: HashSet<String>,
    /// Techniques with confirmed coverage (e.g., from existing detections)
    covered_techniques: HashSet<String>,
    /// Platform filter (empty = all platforms)
    platform_filter: Vec<String>,
}

/// Coverage report
#[derive(Debug, Clone)]
pub struct CoverageReport {
    /// Overall coverage percentage (0-100)
    pub overall_coverage: f64,
    /// Total techniques analyzed
    pub total_techniques: usize,
    /// Techniques with coverage
    pub covered_count: usize,
    /// Coverage by tactic
    pub tactic_coverage: Vec<TacticCoverage>,
    /// Coverage by platform
    pub platform_coverage: HashMap<String, PlatformCoverage>,
    /// Techniques with no coverage (gaps)
    pub gaps: Vec<CoverageGap>,
    /// Data source effectiveness
    pub data_source_coverage: Vec<DataSourceCoverage>,
    /// Recommendations for improving coverage
    pub recommendations: Vec<CoverageRecommendation>,
}

/// Coverage for a single tactic
#[derive(Debug, Clone)]
pub struct TacticCoverage {
    /// Tactic ID
    pub tactic_id: String,
    /// Tactic name
    pub tactic_name: String,
    /// Total techniques in this tactic
    pub total: usize,
    /// Covered techniques
    pub covered: usize,
    /// Coverage percentage
    pub percentage: f64,
}

/// Coverage for a platform
#[derive(Debug, Clone)]
pub struct PlatformCoverage {
    /// Platform name
    pub platform: String,
    /// Total techniques for platform
    pub total: usize,
    /// Covered techniques
    pub covered: usize,
    /// Coverage percentage
    pub percentage: f64,
}

/// A coverage gap (technique without detection)
#[derive(Debug, Clone)]
pub struct CoverageGap {
    /// Technique ID
    pub technique_id: String,
    /// Technique name
    pub technique_name: String,
    /// Associated tactics
    pub tactics: Vec<String>,
    /// Platforms affected
    pub platforms: Vec<String>,
    /// Required data sources for detection
    pub required_data_sources: Vec<String>,
    /// Priority (based on technique prevalence)
    pub priority: GapPriority,
}

/// Gap priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GapPriority {
    /// Critical - commonly used by APTs
    Critical,
    /// High - frequently observed in attacks
    High,
    /// Medium - occasionally used
    Medium,
    /// Low - rarely observed
    Low,
}

impl GapPriority {
    pub fn as_str(&self) -> &'static str {
        match self {
            GapPriority::Critical => "critical",
            GapPriority::High => "high",
            GapPriority::Medium => "medium",
            GapPriority::Low => "low",
        }
    }
}

/// Coverage provided by a data source
#[derive(Debug, Clone)]
pub struct DataSourceCoverage {
    /// Data source name
    pub data_source: String,
    /// Number of techniques detectable
    pub technique_count: usize,
    /// Percentage of total techniques
    pub percentage: f64,
}

/// Recommendation for improving coverage
#[derive(Debug, Clone)]
pub struct CoverageRecommendation {
    /// Recommendation title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Priority
    pub priority: GapPriority,
    /// Techniques that would be covered
    pub techniques_covered: Vec<String>,
    /// Impact percentage (coverage improvement)
    pub impact: f64,
}

impl<'a> CoverageAnalyzer<'a> {
    /// Create a new coverage analyzer
    pub fn new(attack_data: &'a AttackData) -> Self {
        Self {
            attack_data,
            data_sources: HashSet::new(),
            covered_techniques: HashSet::new(),
            platform_filter: Vec::new(),
        }
    }

    /// Add an available data source
    pub fn add_data_source(&mut self, data_source: &str) {
        self.data_sources.insert(data_source.to_lowercase());
    }

    /// Add multiple data sources
    pub fn add_data_sources(&mut self, data_sources: &[&str]) {
        for ds in data_sources {
            self.data_sources.insert(ds.to_lowercase());
        }
    }

    /// Mark a technique as covered (e.g., has existing detection rule)
    pub fn mark_covered(&mut self, technique_id: &str) {
        self.covered_techniques.insert(technique_id.to_uppercase());
    }

    /// Filter analysis to specific platforms
    pub fn filter_platforms(&mut self, platforms: Vec<String>) {
        self.platform_filter = platforms;
    }

    /// Check if a technique is covered based on data sources
    fn is_technique_covered(&self, tech: &Technique) -> bool {
        // Explicitly marked as covered
        if self.covered_techniques.contains(&tech.id) {
            return true;
        }

        // Check if any required data source is available
        for required_ds in &tech.data_sources {
            let required_lower = required_ds.to_lowercase();
            for available_ds in &self.data_sources {
                // Fuzzy match - partial matching for data source names
                if required_lower.contains(available_ds) || available_ds.contains(&required_lower) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if technique matches platform filter
    fn matches_platform(&self, tech: &Technique) -> bool {
        if self.platform_filter.is_empty() {
            return true;
        }

        for platform in &tech.platforms {
            let platform_lower = platform.to_lowercase();
            for filter in &self.platform_filter {
                if platform_lower.contains(&filter.to_lowercase()) {
                    return true;
                }
            }
        }

        false
    }

    /// Analyze coverage and generate report
    pub fn analyze(&self) -> CoverageReport {
        let mut total_techniques = 0;
        let mut covered_count = 0;
        let mut gaps = Vec::new();
        let mut tactic_stats: HashMap<String, (usize, usize, String)> = HashMap::new();
        let mut platform_stats: HashMap<String, (usize, usize)> = HashMap::new();
        let mut data_source_counts: HashMap<String, HashSet<String>> = HashMap::new();

        // Analyze each technique
        for tech in self.attack_data.techniques.values() {
            // Skip deprecated/revoked techniques
            if tech.deprecated || tech.revoked {
                continue;
            }

            // Apply platform filter
            if !self.matches_platform(tech) {
                continue;
            }

            total_techniques += 1;
            let covered = self.is_technique_covered(tech);

            if covered {
                covered_count += 1;
            } else {
                // Track as gap
                gaps.push(CoverageGap {
                    technique_id: tech.id.clone(),
                    technique_name: tech.name.clone(),
                    tactics: tech.tactics.clone(),
                    platforms: tech.platforms.clone(),
                    required_data_sources: tech.data_sources.clone(),
                    priority: self.calculate_gap_priority(&tech.id),
                });
            }

            // Track tactic coverage
            for tactic_name in &tech.tactics {
                let entry =
                    tactic_stats
                        .entry(tactic_name.clone())
                        .or_insert((0, 0, tactic_name.clone()));
                entry.0 += 1;
                if covered {
                    entry.1 += 1;
                }
            }

            // Track platform coverage
            for platform in &tech.platforms {
                let entry = platform_stats.entry(platform.clone()).or_insert((0, 0));
                entry.0 += 1;
                if covered {
                    entry.1 += 1;
                }
            }

            // Track data source effectiveness
            for ds in &tech.data_sources {
                data_source_counts
                    .entry(ds.clone())
                    .or_default()
                    .insert(tech.id.clone());
            }
        }

        // Calculate overall coverage
        let overall_coverage = if total_techniques > 0 {
            (covered_count as f64 / total_techniques as f64) * 100.0
        } else {
            0.0
        };

        // Build tactic coverage
        let mut tactic_coverage: Vec<TacticCoverage> = tactic_stats
            .into_iter()
            .map(|(name, (total, covered, tactic_name))| {
                let tactic_id = self
                    .attack_data
                    .get_tactic(&name)
                    .map(|t| t.id.clone())
                    .unwrap_or_else(|| name.clone());

                TacticCoverage {
                    tactic_id,
                    tactic_name,
                    total,
                    covered,
                    percentage: if total > 0 {
                        (covered as f64 / total as f64) * 100.0
                    } else {
                        0.0
                    },
                }
            })
            .collect();

        // Sort by kill chain order
        tactic_coverage.sort_by(|a, b| {
            let order = [
                "reconnaissance",
                "resource-development",
                "initial-access",
                "execution",
                "persistence",
                "privilege-escalation",
                "defense-evasion",
                "credential-access",
                "discovery",
                "lateral-movement",
                "collection",
                "command-and-control",
                "exfiltration",
                "impact",
            ];

            let a_idx = order
                .iter()
                .position(|&t| a.tactic_name.to_lowercase().contains(t))
                .unwrap_or(99);
            let b_idx = order
                .iter()
                .position(|&t| b.tactic_name.to_lowercase().contains(t))
                .unwrap_or(99);

            a_idx.cmp(&b_idx)
        });

        // Build platform coverage
        let platform_coverage: HashMap<String, PlatformCoverage> = platform_stats
            .into_iter()
            .map(|(platform, (total, covered))| {
                (
                    platform.clone(),
                    PlatformCoverage {
                        platform,
                        total,
                        covered,
                        percentage: if total > 0 {
                            (covered as f64 / total as f64) * 100.0
                        } else {
                            0.0
                        },
                    },
                )
            })
            .collect();

        // Build data source coverage
        let mut data_source_coverage: Vec<DataSourceCoverage> = data_source_counts
            .into_iter()
            .map(|(ds, techs)| DataSourceCoverage {
                data_source: ds,
                technique_count: techs.len(),
                percentage: if total_techniques > 0 {
                    (techs.len() as f64 / total_techniques as f64) * 100.0
                } else {
                    0.0
                },
            })
            .collect();

        // Sort by coverage
        data_source_coverage.sort_by(|a, b| b.technique_count.cmp(&a.technique_count));

        // Sort gaps by priority
        gaps.sort_by(|a, b| a.priority.cmp(&b.priority));

        // Generate recommendations
        let recommendations = self.generate_recommendations(&gaps, &data_source_coverage);

        CoverageReport {
            overall_coverage,
            total_techniques,
            covered_count,
            tactic_coverage,
            platform_coverage,
            gaps,
            data_source_coverage,
            recommendations,
        }
    }

    /// Calculate gap priority based on technique usage
    fn calculate_gap_priority(&self, technique_id: &str) -> GapPriority {
        // Count how many groups use this technique
        let group_count = self
            .attack_data
            .technique_groups
            .get(technique_id)
            .map(|g| g.len())
            .unwrap_or(0);

        match group_count {
            0..=2 => GapPriority::Low,
            3..=5 => GapPriority::Medium,
            6..=10 => GapPriority::High,
            _ => GapPriority::Critical,
        }
    }

    /// Generate coverage improvement recommendations
    fn generate_recommendations(
        &self,
        gaps: &[CoverageGap],
        data_source_coverage: &[DataSourceCoverage],
    ) -> Vec<CoverageRecommendation> {
        let mut recommendations = Vec::new();

        // Find data sources that would cover the most gaps
        let mut ds_impact: HashMap<String, Vec<String>> = HashMap::new();

        for gap in gaps {
            for ds in &gap.required_data_sources {
                ds_impact
                    .entry(ds.clone())
                    .or_default()
                    .push(gap.technique_id.clone());
            }
        }

        // Sort by impact
        let mut ds_list: Vec<_> = ds_impact.into_iter().collect();
        ds_list.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

        // Top 5 data source recommendations
        for (ds, techniques) in ds_list.into_iter().take(5) {
            if self.data_sources.contains(&ds.to_lowercase()) {
                continue; // Already have this data source
            }

            let impact = (techniques.len() as f64 / gaps.len() as f64) * 100.0;
            let priority = if impact > 20.0 {
                GapPriority::Critical
            } else if impact > 10.0 {
                GapPriority::High
            } else if impact > 5.0 {
                GapPriority::Medium
            } else {
                GapPriority::Low
            };

            recommendations.push(CoverageRecommendation {
                title: format!("Add {} data source", ds),
                description: format!(
                    "Collecting '{}' would enable detection of {} additional techniques",
                    ds,
                    techniques.len()
                ),
                priority,
                techniques_covered: techniques,
                impact,
            });
        }

        // Prioritize critical gaps
        let critical_gaps: Vec<_> = gaps
            .iter()
            .filter(|g| g.priority == GapPriority::Critical)
            .take(5)
            .collect();

        if !critical_gaps.is_empty() {
            recommendations.push(CoverageRecommendation {
                title: "Address critical technique gaps".to_string(),
                description: format!(
                    "Focus on detecting {} critical techniques used by multiple threat groups",
                    critical_gaps.len()
                ),
                priority: GapPriority::Critical,
                techniques_covered: critical_gaps
                    .iter()
                    .map(|g| g.technique_id.clone())
                    .collect(),
                impact: (critical_gaps.len() as f64 / gaps.len() as f64) * 100.0,
            });
        }

        recommendations.sort_by(|a, b| a.priority.cmp(&b.priority));
        recommendations
    }

    /// Get gaps filtered by priority
    pub fn gaps_by_priority(&self, priority: GapPriority) -> Vec<CoverageGap> {
        let report = self.analyze();
        report
            .gaps
            .into_iter()
            .filter(|g| g.priority == priority)
            .collect()
    }

    /// Get gaps filtered by tactic
    pub fn gaps_by_tactic(&self, tactic: &str) -> Vec<CoverageGap> {
        let tactic_lower = tactic.to_lowercase();
        let report = self.analyze();
        report
            .gaps
            .into_iter()
            .filter(|g| g.tactics.iter().any(|t| t.to_lowercase() == tactic_lower))
            .collect()
    }

    /// Get gaps filtered by platform
    pub fn gaps_by_platform(&self, platform: &str) -> Vec<CoverageGap> {
        let platform_lower = platform.to_lowercase();
        let report = self.analyze();
        report
            .gaps
            .into_iter()
            .filter(|g| {
                g.platforms
                    .iter()
                    .any(|p| p.to_lowercase().contains(&platform_lower))
            })
            .collect()
    }
}

/// Standard data source categories for common security tools
pub struct DataSourceCategories;

impl DataSourceCategories {
    /// EDR data sources
    pub fn edr() -> Vec<&'static str> {
        vec![
            "process creation",
            "process termination",
            "process access",
            "file creation",
            "file modification",
            "file deletion",
            "registry key creation",
            "registry key modification",
            "network connection",
            "module load",
            "driver load",
        ]
    }

    /// Network monitoring data sources
    pub fn network() -> Vec<&'static str> {
        vec![
            "network traffic",
            "network traffic content",
            "network connection",
            "dns",
            "web traffic",
        ]
    }

    /// Log-based data sources
    pub fn logs() -> Vec<&'static str> {
        vec![
            "windows event logs",
            "application log",
            "authentication logs",
            "command execution",
        ]
    }

    /// Cloud data sources
    pub fn cloud() -> Vec<&'static str> {
        vec![
            "cloud service",
            "cloud storage",
            "instance creation",
            "instance modification",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::recon::mitre::Technique;

    fn create_test_data() -> AttackData {
        let mut data = AttackData::new();

        data.techniques.insert(
            "T1059.001".to_string(),
            Technique {
                id: "T1059.001".to_string(),
                name: "PowerShell".to_string(),
                description: "PowerShell execution".to_string(),
                tactics: vec!["execution".to_string()],
                detection: None,
                platforms: vec!["Windows".to_string()],
                data_sources: vec!["Process Creation".to_string(), "Command Line".to_string()],
                is_subtechnique: true,
                parent_id: Some("T1059".to_string()),
                url: String::new(),
                references: vec![],
                mitigations: vec![],
                deprecated: false,
                revoked: false,
                cves: vec![],
            },
        );

        data.techniques.insert(
            "T1055".to_string(),
            Technique {
                id: "T1055".to_string(),
                name: "Process Injection".to_string(),
                description: "Process injection techniques".to_string(),
                tactics: vec!["defense-evasion".to_string()],
                detection: None,
                platforms: vec!["Windows".to_string(), "Linux".to_string()],
                data_sources: vec!["Process Access".to_string(), "Module Load".to_string()],
                is_subtechnique: false,
                parent_id: None,
                url: String::new(),
                references: vec![],
                mitigations: vec![],
                deprecated: false,
                revoked: false,
                cves: vec![],
            },
        );

        data
    }

    #[test]
    fn test_coverage_analysis() {
        let data = create_test_data();
        let mut analyzer = CoverageAnalyzer::new(&data);

        // No data sources - should show 0 coverage
        let report = analyzer.analyze();
        assert_eq!(report.overall_coverage, 0.0);
        assert_eq!(report.gaps.len(), 2);

        // Add process creation data source
        analyzer.add_data_source("process creation");
        let report = analyzer.analyze();

        // Should now have some coverage
        assert!(report.overall_coverage > 0.0);
    }

    #[test]
    fn test_explicit_coverage() {
        let data = create_test_data();
        let mut analyzer = CoverageAnalyzer::new(&data);

        analyzer.mark_covered("T1055");
        let report = analyzer.analyze();

        assert_eq!(report.covered_count, 1);
        assert!(report.gaps.iter().any(|g| g.technique_id == "T1059.001"));
        assert!(!report.gaps.iter().any(|g| g.technique_id == "T1055"));
    }

    #[test]
    fn test_platform_filter() {
        let data = create_test_data();
        let mut analyzer = CoverageAnalyzer::new(&data);

        analyzer.filter_platforms(vec!["Linux".to_string()]);
        let report = analyzer.analyze();

        // Only T1055 has Linux platform
        assert_eq!(report.total_techniques, 1);
    }

    #[test]
    fn test_tactic_coverage() {
        let data = create_test_data();
        let analyzer = CoverageAnalyzer::new(&data);

        let report = analyzer.analyze();
        assert!(!report.tactic_coverage.is_empty());

        // Check that tactics are tracked
        let execution = report
            .tactic_coverage
            .iter()
            .find(|t| t.tactic_name.contains("execution"));
        assert!(execution.is_some());
    }

    #[test]
    fn test_recommendations() {
        let data = create_test_data();
        let analyzer = CoverageAnalyzer::new(&data);

        let report = analyzer.analyze();
        assert!(!report.recommendations.is_empty());
    }
}
