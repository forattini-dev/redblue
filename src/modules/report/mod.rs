//! Report Generation Module
//!
//! Export scan results to multiple formats:
//! - JSON: Structured data for automation
//! - HTML: Rich visual reports with embedded CSS
//! - Markdown: GitHub-compatible text format
//!
//! Zero external dependencies - all templating done with Rust std.

pub mod json;
pub mod html;
pub mod markdown;

use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub use json::JsonExporter;
pub use html::HtmlExporter;
pub use markdown::MarkdownExporter;

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            Severity::Info => "#17a2b8",
            Severity::Low => "#28a745",
            Severity::Medium => "#ffc107",
            Severity::High => "#fd7e14",
            Severity::Critical => "#dc3545",
        }
    }
}

/// A security finding
#[derive(Debug, Clone)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
}

impl Finding {
    pub fn new(title: impl Into<String>, severity: Severity) -> Self {
        Self {
            title: title.into(),
            description: String::new(),
            severity,
            evidence: None,
            remediation: None,
            references: Vec::new(),
            tags: Vec::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    pub fn add_reference(mut self, reference: impl Into<String>) -> Self {
        self.references.push(reference.into());
        self
    }

    pub fn add_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

/// Host information for report
#[derive(Debug, Clone)]
pub struct HostInfo {
    pub hostname: String,
    pub ip: Option<String>,
    pub ports: Vec<PortInfo>,
    pub technologies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub state: String,
    pub service: String,
    pub version: Option<String>,
}

/// Complete report data structure
#[derive(Debug, Clone)]
pub struct Report {
    pub title: String,
    pub target: String,
    pub scan_date: String,
    pub executive_summary: String,
    pub hosts: Vec<HostInfo>,
    pub findings: Vec<Finding>,
    pub raw_data: HashMap<String, String>,
}

impl Report {
    pub fn new(title: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            target: target.into(),
            scan_date: Self::current_date(),
            executive_summary: String::new(),
            hosts: Vec::new(),
            findings: Vec::new(),
            raw_data: HashMap::new(),
        }
    }

    fn current_date() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Simple date formatting (YYYY-MM-DD HH:MM:SS)
        let days = secs / 86400;
        let time = secs % 86400;
        let hours = time / 3600;
        let minutes = (time % 3600) / 60;
        let seconds = time % 60;

        // Calculate year/month/day from days since 1970
        let mut year = 1970;
        let mut remaining_days = days as i64;

        loop {
            let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                366
            } else {
                365
            };
            if remaining_days < days_in_year {
                break;
            }
            remaining_days -= days_in_year;
            year += 1;
        }

        let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let days_in_months: [i64; 12] = [
            31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30,
            31, 31, 30, 31, 30, 31
        ];

        let mut month = 1;
        for &days_in_month in &days_in_months {
            if remaining_days < days_in_month {
                break;
            }
            remaining_days -= days_in_month;
            month += 1;
        }
        let day = remaining_days + 1;

        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, hours, minutes, seconds)
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.executive_summary = summary.into();
        self
    }

    pub fn add_host(&mut self, host: HostInfo) {
        self.hosts.push(host);
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn add_raw_data(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.raw_data.insert(key.into(), value.into());
    }

    /// Count findings by severity
    pub fn severity_counts(&self) -> HashMap<Severity, usize> {
        let mut counts = HashMap::new();
        for finding in &self.findings {
            *counts.entry(finding.severity).or_insert(0) += 1;
        }
        counts
    }

    /// Export to JSON
    pub fn to_json(&self) -> String {
        JsonExporter::export(self)
    }

    /// Export to HTML
    pub fn to_html(&self) -> String {
        HtmlExporter::export(self)
    }

    /// Export to Markdown
    pub fn to_markdown(&self) -> String {
        MarkdownExporter::export(self)
    }

    /// Save report to file (format auto-detected from extension)
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let path = path.as_ref();
        let content = match path.extension().and_then(|e| e.to_str()) {
            Some("json") => self.to_json(),
            Some("html") | Some("htm") => self.to_html(),
            Some("md") | Some("markdown") => self.to_markdown(),
            _ => return Err("Unknown file format. Use .json, .html, or .md".to_string()),
        };

        fs::write(path, content)
            .map_err(|e| format!("Failed to write report: {}", e))
    }
}
