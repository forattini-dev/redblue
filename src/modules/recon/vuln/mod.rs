//! Vulnerability Intelligence Module
//!
//! Multi-source vulnerability aggregation and correlation with detected technologies.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
//! │ Fingerprinting  │────▶│ CPE Mapping  │────▶│ Vuln Sources    │
//! │                 │     │              │     │                 │
//! │ nginx 1.18.0    │     │ cpe:2.3:a:   │     │ NVD, OSV, KEV   │
//! │ PHP 8.1         │     │ f5:nginx:... │     │ Exploit-DB      │
//! └─────────────────┘     └──────────────┘     └────────┬────────┘
//!                                                       │
//!                                                       ▼
//! ┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
//! │ Risk Report     │◀────│ Risk Score   │◀────│ Deduplication   │
//! │                 │     │              │     │                 │
//! │ CVE-2024-1234   │     │ CVSS + KEV + │     │ Merge by CVE ID │
//! │ Risk: 95/100    │     │ Exploit      │     │                 │
//! └─────────────────┘     └──────────────┘     └─────────────────┘
//! ```

pub mod cpe;
pub mod types;
pub mod nvd;
pub mod osv;
pub mod kev;
pub mod risk;
pub mod exploitdb;

pub use cpe::{CpeMapping, TechCategory, find_cpe, generate_cpe, get_all_cpe_mappings};
pub use types::{Vulnerability, Severity, ExploitRef, VulnSource, DetectedTech, VulnCollection};
pub use risk::{calculate_risk_score, RiskLevel};
pub use nvd::NvdClient;
pub use osv::OsvClient;
pub use kev::KevClient;
pub use exploitdb::ExploitDbClient;
