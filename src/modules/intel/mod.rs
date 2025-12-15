//! Intelligence Module
//!
//! Provides threat intelligence capabilities including:
//!
//! - **Technique Mapping**: Map findings (ports, CVEs, fingerprints) to MITRE ATT&CK techniques
//! - **IOC Extraction**: Extract Indicators of Compromise from scan data
//! - **Navigator Export**: Export technique mappings to ATT&CK Navigator layer format
//! - **TAXII Client**: Sync threat intel from TAXII servers (planned)
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use redblue::modules::intel::{TechniqueMapper, Findings, IocExtractor, IocCollection};
//!
//! let mapper = TechniqueMapper::new();
//!
//! // Map a single port
//! let techniques = mapper.map_port(22);
//! for tech in techniques {
//!     println!("{}: {} ({})", tech.technique_id, tech.name, tech.tactic);
//! }
//!
//! // Map all findings
//! let findings = Findings {
//!     ports: vec![22, 80, 443, 3389],
//!     cves: vec![("CVE-2021-44228".into(), "Log4j RCE".into())],
//!     fingerprints: vec!["wordpress".into()],
//!     banners: vec![],
//! };
//!
//! let result = mapper.map_findings(&findings);
//! println!("Mapped {} techniques across {} tactics",
//!     result.techniques.len(),
//!     result.by_tactic.len()
//! );
//!
//! // Extract IOCs
//! let extractor = IocExtractor::new("example.com");
//! let iocs = extractor.extract_from_port_scan("192.168.1.1", &[22, 80, 443]);
//!
//! let mut collection = IocCollection::new();
//! for ioc in iocs {
//!     collection.add(ioc);
//! }
//! println!("Extracted {} IOCs", collection.len());
//! ```

pub mod attack_database;
pub mod ioc;
pub mod mapper;
pub mod navigator;
pub mod stix;
pub mod taxii;

pub use mapper::{
    Confidence, Findings, MappedTechnique, MappingResult, MappingSource, TechniqueMapper,
};

pub use navigator::{create_layer_from_techniques, NavigatorLayer, TechniqueAnnotation};

pub use ioc::{Ioc, IocCollection, IocConfidence, IocExtractor, IocSource, IocType};
