/// Security modules organized by category
// DNS Intelligence & Reconnaissance
pub mod dns;

// Reconnaissance
pub mod recon {
    pub mod dns;
    pub mod harvester;
    pub mod osint;
    pub mod subdomain;
    pub mod urlharvest;
    pub mod whois;
}

// Network Analysis
pub mod network;

// Web Security
pub mod web;

// SSL/TLS
// TODO: These modules need refactoring to use new crate::crypto and modules::network::tls
// pub mod tls {
//     pub mod audit;
//     pub mod auditor;
//     pub mod cipher;
#[path = "tls/ct-logs.rs"]
pub mod ct_logs;
//     pub mod scanner;
// }

// Data Collection
pub mod collection {
    pub mod dependencies;
    pub mod screenshots;
    pub mod secrets;
}

// Cloud Security
pub mod cloud {
    #[path = "s3-scanner.rs"]
    pub mod s3_scanner;
    pub mod takeover;
}

// Exploitation & Privilege Escalation (⚠️ AUTHORIZED USE ONLY)
pub mod exploit;

// Performance Benchmarking
pub mod benchmark;

// Protocol Monitoring
// pub mod monitor;  // TODO: Needs implementation fixes
