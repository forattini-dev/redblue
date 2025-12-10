/// Security modules organized by category
// DNS Intelligence & Reconnaissance
pub mod dns;

// Proxy & MITM Interception
pub mod proxy;

// Reconnaissance
#[allow(dead_code)]
pub mod recon {
    pub mod asn;
    pub mod breach;
    pub mod crtsh;
    pub mod dns;
    pub mod dnsdumpster;
    pub mod dorks;
    pub mod harvester;
    #[path = "ip-intel.rs"]
    pub mod ip_intel;
    pub mod massdns;
    pub mod osint;
    pub mod secrets;
    pub mod social;
    pub mod subdomain;
    pub mod subdomain_bruteforce;
    pub mod urlharvest;
    pub mod username;
    pub mod vuln;
    pub mod email_correlation;
    pub mod antidetection;
    pub mod reporting;
    pub mod threat_intel;
    pub mod email_validator;
    pub mod email_permutator;
}

// Network Analysis
pub mod network;

// Web Security
pub mod web;

// SSL/TLS Security Testing
pub mod tls;

// CT logs moved to module root for backward compatibility
#[path = "tls/ct-logs.rs"]
pub mod ct_logs;

// Data Collection
pub mod collection {
    pub mod dependencies;
    pub mod screenshots;
    pub mod secrets;
    pub mod screenshot;  // Chrome DevTools Protocol screenshot capture
    pub mod clustering;
    pub mod categorization;
    pub mod creds;
    pub mod login;
    pub mod auth_test;
    pub mod persistence;
    pub mod resume;
    pub mod sarif;
}

// Cloud Security
pub mod cloud {
    #[path = "s3-scanner.rs"]
    pub mod s3_scanner;
    pub mod takeover;
}

// CMS Security Testing
pub mod cms;

// Authentication Testing
pub mod auth;

// Exploitation & Privilege Escalation (⚠️ AUTHORIZED USE ONLY)
pub mod exploit;

// Performance Benchmarking
pub mod benchmark;

// Protocol Monitoring
// pub mod monitor;  // TODO: Needs implementation fixes

// Wordlist Management
pub mod wordlist;

// Scripting Engine
pub mod scripting;

// Built-in HTTP Server for Payload Hosting
pub mod http_server;

// Report Generation (JSON, HTML, Markdown)
pub mod report;

// Service Manager (systemd, launchd, Windows Tasks)
pub mod service;

// AV/EDR Evasion (obfuscation, sandbox detection, network jitter)
pub mod evasion;
