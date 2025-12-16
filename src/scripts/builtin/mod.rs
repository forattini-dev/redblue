//! Built-in Scripts
//!
//! Compiled Rust scripts that implement common security checks.
//! These scripts are included in the binary and require no external files.
//!
//! ## Script Categories
//!
//! - **Discovery**: Banner grabbing, service detection, version identification
//! - **Security**: Security header checks, TLS configuration
//! - **Vulnerability**: Known CVE checks, misconfigurations

// HTTP/Web Scripts
#[path = "http-headers.rs"]
mod http_headers;

#[path = "http-security.rs"]
mod http_security;

#[path = "http-vulns.rs"]
mod http_vulns;

// Service Banner Scripts
#[path = "ssh-banner.rs"]
mod ssh_banner;

#[path = "ftp-banner.rs"]
mod ftp_banner;

#[path = "smtp-banner.rs"]
mod smtp_banner;

#[path = "telnet-info.rs"]
mod telnet_info;

// TLS/SSL Scripts
#[path = "tls-info.rs"]
mod tls_info;

// Database Scripts
#[path = "mysql-info.rs"]
mod mysql_info;

#[path = "redis-info.rs"]
mod redis_info;

#[path = "mongodb-info.rs"]
mod mongodb_info;

// Network Protocol Scripts
#[path = "dns-zone-transfer.rs"]
mod dns_zone_transfer;

#[path = "snmp-info.rs"]
mod snmp_info;

#[path = "rdp-info.rs"]
mod rdp_info;

#[path = "smb-info.rs"]
mod smb_info;

#[path = "ldap-info.rs"]
mod ldap_info;

#[path = "vnc-info.rs"]
mod vnc_info;

// Additional Database Scripts
#[path = "postgres-info.rs"]
mod postgres_info;

#[path = "elasticsearch-info.rs"]
mod elasticsearch_info;

// Container/Cloud Scripts
#[path = "docker-info.rs"]
mod docker_info;

use crate::scripts::Script;

/// Get all built-in scripts
pub fn all_scripts() -> Vec<Box<dyn Script>> {
    vec![
        // HTTP/Web (3 scripts)
        Box::new(http_headers::HttpHeadersScript::new()),
        Box::new(http_security::HttpSecurityScript::new()),
        Box::new(http_vulns::HttpVulnsScript::new()),
        // Service Banners (4 scripts)
        Box::new(ssh_banner::SshBannerScript::new()),
        Box::new(ftp_banner::FtpBannerScript::new()),
        Box::new(smtp_banner::SmtpBannerScript::new()),
        Box::new(telnet_info::TelnetInfoScript::new()),
        // TLS/SSL (1 script)
        Box::new(tls_info::TlsInfoScript::new()),
        // Databases (5 scripts)
        Box::new(mysql_info::MysqlInfoScript::new()),
        Box::new(redis_info::RedisInfoScript::new()),
        Box::new(mongodb_info::MongodbInfoScript::new()),
        Box::new(postgres_info::PostgresInfoScript::new()),
        Box::new(elasticsearch_info::ElasticsearchInfoScript::new()),
        // Network Protocols (6 scripts)
        Box::new(dns_zone_transfer::DnsZoneTransferScript::new()),
        Box::new(snmp_info::SnmpInfoScript::new()),
        Box::new(rdp_info::RdpInfoScript::new()),
        Box::new(smb_info::SmbInfoScript::new()),
        Box::new(ldap_info::LdapInfoScript::new()),
        Box::new(vnc_info::VncInfoScript::new()),
        // Container/Cloud (1 script)
        Box::new(docker_info::DockerInfoScript::new()),
    ]
}

/// Get scripts by category
pub fn scripts_by_category(category: crate::scripts::ScriptCategory) -> Vec<Box<dyn Script>> {
    all_scripts()
        .into_iter()
        .filter(|s| s.metadata().categories.contains(&category))
        .collect()
}

/// Get a specific script by ID
pub fn get_script(id: &str) -> Option<Box<dyn Script>> {
    all_scripts().into_iter().find(|s| s.id() == id)
}
