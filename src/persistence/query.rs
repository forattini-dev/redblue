// Query interface for RedDB - RESTful operations
// Provides list, get, describe, delete operations on stored data

use crate::storage::reddb::RedDb;
use crate::storage::schema::{
    DnsRecordData, HostIntelRecord, HttpHeadersRecord, PortStatus, TlsCertRecord, WhoisRecord,
};
use std::io;
use std::net::IpAddr;
use std::path::Path;

/// Query interface for reading stored scan data
pub struct QueryManager {
    db: RedDb,
}

impl QueryManager {
    /// Open database for querying
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Ok(Self {
            db: RedDb::open(path)?,
        })
    }

    /// List all open ports for a specific IP
    pub fn list_ports(&mut self, ip: IpAddr) -> io::Result<Vec<u16>> {
        self.db.get_open_ports(ip)
    }

    /// List all subdomains for a domain
    pub fn list_subdomains(&mut self, domain: &str) -> io::Result<Vec<String>> {
        self.db.get_subdomains(domain)
    }

    /// List all DNS records for a domain
    pub fn list_dns_records(&mut self, domain: &str) -> io::Result<Vec<DnsRecordData>> {
        self.db.get_dns_records(domain)
    }

    /// List all HTTP records for a host
    pub fn list_http_records(&mut self, host: &str) -> io::Result<Vec<HttpHeadersRecord>> {
        self.db.get_http_by_host(host)
    }

    /// Get WHOIS data for a specific domain
    pub fn get_whois(&mut self, domain: &str) -> io::Result<Option<WhoisRecord>> {
        self.db.get_whois(domain)
    }

    /// Get TLS certificate for a domain
    pub fn get_cert(&mut self, domain: &str) -> io::Result<Option<TlsCertRecord>> {
        self.db.get_cert(domain)
    }

    /// Get specific port status
    pub fn get_port_status(&mut self, ip: IpAddr, port: u16) -> io::Result<Option<PortStatus>> {
        let open_ports = self.db.get_open_ports(ip)?;
        Ok(if open_ports.contains(&port) {
            Some(PortStatus::Open)
        } else {
            None
        })
    }

    /// Get stored host fingerprint
    pub fn get_host_fingerprint(&mut self, ip: IpAddr) -> io::Result<Option<HostIntelRecord>> {
        self.db.get_host_fingerprint(ip)
    }

    /// List all stored host fingerprints
    pub fn list_hosts(&mut self) -> io::Result<Vec<HostIntelRecord>> {
        self.db.list_host_fingerprints()
    }
}

/// Format helpers for displaying query results
pub mod format {
    use super::*;

    pub fn format_ports(ports: &[u16]) -> String {
        if ports.is_empty() {
            return "No open ports found".to_string();
        }

        let mut result = format!("Open Ports ({})\n", ports.len());
        result.push_str("━━━━━━━━━━━━━━━\n");

        for port in ports {
            result.push_str(&format!("  {}  \n", port));
        }

        result
    }

    pub fn format_subdomains(subdomains: &[String]) -> String {
        if subdomains.is_empty() {
            return "No subdomains found".to_string();
        }

        let mut result = format!("Subdomains ({})\n", subdomains.len());
        result.push_str("━━━━━━━━━━━━━━━\n");

        for subdomain in subdomains {
            result.push_str(&format!("  • {}\n", subdomain));
        }

        result
    }

    pub fn format_whois(record: &WhoisRecord) -> String {
        format!(
            "WHOIS Record\n\
             ━━━━━━━━━━━━\n\
             Registrar: {}\n\
             Created:   {}\n\
             Expires:   {}\n\
             Nameservers:\n{}",
            record.registrar,
            record.created_date,
            record.expires_date,
            record
                .nameservers
                .iter()
                .map(|ns| format!("  • {}", ns))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    pub fn format_cert(record: &TlsCertRecord) -> String {
        format!(
            "TLS Certificate\n\
             ━━━━━━━━━━━━━━━\n\
             Subject:     {}\n\
             Issuer:      {}\n\
             Not Before:  {}\n\
             Not After:   {}\n\
             Self-Signed: {}\n\
             SANs:\n{}",
            record.subject,
            record.issuer,
            record.not_before,
            record.not_after,
            if record.self_signed { "Yes" } else { "No" },
            record
                .sans
                .iter()
                .map(|san| format!("  • {}", san))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    pub fn format_dns_records(records: &[DnsRecordData]) -> String {
        if records.is_empty() {
            return "No DNS records found".to_string();
        }

        let mut result = format!("DNS Records ({})\n", records.len());
        result.push_str("━━━━━━━━━━━━━━━\n");

        for record in records {
            result.push_str(&format!(
                "  {} {:?} (TTL: {})\n",
                record.domain, record.record_type, record.ttl
            ));
        }

        result
    }

    pub fn format_host(record: &HostIntelRecord) -> String {
        let mut result = String::new();
        result.push_str("Host Fingerprint\n");
        result.push_str("━━━━━━━━━━━━━━━━\n");
        result.push_str(&format!("IP Address: {}\n", record.ip));
        if let Some(os) = &record.os_family {
            result.push_str(&format!(
                "OS Guess:   {} ({:.0}% confidence)\n",
                os,
                (record.confidence * 100.0).round()
            ));
        } else {
            result.push_str("OS Guess:   unknown\n");
        }
        result.push_str(&format!("Last Seen:  {}\n", record.last_seen));
        result.push_str(&format!("Services ({})\n", record.services.len()));
        result.push_str("━━━━━━━━━━━━━━━━━━━━\n");
        for service in &record.services {
            result.push_str(&format!("Port {:<5}", service.port));
            if let Some(name) = &service.service_name {
                result.push(' ');
                result.push_str(name);
            }
            result.push('\n');
            if let Some(banner) = &service.banner {
                result.push_str(&format!("  Banner: {}\n", banner));
            }
            for hint in &service.os_hints {
                result.push_str(&format!("  Hint:   {}\n", hint));
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_query_manager() {
        // Integration test would require actual database file
        // For now, just test that the API compiles
    }

    #[test]
    fn test_format_ports() {
        let ports = vec![22, 80, 443];
        let formatted = format::format_ports(&ports);
        assert!(formatted.contains("Open Ports (3)"));
        assert!(formatted.contains("22"));
        assert!(formatted.contains("80"));
        assert!(formatted.contains("443"));
    }

    #[test]
    fn test_format_empty_ports() {
        let ports = vec![];
        let formatted = format::format_ports(&ports);
        assert_eq!(formatted, "No open ports found");
    }
}
