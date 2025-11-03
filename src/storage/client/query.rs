// Query interface for RedDb - RESTful operations
// Provides list, get, describe, delete operations on stored data

use crate::storage::encoding::{DecodeError, IpKey};
use crate::storage::schema::{
    DnsRecordData, HostIntelRecord, HttpHeadersRecord, PortStatus, TlsScanRecord, WhoisRecord,
};
use crate::storage::view::RedDbView;
use std::io;
use std::net::IpAddr;
use std::path::Path;

/// Query interface for reading stored scan data
pub struct QueryManager {
    view: RedDbView,
}

impl QueryManager {
    /// Open database for querying
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let view = RedDbView::open(path)?;

        Ok(Self {
            view,
        })
    }

    /// List all open ports for a specific IP
    pub fn list_ports(&mut self, ip: IpAddr) -> io::Result<Vec<u16>> {
        if let Some(ports) = self.view.ports() {
            let records = ports.records_for_ip(&ip).map_err(decode_err_to_io)?;
            let mut open: Vec<u16> = records
                .into_iter()
                .filter(|rec| matches!(rec.status, PortStatus::Open))
                .map(|rec| rec.port)
                .collect();
            open.sort_unstable();
            open.dedup();
            return Ok(open);
        }
        Ok(Vec::new())
    }

    /// List all subdomains for a domain
    pub fn list_subdomains(&mut self, domain: &str) -> io::Result<Vec<String>> {
        if let Some(subdomains) = self.view.subdomains() {
            let records = subdomains
                .records_for_domain(domain)
                .map_err(decode_err_to_io)?;
            let mut values: Vec<String> =
                records.into_iter().map(|record| record.subdomain).collect();
            values.sort();
            values.dedup();
            return Ok(values);
        }

        Ok(Vec::new())
    }

    /// List all DNS records for a domain
    pub fn list_dns_records(&mut self, domain: &str) -> io::Result<Vec<DnsRecordData>> {
        if let Some(dns) = self.view.dns() {
            let records = dns.records_for_domain(domain).map_err(decode_err_to_io)?;
            return Ok(records);
        }
        Ok(Vec::new())
    }

    /// List all HTTP records for a host
    pub fn list_http_records(&mut self, host: &str) -> io::Result<Vec<HttpHeadersRecord>> {
        if let Some(http) = self.view.http() {
            let mut records = http.records_for_host(host).map_err(decode_err_to_io)?;
            records.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            return Ok(records);
        }
        Ok(Vec::new())
    }

    /// Get WHOIS data for a specific domain
    pub fn get_whois(&mut self, domain: &str) -> io::Result<Option<WhoisRecord>> {
        if let Some(whois) = self.view.whois() {
            return whois.get(domain).map_err(decode_err_to_io);
        }
        Ok(None)
    }

    /// Get specific port status
    pub fn get_port_status(&mut self, ip: IpAddr, port: u16) -> io::Result<Option<PortStatus>> {
        if let Some(ports) = self.view.ports() {
            let records = ports.records_for_ip(&ip).map_err(decode_err_to_io)?;
            for record in records {
                if record.port == port {
                    return Ok(Some(record.status));
                }
            }
            return Ok(None);
        }
        Ok(None)
    }

    /// Get stored host fingerprint
    pub fn get_host_fingerprint(&mut self, ip: IpAddr) -> io::Result<Option<HostIntelRecord>> {
        if let Some(hosts) = self.view.hosts() {
            return hosts
                .get(ip)
                .map_err(decode_err_to_io);
        }
        Ok(None)
    }

    /// List all stored host fingerprints
    pub fn list_hosts(&mut self) -> io::Result<Vec<HostIntelRecord>> {
        if let Some(hosts) = self.view.hosts() {
            let mut records = hosts
                .all()
                .map_err(decode_err_to_io)?;
            records.sort_by(|a, b| IpKey::from(&a.ip).cmp(&IpKey::from(&b.ip)));
            return Ok(records);
        }
        Ok(Vec::new())
    }

    /// List TLS scans for a given host
    pub fn list_tls_scans(&mut self, host: &str) -> io::Result<Vec<TlsScanRecord>> {
        if let Some(tls) = self.view.tls() {
            let mut scans = tls.records_for_host(host).map_err(decode_err_to_io)?;
            scans.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            return Ok(scans);
        }
        Ok(Vec::new())
    }

    /// Get the most recent TLS scan for a host
    pub fn latest_tls_scan(&mut self, host: &str) -> io::Result<Option<TlsScanRecord>> {
        if let Some(tls) = self.view.tls() {
            let mut scans = tls.records_for_host(host).map_err(decode_err_to_io)?;
            scans.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            return Ok(scans.into_iter().next());
        }
        Ok(None)
    }
}

fn decode_err_to_io(err: DecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.0)
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
    fn query_manager_compiles() {
        // Placeholder to ensure module compiles; integration tests live elsewhere.
        let _ = QueryManager::open("/tmp/non-existent.rdb");
    }

    #[test]
    fn format_ports_output() {
        let ports = vec![22, 80, 443];
        let formatted = format::format_ports(&ports);
        assert!(formatted.contains("Open Ports (3)"));
        assert!(formatted.contains("22"));
        assert!(formatted.contains("80"));
        assert!(formatted.contains("443"));
    }

    #[test]
    fn format_host_output() {
        let record = HostIntelRecord {
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            os_family: Some("linux".into()),
            confidence: 0.85,
            last_seen: 1_700_000_000,
            services: Vec::new(),
        };
        let formatted = format::format_host(&record);
        assert!(formatted.contains("linux"));
    }
}
