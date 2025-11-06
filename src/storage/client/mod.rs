// Unified storage client for writers/readers.
// Provides the same API previously exposed via crate::persistence.

pub mod query;

pub use query::QueryManager;

use crate::config;
use crate::storage::reddb::RedDb;
use crate::storage::schema::{
    DnsRecordData, DnsRecordType, HostIntelRecord, HttpHeadersRecord, PortStatus, SubdomainSource,
    TlsScanRecord,
};
use crate::storage::service::StorageService;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Handles persistence for scan results (writer-facing API).
pub struct PersistenceManager {
    db: Option<RedDb>,
    db_path: Option<PathBuf>,
    target: String,
}

impl PersistenceManager {
    /// Create new persistence manager
    pub fn new(target: &str, persist: Option<bool>) -> Result<Self, String> {
        let config = config::get();

        // Determine if we should persist
        let should_persist = persist.unwrap_or(config.database.auto_persist);

        let (db, db_path) = if should_persist {
            let path = Self::get_db_path(target)?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create database directory: {}", e))?;
            }
            let db = RedDb::open(&path).map_err(|e| format!("Failed to open database: {}", e))?;
            StorageService::global().ensure_target_partition(target, path.clone(), None, None);
            (Some(db), Some(path))
        } else {
            (None, None)
        };

        Ok(Self {
            db,
            db_path,
            target: target.to_string(),
        })
    }

    /// Get database file path for target
    fn get_db_path(target: &str) -> Result<PathBuf, String> {
        let config = config::get();

        // Base directory
        let base_dir = if let Some(dir) = &config.database.db_dir {
            PathBuf::from(dir)
        } else {
            std::env::current_dir()
                .map_err(|e| format!("Failed to get current directory: {}", e))?
        };

        // File name
        let filename = if config.database.auto_name {
            format!("{}.rdb", sanitize_filename(target))
        } else {
            "scan.rdb".to_string()
        };

        Ok(base_dir.join(filename))
    }

    /// Check if persistence is enabled
    pub fn is_enabled(&self) -> bool {
        self.db.is_some()
    }

    /// Get database path
    pub fn db_path(&self) -> Option<&PathBuf> {
        self.db_path.as_ref()
    }

    /// Add port scan result
    pub fn add_port_scan(
        &mut self,
        ip: IpAddr,
        port: u16,
        state: u8,
        _service_id: u8,
    ) -> Result<(), String> {
        if let Some(db) = &mut self.db {
            let status = match state {
                0 => PortStatus::Open,
                1 => PortStatus::Closed,
                2 => PortStatus::Filtered,
                3 => PortStatus::OpenFiltered,
                _ => PortStatus::Open,
            };
            db.save_port_scan(ip, port, status)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add DNS record
    pub fn add_dns_record(
        &mut self,
        domain: &str,
        record_type: u16,
        ttl: u32,
        value: &str,
    ) -> Result<(), String> {
        if let Some(db) = &mut self.db {
            if let Some(rt) = map_dns_record_type(record_type) {
                let record = DnsRecordData {
                    domain: domain.to_string(),
                    record_type: rt,
                    value: value.to_string(),
                    ttl,
                    timestamp: current_timestamp(),
                };
                db.save_dns(record)
                    .map_err(|e| format!("Database error: {}", e))?;
            }
        }
        Ok(())
    }

    /// Add subdomain
    pub fn add_subdomain(
        &mut self,
        parent: &str,
        subdomain: &str,
        status: u8,
        ips: &[IpAddr],
    ) -> Result<(), String> {
        if let Some(db) = &mut self.db {
            let source = map_subdomain_source_id(status);
            let ip_list: Vec<IpAddr> = ips.to_vec();
            db.save_subdomain(parent, subdomain, ip_list, source)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add WHOIS data
    pub fn add_whois(
        &mut self,
        domain: &str,
        registrar: &str,
        created: u32,
        expires: u32,
        nameservers: &[String],
    ) -> Result<(), String> {
        if let Some(db) = &mut self.db {
            db.save_whois(domain, registrar, created, expires, nameservers.to_vec())
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add TLS scan result
    pub fn add_tls_scan(&mut self, mut record: TlsScanRecord) -> Result<(), String> {
        if let Some(db) = &mut self.db {
            if record.timestamp == 0 {
                record.timestamp = current_timestamp();
            }
            db.save_tls_scan(record)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add HTTP capture
    pub fn add_http_capture(&mut self, mut record: HttpHeadersRecord) -> Result<(), String> {
        if let Some(db) = &mut self.db {
            if record.timestamp == 0 {
                record.timestamp = current_timestamp();
            }
            db.save_http(record)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add host fingerprint/intel record
    pub fn add_host_intel(&mut self, record: HostIntelRecord) -> Result<(), String> {
        if let Some(db) = &mut self.db {
            db.save_host_fingerprint(record)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Commit and finalize database
    pub fn commit(mut self) -> Result<Option<PathBuf>, String> {
        if let Some(mut db) = self.db {
            db.flush().map_err(|e| format!("Database error: {}", e))?;
            if let Some(path) = &self.db_path {
                let service = StorageService::global();
                let _ = service.refresh_target_partition(&self.target, path);
            }
            Ok(self.db_path)
        } else {
            Ok(None)
        }
    }
}

/// Sanitize filename (remove invalid characters)
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect()
}

fn current_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs() as u32
}

fn map_dns_record_type(code: u16) -> Option<DnsRecordType> {
    match code {
        1 => Some(DnsRecordType::A),
        2 => Some(DnsRecordType::NS),
        5 => Some(DnsRecordType::CNAME),
        15 => Some(DnsRecordType::MX),
        16 => Some(DnsRecordType::TXT),
        28 => Some(DnsRecordType::AAAA),
        _ => None,
    }
}

fn map_subdomain_source_id(code: u8) -> SubdomainSource {
    match code {
        0 => SubdomainSource::DnsBruteforce,
        1 => SubdomainSource::CertTransparency,
        2 => SubdomainSource::SearchEngine,
        3 => SubdomainSource::WebCrawl,
        _ => SubdomainSource::SearchEngine,
    }
}
