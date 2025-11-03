// Database persistence helper
// Manages .rdb file creation and data storage

pub mod query;

pub use query::QueryManager;

use crate::config;
use crate::storage::schema::HostIntelRecord;
use crate::storage::{BinaryPortScanRecord as PortScanRecord, BinaryWriter};
use std::path::PathBuf;

/// Persistence manager for scan results
pub struct PersistenceManager {
    writer: Option<BinaryWriter>,
    db_path: Option<PathBuf>,
}

impl PersistenceManager {
    /// Create new persistence manager
    pub fn new(target: &str, persist: Option<bool>) -> Result<Self, String> {
        let config = config::get();

        // Determine if we should persist
        let should_persist = persist.unwrap_or(config.database.auto_persist);

        let (writer, db_path) = if should_persist {
            let path = Self::get_db_path(target)?;
            let w = BinaryWriter::create(path.to_str().unwrap())
                .map_err(|e| format!("Failed to create database: {}", e))?;
            (Some(w), Some(path))
        } else {
            (None, None)
        };

        Ok(Self { writer, db_path })
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
        self.writer.is_some()
    }

    /// Get database path
    pub fn db_path(&self) -> Option<&PathBuf> {
        self.db_path.as_ref()
    }

    /// Add port scan result
    pub fn add_port_scan(
        &mut self,
        ip: u32,
        port: u16,
        state: u8,
        service_id: u8,
    ) -> Result<(), String> {
        if let Some(writer) = &mut self.writer {
            let record = PortScanRecord::new(ip, port, state, service_id);
            writer
                .add_port_scan(record)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add DNS record
    pub fn add_dns_record(
        &mut self,
        domain: &str,
        record_type: u8,
        ttl: u32,
        data: &[u8],
    ) -> Result<(), String> {
        if let Some(writer) = &mut self.writer {
            writer
                .add_dns_record(domain, record_type, ttl, data)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add subdomain
    pub fn add_subdomain(
        &mut self,
        parent: &str,
        subdomain: &str,
        status: u8,
        ips: &[u32],
    ) -> Result<(), String> {
        if let Some(writer) = &mut self.writer {
            writer
                .add_subdomain(parent, subdomain, status, ips)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add WHOIS data
    pub fn add_whois(&mut self, domain: &str, data: &[u8]) -> Result<(), String> {
        if let Some(writer) = &mut self.writer {
            writer
                .add_whois(domain, data)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add TLS certificate
    pub fn add_tls_cert(&mut self, domain: &str, data: &[u8]) -> Result<(), String> {
        if let Some(writer) = &mut self.writer {
            writer
                .add_tls_cert(domain, data)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add HTTP headers
    pub fn add_http_headers(&mut self, url: &str, headers: &[u8]) -> Result<(), String> {
        if let Some(writer) = &mut self.writer {
            writer
                .add_http_headers(url, headers)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add host fingerprint/intel record
    pub fn add_host_intel(&mut self, record: HostIntelRecord) -> Result<(), String> {
        if let Some(writer) = &mut self.writer {
            writer
                .add_host_intel(record)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Commit and finalize database
    pub fn commit(self) -> Result<Option<PathBuf>, String> {
        if let Some(writer) = self.writer {
            writer
                .commit()
                .map_err(|e| format!("Database error: {}", e))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("example.com"), "example.com");
        assert_eq!(sanitize_filename("192.168.1.1"), "192.168.1.1");
        assert_eq!(sanitize_filename("test/path"), "test_path");
        assert_eq!(sanitize_filename("test:8080"), "test_8080");
    }

    #[test]
    fn test_persistence_disabled() {
        let pm = PersistenceManager::new("test.com", Some(false)).unwrap();
        assert!(!pm.is_enabled());
        assert!(pm.db_path().is_none());
    }

    #[test]
    fn test_persistence_enabled() {
        let pm = PersistenceManager::new("test.com", Some(true)).unwrap();
        assert!(pm.is_enabled());
        assert!(pm.db_path().is_some());

        let path = pm.db_path().unwrap();
        assert!(path.to_string_lossy().contains("test.com.rdb"));
    }
}
