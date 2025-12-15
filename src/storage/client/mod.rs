// Unified storage client for writers/readers.
// Provides the same API previously exposed via crate::persistence.

pub mod query;

pub use super::keyring::PasswordSource;
pub use query::QueryManager;

use crate::config;
use crate::storage::keyring::resolve_password;
use crate::storage::records::{
    DnsRecordData, DnsRecordType, HostIntelRecord, HttpHeadersRecord, PortStatus,
    ProxyConnectionRecord, ProxyHttpRequestRecord, ProxyHttpResponseRecord, ProxyWebSocketRecord,
    SubdomainSource, TlsScanRecord,
};
use crate::storage::reddb::RedDb;
use crate::storage::service::StorageService;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Persistence configuration options
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// Database path (if None, auto-generated from target)
    pub db_path: Option<PathBuf>,
    /// Password for encryption (from flag, env, or keyring)
    pub password: Option<String>,
    /// Force persistence even if auto_persist is disabled
    pub force_save: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            db_path: None,
            password: None,
            force_save: false,
        }
    }
}

impl PersistenceConfig {
    /// Create a new config with --save flag
    pub fn with_save() -> Self {
        Self {
            force_save: true,
            ..Default::default()
        }
    }

    /// Set database path
    pub fn with_db_path(mut self, path: PathBuf) -> Self {
        self.db_path = Some(path);
        self
    }

    /// Set password explicitly
    pub fn with_password(mut self, password: String) -> Self {
        self.password = Some(password);
        self
    }
}

/// Handles persistence for scan results (writer-facing API).
pub struct PersistenceManager {
    db: Option<RedDb>,
    db_path: Option<PathBuf>,
    target: String,
    /// Password source used (for informational purposes)
    password_source: PasswordSource,
}

impl PersistenceManager {
    /// Create new persistence manager (legacy API for backward compatibility)
    pub fn new(target: &str, persist: Option<bool>) -> Result<Self, String> {
        let config = PersistenceConfig {
            force_save: persist.unwrap_or(false),
            ..Default::default()
        };
        Self::with_config(target, config)
    }

    /// Create persistence manager with explicit configuration
    /// This is the recommended way to create a PersistenceManager
    pub fn with_config(target: &str, config: PersistenceConfig) -> Result<Self, String> {
        let global_config = config::get();

        // Determine if we should persist
        let should_persist = config.force_save || global_config.database.auto_persist;

        if !should_persist {
            return Ok(Self {
                db: None,
                db_path: None,
                target: target.to_string(),
                password_source: PasswordSource::None,
            });
        }

        // Determine database path
        let path = match config.db_path {
            Some(p) => p,
            None => Self::get_db_path(target)?,
        };

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create database directory: {}", e))?;
        }

        // Resolve password from hierarchy: flag > env > keyring > none
        let password_source = resolve_password(config.password.as_deref());

        // Open database with encryption if password is available
        let db = match password_source.password() {
            Some(pwd) => RedDb::open_encrypted(&path, pwd)
                .map_err(|e| format!("Failed to open encrypted database: {}", e))?,
            None => {
                // No password - check if existing file is encrypted
                if path.exists() && RedDb::is_encrypted_file(&path) {
                    return Err("Database is encrypted but no password provided.\n\
                        Set password with: rb config set-password\n\
                        Or use: --db-password <password>\n\
                        Or set: REDBLUE_DB_KEY environment variable"
                        .to_string());
                }
                // Open unencrypted (WARNING: not recommended)
                RedDb::open(&path).map_err(|e| format!("Failed to open database: {}", e))?
            }
        };

        StorageService::global().ensure_target_partition(target, path.clone(), None, None);

        Ok(Self {
            db: Some(db),
            db_path: Some(path),
            target: target.to_string(),
            password_source,
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

    /// Get the password source used
    pub fn password_source(&self) -> &PasswordSource {
        &self.password_source
    }

    /// Check if database is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.password_source.is_encrypted()
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

    /// Add proxy connection record
    pub fn add_proxy_connection(&mut self, record: ProxyConnectionRecord) -> Result<(), String> {
        if let Some(db) = &mut self.db {
            db.save_proxy_connection(record)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add proxy HTTP request record
    pub fn add_proxy_http_request(&mut self, record: ProxyHttpRequestRecord) -> Result<(), String> {
        if let Some(db) = &mut self.db {
            db.save_proxy_http_request(record)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add proxy HTTP response record
    pub fn add_proxy_http_response(
        &mut self,
        record: ProxyHttpResponseRecord,
    ) -> Result<(), String> {
        if let Some(db) = &mut self.db {
            db.save_proxy_http_response(record)
                .map_err(|e| format!("Database error: {}", e))?;
        }
        Ok(())
    }

    /// Add proxy WebSocket frame record
    pub fn add_proxy_websocket(&mut self, record: ProxyWebSocketRecord) -> Result<(), String> {
        if let Some(db) = &mut self.db {
            db.save_proxy_websocket(record)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to serialize tests that modify global state
    static CLIENT_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Create a unique temp directory for tests
    fn create_test_dir(test_name: &str) -> PathBuf {
        let unique_id = uuid::Uuid::new_v4();
        let dir = std::env::temp_dir()
            .join("redblue_tests")
            .join(format!("{}_{}", test_name, unique_id));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Cleanup a test directory
    fn cleanup_test_dir(dir: &PathBuf) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_persistence_config_default() {
        let config = PersistenceConfig::default();
        assert!(config.db_path.is_none());
        assert!(config.password.is_none());
        assert!(!config.force_save);
    }

    #[test]
    fn test_persistence_config_with_save() {
        let config = PersistenceConfig::with_save();
        assert!(config.force_save);
        assert!(config.db_path.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_persistence_config_builder() {
        let config = PersistenceConfig::default()
            .with_db_path(PathBuf::from("/tmp/test.rdb"))
            .with_password("mypassword".to_string());

        assert_eq!(config.db_path, Some(PathBuf::from("/tmp/test.rdb")));
        assert_eq!(config.password, Some("mypassword".to_string()));
    }

    #[test]
    fn test_persistence_config_chain() {
        let config = PersistenceConfig::with_save()
            .with_db_path(PathBuf::from("/custom/path.rdb"))
            .with_password("secret".to_string());

        assert!(config.force_save);
        assert_eq!(config.db_path, Some(PathBuf::from("/custom/path.rdb")));
        assert_eq!(config.password, Some("secret".to_string()));
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("normal"), "normal");
        assert_eq!(sanitize_filename("with/slash"), "with_slash");
        assert_eq!(sanitize_filename("with\\backslash"), "with_backslash");
        assert_eq!(sanitize_filename("with:colon"), "with_colon");
        assert_eq!(sanitize_filename("with*star"), "with_star");
        assert_eq!(sanitize_filename("with?question"), "with_question");
        assert_eq!(sanitize_filename("with\"quote"), "with_quote");
        assert_eq!(sanitize_filename("with<less"), "with_less");
        assert_eq!(sanitize_filename("with>greater"), "with_greater");
        assert_eq!(sanitize_filename("with|pipe"), "with_pipe");
        assert_eq!(
            sanitize_filename("http://example.com/path?q=1"),
            "http___example.com_path_q=1"
        );
    }

    #[test]
    fn test_sanitize_filename_preserves_valid() {
        assert_eq!(sanitize_filename("example.com"), "example.com");
        assert_eq!(sanitize_filename("192.168.1.1"), "192.168.1.1");
        assert_eq!(sanitize_filename("file-name_123"), "file-name_123");
    }

    #[test]
    fn test_map_dns_record_type() {
        assert_eq!(map_dns_record_type(1), Some(DnsRecordType::A));
        assert_eq!(map_dns_record_type(2), Some(DnsRecordType::NS));
        assert_eq!(map_dns_record_type(5), Some(DnsRecordType::CNAME));
        assert_eq!(map_dns_record_type(15), Some(DnsRecordType::MX));
        assert_eq!(map_dns_record_type(16), Some(DnsRecordType::TXT));
        assert_eq!(map_dns_record_type(28), Some(DnsRecordType::AAAA));
        assert_eq!(map_dns_record_type(99), None);
        assert_eq!(map_dns_record_type(0), None);
    }

    #[test]
    fn test_map_subdomain_source_id() {
        assert!(matches!(
            map_subdomain_source_id(0),
            SubdomainSource::DnsBruteforce
        ));
        assert!(matches!(
            map_subdomain_source_id(1),
            SubdomainSource::CertTransparency
        ));
        assert!(matches!(
            map_subdomain_source_id(2),
            SubdomainSource::SearchEngine
        ));
        assert!(matches!(
            map_subdomain_source_id(3),
            SubdomainSource::WebCrawl
        ));
        // Unknown codes default to SearchEngine
        assert!(matches!(
            map_subdomain_source_id(4),
            SubdomainSource::SearchEngine
        ));
        assert!(matches!(
            map_subdomain_source_id(255),
            SubdomainSource::SearchEngine
        ));
    }

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        // Should be a reasonable Unix timestamp (after 2020)
        assert!(ts > 1577836800); // Jan 1, 2020
                                  // And not too far in the future
        assert!(ts < 2524608000); // Jan 1, 2050
    }

    #[test]
    fn test_persistence_manager_disabled() {
        let _lock = CLIENT_TEST_LOCK.lock().unwrap();

        // Create with force_save=false
        // Note: persistence may still be enabled if global auto_persist is true
        let pm = PersistenceManager::new("test-target-disabled", Some(false)).unwrap();

        // The test behavior depends on the global config
        let global_config = crate::config::get();
        if global_config.database.auto_persist {
            // When auto_persist is enabled, manager will be enabled even with force_save=false
            assert!(pm.is_enabled());
        } else {
            // When auto_persist is disabled, manager will also be disabled
            assert!(!pm.is_enabled());
            assert!(pm.db_path().is_none());
            assert!(!pm.is_encrypted());
        }
    }

    #[test]
    fn test_persistence_manager_with_config_no_save() {
        let _lock = CLIENT_TEST_LOCK.lock().unwrap();

        let config = PersistenceConfig::default(); // force_save = false
                                                   // Note: This might enable if auto_persist is true in config
        let pm = PersistenceManager::with_config("test-target", config);
        // Result depends on global config - just verify it doesn't panic
        assert!(pm.is_ok());
    }

    #[test]
    fn test_persistence_manager_with_explicit_path() {
        let _lock = CLIENT_TEST_LOCK.lock().unwrap();

        let dir = create_test_dir("explicit_path");
        let db_path = dir.join("explicit.rdb");

        let config = PersistenceConfig::with_save()
            .with_db_path(db_path.clone())
            .with_password("testpwd123".to_string());

        let pm = PersistenceManager::with_config("test-target", config).unwrap();

        assert!(pm.is_enabled());
        assert_eq!(pm.db_path(), Some(&db_path));
        assert!(pm.is_encrypted());
        assert!(matches!(pm.password_source(), PasswordSource::Flag(_)));

        cleanup_test_dir(&dir);
    }

    #[test]
    fn test_persistence_manager_add_port_scan() {
        let _lock = CLIENT_TEST_LOCK.lock().unwrap();

        let dir = create_test_dir("port_scan");
        let db_path = dir.join("ports.rdb");

        let config = PersistenceConfig::with_save()
            .with_db_path(db_path)
            .with_password("testpwd".to_string());

        let mut pm = PersistenceManager::with_config("192.168.1.1", config).unwrap();

        // Add port scans
        let result = pm.add_port_scan("192.168.1.1".parse().unwrap(), 80, 0, 0);
        assert!(result.is_ok());

        let result = pm.add_port_scan("192.168.1.1".parse().unwrap(), 443, 0, 0);
        assert!(result.is_ok());

        // Commit should work
        let path = pm.commit().unwrap();
        assert!(path.is_some());

        cleanup_test_dir(&dir);
    }

    #[test]
    fn test_persistence_manager_add_dns_record() {
        let _lock = CLIENT_TEST_LOCK.lock().unwrap();

        let dir = create_test_dir("dns_record");
        let db_path = dir.join("dns.rdb");

        let config = PersistenceConfig::with_save()
            .with_db_path(db_path)
            .with_password("dnstest".to_string());

        let mut pm = PersistenceManager::with_config("example.com", config).unwrap();

        // Add DNS records
        let result = pm.add_dns_record("example.com", 1, 3600, "93.184.216.34");
        assert!(result.is_ok());

        let result = pm.add_dns_record("example.com", 15, 3600, "mail.example.com");
        assert!(result.is_ok());

        // Unknown type should be ignored (no error)
        let result = pm.add_dns_record("example.com", 999, 3600, "unknown");
        assert!(result.is_ok());

        let path = pm.commit().unwrap();
        assert!(path.is_some());

        cleanup_test_dir(&dir);
    }

    #[test]
    fn test_persistence_manager_add_subdomain() {
        let _lock = CLIENT_TEST_LOCK.lock().unwrap();

        let dir = create_test_dir("subdomain");
        let db_path = dir.join("subdomains.rdb");

        let config = PersistenceConfig::with_save()
            .with_db_path(db_path)
            .with_password("subtest".to_string());

        let mut pm = PersistenceManager::with_config("example.com", config).unwrap();

        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = pm.add_subdomain("example.com", "www", 0, &ips);
        assert!(result.is_ok());

        let path = pm.commit().unwrap();
        assert!(path.is_some());

        cleanup_test_dir(&dir);
    }

    #[test]
    fn test_persistence_manager_add_whois() {
        let _lock = CLIENT_TEST_LOCK.lock().unwrap();

        let dir = create_test_dir("whois");
        let db_path = dir.join("whois.rdb");

        let config = PersistenceConfig::with_save()
            .with_db_path(db_path)
            .with_password("whoistest".to_string());

        let mut pm = PersistenceManager::with_config("example.com", config).unwrap();

        let nameservers = vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()];
        let result = pm.add_whois(
            "example.com",
            "Test Registrar",
            1000000,
            2000000,
            &nameservers,
        );
        assert!(result.is_ok());

        let path = pm.commit().unwrap();
        assert!(path.is_some());

        cleanup_test_dir(&dir);
    }

    #[test]
    fn test_persistence_manager_disabled_operations() {
        let _lock = CLIENT_TEST_LOCK.lock().unwrap();

        // Create manager - behavior depends on global config
        let mut pm = PersistenceManager::new("test-disabled-ops", Some(false)).unwrap();

        // Check enabled state before commit (which moves self)
        let global_config = crate::config::get();
        let was_enabled = pm.is_enabled();

        // All operations should succeed regardless of enabled state
        assert!(pm
            .add_port_scan("1.2.3.4".parse().unwrap(), 80, 0, 0)
            .is_ok());
        assert!(pm.add_dns_record("test.com", 1, 3600, "1.2.3.4").is_ok());
        assert!(pm.add_subdomain("test.com", "www", 0, &[]).is_ok());
        assert!(pm.add_whois("test.com", "reg", 0, 0, &[]).is_ok());

        // If persistence is disabled, commit returns None
        // If auto_persist is enabled, it will return Some(path)
        let path = pm.commit().unwrap();
        if !global_config.database.auto_persist && !was_enabled {
            assert!(path.is_none());
        }
    }

    #[test]
    fn test_persistence_manager_port_states() {
        let _lock = CLIENT_TEST_LOCK.lock().unwrap();

        let dir = create_test_dir("port_states");
        let db_path = dir.join("states.rdb");

        let config = PersistenceConfig::with_save()
            .with_db_path(db_path)
            .with_password("statetest".to_string());

        let mut pm = PersistenceManager::with_config("test", config).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Test all port states
        assert!(pm.add_port_scan(ip, 80, 0, 0).is_ok()); // Open
        assert!(pm.add_port_scan(ip, 81, 1, 0).is_ok()); // Closed
        assert!(pm.add_port_scan(ip, 82, 2, 0).is_ok()); // Filtered
        assert!(pm.add_port_scan(ip, 83, 3, 0).is_ok()); // OpenFiltered
        assert!(pm.add_port_scan(ip, 84, 99, 0).is_ok()); // Unknown -> Open

        let _ = pm.commit();

        cleanup_test_dir(&dir);
    }

    // Note: The encrypted file detection test was removed because it depends
    // on global state (env vars, keyring) which is hard to isolate in tests.
    // The functionality is covered by storage/keyring tests and integration tests.
}
