/// Service Banner Grabbing & OS Fingerprinting
///
/// Extract intelligence from service banners:
/// - Service identification (SSH, FTP, SMTP, HTTP, MySQL, etc.)
/// - Version detection
/// - OS hints from banner strings
/// - Security implications
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ServiceBanner {
    pub host: String,
    pub port: u16,
    pub service: ServiceType,
    pub banner: String,
    pub version: Option<String>,
    pub os_hints: Vec<String>,
    pub security_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ServiceType {
    SSH,
    FTP,
    SMTP,
    HTTP,
    MySQL,
    PostgreSQL,
    MongoDB,
    Redis,
    Telnet,
    LDAP,
    SMB,
    MSSQL,
    Unknown,
}

impl ServiceBanner {
    /// Grab banner from a service
    pub fn grab(host: &str, port: u16) -> Result<Self, String> {
        let service = Self::identify_service_by_port(port);

        let banner = match service {
            ServiceType::SSH => Self::grab_ssh_banner(host, port)?,
            ServiceType::FTP => Self::grab_ftp_banner(host, port)?,
            ServiceType::SMTP => Self::grab_smtp_banner(host, port)?,
            ServiceType::HTTP => Self::grab_http_banner(host, port)?,
            _ => Self::grab_generic_banner(host, port)?,
        };

        let version = Self::extract_version(&banner, &service);
        let os_hints = Self::extract_os_hints(&banner, &service);
        let security_notes = Self::analyze_security(&banner, &service);

        Ok(ServiceBanner {
            host: host.to_string(),
            port,
            service,
            banner,
            version,
            os_hints,
            security_notes,
        })
    }

    /// Identify likely service based on port number
    fn identify_service_by_port(port: u16) -> ServiceType {
        match port {
            21 => ServiceType::FTP,
            22 => ServiceType::SSH,
            23 => ServiceType::Telnet,
            25 | 587 => ServiceType::SMTP,
            80 | 8080 | 8000 => ServiceType::HTTP,
            443 | 8443 => ServiceType::HTTP,
            389 | 636 => ServiceType::LDAP,
            445 => ServiceType::SMB,
            1433 => ServiceType::MSSQL,
            3306 => ServiceType::MySQL,
            5432 => ServiceType::PostgreSQL,
            6379 => ServiceType::Redis,
            27017 => ServiceType::MongoDB,
            _ => ServiceType::Unknown,
        }
    }

    /// Grab SSH banner (SSH-2.0-OpenSSH_...)
    fn grab_ssh_banner(host: &str, port: u16) -> Result<String, String> {
        let addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&addr).map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

        let mut buffer = [0u8; 512];
        match stream.read(&mut buffer) {
            Ok(n) if n > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                Ok(banner.trim().to_string())
            }
            _ => Err("Failed to read SSH banner".to_string()),
        }
    }

    /// Grab FTP banner (220 ...)
    fn grab_ftp_banner(host: &str, port: u16) -> Result<String, String> {
        let addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&addr).map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

        let mut buffer = [0u8; 512];
        match stream.read(&mut buffer) {
            Ok(n) if n > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                Ok(banner.trim().to_string())
            }
            _ => Err("Failed to read FTP banner".to_string()),
        }
    }

    /// Grab SMTP banner (220 ...)
    fn grab_smtp_banner(host: &str, port: u16) -> Result<String, String> {
        let addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&addr).map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

        let mut buffer = [0u8; 512];
        match stream.read(&mut buffer) {
            Ok(n) if n > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                Ok(banner.trim().to_string())
            }
            _ => Err("Failed to read SMTP banner".to_string()),
        }
    }

    /// Grab HTTP banner (Server header)
    fn grab_http_banner(host: &str, port: u16) -> Result<String, String> {
        let addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&addr).map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

        // Send HTTP request
        let request = format!("HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", host);
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("Failed to send request: {}", e))?;

        // Read response
        let mut buffer = [0u8; 2048];
        match stream.read(&mut buffer) {
            Ok(n) if n > 0 => {
                let response = String::from_utf8_lossy(&buffer[..n]).to_string();

                // Extract Server header
                for line in response.lines() {
                    if line.to_lowercase().starts_with("server:") {
                        return Ok(line[7..].trim().to_string());
                    }
                }

                Ok("HTTP (no Server header)".to_string())
            }
            _ => Err("Failed to read HTTP response".to_string()),
        }
    }

    /// Grab generic banner (try to read whatever the service sends)
    fn grab_generic_banner(host: &str, port: u16) -> Result<String, String> {
        let addr = format!("{}:{}", host, port);
        let mut stream =
            TcpStream::connect(&addr).map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(3))).ok();

        let mut buffer = [0u8; 1024];
        match stream.read(&mut buffer) {
            Ok(n) if n > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                Ok(banner.trim().to_string())
            }
            _ => Ok("No banner received".to_string()),
        }
    }

    /// Extract version information from banner
    fn extract_version(banner: &str, service: &ServiceType) -> Option<String> {
        match service {
            ServiceType::SSH => {
                // SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7
                if let Some(version_start) = banner.find("OpenSSH_") {
                    let version_str = &banner[version_start + 8..];
                    if let Some(space_pos) = version_str.find(' ') {
                        return Some(version_str[..space_pos].to_string());
                    }
                }
            }

            ServiceType::FTP => {
                // 220 (vsFTPd 3.0.3)
                if let Some(start) = banner.find('(') {
                    if let Some(end) = banner.find(')') {
                        return Some(banner[start + 1..end].to_string());
                    }
                }
            }

            ServiceType::HTTP => {
                // nginx/1.18.0 (Ubuntu)
                // Apache/2.4.41 (Ubuntu)
                if banner.contains('/') {
                    let parts: Vec<&str> = banner.split_whitespace().collect();
                    if let Some(first) = parts.get(0) {
                        return Some(first.to_string());
                    }
                }
            }

            _ => {}
        }

        None
    }

    /// Extract OS hints from banner
    fn extract_os_hints(banner: &str, service: &ServiceType) -> Vec<String> {
        let mut hints = Vec::new();
        let lower = banner.to_lowercase();

        // Common OS patterns
        if lower.contains("ubuntu") {
            hints.push("Ubuntu".to_string());
        }
        if lower.contains("debian") {
            hints.push("Debian".to_string());
        }
        if lower.contains("centos") || lower.contains("redhat") || lower.contains("rhel") {
            hints.push("CentOS/RHEL".to_string());
        }
        if lower.contains("windows") || lower.contains("microsoft") {
            hints.push("Windows".to_string());
        }
        if lower.contains("freebsd") {
            hints.push("FreeBSD".to_string());
        }

        // SSH-specific OS hints
        if matches!(service, ServiceType::SSH) && banner.contains("Debian") {
            if let Some(version_start) = banner.find("Debian-") {
                let version_str = &banner[version_start..];
                if let Some(space_pos) = version_str.find(' ') {
                    hints.push(version_str[..space_pos].to_string());
                } else {
                    hints.push(version_str.to_string());
                }
            }
        }

        hints
    }

    /// Analyze banner for security implications
    fn analyze_security(banner: &str, service: &ServiceType) -> Vec<String> {
        let mut notes = Vec::new();

        // Check for outdated versions (simplified)
        match service {
            ServiceType::SSH => {
                if banner.contains("OpenSSH_6") || banner.contains("OpenSSH_5") {
                    notes.push("⚠️  Outdated OpenSSH version detected".to_string());
                }
                if banner.contains("SSH-1.") {
                    notes.push("🔴 CRITICAL: SSH Protocol 1 is insecure!".to_string());
                }
            }

            ServiceType::FTP => {
                notes.push("⚠️  FTP transmits credentials in plaintext".to_string());
            }

            ServiceType::Telnet => {
                notes.push("🔴 CRITICAL: Telnet is insecure! Use SSH instead".to_string());
            }

            ServiceType::HTTP => {
                if banner.contains("Microsoft-IIS/6") || banner.contains("Microsoft-IIS/7") {
                    notes.push("⚠️  Outdated IIS version detected".to_string());
                }
            }

            _ => {}
        }

        // Version disclosure
        if banner.contains('/') || banner.contains("version") {
            notes.push("ℹ️  Version information disclosed in banner".to_string());
        }

        notes
    }

    /// Generate human-readable report
    pub fn report(&self) -> String {
        let mut report = String::new();

        report.push_str(&format!("Host: {}:{}\n", self.host, self.port));
        report.push_str(&format!("Service: {:?}\n", self.service));
        report.push_str(&format!("Banner: {}\n", self.banner));

        if let Some(ref version) = self.version {
            report.push_str(&format!("Version: {}\n", version));
        }

        if !self.os_hints.is_empty() {
            report.push_str("\nOS Hints:\n");
            for hint in &self.os_hints {
                report.push_str(&format!("  - {}\n", hint));
            }
        }

        if !self.security_notes.is_empty() {
            report.push_str("\nSecurity Notes:\n");
            for note in &self.security_notes {
                report.push_str(&format!("  {}\n", note));
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_identification() {
        assert_eq!(
            ServiceBanner::identify_service_by_port(22),
            ServiceType::SSH
        );
        assert_eq!(
            ServiceBanner::identify_service_by_port(80),
            ServiceType::HTTP
        );
        assert_eq!(
            ServiceBanner::identify_service_by_port(3306),
            ServiceType::MySQL
        );
    }

    #[test]
    fn test_extract_os_hints() {
        let banner = "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7";
        let hints = ServiceBanner::extract_os_hints(banner, &ServiceType::SSH);

        assert!(hints.iter().any(|h| h.contains("Debian")));
    }

    #[test]
    fn test_security_analysis() {
        let banner_old = "SSH-2.0-OpenSSH_5.3";
        let notes = ServiceBanner::analyze_security(banner_old, &ServiceType::SSH);

        assert!(notes.iter().any(|n| n.contains("Outdated")));
    }
}
