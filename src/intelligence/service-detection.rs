/// Service Detection and Version Fingerprinting
///
/// Advanced service detection beyond simple port-to-service mapping.
/// Uses multiple techniques:
///
/// - Banner grabbing and analysis
/// - Protocol-specific probes
/// - Behavioral fingerprinting
/// - Timing characteristics
/// - Error response patterns
///
/// Goal: Identify exact service implementation and version, not just "HTTP" but
/// "nginx 1.18.0 on Ubuntu 20.04"
use crate::intelligence::banner_analysis::{
    analyze_ftp_banner, analyze_http_server, analyze_smtp_banner, analyze_ssh_banner, ServiceType,
};
use crate::intelligence::timing_analysis::TimingSignature;
use std::collections::HashMap;

/// Comprehensive service detection result
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub port: u16,
    pub protocol: String,          // TCP/UDP
    pub service_type: ServiceType, // SSH, HTTP, etc.
    pub vendor: Option<String>,    // nginx, Apache, OpenSSH
    pub version: Option<String>,   // Exact version number
    pub os_hint: Option<String>,   // OS detected from service
    pub cpe: Option<String>,       // CPE identifier for vulnerability scanning
    pub confidence: f32,           // 0.0 to 1.0
    pub detection_methods: Vec<String>,
}

/// Service probe result
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub success: bool,
    pub response: Vec<u8>,
    pub timing: TimingSignature,
}

/// Common service signatures for quick identification
pub fn get_service_signatures() -> HashMap<u16, Vec<&'static str>> {
    let mut sigs: HashMap<u16, Vec<&'static str>> = HashMap::new();

    // SSH signatures
    sigs.insert(22, vec!["SSH-", "OpenSSH", "dropbear"]);

    // HTTP signatures
    sigs.insert(80, vec!["HTTP/1.", "Server:", "nginx", "Apache"]);
    sigs.insert(8080, vec!["HTTP/1.", "Server:", "Tomcat", "Jetty"]);

    // FTP signatures
    sigs.insert(21, vec!["220", "FTP", "ProFTPD", "vsftpd"]);

    // SMTP signatures
    sigs.insert(25, vec!["220", "SMTP", "ESMTP", "Postfix", "Sendmail"]);

    // Database signatures
    sigs.insert(3306, vec!["mysql_native_password", "MariaDB"]);
    sigs.insert(5432, vec!["PostgreSQL", "FATAL", "SCRAM-SHA-256"]);
    sigs.insert(1433, vec!["MSSQL", "SQL Server"]);
    sigs.insert(27017, vec!["MongoDB", "version"]);
    sigs.insert(6379, vec!["REDIS", "-ERR", "+PONG"]);

    // Other services
    sigs.insert(53, vec!["BIND", "dnsmasq"]);
    sigs.insert(389, vec!["LDAP", "supportedLDAPVersion"]);
    sigs.insert(445, vec!["SMB", "Samba"]);

    sigs
}

/// Detect service on a port using multiple methods
pub fn detect_service(
    port: u16,
    banner: Option<String>,
    timing: Option<TimingSignature>,
    probe_responses: &HashMap<String, Vec<u8>>,
) -> ServiceInfo {
    let mut info = ServiceInfo {
        port,
        protocol: "TCP".to_string(),
        service_type: ServiceType::Unknown,
        vendor: None,
        version: None,
        os_hint: None,
        cpe: None,
        confidence: 0.0,
        detection_methods: Vec::new(),
    };

    // Method 1: Port-based initial guess
    info.service_type = guess_service_by_port(port);
    if info.service_type != ServiceType::Unknown {
        info.detection_methods
            .push("Port number heuristic".to_string());
        info.confidence = 0.3;
    }

    // Method 2: Banner analysis
    if let Some(banner_text) = banner {
        if let Some(service_info) = analyze_banner_for_service(&banner_text, port) {
            info.service_type = service_info.service_type;
            info.vendor = service_info.vendor;
            info.version = service_info.version;
            info.os_hint = service_info.os_hint;
            info.detection_methods.push("Banner analysis".to_string());
            info.confidence = info.confidence.max(0.8);
        }
    }

    // Method 3: Timing analysis
    if let Some(timing_sig) = timing {
        if let Some(timing_service) = infer_service_from_timing(port, &timing_sig) {
            if info.service_type == ServiceType::Unknown {
                info.service_type = timing_service;
                info.detection_methods.push("Timing behavior".to_string());
                info.confidence = info.confidence.max(0.5);
            }
        }
    }

    // Method 4: Protocol-specific probes
    if !probe_responses.is_empty() {
        if let Some(probe_service) = analyze_probe_responses(port, probe_responses) {
            if info.service_type == ServiceType::Unknown {
                info.service_type = probe_service;
                info.detection_methods.push("Protocol probe".to_string());
                info.confidence = info.confidence.max(0.7);
            }
        }
    }

    // Generate CPE if we have vendor and version
    if let (Some(vendor), Some(version)) = (&info.vendor, &info.version) {
        info.cpe = Some(generate_cpe(&info.service_type, vendor, version));
    }

    info
}

/// Guess service based on port number
fn guess_service_by_port(port: u16) -> ServiceType {
    match port {
        21 => ServiceType::FTP,
        22 => ServiceType::SSH,
        25 => ServiceType::SMTP,
        53 => ServiceType::DNS,
        80 | 8080 | 8000 | 8888 => ServiceType::HTTP,
        110 => ServiceType::POP3,
        143 => ServiceType::IMAP,
        389 | 636 => ServiceType::LDAP,
        443 | 8443 => ServiceType::HTTP, // HTTPS
        445 => ServiceType::SMB,
        1433 => ServiceType::MSSQL,
        3306 => ServiceType::MySQL,
        5432 => ServiceType::PostgreSQL,
        6379 => ServiceType::Redis,
        27017 => ServiceType::MongoDB,
        _ => ServiceType::Unknown,
    }
}

/// Analyze banner text to extract service information
fn analyze_banner_for_service(banner: &str, port: u16) -> Option<ServiceInfo> {
    let lower = banner.to_lowercase();

    // SSH detection
    if banner.starts_with("SSH-") {
        let banner_info = analyze_ssh_banner(banner);
        return Some(ServiceInfo {
            port,
            protocol: "TCP".to_string(),
            service_type: ServiceType::SSH,
            vendor: banner_info.vendor,
            version: banner_info.version,
            os_hint: banner_info.os_hints.first().cloned(),
            cpe: None,
            confidence: 0.9,
            detection_methods: vec!["SSH banner".to_string()],
        });
    }

    // FTP detection
    if lower.contains("220") && (lower.contains("ftp") || port == 21) {
        let banner_info = analyze_ftp_banner(banner);
        return Some(ServiceInfo {
            port,
            protocol: "TCP".to_string(),
            service_type: ServiceType::FTP,
            vendor: banner_info.vendor,
            version: banner_info.version,
            os_hint: banner_info.os_hints.first().cloned(),
            cpe: None,
            confidence: 0.9,
            detection_methods: vec!["FTP banner".to_string()],
        });
    }

    // HTTP detection
    if lower.contains("http/1.") || lower.contains("server:") {
        let server = banner
            .lines()
            .find(|line| line.to_lowercase().starts_with("server:"))
            .map(|line| line.split(':').nth(1).unwrap_or("").trim())
            .unwrap_or("");

        if !server.is_empty() {
            let banner_info = analyze_http_server(server);
            return Some(ServiceInfo {
                port,
                protocol: "TCP".to_string(),
                service_type: ServiceType::HTTP,
                vendor: banner_info.vendor,
                version: banner_info.version,
                os_hint: banner_info.os_hints.first().cloned(),
                cpe: None,
                confidence: 0.8,
                detection_methods: vec!["HTTP Server header".to_string()],
            });
        }
    }

    // SMTP detection
    if lower.contains("220") && (lower.contains("smtp") || lower.contains("esmtp") || port == 25) {
        let banner_info = analyze_smtp_banner(banner);
        return Some(ServiceInfo {
            port,
            protocol: "TCP".to_string(),
            service_type: ServiceType::SMTP,
            vendor: banner_info.vendor,
            version: banner_info.version,
            os_hint: banner_info.os_hints.first().cloned(),
            cpe: None,
            confidence: 0.9,
            detection_methods: vec!["SMTP banner".to_string()],
        });
    }

    None
}

/// Infer service from timing characteristics
fn infer_service_from_timing(port: u16, timing: &TimingSignature) -> Option<ServiceType> {
    let response_ms = timing.first_response_time?.as_millis();

    // Database services typically respond very fast
    if response_ms < 50 && matches!(port, 3306 | 5432 | 27017 | 6379) {
        return Some(guess_service_by_port(port));
    }

    // Web servers have variable response times
    if response_ms < 100 && matches!(port, 80 | 443 | 8080 | 8443) {
        return Some(ServiceType::HTTP);
    }

    None
}

/// Analyze responses to protocol-specific probes
fn analyze_probe_responses(
    _port: u16,
    responses: &HashMap<String, Vec<u8>>,
) -> Option<ServiceType> {
    // Check for HTTP probe
    if let Some(http_response) = responses.get("HTTP_GET") {
        if http_response.starts_with(b"HTTP/") {
            return Some(ServiceType::HTTP);
        }
    }

    // Check for SSH probe
    if let Some(ssh_response) = responses.get("SSH_BANNER") {
        if ssh_response.starts_with(b"SSH-") {
            return Some(ServiceType::SSH);
        }
    }

    // Check for database probes
    if let Some(mysql_response) = responses.get("MYSQL_HANDSHAKE") {
        if mysql_response.len() > 4 && mysql_response[4] == 10 {
            // MySQL protocol version 10
            return Some(ServiceType::MySQL);
        }
    }

    None
}

/// Generate CPE (Common Platform Enumeration) identifier
fn generate_cpe(service_type: &ServiceType, vendor: &str, version: &str) -> String {
    let vendor_lower = vendor.to_lowercase();

    let product = match service_type {
        ServiceType::SSH if vendor_lower.contains("openssh") => "openssh",
        ServiceType::HTTP if vendor_lower.contains("nginx") => "nginx",
        ServiceType::HTTP if vendor_lower.contains("apache") => "httpd",
        ServiceType::MySQL => "mysql",
        ServiceType::PostgreSQL => "postgresql",
        _ => vendor_lower.as_str(),
    };

    format!("cpe:/a:{}:{}:{}", vendor_lower, product, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guess_service_by_port() {
        assert_eq!(guess_service_by_port(22), ServiceType::SSH);
        assert_eq!(guess_service_by_port(80), ServiceType::HTTP);
        assert_eq!(guess_service_by_port(3306), ServiceType::MySQL);
    }

    #[test]
    fn test_generate_cpe() {
        let cpe = generate_cpe(&ServiceType::SSH, "OpenSSH", "8.2p1");
        assert!(cpe.contains("openssh"));
        assert!(cpe.contains("8.2p1"));
    }

    #[test]
    fn test_detect_service_with_banner() {
        let banner = Some("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5".to_string());
        let info = detect_service(22, banner, None, &HashMap::new());

        assert_eq!(info.service_type, ServiceType::SSH);
        assert_eq!(info.vendor, Some("OpenSSH".to_string()));
        assert!(info.confidence > 0.8);
    }
}
