/// Banner Analysis for Service Fingerprinting
///
/// Service banners contain valuable intelligence:
/// - Version strings and build numbers
/// - Vendor-specific identifiers
/// - Operating system hints
/// - Configuration information
/// - Custom modifications
///
/// Different implementations of the same service often have distinct banner formats.
/// By analyzing banner structure, content, and timing, we can fingerprint the exact
/// service implementation and sometimes detect security misconfigurations.
use std::collections::HashMap;

/// Banner analysis result
#[derive(Debug, Clone)]
pub struct BannerInfo {
    pub raw_banner: String,
    pub service_type: ServiceType,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub os_hints: Vec<String>,
    pub is_modified: bool,
    pub custom_fields: HashMap<String, String>,
}

/// Service type detected from banner
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceType {
    SSH,
    FTP,
    HTTP,
    SMTP,
    POP3,
    IMAP,
    MySQL,
    PostgreSQL,
    MSSQL,
    MongoDB,
    Redis,
    Telnet,
    SMB,
    LDAP,
    DNS,
    Unknown,
}

impl ServiceType {
    pub fn name(&self) -> &'static str {
        match self {
            ServiceType::SSH => "SSH",
            ServiceType::FTP => "FTP",
            ServiceType::HTTP => "HTTP",
            ServiceType::SMTP => "SMTP",
            ServiceType::POP3 => "POP3",
            ServiceType::IMAP => "IMAP",
            ServiceType::MySQL => "MySQL",
            ServiceType::PostgreSQL => "PostgreSQL",
            ServiceType::MSSQL => "MSSQL",
            ServiceType::MongoDB => "MongoDB",
            ServiceType::Redis => "Redis",
            ServiceType::Telnet => "Telnet",
            ServiceType::SMB => "SMB",
            ServiceType::LDAP => "LDAP",
            ServiceType::DNS => "DNS",
            ServiceType::Unknown => "Unknown",
        }
    }
}

/// Analyze SSH banner
///
/// SSH banners follow format: SSH-<version>-<implementation>
///
/// Examples:
/// - OpenSSH: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
/// - Dropbear: "SSH-2.0-dropbear_2020.81"
/// - Cisco: "SSH-2.0-Cisco-1.25"
/// - Windows: "SSH-2.0-OpenSSH_for_Windows_8.1"
pub fn analyze_ssh_banner(banner: &str) -> BannerInfo {
    let mut info = BannerInfo {
        raw_banner: banner.to_string(),
        service_type: ServiceType::SSH,
        version: None,
        vendor: None,
        os_hints: Vec::new(),
        is_modified: false,
        custom_fields: HashMap::new(),
    };

    // Standard SSH banner format: SSH-<protocol_version>-<software_version>
    if !banner.starts_with("SSH-") {
        info.is_modified = true;
        return info;
    }

    let parts: Vec<&str> = banner.split('-').collect();
    if parts.len() < 3 {
        info.is_modified = true;
        return info;
    }

    // Extract protocol version
    info.custom_fields
        .insert("protocol_version".to_string(), parts[1].to_string());

    // Extract software version
    let software = parts[2..].join("-");
    info.version = Some(software.clone());

    // Detect vendor
    if software.contains("OpenSSH") {
        info.vendor = Some("OpenSSH".to_string());

        // Extract OS from OpenSSH banner
        if software.contains("Ubuntu") {
            info.os_hints.push("Ubuntu Linux".to_string());
        } else if software.contains("Debian") {
            info.os_hints.push("Debian Linux".to_string());
        } else if software.contains("FreeBSD") {
            info.os_hints.push("FreeBSD".to_string());
        } else if software.contains("Windows") {
            info.os_hints.push("Windows".to_string());
        } else if software.contains("RHEL") || software.contains("Red Hat") {
            info.os_hints.push("Red Hat Linux".to_string());
        }
    } else if software.contains("dropbear") {
        info.vendor = Some("Dropbear".to_string());
        info.os_hints.push("Embedded Linux".to_string());
    } else if software.contains("Cisco") {
        info.vendor = Some("Cisco".to_string());
        info.os_hints.push("Cisco IOS".to_string());
    } else if software.contains("libssh") {
        info.vendor = Some("libssh".to_string());
    }

    info
}

/// Analyze FTP banner
///
/// FTP banners reveal implementation details:
///
/// Examples:
/// - ProFTPD: "220 ProFTPD 1.3.6 Server (Debian)"
/// - vsftpd: "220 (vsFTPd 3.0.3)"
/// - Pure-FTPd: "220---------- Welcome to Pure-FTPd ----------"
/// - IIS: "220 Microsoft FTP Service"
/// - FileZilla: "220-FileZilla Server 0.9.60 beta"
pub fn analyze_ftp_banner(banner: &str) -> BannerInfo {
    let mut info = BannerInfo {
        raw_banner: banner.to_string(),
        service_type: ServiceType::FTP,
        version: None,
        vendor: None,
        os_hints: Vec::new(),
        is_modified: false,
        custom_fields: HashMap::new(),
    };

    let lower = banner.to_lowercase();

    // Detect ProFTPD
    if lower.contains("proftpd") {
        info.vendor = Some("ProFTPD".to_string());
        if let Some(version) = extract_version_pattern(&lower, "proftpd", &[" ", "\n"]) {
            info.version = Some(version);
        }
        if lower.contains("debian") {
            info.os_hints.push("Debian Linux".to_string());
        } else if lower.contains("ubuntu") {
            info.os_hints.push("Ubuntu Linux".to_string());
        }
    }
    // Detect vsftpd
    else if lower.contains("vsftpd") {
        info.vendor = Some("vsftpd".to_string());
        if let Some(version) = extract_version_pattern(&lower, "vsftpd", &[" ", ")"]) {
            info.version = Some(version);
        }
        info.os_hints.push("Linux".to_string());
    }
    // Detect Pure-FTPd
    else if lower.contains("pure-ftpd") {
        info.vendor = Some("Pure-FTPd".to_string());
    }
    // Detect Microsoft IIS FTP
    else if lower.contains("microsoft ftp") {
        info.vendor = Some("Microsoft IIS".to_string());
        info.os_hints.push("Windows".to_string());
    }
    // Detect FileZilla Server
    else if lower.contains("filezilla") {
        info.vendor = Some("FileZilla Server".to_string());
        if let Some(version) = extract_version_pattern(&lower, "filezilla server", &["\n", " "]) {
            info.version = Some(version);
        }
        info.os_hints.push("Windows".to_string());
    }

    // Check if banner is heavily modified (missing standard identifiers)
    if !lower.contains("220") && !banner.is_empty() {
        info.is_modified = true;
    }

    info
}

/// Analyze HTTP Server header
///
/// Examples:
/// - Apache: "Apache/2.4.41 (Ubuntu)"
/// - nginx: "nginx/1.18.0"
/// - IIS: "Microsoft-IIS/10.0"
/// - LiteSpeed: "LiteSpeed"
/// - Caddy: "Caddy"
pub fn analyze_http_server(server_header: &str) -> BannerInfo {
    let mut info = BannerInfo {
        raw_banner: server_header.to_string(),
        service_type: ServiceType::HTTP,
        version: None,
        vendor: None,
        os_hints: Vec::new(),
        is_modified: false,
        custom_fields: HashMap::new(),
    };

    let lower = server_header.to_lowercase();

    // Detect Apache
    if lower.contains("apache") {
        info.vendor = Some("Apache".to_string());
        if let Some(version) = extract_version_pattern(&lower, "apache/", &[" ", "("]) {
            info.version = Some(version);
        }
        if lower.contains("ubuntu") {
            info.os_hints.push("Ubuntu Linux".to_string());
        } else if lower.contains("debian") {
            info.os_hints.push("Debian Linux".to_string());
        } else if lower.contains("centos") {
            info.os_hints.push("CentOS Linux".to_string());
        } else if lower.contains("win32") || lower.contains("win64") {
            info.os_hints.push("Windows".to_string());
        }
    }
    // Detect nginx
    else if lower.contains("nginx") {
        info.vendor = Some("nginx".to_string());
        if let Some(version) = extract_version_pattern(&lower, "nginx/", &[" ", "\n"]) {
            info.version = Some(version);
        }
        info.os_hints.push("Linux/Unix".to_string());
    }
    // Detect Microsoft IIS
    else if lower.contains("microsoft-iis") {
        info.vendor = Some("Microsoft IIS".to_string());
        if let Some(version) = extract_version_pattern(&lower, "microsoft-iis/", &[" ", "\n"]) {
            info.version = Some(version);
        }
        info.os_hints.push("Windows".to_string());
    }
    // Detect LiteSpeed
    else if lower.contains("litespeed") {
        info.vendor = Some("LiteSpeed".to_string());
    }
    // Detect Caddy
    else if lower.contains("caddy") {
        info.vendor = Some("Caddy".to_string());
    }
    // Detect Cloudflare
    else if lower.contains("cloudflare") {
        info.vendor = Some("Cloudflare".to_string());
        info.custom_fields
            .insert("proxy".to_string(), "Cloudflare CDN".to_string());
    }

    // Empty or very short server header suggests intentional hiding
    if server_header.is_empty() || server_header.len() < 3 {
        info.is_modified = true;
    }

    info
}

/// Analyze SMTP banner
///
/// Examples:
/// - Postfix: "220 mail.example.com ESMTP Postfix"
/// - Sendmail: "220 mail.example.com ESMTP Sendmail 8.15.2"
/// - Exchange: "220 mail.example.com Microsoft ESMTP MAIL Service"
/// - Exim: "220 mail.example.com ESMTP Exim 4.94.2"
pub fn analyze_smtp_banner(banner: &str) -> BannerInfo {
    let mut info = BannerInfo {
        raw_banner: banner.to_string(),
        service_type: ServiceType::SMTP,
        version: None,
        vendor: None,
        os_hints: Vec::new(),
        is_modified: detect_banner_modification(banner, &ServiceType::SMTP),
        custom_fields: HashMap::new(),
    };

    let lower = banner.to_lowercase();

    // Postfix detection
    if lower.contains("postfix") {
        info.vendor = Some("Postfix".to_string());

        // Try to extract version
        if let Some(version) = extract_version_pattern(banner, "Postfix", &[" ", "\r", "\n", ")"]) {
            info.version = Some(version);
        }

        // Postfix is typically on Linux
        info.os_hints.push("Linux".to_string());

        // Check for OS hints in banner
        if lower.contains("ubuntu") {
            info.os_hints.push("Ubuntu Linux".to_string());
        } else if lower.contains("debian") {
            info.os_hints.push("Debian Linux".to_string());
        } else if lower.contains("centos") || lower.contains("rhel") {
            info.os_hints.push("CentOS/RHEL".to_string());
        }
    }
    // Sendmail detection
    else if lower.contains("sendmail") {
        info.vendor = Some("Sendmail".to_string());

        // Sendmail version format: "8.15.2/8.15.2" - extract first version
        if let Some(version) = extract_version_pattern(banner, "Sendmail", &[" ", "/", "\r", "\n"])
        {
            info.version = Some(version);
        }

        // Sendmail is common on Unix/BSD
        info.os_hints.push("Unix/BSD".to_string());
    }
    // Microsoft Exchange detection
    else if lower.contains("microsoft") && (lower.contains("exchange") || lower.contains("esmtp"))
    {
        info.vendor = Some("Microsoft Exchange".to_string());

        // Try to extract version from "Version X.X.X"
        if let Some(version) = extract_version_pattern(banner, "Version", &[" ", "\r", "\n"]) {
            info.version = Some(version);
        }

        info.os_hints.push("Windows Server".to_string());

        // Detect Exchange version from banner patterns
        if lower.contains("exchange server 2019") {
            info.version = Some("2019".to_string());
        } else if lower.contains("exchange server 2016") {
            info.version = Some("2016".to_string());
        } else if lower.contains("exchange server 2013") {
            info.version = Some("2013".to_string());
        }
    }
    // Exim detection
    else if lower.contains("exim") {
        info.vendor = Some("Exim".to_string());

        // Exim version: "Exim 4.94.2"
        if let Some(version) = extract_version_pattern(banner, "Exim", &[" ", "\r", "\n"]) {
            info.version = Some(version);
        }

        // Exim is default on Debian
        info.os_hints.push("Debian Linux".to_string());
    }
    // qmail detection
    else if lower.contains("qmail") {
        info.vendor = Some("qmail".to_string());
        info.os_hints.push("Unix/Linux".to_string());
    }
    // Zimbra detection
    else if lower.contains("zimbra") {
        info.vendor = Some("Zimbra".to_string());
        info.os_hints.push("Linux".to_string());

        if let Some(version) = extract_version_pattern(banner, "Zimbra", &[" ", "\r", "\n"]) {
            info.version = Some(version);
        }
    }
    // Dovecot detection (sometimes shows up in SMTP)
    else if lower.contains("dovecot") {
        info.vendor = Some("Dovecot".to_string());
        info.os_hints.push("Linux".to_string());
    }

    info
}

/// Analyze DNS server response for fingerprinting
///
/// DNS servers can be fingerprinted using:
/// - VERSION.BIND query (CHAOS class TXT record)
/// - Response patterns and flags
/// - EDNS support and options
///
/// Examples:
/// - BIND: "9.16.1-Ubuntu"
/// - dnsmasq: "dnsmasq-2.80"
/// - PowerDNS: "PowerDNS Authoritative Server 4.3.0"
/// - Windows DNS: "Microsoft DNS 6.1.7601"
/// - Unbound: "unbound 1.9.4"
pub fn analyze_dns_version(version_response: &str) -> BannerInfo {
    let mut info = BannerInfo {
        raw_banner: version_response.to_string(),
        service_type: ServiceType::DNS,
        version: None,
        vendor: None,
        os_hints: Vec::new(),
        is_modified: false,
        custom_fields: HashMap::new(),
    };

    let lower = version_response.to_lowercase();

    // BIND detection
    if lower.contains("bind") {
        info.vendor = Some("ISC BIND".to_string());

        // Extract version: "9.16.1-Ubuntu" or "9.16.1"
        if let Some(version) =
            extract_version_pattern(version_response, "BIND", &["-", " ", "\r", "\n"])
        {
            info.version = Some(version);
        } else if let Some(pos) = lower.find("bind") {
            // Try to find version after "bind"
            let after_bind = &version_response[pos + 4..];
            if let Some(version) = extract_version_pattern(after_bind, "", &["-", " ", "\r", "\n"])
            {
                info.version = Some(version);
            }
        }

        // OS detection from version string
        if lower.contains("ubuntu") {
            info.os_hints.push("Ubuntu Linux".to_string());
        } else if lower.contains("debian") {
            info.os_hints.push("Debian Linux".to_string());
        } else if lower.contains("redhat") || lower.contains("rhel") {
            info.os_hints.push("Red Hat Enterprise Linux".to_string());
        } else if lower.contains("win") || lower.contains("windows") {
            info.os_hints.push("Windows".to_string());
        }
    }
    // dnsmasq detection
    else if lower.contains("dnsmasq") {
        info.vendor = Some("dnsmasq".to_string());

        // Extract version: "dnsmasq-2.80"
        if let Some(version) =
            extract_version_pattern(version_response, "dnsmasq-", &[" ", "\r", "\n"])
        {
            info.version = Some(version);
        } else if let Some(version) =
            extract_version_pattern(version_response, "dnsmasq", &[" ", "\r", "\n"])
        {
            info.version = Some(version);
        }

        // dnsmasq is typically on embedded/router devices or Linux
        info.os_hints.push("Linux/Embedded".to_string());
    }
    // PowerDNS detection
    else if lower.contains("powerdns") {
        info.vendor = Some("PowerDNS".to_string());

        // Extract version from "PowerDNS Authoritative Server 4.3.0"
        if let Some(version) =
            extract_version_pattern(version_response, "Server", &[" ", "\r", "\n"])
        {
            info.version = Some(version);
        }

        info.os_hints.push("Linux".to_string());
    }
    // Microsoft DNS detection
    else if lower.contains("microsoft") && lower.contains("dns") {
        info.vendor = Some("Microsoft DNS".to_string());

        // Extract Windows version
        if let Some(version) = extract_version_pattern(version_response, "DNS", &[" ", "\r", "\n"])
        {
            info.version = Some(version);
        }

        info.os_hints.push("Windows Server".to_string());

        // Detect Windows Server version
        if lower.contains("6.3") {
            info.os_hints.push("Windows Server 2012 R2".to_string());
        } else if lower.contains("10.0") {
            info.os_hints.push("Windows Server 2016/2019".to_string());
        }
    }
    // Unbound detection
    else if lower.contains("unbound") {
        info.vendor = Some("Unbound".to_string());

        // Extract version: "unbound 1.9.4"
        if let Some(version) =
            extract_version_pattern(version_response, "unbound", &[" ", "\r", "\n"])
        {
            info.version = Some(version);
        }

        info.os_hints.push("Unix/Linux".to_string());
    }
    // Knot DNS detection
    else if lower.contains("knot") {
        info.vendor = Some("Knot DNS".to_string());

        if let Some(version) =
            extract_version_pattern(version_response, "Knot DNS", &[" ", "\r", "\n"])
        {
            info.version = Some(version);
        }

        info.os_hints.push("Linux".to_string());
    }
    // NSD (Name Server Daemon) detection
    else if lower.contains("nsd") {
        info.vendor = Some("NSD".to_string());

        if let Some(version) = extract_version_pattern(version_response, "NSD", &[" ", "\r", "\n"])
        {
            info.version = Some(version);
        }

        info.os_hints.push("Unix/Linux".to_string());
    }
    // Cloudflare DNS detection
    else if lower.contains("cloudflare") {
        info.vendor = Some("Cloudflare DNS".to_string());
        info.os_hints.push("Cloud Service".to_string());
    }
    // Google Public DNS detection
    else if lower.contains("google") && lower.contains("public dns") {
        info.vendor = Some("Google Public DNS".to_string());
        info.os_hints.push("Cloud Service".to_string());
    }

    // If version string is hidden or modified
    if version_response.is_empty() || version_response.len() < 3 {
        info.is_modified = true;
    }

    info
}

/// Analyze database banners
///
/// MySQL example: "5.7.33-0ubuntu0.18.04.1"
/// PostgreSQL example: "PostgreSQL 13.3 on x86_64-pc-linux-gnu"
/// MongoDB example: "MongoDB 4.4.6"
/// MSSQL example: "Microsoft SQL Server 2019 (RTM) - 15.0.2000.5"
/// Redis example: "Redis server v=6.2.6"
pub fn analyze_database_banner(banner: &str, db_type: ServiceType) -> BannerInfo {
    let mut info = BannerInfo {
        raw_banner: banner.to_string(),
        service_type: db_type.clone(),
        version: None,
        vendor: None,
        os_hints: Vec::new(),
        is_modified: false,
        custom_fields: HashMap::new(),
    };

    let lower = banner.to_lowercase();

    match db_type {
        ServiceType::MySQL => {
            // Detect MariaDB first (fork of MySQL)
            if lower.contains("mariadb") {
                info.vendor = Some("MariaDB".to_string());

                // Extract MariaDB version
                if let Some(version) = extract_version_pattern(banner, "MariaDB", &["-", " ", "\n"])
                {
                    info.version = Some(version);
                }
            } else {
                info.vendor = Some("MySQL".to_string());

                // MySQL version format: "5.7.33-0ubuntu0.18.04.1"
                // Extract just the core version (5.7.33)
                if let Some(dash_pos) = banner.find('-') {
                    let version_part = &banner[..dash_pos];
                    if version_part.chars().any(|c| c.is_ascii_digit()) {
                        info.version = Some(version_part.to_string());
                    }
                } else {
                    info.version = Some(banner.to_string());
                }
            }

            // OS detection
            if lower.contains("ubuntu") {
                info.os_hints.push("Ubuntu Linux".to_string());
            } else if lower.contains("debian") {
                info.os_hints.push("Debian Linux".to_string());
            } else if lower.contains("centos") || lower.contains("rhel") {
                info.os_hints.push("CentOS/RHEL".to_string());
            } else if lower.contains("win") {
                info.os_hints.push("Windows".to_string());
            }
        }
        ServiceType::PostgreSQL => {
            info.vendor = Some("PostgreSQL".to_string());

            // Extract version: "PostgreSQL 13.3 on x86_64-pc-linux-gnu"
            if let Some(version) = extract_version_pattern(banner, "PostgreSQL", &[" ", "on"]) {
                info.version = Some(version);
            }

            // Architecture and OS detection
            if lower.contains("x86_64") {
                info.custom_fields
                    .insert("architecture".to_string(), "x86_64".to_string());
            } else if lower.contains("aarch64") || lower.contains("arm64") {
                info.custom_fields
                    .insert("architecture".to_string(), "ARM64".to_string());
            }

            if lower.contains("linux-gnu") || lower.contains("linux") {
                info.os_hints.push("Linux".to_string());

                if lower.contains("ubuntu") {
                    info.os_hints.push("Ubuntu".to_string());
                } else if lower.contains("debian") {
                    info.os_hints.push("Debian".to_string());
                }
            } else if lower.contains("mingw") || lower.contains("windows") {
                info.os_hints.push("Windows".to_string());
            } else if lower.contains("darwin") || lower.contains("apple") {
                info.os_hints.push("macOS".to_string());
            }
        }
        ServiceType::MongoDB => {
            info.vendor = Some("MongoDB".to_string());

            // Extract version: "MongoDB 4.4.6"
            if let Some(version) = extract_version_pattern(banner, "MongoDB", &[" ", "-", "\n"]) {
                info.version = Some(version);
            } else if let Some(version) = extract_version_pattern(banner, "v", &[" ", "-", "\n"]) {
                info.version = Some(version);
            }

            // MongoDB is typically on Linux
            if lower.contains("linux") {
                info.os_hints.push("Linux".to_string());
            } else if lower.contains("win") {
                info.os_hints.push("Windows".to_string());
            }
        }
        ServiceType::MSSQL => {
            info.vendor = Some("Microsoft SQL Server".to_string());

            // Extract version from "Microsoft SQL Server 2019 (RTM) - 15.0.2000.5"
            if lower.contains("2022") {
                info.version = Some("2022".to_string());
            } else if lower.contains("2019") {
                info.version = Some("2019".to_string());
            } else if lower.contains("2017") {
                info.version = Some("2017".to_string());
            } else if lower.contains("2016") {
                info.version = Some("2016".to_string());
            } else if lower.contains("2014") {
                info.version = Some("2014".to_string());
            } else if lower.contains("2012") {
                info.version = Some("2012".to_string());
            }

            // Extract detailed version number (15.0.2000.5)
            if let Some(dash_pos) = banner.rfind(" - ") {
                let detailed_version = &banner[dash_pos + 3..];
                if detailed_version.chars().any(|c| c.is_ascii_digit()) {
                    info.custom_fields.insert(
                        "build_version".to_string(),
                        detailed_version.trim().to_string(),
                    );
                }
            }

            // MSSQL is Windows Server
            info.os_hints.push("Windows Server".to_string());

            // Detect edition
            if lower.contains("express") {
                info.custom_fields
                    .insert("edition".to_string(), "Express".to_string());
            } else if lower.contains("standard") {
                info.custom_fields
                    .insert("edition".to_string(), "Standard".to_string());
            } else if lower.contains("enterprise") {
                info.custom_fields
                    .insert("edition".to_string(), "Enterprise".to_string());
            }
        }
        ServiceType::Redis => {
            info.vendor = Some("Redis".to_string());

            // Redis version format: "Redis server v=6.2.6" or just "6.2.6"
            if let Some(version) = extract_version_pattern(banner, "v=", &[" ", ",", "\r", "\n"]) {
                info.version = Some(version);
            } else if let Some(version) =
                extract_version_pattern(banner, "Redis", &[" ", ",", "\r", "\n"])
            {
                info.version = Some(version);
            } else {
                // Banner might just be the version number
                if banner.chars().any(|c| c.is_ascii_digit()) {
                    info.version = Some(banner.trim().to_string());
                }
            }

            // Redis is typically on Linux
            info.os_hints.push("Linux".to_string());
        }
        _ => {}
    }

    info
}

/// Extract version number from banner using pattern matching
fn extract_version_pattern(text: &str, marker: &str, terminators: &[&str]) -> Option<String> {
    if let Some(start_pos) = text.find(marker) {
        let after_marker = &text[start_pos + marker.len()..];

        // Skip non-digit characters
        let version_start = after_marker
            .chars()
            .position(|c| c.is_ascii_digit())
            .unwrap_or(0);

        let version_part = &after_marker[version_start..];

        // Find the end of version string
        let mut end_pos = version_part.len();
        for term in terminators {
            if let Some(pos) = version_part.find(term) {
                end_pos = end_pos.min(pos);
            }
        }

        let version = version_part[..end_pos].trim();
        if !version.is_empty() {
            return Some(version.to_string());
        }
    }

    None
}

/// Compare banners to detect modifications
pub fn detect_banner_modification(banner: &str, service_type: &ServiceType) -> bool {
    let lower = banner.to_lowercase();

    match service_type {
        ServiceType::SSH => {
            // SSH should start with "SSH-"
            !banner.starts_with("SSH-")
        }
        ServiceType::FTP => {
            // FTP should have response code 220
            !lower.contains("220")
        }
        ServiceType::HTTP => {
            // HTTP Server header is often intentionally hidden
            banner.is_empty() || banner.len() < 3
        }
        ServiceType::SMTP => {
            // SMTP should have response code 220
            !lower.contains("220")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_ssh_openssh() {
        let banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
        let info = analyze_ssh_banner(banner);

        assert_eq!(info.service_type, ServiceType::SSH);
        assert_eq!(info.vendor, Some("OpenSSH".to_string()));
        assert!(info.os_hints.contains(&"Ubuntu Linux".to_string()));
        assert!(!info.is_modified);
    }

    #[test]
    fn test_analyze_ssh_dropbear() {
        let banner = "SSH-2.0-dropbear_2020.81";
        let info = analyze_ssh_banner(banner);

        assert_eq!(info.vendor, Some("Dropbear".to_string()));
        assert!(info.os_hints.contains(&"Embedded Linux".to_string()));
    }

    #[test]
    fn test_analyze_ftp_proftpd() {
        let banner = "220 ProFTPD 1.3.6 Server (Debian)";
        let info = analyze_ftp_banner(banner);

        assert_eq!(info.service_type, ServiceType::FTP);
        assert_eq!(info.vendor, Some("ProFTPD".to_string()));
        assert!(info.os_hints.contains(&"Debian Linux".to_string()));
    }

    #[test]
    fn test_analyze_http_apache() {
        let server = "Apache/2.4.41 (Ubuntu)";
        let info = analyze_http_server(server);

        assert_eq!(info.vendor, Some("Apache".to_string()));
        assert!(info.os_hints.contains(&"Ubuntu Linux".to_string()));
    }

    #[test]
    fn test_analyze_http_nginx() {
        let server = "nginx/1.18.0";
        let info = analyze_http_server(server);

        assert_eq!(info.vendor, Some("nginx".to_string()));
        assert_eq!(info.version, Some("1.18.0".to_string()));
    }

    #[test]
    fn test_extract_version_pattern() {
        let text = "nginx/1.18.0 (Ubuntu)";
        let version = extract_version_pattern(text, "nginx/", &[" ", "("]);
        assert_eq!(version, Some("1.18.0".to_string()));
    }

    #[test]
    fn test_detect_modified_banner() {
        assert!(detect_banner_modification("Welcome!", &ServiceType::SSH));
        assert!(!detect_banner_modification(
            "SSH-2.0-OpenSSH",
            &ServiceType::SSH
        ));

        assert!(detect_banner_modification(
            "Welcome to FTP",
            &ServiceType::FTP
        ));
        assert!(!detect_banner_modification(
            "220 ProFTPD",
            &ServiceType::FTP
        ));
    }
}
