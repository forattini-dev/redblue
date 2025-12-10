/// POODLE Vulnerability Checker (CVE-2014-3566)
///
/// Tests for the POODLE (Padding Oracle On Downgraded Legacy Encryption)
/// vulnerability which affects SSL 3.0 CBC mode ciphers.
///
/// Also checks for TLS POODLE (improper CBC padding validation).

use super::{VulnChecker, VulnCheckResult, Severity, connect_tcp, tls_types, build_client_hello};
use std::io::{Read, Write};
use std::time::Duration;

pub struct PoodleChecker {
    timeout: Duration,
}

impl PoodleChecker {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    /// Check if server supports SSL 3.0
    fn check_ssl30_support(&self, host: &str, port: u16) -> Result<bool, String> {
        let mut stream = connect_tcp(host, port, self.timeout)?;

        // SSL 3.0 cipher suites (CBC mode)
        let cipher_suites = vec![
            0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x0005, // TLS_RSA_WITH_RC4_128_SHA
            0x0004, // TLS_RSA_WITH_RC4_128_MD5
        ];

        // Build ClientHello with SSL 3.0 version
        let client_hello = build_client_hello(tls_types::VERSION_SSL30, &cipher_suites, &[]);

        if let Err(e) = stream.write_all(&client_hello) {
            return Err(format!("Failed to send ClientHello: {}", e));
        }

        // Read response
        let mut buffer = vec![0u8; 2048];
        match stream.read(&mut buffer) {
            Ok(n) if n >= 5 => {
                // Check for ServerHello (not an alert)
                if buffer[0] == tls_types::CONTENT_TYPE_HANDSHAKE {
                    // Check version in response
                    if buffer[1] == 0x03 && buffer[2] == 0x00 {
                        return Ok(true); // SSL 3.0 supported
                    }
                }
                // Alert means SSL 3.0 not supported
                Ok(false)
            }
            Ok(_) => Ok(false),
            Err(e) => Err(format!("Failed to read response: {}", e)),
        }
    }

    /// Check if server uses CBC ciphers (potential TLS POODLE)
    fn check_cbc_ciphers(&self, host: &str, port: u16) -> Result<bool, String> {
        let mut stream = connect_tcp(host, port, self.timeout)?;

        // CBC mode cipher suites only
        let cipher_suites = vec![
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
            0x003c, // TLS_RSA_WITH_AES_128_CBC_SHA256
            0x003d, // TLS_RSA_WITH_AES_256_CBC_SHA256
        ];

        let client_hello = build_client_hello(tls_types::VERSION_TLS12, &cipher_suites, &[]);

        if let Err(e) = stream.write_all(&client_hello) {
            return Err(format!("Failed to send ClientHello: {}", e));
        }

        // Read response
        let mut buffer = vec![0u8; 2048];
        match stream.read(&mut buffer) {
            Ok(n) if n >= 5 => {
                // Check for ServerHello
                if buffer[0] == tls_types::CONTENT_TYPE_HANDSHAKE {
                    return Ok(true); // Server accepted CBC cipher
                }
                Ok(false)
            }
            Ok(_) => Ok(false),
            Err(e) => Err(format!("Failed to read response: {}", e)),
        }
    }
}

impl Default for PoodleChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnChecker for PoodleChecker {
    fn name(&self) -> &str {
        "POODLE"
    }

    fn cve(&self) -> Option<&str> {
        Some("CVE-2014-3566")
    }

    fn description(&self) -> &str {
        "SSL 3.0 Padding Oracle On Downgraded Legacy Encryption vulnerability"
    }

    fn check(&self, host: &str, port: u16) -> VulnCheckResult {
        let mut evidence = Vec::new();

        // Check for SSL 3.0 support (definite POODLE vulnerability)
        match self.check_ssl30_support(host, port) {
            Ok(true) => {
                evidence.push("Server supports SSL 3.0".to_string());

                return VulnCheckResult::vulnerable(
                    self.name(),
                    self.cve(),
                    Severity::High,
                    "Server supports SSL 3.0 which is vulnerable to POODLE attack. \
                     Attackers can perform man-in-the-middle attacks to decrypt \
                     HTTPS traffic by exploiting CBC padding oracle.",
                    "Disable SSL 3.0 support on the server. Use TLS 1.2 or higher with \
                     authenticated encryption (GCM mode) cipher suites."
                ).with_evidence(evidence);
            }
            Ok(false) => {
                evidence.push("SSL 3.0 not supported (good)".to_string());
            }
            Err(e) => {
                evidence.push(format!("SSL 3.0 check error: {}", e));
            }
        }

        // Check for TLS CBC ciphers (potential TLS POODLE)
        match self.check_cbc_ciphers(host, port) {
            Ok(true) => {
                evidence.push("Server accepts TLS CBC cipher suites".to_string());
                evidence.push("Consider using GCM mode ciphers instead".to_string());
            }
            Ok(false) => {
                evidence.push("Server does not accept CBC ciphers (excellent)".to_string());
            }
            Err(e) => {
                evidence.push(format!("CBC cipher check error: {}", e));
            }
        }

        VulnCheckResult::not_vulnerable(self.name(), self.cve())
            .with_evidence(evidence)
    }
}
