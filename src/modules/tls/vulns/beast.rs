/// BEAST Vulnerability Checker (CVE-2011-3389)
///
/// Tests for Browser Exploit Against SSL/TLS vulnerability.
/// Affects TLS 1.0 with CBC mode ciphers.

use super::{VulnChecker, VulnCheckResult, Severity, connect_tcp, tls_types, build_client_hello};
use std::io::{Read, Write};
use std::time::Duration;

pub struct BeastChecker {
    timeout: Duration,
}

impl BeastChecker {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    /// Check if server supports TLS 1.0 with CBC ciphers
    fn check_tls10_cbc(&self, host: &str, port: u16) -> Result<(bool, Vec<String>), String> {
        let mut stream = connect_tcp(host, port, self.timeout)?;
        let mut evidence = Vec::new();

        // TLS 1.0 CBC cipher suites
        let cipher_suites = vec![
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        ];

        // Build ClientHello with TLS 1.0
        let client_hello = build_client_hello(tls_types::VERSION_TLS10, &cipher_suites, &[]);

        if let Err(e) = stream.write_all(&client_hello) {
            return Err(format!("Failed to send ClientHello: {}", e));
        }

        // Read response
        let mut buffer = vec![0u8; 2048];
        match stream.read(&mut buffer) {
            Ok(n) if n >= 5 => {
                if buffer[0] == tls_types::CONTENT_TYPE_HANDSHAKE {
                    // Check if TLS 1.0 was accepted
                    if buffer[1] == 0x03 && buffer[2] == 0x01 {
                        evidence.push("Server accepted TLS 1.0".to_string());

                        // Extract selected cipher from ServerHello
                        if n > 44 {
                            let cipher = ((buffer[43] as u16) << 8) | (buffer[44] as u16);
                            let cipher_name = self.cipher_name(cipher);
                            evidence.push(format!("Selected cipher: {} (0x{:04x})", cipher_name, cipher));

                            // Check if it's a CBC cipher
                            if self.is_cbc_cipher(cipher) {
                                evidence.push("Cipher uses CBC mode".to_string());
                                return Ok((true, evidence));
                            }
                        }
                    }
                }
                Ok((false, evidence))
            }
            Ok(_) => Ok((false, evidence)),
            Err(e) => Err(format!("Failed to read response: {}", e)),
        }
    }

    fn is_cbc_cipher(&self, cipher: u16) -> bool {
        // Common CBC cipher suites
        matches!(cipher,
            0x002f | // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035 | // TLS_RSA_WITH_AES_256_CBC_SHA
            0x000a | // TLS_RSA_WITH_3DES_EDE_CBC_SHA
            0x003c | // TLS_RSA_WITH_AES_128_CBC_SHA256
            0x003d | // TLS_RSA_WITH_AES_256_CBC_SHA256
            0x0033 | // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
            0x0039   // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        )
    }

    fn cipher_name(&self, cipher: u16) -> &str {
        match cipher {
            0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
            0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
            0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",
            0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
            0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
            0x1301 => "TLS_AES_128_GCM_SHA256",
            0x1302 => "TLS_AES_256_GCM_SHA384",
            _ => "Unknown",
        }
    }
}

impl Default for BeastChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnChecker for BeastChecker {
    fn name(&self) -> &str {
        "BEAST"
    }

    fn cve(&self) -> Option<&str> {
        Some("CVE-2011-3389")
    }

    fn description(&self) -> &str {
        "Browser Exploit Against SSL/TLS (TLS 1.0 CBC vulnerability)"
    }

    fn check(&self, host: &str, port: u16) -> VulnCheckResult {
        match self.check_tls10_cbc(host, port) {
            Ok((true, evidence)) => {
                VulnCheckResult::vulnerable(
                    self.name(),
                    self.cve(),
                    Severity::Medium,
                    "Server supports TLS 1.0 with CBC mode ciphers, vulnerable to BEAST attack. \
                     While modern browsers have mitigations, this is still a security weakness.",
                    "Disable TLS 1.0 and TLS 1.1 support. Use TLS 1.2 or TLS 1.3 with \
                     GCM or ChaCha20 cipher suites."
                ).with_evidence(evidence)
            }
            Ok((false, evidence)) => {
                VulnCheckResult::not_vulnerable(self.name(), self.cve())
                    .with_evidence(evidence)
            }
            Err(e) => VulnCheckResult::error(self.name(), &e),
        }
    }
}
