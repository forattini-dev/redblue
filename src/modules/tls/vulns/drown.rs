/// DROWN Vulnerability Checker (CVE-2016-0800)
///
/// Tests for Decrypting RSA with Obsolete and Weakened eNcryption.
/// Servers supporting SSLv2 can have their modern TLS sessions decrypted.

use super::{VulnChecker, VulnCheckResult, Severity, connect_tcp, tls_types};
use std::io::{Read, Write};
use std::time::Duration;

pub struct DrownChecker {
    timeout: Duration,
}

impl DrownChecker {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    /// Check if server supports SSLv2 (core DROWN vulnerability)
    fn check_sslv2_support(&self, host: &str, port: u16) -> Result<(bool, Vec<String>), String> {
        let mut stream = connect_tcp(host, port, self.timeout)?;
        let mut evidence = Vec::new();

        // Build SSLv2 ClientHello
        let client_hello = self.build_sslv2_client_hello();

        if let Err(e) = stream.write_all(&client_hello) {
            return Err(format!("Failed to send SSLv2 ClientHello: {}", e));
        }

        evidence.push("Sent SSLv2 ClientHello".to_string());

        // Read response
        let mut buffer = vec![0u8; 2048];
        match stream.read(&mut buffer) {
            Ok(n) if n >= 3 => {
                // SSLv2 ServerHello format:
                // Byte 0: Message length high bits (0x80 | len)
                // Byte 2: Message type (4 = ServerHello)

                // Check for SSLv2 record format
                if (buffer[0] & 0x80) != 0 {
                    let msg_type = buffer[2];

                    if msg_type == 0x04 {
                        // SSLv2 ServerHello - VULNERABLE!
                        evidence.push("Server responded with SSLv2 ServerHello - VULNERABLE!".to_string());

                        // Extract certificate and cipher info if available
                        if n > 11 {
                            let cert_len = ((buffer[5] as usize) << 8) | (buffer[6] as usize);
                            let cipher_specs_len = ((buffer[7] as usize) << 8) | (buffer[8] as usize);
                            evidence.push(format!("Certificate length: {} bytes", cert_len));
                            evidence.push(format!("Cipher specs length: {} bytes", cipher_specs_len));

                            // Parse cipher specs
                            if n > 11 + cipher_specs_len {
                                let ciphers = self.parse_sslv2_ciphers(&buffer[11..11 + cipher_specs_len]);
                                for cipher in ciphers {
                                    evidence.push(format!("SSLv2 cipher: {}", cipher));
                                }
                            }
                        }

                        return Ok((true, evidence));
                    } else if msg_type == 0x00 {
                        // SSLv2 Error
                        evidence.push("Server sent SSLv2 error response".to_string());
                        return Ok((false, evidence));
                    }
                }

                // Check for TLS alert (server doesn't speak SSLv2)
                if buffer[0] == tls_types::CONTENT_TYPE_ALERT {
                    evidence.push("Server responded with TLS alert (SSLv2 not supported - good)".to_string());
                    return Ok((false, evidence));
                }

                evidence.push(format!("Unexpected response: {:02x} {:02x} {:02x}",
                    buffer[0], buffer[1], buffer[2]));
            }
            Ok(_) => {
                evidence.push("Server closed connection (SSLv2 likely not supported)".to_string());
            }
            Err(e) => {
                evidence.push(format!("Connection error: {} (SSLv2 likely not supported)", e));
            }
        }

        Ok((false, evidence))
    }

    /// Check for export-grade RSA ciphers (Special DROWN)
    fn check_export_rsa(&self, host: &str, port: u16) -> Result<(bool, Vec<String>), String> {
        let mut stream = connect_tcp(host, port, self.timeout)?;
        let mut evidence = Vec::new();

        // Export-grade RSA cipher suites
        let cipher_suites = vec![
            0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
            0x0006, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
            0x0008, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
            0x0062, // TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
            0x0064, // TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
        ];

        let client_hello = self.build_tls_client_hello(&cipher_suites);

        if let Err(e) = stream.write_all(&client_hello) {
            return Err(format!("Failed to send ClientHello: {}", e));
        }

        let mut buffer = vec![0u8; 2048];
        match stream.read(&mut buffer) {
            Ok(n) if n >= 5 => {
                if buffer[0] == tls_types::CONTENT_TYPE_HANDSHAKE {
                    // ServerHello - server accepted export cipher
                    if n > 44 {
                        let cipher = ((buffer[43] as u16) << 8) | (buffer[44] as u16);
                        if cipher_suites.contains(&cipher) {
                            evidence.push(format!(
                                "Server accepted export RSA cipher: {}",
                                self.export_cipher_name(cipher)
                            ));
                            return Ok((true, evidence));
                        }
                    }
                }
                evidence.push("Export RSA ciphers not supported".to_string());
            }
            Ok(_) => {
                evidence.push("Export RSA ciphers not supported".to_string());
            }
            Err(e) => {
                return Err(format!("Read error: {}", e));
            }
        }

        Ok((false, evidence))
    }

    /// Build SSLv2 ClientHello
    fn build_sslv2_client_hello(&self) -> Vec<u8> {
        let mut hello = Vec::new();

        // SSLv2 cipher specs (3 bytes each)
        let cipher_specs = vec![
            // SSL_CK_RC4_128_WITH_MD5
            0x01, 0x00, 0x80,
            // SSL_CK_RC4_128_EXPORT40_WITH_MD5
            0x02, 0x00, 0x80,
            // SSL_CK_RC2_128_CBC_WITH_MD5
            0x03, 0x00, 0x80,
            // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
            0x04, 0x00, 0x80,
            // SSL_CK_IDEA_128_CBC_WITH_MD5
            0x05, 0x00, 0x80,
            // SSL_CK_DES_64_CBC_WITH_MD5
            0x06, 0x00, 0x40,
            // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
            0x07, 0x00, 0xc0,
        ];

        // Challenge (16 bytes)
        let challenge = [0x01; 16];

        // Message body
        let mut body = Vec::new();
        body.push(0x01); // MSG_CLIENT_HELLO

        // Version: SSLv2 (0x0002)
        body.push(0x00);
        body.push(0x02);

        // Cipher specs length
        body.push((cipher_specs.len() >> 8) as u8);
        body.push(cipher_specs.len() as u8);

        // Session ID length (0)
        body.push(0x00);
        body.push(0x00);

        // Challenge length
        body.push((challenge.len() >> 8) as u8);
        body.push(challenge.len() as u8);

        // Cipher specs
        body.extend_from_slice(&cipher_specs);

        // Challenge
        body.extend_from_slice(&challenge);

        // SSLv2 record header (2-byte length with high bit set)
        let len = body.len();
        hello.push(0x80 | ((len >> 8) as u8));
        hello.push(len as u8);
        hello.extend_from_slice(&body);

        hello
    }

    /// Build TLS ClientHello for export cipher check
    fn build_tls_client_hello(&self, cipher_suites: &[u16]) -> Vec<u8> {
        let mut hello = Vec::new();

        // Client version (TLS 1.0 - most compatible with export ciphers)
        hello.extend_from_slice(&tls_types::VERSION_TLS10);

        // Random (32 bytes)
        hello.extend_from_slice(&[0u8; 32]);

        // Session ID length (0)
        hello.push(0);

        // Cipher suites
        let cs_len = (cipher_suites.len() * 2) as u16;
        hello.push((cs_len >> 8) as u8);
        hello.push(cs_len as u8);
        for cs in cipher_suites {
            hello.push((*cs >> 8) as u8);
            hello.push(*cs as u8);
        }

        // Compression methods
        hello.push(1);
        hello.push(0); // NULL

        // Build handshake record
        let mut record = Vec::new();
        record.push(tls_types::HANDSHAKE_TYPE_CLIENT_HELLO);
        record.push(0);
        record.push((hello.len() >> 8) as u8);
        record.push(hello.len() as u8);
        record.extend_from_slice(&hello);

        // Build TLS record
        let mut tls_record = Vec::new();
        tls_record.push(tls_types::CONTENT_TYPE_HANDSHAKE);
        tls_record.extend_from_slice(&tls_types::VERSION_TLS10);
        tls_record.push((record.len() >> 8) as u8);
        tls_record.push(record.len() as u8);
        tls_record.extend_from_slice(&record);

        tls_record
    }

    fn parse_sslv2_ciphers(&self, data: &[u8]) -> Vec<&str> {
        let mut ciphers = Vec::new();
        let mut i = 0;

        while i + 3 <= data.len() {
            let cipher = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);

            let name = match cipher {
                0x010080 => "SSL_CK_RC4_128_WITH_MD5",
                0x020080 => "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
                0x030080 => "SSL_CK_RC2_128_CBC_WITH_MD5",
                0x040080 => "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
                0x050080 => "SSL_CK_IDEA_128_CBC_WITH_MD5",
                0x060040 => "SSL_CK_DES_64_CBC_WITH_MD5",
                0x0700c0 => "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
                _ => "Unknown SSLv2 cipher",
            };
            ciphers.push(name);
            i += 3;
        }

        ciphers
    }

    fn export_cipher_name(&self, cipher: u16) -> &str {
        match cipher {
            0x0003 => "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
            0x0006 => "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
            0x0008 => "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
            0x0062 => "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
            0x0064 => "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
            _ => "Unknown export cipher",
        }
    }
}

impl Default for DrownChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnChecker for DrownChecker {
    fn name(&self) -> &str {
        "DROWN"
    }

    fn cve(&self) -> Option<&str> {
        Some("CVE-2016-0800")
    }

    fn description(&self) -> &str {
        "Decrypting RSA with Obsolete and Weakened eNcryption (SSLv2 attack)"
    }

    fn check(&self, host: &str, port: u16) -> VulnCheckResult {
        let mut evidence = Vec::new();

        // Check for SSLv2 support (main DROWN vulnerability)
        match self.check_sslv2_support(host, port) {
            Ok((true, mut sslv2_evidence)) => {
                evidence.append(&mut sslv2_evidence);

                return VulnCheckResult::vulnerable(
                    self.name(),
                    self.cve(),
                    Severity::Critical,
                    "Server supports SSLv2 protocol. DROWN allows attackers to decrypt \
                     modern TLS connections by performing cross-protocol attacks using \
                     SSLv2 as an oracle. Even if SSLv2 is only enabled on a different \
                     server sharing the same RSA key, modern TLS sessions are at risk.",
                    "Disable SSLv2 on all servers. Ensure no servers sharing the same \
                     RSA private key have SSLv2 enabled. Consider rotating RSA keys \
                     if SSLv2 was ever exposed."
                ).with_evidence(evidence);
            }
            Ok((false, mut sslv2_evidence)) => {
                evidence.append(&mut sslv2_evidence);
            }
            Err(e) => {
                evidence.push(format!("SSLv2 check error: {}", e));
            }
        }

        // Check for export RSA ciphers (Special DROWN)
        match self.check_export_rsa(host, port) {
            Ok((true, mut export_evidence)) => {
                evidence.append(&mut export_evidence);

                return VulnCheckResult::vulnerable(
                    self.name(),
                    self.cve(),
                    Severity::High,
                    "Server supports export-grade RSA ciphers. Special DROWN attack \
                     can exploit these weak ciphers to decrypt TLS sessions faster \
                     than general DROWN.",
                    "Disable all export cipher suites. Use only modern cipher suites \
                     with forward secrecy (ECDHE)."
                ).with_evidence(evidence);
            }
            Ok((false, mut export_evidence)) => {
                evidence.append(&mut export_evidence);
            }
            Err(e) => {
                evidence.push(format!("Export RSA check error: {}", e));
            }
        }

        VulnCheckResult::not_vulnerable(self.name(), self.cve())
            .with_evidence(evidence)
    }
}
