/// ROBOT Vulnerability Checker (Return Of Bleichenbacher's Oracle Threat)
///
/// Tests for RSA PKCS#1 v1.5 padding oracle vulnerabilities.
/// Affects servers using RSA key exchange ciphers with improper error handling.

use super::{VulnChecker, VulnCheckResult, Severity, connect_tcp, tls_types, build_client_hello};
use std::io::{Read, Write};
use std::time::Duration;

pub struct RobotChecker {
    timeout: Duration,
}

impl RobotChecker {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    /// Check if server supports RSA key exchange ciphers
    fn check_rsa_ciphers(&self, host: &str, port: u16) -> Result<(bool, Vec<u16>), String> {
        let mut stream = connect_tcp(host, port, self.timeout)?;

        // RSA key exchange cipher suites (vulnerable to ROBOT if padding oracle exists)
        let cipher_suites = vec![
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x003c, // TLS_RSA_WITH_AES_128_CBC_SHA256
            0x003d, // TLS_RSA_WITH_AES_256_CBC_SHA256
            0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
            0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        ];

        let client_hello = build_client_hello(tls_types::VERSION_TLS12, &cipher_suites, &[]);

        if let Err(e) = stream.write_all(&client_hello) {
            return Err(format!("Failed to send ClientHello: {}", e));
        }

        let mut buffer = vec![0u8; 4096];
        match stream.read(&mut buffer) {
            Ok(n) if n >= 5 => {
                if buffer[0] == tls_types::CONTENT_TYPE_HANDSHAKE {
                    // Extract selected cipher from ServerHello
                    if n > 44 {
                        let cipher = ((buffer[43] as u16) << 8) | (buffer[44] as u16);
                        if cipher_suites.contains(&cipher) {
                            return Ok((true, vec![cipher]));
                        }
                    }
                }
                Ok((false, vec![]))
            }
            Ok(_) => Ok((false, vec![])),
            Err(e) => Err(format!("Failed to read response: {}", e)),
        }
    }

    /// Perform timing-based oracle check (simplified)
    /// Full ROBOT requires multiple probes with different padding
    fn check_padding_oracle(&self, host: &str, port: u16) -> Result<(bool, Vec<String>), String> {
        let mut evidence = Vec::new();
        let mut timings = Vec::new();

        // Send multiple ClientKeyExchange with different PKCS#1 padding patterns
        // Vulnerable servers will show timing differences based on padding validity
        let padding_tests = [
            // Valid PKCS#1 v1.5 padding pattern start
            (0x00, 0x02, "Valid PKCS#1 v1.5 start"),
            // Wrong first byte
            (0x01, 0x02, "Wrong block type byte 1"),
            // Wrong block type
            (0x00, 0x01, "Wrong block type (signature)"),
            // All zeros
            (0x00, 0x00, "Invalid padding start"),
        ];

        for (byte1, byte2, desc) in padding_tests {
            let start = std::time::Instant::now();

            let mut stream = match connect_tcp(host, port, self.timeout) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Send ClientHello
            let cipher_suites = vec![0x002f]; // TLS_RSA_WITH_AES_128_CBC_SHA
            let client_hello = build_client_hello(tls_types::VERSION_TLS12, &cipher_suites, &[]);

            if stream.write_all(&client_hello).is_err() {
                continue;
            }

            // Read ServerHello + Certificate + ServerHelloDone
            let mut buffer = vec![0u8; 8192];
            let mut total = 0;
            loop {
                match stream.read(&mut buffer[total..]) {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n;
                        if total >= buffer.len() - 100 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            // Build malformed ClientKeyExchange with specific padding
            let client_key_exchange = self.build_malformed_cke(byte1, byte2);

            if stream.write_all(&client_key_exchange).is_ok() {
                // Read response and measure time
                let mut response = vec![0u8; 256];
                let _ = stream.read(&mut response);
            }

            let elapsed = start.elapsed();
            timings.push((desc, elapsed.as_micros()));
        }

        // Analyze timing differences
        if timings.len() >= 4 {
            let valid_time = timings[0].1;
            let mut has_oracle = false;

            for (desc, time) in &timings[1..] {
                // Significant timing difference suggests oracle
                let diff = if *time > valid_time {
                    *time - valid_time
                } else {
                    valid_time - *time
                };

                evidence.push(format!("{}: {}μs (diff: {}μs)", desc, time, diff));

                // If timing differs by more than 10%, potential oracle
                if diff > valid_time / 10 {
                    has_oracle = true;
                }
            }

            return Ok((has_oracle, evidence));
        }

        Ok((false, evidence))
    }

    /// Build a malformed ClientKeyExchange message
    fn build_malformed_cke(&self, byte1: u8, byte2: u8) -> Vec<u8> {
        let mut cke = Vec::new();

        // Fake encrypted pre-master secret (256 bytes for 2048-bit RSA)
        let mut encrypted_pms = vec![0u8; 256];
        encrypted_pms[0] = byte1;
        encrypted_pms[1] = byte2;
        // Fill rest with random-ish data
        for i in 2..256 {
            encrypted_pms[i] = ((i * 7) % 256) as u8;
        }

        // ClientKeyExchange handshake message
        let mut handshake = Vec::new();
        handshake.push(16); // HandshakeType: ClientKeyExchange

        // Length of encrypted PMS (256 bytes) + 2 byte length prefix
        let pms_len = encrypted_pms.len() + 2;
        handshake.push(0);
        handshake.push((pms_len >> 8) as u8);
        handshake.push(pms_len as u8);

        // Length of encrypted PMS
        handshake.push((encrypted_pms.len() >> 8) as u8);
        handshake.push(encrypted_pms.len() as u8);
        handshake.extend_from_slice(&encrypted_pms);

        // TLS record
        cke.push(tls_types::CONTENT_TYPE_HANDSHAKE);
        cke.extend_from_slice(&tls_types::VERSION_TLS12);
        cke.push((handshake.len() >> 8) as u8);
        cke.push(handshake.len() as u8);
        cke.extend_from_slice(&handshake);

        cke
    }

    fn cipher_name(&self, cipher: u16) -> &str {
        match cipher {
            0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
            0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
            0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",
            0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
            0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
            0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            _ => "Unknown RSA cipher",
        }
    }
}

impl Default for RobotChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnChecker for RobotChecker {
    fn name(&self) -> &str {
        "ROBOT"
    }

    fn cve(&self) -> Option<&str> {
        // ROBOT doesn't have a single CVE - it affects many implementations
        None
    }

    fn description(&self) -> &str {
        "Return Of Bleichenbacher's Oracle Threat - RSA padding oracle attack"
    }

    fn check(&self, host: &str, port: u16) -> VulnCheckResult {
        let mut evidence = Vec::new();

        // First check if RSA ciphers are supported
        match self.check_rsa_ciphers(host, port) {
            Ok((true, ciphers)) => {
                for cipher in &ciphers {
                    evidence.push(format!("RSA cipher supported: {}", self.cipher_name(*cipher)));
                }
            }
            Ok((false, _)) => {
                evidence.push("No RSA key exchange ciphers supported (good)".to_string());
                return VulnCheckResult::not_vulnerable(self.name(), self.cve())
                    .with_evidence(evidence);
            }
            Err(e) => {
                return VulnCheckResult::error(self.name(), &e);
            }
        }

        // Check for padding oracle via timing
        match self.check_padding_oracle(host, port) {
            Ok((true, mut oracle_evidence)) => {
                evidence.append(&mut oracle_evidence);

                return VulnCheckResult::vulnerable(
                    self.name(),
                    self.cve(),
                    Severity::High,
                    "Server appears to have a Bleichenbacher RSA padding oracle. \
                     Timing differences in responses to malformed PKCS#1 v1.5 padding \
                     allow attackers to decrypt RSA-encrypted TLS sessions.",
                    "Disable RSA key exchange cipher suites. Use ECDHE or DHE for \
                     forward secrecy. If RSA must be used, ensure constant-time \
                     padding validation."
                ).with_evidence(evidence);
            }
            Ok((false, mut oracle_evidence)) => {
                evidence.append(&mut oracle_evidence);
                evidence.push("No obvious timing oracle detected".to_string());
                evidence.push("Note: RSA ciphers still present - recommend disabling".to_string());
            }
            Err(e) => {
                evidence.push(format!("Oracle check error: {}", e));
            }
        }

        // RSA ciphers are supported but no oracle detected
        // Still report as informational
        VulnCheckResult::not_vulnerable(self.name(), self.cve())
            .with_evidence(evidence)
    }
}
