/// CCS Injection Vulnerability Checker (CVE-2014-0224)
///
/// Tests for OpenSSL ChangeCipherSpec injection vulnerability.
/// Allows man-in-the-middle attackers to use zero-length master secret.

use super::{VulnChecker, VulnCheckResult, Severity, connect_tcp, tls_types, build_client_hello};
use std::io::{Read, Write};
use std::time::Duration;

pub struct CcsInjectionChecker {
    timeout: Duration,
}

impl CcsInjectionChecker {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    /// Check for CCS injection vulnerability
    /// Vulnerable servers accept CCS before key exchange is complete
    fn check_early_ccs(&self, host: &str, port: u16) -> Result<(bool, Vec<String>), String> {
        let mut stream = connect_tcp(host, port, self.timeout)?;
        let mut evidence = Vec::new();

        // Standard cipher suites
        let cipher_suites = vec![
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        ];

        // Send ClientHello
        let client_hello = build_client_hello(tls_types::VERSION_TLS12, &cipher_suites, &[]);

        if let Err(e) = stream.write_all(&client_hello) {
            return Err(format!("Failed to send ClientHello: {}", e));
        }

        // Read ServerHello + Certificate + ServerHelloDone
        let mut buffer = vec![0u8; 8192];
        let mut total_read = 0;
        let mut got_server_hello_done = false;

        loop {
            match stream.read(&mut buffer[total_read..]) {
                Ok(0) => break,
                Ok(n) => {
                    total_read += n;

                    // Check for ServerHelloDone
                    if self.contains_server_hello_done(&buffer[..total_read]) {
                        got_server_hello_done = true;
                        evidence.push("Received ServerHelloDone".to_string());
                        break;
                    }

                    if total_read >= buffer.len() - 100 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        if !got_server_hello_done {
            return Err("Did not receive ServerHelloDone".to_string());
        }

        // Now send premature ChangeCipherSpec BEFORE ClientKeyExchange
        // Vulnerable servers will accept this
        let early_ccs = self.build_change_cipher_spec();

        if let Err(e) = stream.write_all(&early_ccs) {
            return Err(format!("Failed to send early CCS: {}", e));
        }

        evidence.push("Sent premature ChangeCipherSpec".to_string());

        // Read response
        let mut response = vec![0u8; 256];
        match stream.read(&mut response) {
            Ok(n) if n >= 5 => {
                // Check response type
                let content_type = response[0];

                match content_type {
                    tls_types::CONTENT_TYPE_ALERT => {
                        // Alert response - server rejected early CCS (good!)
                        if n >= 7 {
                            let alert_level = response[5];
                            let alert_desc = response[6];
                            evidence.push(format!(
                                "Server sent alert: level={}, desc={} ({})",
                                alert_level,
                                alert_desc,
                                self.alert_description(alert_desc)
                            ));
                        }
                        return Ok((false, evidence));
                    }
                    tls_types::CONTENT_TYPE_CHANGE_CIPHER_SPEC => {
                        // Server sent CCS back - VULNERABLE!
                        evidence.push("Server accepted early CCS - VULNERABLE!".to_string());
                        return Ok((true, evidence));
                    }
                    tls_types::CONTENT_TYPE_HANDSHAKE => {
                        // Server continued handshake - might be vulnerable
                        evidence.push("Server continued handshake after early CCS".to_string());
                        return Ok((true, evidence));
                    }
                    _ => {
                        evidence.push(format!("Unexpected response type: {}", content_type));
                    }
                }
            }
            Ok(_) => {
                evidence.push("Server closed connection (likely not vulnerable)".to_string());
            }
            Err(e) => {
                evidence.push(format!("Read error: {} (likely not vulnerable)", e));
            }
        }

        Ok((false, evidence))
    }

    /// Build ChangeCipherSpec message
    fn build_change_cipher_spec(&self) -> Vec<u8> {
        vec![
            tls_types::CONTENT_TYPE_CHANGE_CIPHER_SPEC, // Content type
            0x03, 0x03,                                  // TLS 1.2
            0x00, 0x01,                                  // Length: 1
            0x01,                                        // CCS message
        ]
    }

    fn contains_server_hello_done(&self, data: &[u8]) -> bool {
        let mut pos = 0;
        while pos + 5 < data.len() {
            let content_type = data[pos];
            let length = ((data[pos + 3] as usize) << 8) | (data[pos + 4] as usize);

            if content_type == tls_types::CONTENT_TYPE_HANDSHAKE && pos + 5 + length <= data.len() {
                // Scan handshake messages in this record
                let record = &data[pos + 5..pos + 5 + length];
                let mut hpos = 0;

                while hpos + 4 <= record.len() {
                    let hs_type = record[hpos];
                    let hs_len = ((record[hpos + 1] as usize) << 16)
                        | ((record[hpos + 2] as usize) << 8)
                        | (record[hpos + 3] as usize);

                    if hs_type == tls_types::HANDSHAKE_TYPE_SERVER_HELLO_DONE {
                        return true;
                    }

                    hpos += 4 + hs_len;
                }
            }

            pos += 5 + length;
        }
        false
    }

    fn alert_description(&self, desc: u8) -> &str {
        match desc {
            0 => "close_notify",
            10 => "unexpected_message",
            20 => "bad_record_mac",
            40 => "handshake_failure",
            42 => "bad_certificate",
            43 => "unsupported_certificate",
            44 => "certificate_revoked",
            45 => "certificate_expired",
            46 => "certificate_unknown",
            47 => "illegal_parameter",
            48 => "unknown_ca",
            49 => "access_denied",
            50 => "decode_error",
            51 => "decrypt_error",
            70 => "protocol_version",
            71 => "insufficient_security",
            80 => "internal_error",
            86 => "inappropriate_fallback",
            90 => "user_canceled",
            100 => "no_renegotiation",
            110 => "unsupported_extension",
            _ => "unknown",
        }
    }
}

impl Default for CcsInjectionChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnChecker for CcsInjectionChecker {
    fn name(&self) -> &str {
        "CCS Injection"
    }

    fn cve(&self) -> Option<&str> {
        Some("CVE-2014-0224")
    }

    fn description(&self) -> &str {
        "OpenSSL ChangeCipherSpec injection vulnerability"
    }

    fn check(&self, host: &str, port: u16) -> VulnCheckResult {
        match self.check_early_ccs(host, port) {
            Ok((true, evidence)) => {
                VulnCheckResult::vulnerable(
                    self.name(),
                    self.cve(),
                    Severity::High,
                    "Server accepts ChangeCipherSpec before key exchange is complete. \
                     This allows man-in-the-middle attackers to inject a predictable \
                     master secret and decrypt TLS sessions.",
                    "Update OpenSSL to version 1.0.1h or later (or 1.0.0m/0.9.8za). \
                     Ensure all SSL libraries are patched."
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
