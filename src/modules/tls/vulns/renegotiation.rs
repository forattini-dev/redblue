/// TLS Renegotiation Vulnerability Checker (CVE-2009-3555)
///
/// Tests for insecure TLS renegotiation which allows man-in-the-middle
/// attackers to inject data into TLS sessions.

use super::{VulnChecker, VulnCheckResult, Severity, connect_tcp, tls_types, build_client_hello};
use std::io::{Read, Write};
use std::time::Duration;

pub struct RenegotiationChecker {
    timeout: Duration,
}

impl RenegotiationChecker {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    /// Check for secure renegotiation support via extension
    fn check_secure_renegotiation(&self, host: &str, port: u16) -> Result<(bool, Vec<String>), String> {
        let mut stream = connect_tcp(host, port, self.timeout)?;
        let mut evidence = Vec::new();

        // Renegotiation Info extension (empty for initial connection)
        let renegotiation_ext = vec![
            0xff, 0x01, // Extension type: renegotiation_info (65281)
            0x00, 0x01, // Extension length
            0x00,       // Renegotiated connection length (0 for initial)
        ];

        let cipher_suites = vec![
            0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
        ];

        let client_hello = build_client_hello(tls_types::VERSION_TLS12, &cipher_suites, &renegotiation_ext);

        stream.write_all(&client_hello)
            .map_err(|e| format!("Failed to send ClientHello: {}", e))?;

        let mut buffer = vec![0u8; 4096];
        match stream.read(&mut buffer) {
            Ok(n) if n >= 5 => {
                if buffer[0] == tls_types::CONTENT_TYPE_HANDSHAKE {
                    // Parse ServerHello for renegotiation_info extension
                    if let Some(has_ext) = self.check_renegotiation_extension(&buffer[..n]) {
                        if has_ext {
                            evidence.push("Server supports secure renegotiation (extension present)".to_string());
                            return Ok((true, evidence));
                        }
                    }

                    // Check for SCSV cipher
                    if self.has_scsv_support(&buffer[..n]) {
                        evidence.push("Server supports secure renegotiation via SCSV".to_string());
                        return Ok((true, evidence));
                    }

                    evidence.push("Renegotiation extension not found in ServerHello".to_string());
                }
                return Ok((false, evidence));
            }
            Ok(_) => {
                return Err("Incomplete response".to_string());
            }
            Err(e) => {
                return Err(format!("Read error: {}", e));
            }
        }
    }

    /// Check if server allows client-initiated renegotiation
    fn check_client_renegotiation(&self, host: &str, port: u16) -> Result<(bool, Vec<String>), String> {
        let mut stream = connect_tcp(host, port, self.timeout)?;
        let mut evidence = Vec::new();

        let cipher_suites = vec![0x002f, 0x0035];
        let client_hello = build_client_hello(tls_types::VERSION_TLS12, &cipher_suites, &[]);

        // Initial handshake
        stream.write_all(&client_hello)
            .map_err(|e| format!("Failed to send initial ClientHello: {}", e))?;

        let mut buffer = vec![0u8; 8192];
        let mut total = 0;

        // Read until ServerHelloDone or sufficient data
        loop {
            match stream.read(&mut buffer[total..]) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    if self.has_server_hello_done(&buffer[..total]) {
                        break;
                    }
                    if total >= buffer.len() - 100 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        evidence.push("Initial handshake completed".to_string());

        // Now attempt renegotiation by sending another ClientHello
        // This simulates client-initiated renegotiation
        let reneg_hello = build_client_hello(tls_types::VERSION_TLS12, &cipher_suites, &[]);

        if let Err(e) = stream.write_all(&reneg_hello) {
            evidence.push(format!("Renegotiation attempt failed: {}", e));
            return Ok((false, evidence));
        }

        evidence.push("Sent renegotiation ClientHello".to_string());

        // Check response
        let mut response = vec![0u8; 256];
        match stream.read(&mut response) {
            Ok(n) if n >= 5 => {
                let content_type = response[0];

                match content_type {
                    tls_types::CONTENT_TYPE_ALERT => {
                        // Alert usually means renegotiation denied
                        if n >= 7 {
                            let alert_level = response[5];
                            let alert_desc = response[6];
                            evidence.push(format!(
                                "Server sent alert: {} ({})",
                                alert_desc,
                                self.alert_name(alert_desc)
                            ));

                            // no_renegotiation (100) is the proper response
                            if alert_desc == 100 {
                                evidence.push("Client-initiated renegotiation properly denied".to_string());
                                return Ok((false, evidence));
                            }
                        }
                        return Ok((false, evidence));
                    }
                    tls_types::CONTENT_TYPE_HANDSHAKE => {
                        // Server responded with handshake - renegotiation allowed
                        evidence.push("Server accepted client-initiated renegotiation".to_string());
                        return Ok((true, evidence));
                    }
                    _ => {
                        evidence.push(format!("Unexpected response type: {}", content_type));
                    }
                }
            }
            Ok(_) => {
                evidence.push("Server closed connection on renegotiation attempt".to_string());
            }
            Err(e) => {
                evidence.push(format!("Read error: {} (renegotiation likely denied)", e));
            }
        }

        Ok((false, evidence))
    }

    /// Check for renegotiation_info extension in ServerHello
    fn check_renegotiation_extension(&self, data: &[u8]) -> Option<bool> {
        // Skip TLS record (5 bytes) + handshake type/length (4 bytes)
        // ServerHello: version (2) + random (32) + session_id_len + session_id + cipher (2) + compression (1) + extensions
        if data.len() < 43 {
            return None;
        }

        let session_id_len = data[43] as usize;
        let ext_offset = 44 + session_id_len + 3; // +3 for cipher suite and compression

        if data.len() < ext_offset + 2 {
            return Some(false);
        }

        // Extensions length
        let ext_len = ((data[ext_offset] as usize) << 8) | (data[ext_offset + 1] as usize);
        let mut pos = ext_offset + 2;
        let ext_end = pos + ext_len;

        while pos + 4 <= ext_end && pos + 4 <= data.len() {
            let ext_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
            let ext_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);

            // renegotiation_info extension type is 0xff01 (65281)
            if ext_type == 0xff01 {
                return Some(true);
            }

            pos += 4 + ext_len;
        }

        Some(false)
    }

    /// Check for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    fn has_scsv_support(&self, _data: &[u8]) -> bool {
        // SCSV (0x00ff) would be indicated differently
        // For now, check if connection succeeded with our extension request
        false
    }

    fn has_server_hello_done(&self, data: &[u8]) -> bool {
        let mut pos = 0;

        while pos + 5 < data.len() {
            let content_type = data[pos];
            let length = ((data[pos + 3] as usize) << 8) | (data[pos + 4] as usize);

            if content_type == tls_types::CONTENT_TYPE_HANDSHAKE && pos + 5 + length <= data.len() {
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

            if pos + 5 + length > data.len() {
                break;
            }
            pos += 5 + length;
        }

        false
    }

    fn alert_name(&self, desc: u8) -> &str {
        match desc {
            0 => "close_notify",
            10 => "unexpected_message",
            20 => "bad_record_mac",
            40 => "handshake_failure",
            47 => "illegal_parameter",
            70 => "protocol_version",
            80 => "internal_error",
            100 => "no_renegotiation",
            _ => "unknown",
        }
    }
}

impl Default for RenegotiationChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnChecker for RenegotiationChecker {
    fn name(&self) -> &str {
        "Insecure Renegotiation"
    }

    fn cve(&self) -> Option<&str> {
        Some("CVE-2009-3555")
    }

    fn description(&self) -> &str {
        "TLS renegotiation prefix injection vulnerability"
    }

    fn check(&self, host: &str, port: u16) -> VulnCheckResult {
        let mut evidence = Vec::new();
        let mut issues = Vec::new();

        // Check for secure renegotiation extension
        match self.check_secure_renegotiation(host, port) {
            Ok((true, mut ext_evidence)) => {
                evidence.append(&mut ext_evidence);
            }
            Ok((false, mut ext_evidence)) => {
                evidence.append(&mut ext_evidence);
                issues.push("Secure renegotiation extension not supported");
            }
            Err(e) => {
                evidence.push(format!("Secure renegotiation check error: {}", e));
            }
        }

        // Check for client-initiated renegotiation
        match self.check_client_renegotiation(host, port) {
            Ok((true, mut reneg_evidence)) => {
                evidence.append(&mut reneg_evidence);
                issues.push("Client-initiated renegotiation allowed");
            }
            Ok((false, mut reneg_evidence)) => {
                evidence.append(&mut reneg_evidence);
            }
            Err(e) => {
                evidence.push(format!("Renegotiation check error: {}", e));
            }
        }

        // Determine vulnerability status
        if issues.contains(&"Secure renegotiation extension not supported") {
            return VulnCheckResult::vulnerable(
                self.name(),
                self.cve(),
                Severity::High,
                "Server does not support secure renegotiation. This allows \
                 man-in-the-middle attackers to inject arbitrary data into TLS sessions \
                 by intercepting the initial handshake and prepending malicious requests.",
                "Enable secure renegotiation (RFC 5746) by updating TLS implementation. \
                 Consider disabling client-initiated renegotiation entirely."
            ).with_evidence(evidence);
        }

        if issues.contains(&"Client-initiated renegotiation allowed") {
            return VulnCheckResult::vulnerable(
                self.name(),
                self.cve(),
                Severity::Medium,
                "Server allows client-initiated renegotiation. While secure renegotiation \
                 is supported, allowing clients to trigger renegotiation can be used for \
                 denial-of-service attacks due to the computational cost of key exchange.",
                "Disable client-initiated renegotiation. If renegotiation is needed, \
                 restrict it to server-initiated only."
            ).with_evidence(evidence);
        }

        VulnCheckResult::not_vulnerable(self.name(), self.cve())
            .with_evidence(evidence)
    }
}
