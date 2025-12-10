/// LOGJAM Vulnerability Checker (CVE-2015-4000)
///
/// Tests for weak Diffie-Hellman key exchange parameters.
/// Servers using DH parameters smaller than 1024 bits are vulnerable.

use super::{VulnChecker, VulnCheckResult, Severity, connect_tcp, tls_types, build_client_hello};
use std::io::{Read, Write};
use std::time::Duration;

pub struct LogjamChecker {
    timeout: Duration,
}

impl LogjamChecker {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    /// Check for export-grade DH ciphers (512-bit)
    fn check_export_dh(&self, host: &str, port: u16) -> Result<bool, String> {
        let mut stream = connect_tcp(host, port, self.timeout)?;

        // Export-grade DH cipher suites (DHE_EXPORT)
        let cipher_suites = vec![
            0x0014, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
            0x0011, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        ];

        let client_hello = build_client_hello(tls_types::VERSION_TLS10, &cipher_suites, &[]);

        if let Err(e) = stream.write_all(&client_hello) {
            return Err(format!("Failed to send ClientHello: {}", e));
        }

        let mut buffer = vec![0u8; 2048];
        match stream.read(&mut buffer) {
            Ok(n) if n >= 5 => {
                // ServerHello means export cipher accepted
                if buffer[0] == tls_types::CONTENT_TYPE_HANDSHAKE {
                    return Ok(true);
                }
                Ok(false)
            }
            Ok(_) => Ok(false),
            Err(e) => Err(format!("Failed to read response: {}", e)),
        }
    }

    /// Check if server accepts DHE ciphers and estimate DH parameter size
    fn check_dhe_params(&self, host: &str, port: u16) -> Result<(bool, Option<usize>, Vec<String>), String> {
        let mut stream = connect_tcp(host, port, self.timeout)?;
        let mut evidence = Vec::new();

        // DHE cipher suites
        let cipher_suites = vec![
            0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
            0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
            0x009e, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            0x009f, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        ];

        let client_hello = build_client_hello(tls_types::VERSION_TLS12, &cipher_suites, &[]);

        if let Err(e) = stream.write_all(&client_hello) {
            return Err(format!("Failed to send ClientHello: {}", e));
        }

        // Read server response (need ServerKeyExchange for DH params)
        let mut buffer = vec![0u8; 8192];
        let mut total_read = 0;

        loop {
            match stream.read(&mut buffer[total_read..]) {
                Ok(0) => break,
                Ok(n) => {
                    total_read += n;
                    // Look for ServerKeyExchange
                    if let Some(dh_size) = self.extract_dh_param_size(&buffer[..total_read]) {
                        evidence.push(format!("DH parameter size: {} bits", dh_size));

                        if dh_size < 1024 {
                            evidence.push("WEAK: DH parameters less than 1024 bits".to_string());
                            return Ok((true, Some(dh_size), evidence));
                        } else if dh_size < 2048 {
                            evidence.push("WARNING: DH parameters less than 2048 bits".to_string());
                        } else {
                            evidence.push("DH parameter size is acceptable".to_string());
                        }
                        return Ok((false, Some(dh_size), evidence));
                    }

                    if total_read >= buffer.len() - 100 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        Ok((false, None, evidence))
    }

    /// Extract DH parameter size from ServerKeyExchange
    fn extract_dh_param_size(&self, data: &[u8]) -> Option<usize> {
        let mut pos = 0;

        while pos + 5 < data.len() {
            let content_type = data[pos];
            let length = ((data[pos + 3] as usize) << 8) | (data[pos + 4] as usize);

            if content_type == tls_types::CONTENT_TYPE_HANDSHAKE && pos + 5 + length <= data.len() {
                let record = &data[pos + 5..pos + 5 + length];

                // Look for ServerKeyExchange (type 12)
                if !record.is_empty() && record[0] == tls_types::HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE {
                    // DHE ServerKeyExchange format:
                    // - Handshake type (1 byte)
                    // - Length (3 bytes)
                    // - DH p length (2 bytes)
                    // - DH p value
                    // - DH g length (2 bytes)
                    // - DH g value
                    // - DH Ys length (2 bytes)
                    // - DH Ys value

                    if record.len() > 6 {
                        let p_len = ((record[4] as usize) << 8) | (record[5] as usize);
                        // DH parameter size in bits
                        return Some(p_len * 8);
                    }
                }
            }

            pos += 5 + length;
        }

        None
    }
}

impl Default for LogjamChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnChecker for LogjamChecker {
    fn name(&self) -> &str {
        "LOGJAM"
    }

    fn cve(&self) -> Option<&str> {
        Some("CVE-2015-4000")
    }

    fn description(&self) -> &str {
        "Weak Diffie-Hellman key exchange vulnerability"
    }

    fn check(&self, host: &str, port: u16) -> VulnCheckResult {
        let mut evidence = Vec::new();

        // Check for export-grade DH (critical)
        match self.check_export_dh(host, port) {
            Ok(true) => {
                evidence.push("Server accepts EXPORT-grade DHE ciphers (512-bit)".to_string());

                return VulnCheckResult::vulnerable(
                    self.name(),
                    self.cve(),
                    Severity::Critical,
                    "Server accepts export-grade DHE cipher suites with 512-bit parameters. \
                     This allows man-in-the-middle attackers to downgrade connections and \
                     decrypt traffic.",
                    "Disable export cipher suites. Use DHE with 2048-bit or larger parameters, \
                     or prefer ECDHE cipher suites."
                ).with_evidence(evidence);
            }
            Ok(false) => {
                evidence.push("Export-grade DHE not supported (good)".to_string());
            }
            Err(e) => {
                evidence.push(format!("Export DHE check error: {}", e));
            }
        }

        // Check DH parameter size
        match self.check_dhe_params(host, port) {
            Ok((vulnerable, Some(size), mut dhe_evidence)) => {
                evidence.append(&mut dhe_evidence);

                if vulnerable {
                    return VulnCheckResult::vulnerable(
                        self.name(),
                        self.cve(),
                        Severity::High,
                        &format!("Server uses weak {}-bit DH parameters. Parameters under 1024 bits \
                                 can be broken with precomputation attacks.", size),
                        "Use 2048-bit or larger DH parameters, or switch to ECDHE cipher suites."
                    ).with_evidence(evidence);
                }
            }
            Ok((_, None, mut dhe_evidence)) => {
                evidence.append(&mut dhe_evidence);
                evidence.push("Could not determine DH parameter size (may use ECDHE only)".to_string());
            }
            Err(e) => {
                evidence.push(format!("DHE param check error: {}", e));
            }
        }

        VulnCheckResult::not_vulnerable(self.name(), self.cve())
            .with_evidence(evidence)
    }
}
