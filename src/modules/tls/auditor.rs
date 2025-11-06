/// TLS Security Auditor
///
/// Replaces: sslyze, testssl.sh
///
/// Features:
/// - TLS version enumeration (1.0, 1.1, 1.2, 1.3)
/// - Cipher suite enumeration
/// - Known vulnerability checks
/// - Certificate validation
///
/// NO external dependencies - all implemented from scratch
use crate::modules::tls::scanner::{
    CipherStrength as ScannerCipherStrength, SecurityIssue, Severity as ScannerSeverity,
    TlsScanner, TlsVersion,
};
use crate::protocols::{
    tls12::Tls12Client,
    tls_cert::{CertificateInfo, TlsClient},
};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TlsAuditResult {
    pub host: String,
    pub port: u16,
    pub supported_versions: Vec<TlsVersionInfo>,
    pub supported_ciphers: Vec<CipherInfo>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub certificate_valid: bool,
    pub certificate_chain: Vec<CertificateInfo>,
    pub negotiated_version: Option<String>,
    pub negotiated_cipher: Option<String>,
    pub negotiated_cipher_code: Option<u16>,
    pub negotiated_cipher_strength: Option<CipherStrength>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub ja3_raw: Option<String>,
    pub ja3s_raw: Option<String>,
    pub peer_fingerprints: Vec<String>,
    pub certificate_chain_pem: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TlsVersionInfo {
    pub version: String,
    pub supported: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CipherInfo {
    pub name: String,
    pub code: u16,
    pub strength: CipherStrength,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CipherStrength {
    Weak,
    Medium,
    Strong,
}

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub name: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

pub struct TlsAuditor {
    timeout: Duration,
}

impl TlsAuditor {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Run full TLS audit
    pub fn audit(&self, host: &str, port: u16) -> Result<TlsAuditResult, String> {
        let mut result = TlsAuditResult {
            host: host.to_string(),
            port,
            supported_versions: Vec::new(),
            supported_ciphers: Vec::new(),
            vulnerabilities: Vec::new(),
            certificate_valid: false,
            certificate_chain: Vec::new(),
            negotiated_version: None,
            negotiated_cipher: None,
            negotiated_cipher_code: None,
            negotiated_cipher_strength: None,
            ja3: None,
            ja3s: None,
            ja3_raw: None,
            ja3s_raw: None,
            peer_fingerprints: Vec::new(),
            certificate_chain_pem: Vec::new(),
        };

        let scanner = TlsScanner::with_timeout(self.timeout);
        let scan_results = scanner.scan_all(host, port)?;
        result.supported_versions = scan_results
            .iter()
            .map(|r| TlsVersionInfo {
                version: r.version.as_str().to_string(),
                supported: r.supported,
                error: r.error.clone(),
            })
            .collect();

        // Flag legacy protocol support as vulnerabilities
        for version in &result.supported_versions {
            if !version.supported {
                continue;
            }
            match version.version.as_str() {
                "TLS 1.0" => self.ensure_vulnerability(
                    &mut result.vulnerabilities,
                    "Legacy protocol enabled (TLS 1.0)",
                    Severity::Critical,
                    "Server negotiates TLS 1.0 which is vulnerable to BEAST/POODLE/Lucky13. Disable TLS 1.0 or restrict to modern clients."
                        .to_string(),
                ),
                "TLS 1.1" => self.ensure_vulnerability(
                    &mut result.vulnerabilities,
                    "Legacy protocol enabled (TLS 1.1)",
                    Severity::High,
                    "Server negotiates TLS 1.1 which lacks modern security guarantees. Disable TLS 1.1 in favor of TLS 1.2+."
                        .to_string(),
                ),
                "SSLv2" | "SSLv3" => self.ensure_vulnerability(
                    &mut result.vulnerabilities,
                    &format!("Legacy protocol enabled ({})", version.version),
                    Severity::Critical,
                    format!(
                        "Server negotiates {} which is cryptographically broken. Disable immediately.",
                        version.version
                    ),
                ),
                _ => {}
            }
        }

        result.supported_ciphers = self.extract_cipher_info(&scan_results);

        let scanner_issues = scanner.check_vulnerabilities(&scan_results);
        result.vulnerabilities = scanner_issues
            .into_iter()
            .map(|issue| self.convert_issue(issue))
            .collect();

        let mut handshake_ja3 = None;
        let mut handshake_ja3_raw = None;
        let mut handshake_ja3s = None;
        let mut handshake_ja3s_raw = None;
        let mut handshake_fingerprints: Vec<String> = Vec::new();
        let mut handshake_pem: Vec<String> = Vec::new();

        let (tls12_supported, tls12_error, negotiated_cipher, certs_from_tls) =
            match Tls12Client::connect_with_timeout(host, port, self.timeout) {
                Ok(client) => {
                    handshake_ja3 = client.ja3().map(|s| s.to_string());
                    handshake_ja3_raw = client.ja3_raw().map(|s| s.to_string());
                    handshake_ja3s = client.ja3s().map(|s| s.to_string());
                    handshake_ja3s_raw = client.ja3s_raw().map(|s| s.to_string());
                    handshake_fingerprints = client.peer_certificate_fingerprints();
                    handshake_pem = client.certificate_chain_pem();

                    let cipher = client.selected_cipher_suite();
                    let certificates = client
                        .peer_certificates()
                        .iter()
                        .map(CertificateInfo::from)
                        .collect::<Vec<_>>();
                    (true, None, cipher, Some(certificates))
                }
                Err(err) => (false, Some(err.clone()), None, None),
            };

        if let Some(version_info) = result
            .supported_versions
            .iter_mut()
            .find(|v| v.version == "TLS 1.2")
        {
            version_info.supported = tls12_supported;
            if let Some(err) = tls12_error.clone() {
                version_info.error = Some(err.clone());
                if tls12_supported {
                    version_info.supported = false;
                }
            }
        }

        if tls12_supported {
            result.negotiated_version = Some("TLS 1.2".to_string());
            if let Some(code) = negotiated_cipher {
                let (name, strength) = cipher_meta(code);
                result.negotiated_cipher = Some(name.clone());
                result.negotiated_cipher_code = Some(code);
                result.negotiated_cipher_strength = Some(strength.clone());
                if !result
                    .supported_ciphers
                    .iter()
                    .any(|cipher| cipher.code == code)
                {
                    result.supported_ciphers.push(CipherInfo {
                        name,
                        code,
                        strength,
                    });
                }
            }
        } else if let Some(err) = tls12_error.clone() {
            result.vulnerabilities.push(Vulnerability {
                name: "TLS 1.2 Handshake Failed".to_string(),
                severity: Severity::High,
                description: format!(
                    "Unable to complete TLS 1.2 handshake: {}. Server may require legacy protocol.",
                    err
                ),
            });
        }

        if let Some(chain) = certs_from_tls {
            result.certificate_valid =
                validate_certificate_chain(&chain, &mut result.vulnerabilities);
            result.certificate_chain = chain;
        } else {
            let tls_client = TlsClient::new();
            if let Ok(chain) = tls_client.get_certificate_chain(host, port) {
                result.certificate_valid =
                    validate_certificate_chain(&chain, &mut result.vulnerabilities);
                result.certificate_chain = chain;
            }
        }

        result.ja3 = handshake_ja3;
        result.ja3_raw = handshake_ja3_raw;
        result.ja3s = handshake_ja3s;
        result.ja3s_raw = handshake_ja3s_raw;
        result.peer_fingerprints = handshake_fingerprints;
        result.certificate_chain_pem = handshake_pem;

        Ok(result)
    }

    fn convert_issue(&self, issue: SecurityIssue) -> Vulnerability {
        Vulnerability {
            name: issue.title,
            severity: match issue.severity {
                ScannerSeverity::Low => Severity::Low,
                ScannerSeverity::Medium => Severity::Medium,
                ScannerSeverity::High => Severity::High,
                ScannerSeverity::Critical => Severity::Critical,
            },
            description: issue.description,
        }
    }

    fn extract_cipher_info(
        &self,
        results: &[crate::modules::tls::scanner::ProtocolScanResult],
    ) -> Vec<CipherInfo> {
        let mut ciphers = Vec::new();
        for result in results {
            if !result.supported {
                continue;
            }
            if result.version != TlsVersion::TLS12 {
                continue;
            }
            for cipher in &result.supported_ciphers {
                ciphers.push(CipherInfo {
                    name: cipher.name.clone(),
                    code: cipher.id,
                    strength: map_cipher_strength(cipher.strength.clone()),
                });
            }
        }
        ciphers
    }

    fn ensure_vulnerability(
        &self,
        list: &mut Vec<Vulnerability>,
        name: &str,
        severity: Severity,
        description: String,
    ) {
        if list.iter().any(|v| v.name == name) {
            return;
        }
        list.push(Vulnerability {
            name: name.to_string(),
            severity,
            description,
        });
    }
}

impl Default for TlsAuditor {
    fn default() -> Self {
        Self::new()
    }
}

fn map_cipher_strength(strength: ScannerCipherStrength) -> CipherStrength {
    match strength {
        ScannerCipherStrength::Secure => CipherStrength::Strong,
        ScannerCipherStrength::Weak => CipherStrength::Medium,
        ScannerCipherStrength::Insecure | ScannerCipherStrength::NullCipher => CipherStrength::Weak,
    }
}

fn validate_certificate_chain(chain: &[CertificateInfo], vulns: &mut Vec<Vulnerability>) -> bool {
    if chain.is_empty() {
        vulns.push(Vulnerability {
            name: "No Certificate Presented".to_string(),
            severity: Severity::Critical,
            description: "Server did not present any certificate during the TLS handshake."
                .to_string(),
        });
        return false;
    }

    let mut overall_valid = true;

    for (index, cert) in chain.iter().enumerate() {
        if TlsClient::is_not_yet_valid(cert) {
            overall_valid = false;
            vulns.push(Vulnerability {
                name: format!("Certificate Not Yet Valid (#{} in chain)", index + 1),
                severity: Severity::Medium,
                description: format!(
                    "Certificate for '{}' is not valid until {}.",
                    cert.subject, cert.valid_from
                ),
            });
        }

        if TlsClient::is_expired(cert) {
            overall_valid = false;
            vulns.push(Vulnerability {
                name: format!("Expired Certificate (#{} in chain)", index + 1),
                severity: Severity::High,
                description: format!(
                    "Certificate for '{}' expired on {}.",
                    cert.subject, cert.valid_until
                ),
            });
        }

        if index + 1 < chain.len() {
            let next = &chain[index + 1];
            if cert.issuer != next.subject {
                overall_valid = false;
                vulns.push(Vulnerability {
                    name: "Broken Certificate Chain".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "Issuer '{}' does not match next certificate subject '{}'.",
                        cert.issuer, next.subject
                    ),
                });
            }
        } else if !TlsClient::is_self_signed(cert) {
            vulns.push(Vulnerability {
                name: "Untrusted Root".to_string(),
                severity: Severity::Medium,
                description: format!(
                    "Terminal certificate '{}' is not self-signed; root CA may be missing from the chain.",
                    cert.subject
                ),
            });
        }
    }

    if chain.len() == 1 {
        vulns.push(Vulnerability {
            name: "Single-certificate Chain".to_string(),
            severity: Severity::Low,
            description: "Server delivered only the leaf certificate; browsers may fail without intermediates.".to_string(),
        });
    }

    overall_valid
}

fn cipher_meta(code: u16) -> (String, CipherStrength) {
    match code {
        0xC02F => (
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
            CipherStrength::Strong,
        ),
        0xC030 => (
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
            CipherStrength::Strong,
        ),
        0x003C => (
            "TLS_RSA_WITH_AES_128_CBC_SHA256".to_string(),
            CipherStrength::Medium,
        ),
        0x003D => (
            "TLS_RSA_WITH_AES_256_CBC_SHA256".to_string(),
            CipherStrength::Medium,
        ),
        0x002F => (
            "TLS_RSA_WITH_AES_128_CBC_SHA".to_string(),
            CipherStrength::Weak,
        ),
        other => (format!("0x{:04X}", other), CipherStrength::Medium),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auditor_creation() {
        let auditor = TlsAuditor::new();
        assert_eq!(auditor.timeout.as_secs(), 10);
    }

    #[test]
    fn test_cipher_strength() {
        let weak = CipherStrength::Weak;
        let strong = CipherStrength::Strong;
        assert_ne!(weak, strong);
    }
}
