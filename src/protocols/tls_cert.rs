use super::tls::TlsClient as RawTlsClient;
/// TLS Certificate Information Module
///
/// Provides display-friendly certificate information structures and
/// a simple TLS client for fetching certificate chains.
///
/// This module bridges the low-level X.509 parsing with the high-level
/// TLS auditing functionality.
use super::x509::X509Certificate;
use std::time::Duration;

/// Display-friendly certificate information
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub version: u8,
    pub valid_from: String,
    pub valid_until: String,
    pub san: Vec<String>,
    pub is_self_signed: bool,
}

impl CertificateInfo {
    /// Create from X509Certificate reference
    pub fn from_x509(cert: &X509Certificate) -> Self {
        let subject = format_dn(&cert.subject);
        let issuer = format_dn(&cert.issuer);
        let is_self_signed = cert.subject == cert.issuer;

        // Extract serial number as hex string
        let serial_number = cert
            .serial_number
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");

        // Format signature algorithm
        let signature_algorithm = oid_to_name(&cert.signature_algorithm.algorithm);

        // Format public key algorithm
        let public_key_algorithm = oid_to_name(&cert.subject_public_key_info.algorithm.algorithm);

        // Format validity dates (Validity has String fields)
        let valid_from = cert.validity.not_before.clone();
        let valid_until = cert.validity.not_after.clone();

        // Extract SANs from extensions
        let san = extract_sans(&cert.extensions);

        Self {
            subject,
            issuer,
            serial_number,
            signature_algorithm,
            public_key_algorithm,
            version: cert.version,
            valid_from,
            valid_until,
            san,
            is_self_signed,
        }
    }
}

impl From<&X509Certificate> for CertificateInfo {
    fn from(cert: &X509Certificate) -> Self {
        CertificateInfo::from_x509(cert)
    }
}

/// Simple TLS client for fetching certificate chains
pub struct TlsClient {
    timeout: Duration,
}

impl TlsClient {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Get certificate chain from a host
    pub fn get_certificate_chain(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Vec<CertificateInfo>, String> {
        // Use the raw TLS client to get X509 certificates
        let certs = RawTlsClient::get_certificates(host, port)?;
        Ok(certs.iter().map(CertificateInfo::from).collect())
    }

    /// Check if a certificate is not yet valid
    pub fn is_not_yet_valid(_cert: &CertificateInfo) -> bool {
        // Real implementation would parse valid_from date and compare with current time
        // For now, assume certificates are valid
        false
    }

    /// Check if a certificate is expired
    pub fn is_expired(_cert: &CertificateInfo) -> bool {
        // Real implementation would parse valid_until date and compare with current time
        // For now, assume certificates are not expired
        false
    }

    /// Check if a certificate is self-signed
    pub fn is_self_signed(cert: &CertificateInfo) -> bool {
        cert.is_self_signed
    }
}

impl Default for TlsClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a Distinguished Name for display
fn format_dn(dn: &super::x509::DistinguishedName) -> String {
    let mut parts = Vec::new();

    if let Some(cn) = &dn.common_name {
        parts.push(format!("CN={}", cn));
    }
    if let Some(o) = &dn.organization {
        parts.push(format!("O={}", o));
    }
    if let Some(ou) = &dn.organizational_unit {
        parts.push(format!("OU={}", ou));
    }
    if let Some(l) = &dn.locality {
        parts.push(format!("L={}", l));
    }
    if let Some(st) = &dn.state {
        parts.push(format!("ST={}", st));
    }
    if let Some(c) = &dn.country {
        parts.push(format!("C={}", c));
    }

    if parts.is_empty() {
        "Unknown".to_string()
    } else {
        parts.join(", ")
    }
}

/// Convert OID to human-readable name
fn oid_to_name(oid: &str) -> String {
    match oid {
        // Signature algorithms
        "1.2.840.113549.1.1.11" => "SHA256withRSA".to_string(),
        "1.2.840.113549.1.1.12" => "SHA384withRSA".to_string(),
        "1.2.840.113549.1.1.13" => "SHA512withRSA".to_string(),
        "1.2.840.113549.1.1.5" => "SHA1withRSA".to_string(),
        "1.2.840.113549.1.1.4" => "MD5withRSA".to_string(),
        "1.2.840.10045.4.3.2" => "SHA256withECDSA".to_string(),
        "1.2.840.10045.4.3.3" => "SHA384withECDSA".to_string(),
        "1.2.840.10045.4.3.4" => "SHA512withECDSA".to_string(),
        // Public key algorithms
        "1.2.840.113549.1.1.1" => "RSA".to_string(),
        "1.2.840.10045.2.1" => "EC".to_string(),
        "1.3.101.110" => "X25519".to_string(),
        "1.3.101.112" => "Ed25519".to_string(),
        // Return OID if unknown
        _ => oid.to_string(),
    }
}

/// Format validity time for display
fn format_validity(validity: &str) -> String {
    validity.to_string()
}

/// Extract Subject Alternative Names from extensions
fn extract_sans(extensions: &[super::x509::Extension]) -> Vec<String> {
    let mut sans = Vec::new();

    for ext in extensions {
        // SAN extension OID: 2.5.29.17
        if ext.oid == "2.5.29.17" {
            // Parse the SAN extension value
            // This is a simplified extraction - real SANs are ASN.1 encoded
            if let Some(parsed_sans) = parse_san_extension(&ext.value) {
                sans.extend(parsed_sans);
            }
        }
    }

    sans
}

/// Parse SAN extension value (simplified)
fn parse_san_extension(data: &[u8]) -> Option<Vec<String>> {
    let mut sans = Vec::new();
    let mut pos = 0;

    // Skip SEQUENCE tag if present
    if pos < data.len() && data[pos] == 0x30 {
        pos += 1;
        if pos < data.len() {
            // Skip length
            if data[pos] & 0x80 == 0 {
                pos += 1;
            } else {
                let len_bytes = (data[pos] & 0x7f) as usize;
                pos += 1 + len_bytes;
            }
        }
    }

    // Parse each SAN entry
    while pos < data.len() {
        let tag = data[pos];
        pos += 1;

        if pos >= data.len() {
            break;
        }

        let len = if data[pos] & 0x80 == 0 {
            let l = data[pos] as usize;
            pos += 1;
            l
        } else {
            let len_bytes = (data[pos] & 0x7f) as usize;
            pos += 1;
            if pos + len_bytes > data.len() {
                break;
            }
            let mut l = 0usize;
            for i in 0..len_bytes {
                l = (l << 8) | data[pos + i] as usize;
            }
            pos += len_bytes;
            l
        };

        if pos + len > data.len() {
            break;
        }

        let value = &data[pos..pos + len];
        pos += len;

        match tag {
            0x82 => {
                // dNSName
                if let Ok(s) = std::str::from_utf8(value) {
                    sans.push(s.to_string());
                }
            }
            0x87 => {
                // iPAddress
                if len == 4 {
                    sans.push(format!(
                        "{}.{}.{}.{}",
                        value[0], value[1], value[2], value[3]
                    ));
                } else if len == 16 {
                    // IPv6
                    let parts: Vec<String> = (0..8)
                        .map(|i| {
                            format!("{:x}", u16::from_be_bytes([value[i * 2], value[i * 2 + 1]]))
                        })
                        .collect();
                    sans.push(parts.join(":"));
                }
            }
            _ => {
                // Skip other types (email, URI, etc.)
            }
        }
    }

    if sans.is_empty() {
        None
    } else {
        Some(sans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_to_name() {
        assert_eq!(oid_to_name("1.2.840.113549.1.1.11"), "SHA256withRSA");
        assert_eq!(oid_to_name("1.2.840.113549.1.1.1"), "RSA");
        assert_eq!(oid_to_name("1.2.840.10045.2.1"), "EC");
        assert_eq!(oid_to_name("unknown.oid"), "unknown.oid");
    }
}
