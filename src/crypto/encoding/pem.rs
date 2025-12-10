//! PEM (Privacy-Enhanced Mail) Format Handler
//!
//! Implements PEM encoding/decoding as specified in RFC 7468.
//!
//! # PEM Format
//!
//! ```text
//! -----BEGIN <LABEL>-----
//! <Base64-encoded data, typically 64 chars per line>
//! -----END <LABEL>-----
//! ```
//!
//! # Common Labels
//!
//! - `CERTIFICATE` - X.509 certificate
//! - `PRIVATE KEY` - PKCS#8 private key
//! - `RSA PRIVATE KEY` - PKCS#1 RSA private key
//! - `EC PRIVATE KEY` - SEC 1 EC private key
//! - `PUBLIC KEY` - PKIX public key
//! - `CERTIFICATE REQUEST` - PKCS#10 CSR
//! - `X509 CRL` - Certificate revocation list
//!
//! # Example
//!
//! ```rust
//! use redblue::crypto::encoding::pem::{PemBlock, PemLabel};
//!
//! let cert_data = vec![0x30, 0x82, ...]; // DER-encoded certificate
//! let pem = PemBlock::new(PemLabel::Certificate, cert_data);
//! let encoded = pem.encode();
//! ```

use super::base64::{base64_decode, base64_encode_wrapped};

/// Common PEM labels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemLabel {
    /// X.509 Certificate
    Certificate,
    /// PKCS#8 Private Key
    PrivateKey,
    /// PKCS#8 Encrypted Private Key
    EncryptedPrivateKey,
    /// RSA Private Key (PKCS#1)
    RsaPrivateKey,
    /// EC Private Key (SEC 1)
    EcPrivateKey,
    /// Public Key (PKIX)
    PublicKey,
    /// RSA Public Key (PKCS#1)
    RsaPublicKey,
    /// Certificate Request (PKCS#10 CSR)
    CertificateRequest,
    /// X.509 CRL
    X509Crl,
    /// Custom label
    Custom,
}

impl PemLabel {
    /// Get the label string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Certificate => "CERTIFICATE",
            Self::PrivateKey => "PRIVATE KEY",
            Self::EncryptedPrivateKey => "ENCRYPTED PRIVATE KEY",
            Self::RsaPrivateKey => "RSA PRIVATE KEY",
            Self::EcPrivateKey => "EC PRIVATE KEY",
            Self::PublicKey => "PUBLIC KEY",
            Self::RsaPublicKey => "RSA PUBLIC KEY",
            Self::CertificateRequest => "CERTIFICATE REQUEST",
            Self::X509Crl => "X509 CRL",
            Self::Custom => "UNKNOWN",
        }
    }

    /// Parse label from string
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CERTIFICATE" => Self::Certificate,
            "PRIVATE KEY" => Self::PrivateKey,
            "ENCRYPTED PRIVATE KEY" => Self::EncryptedPrivateKey,
            "RSA PRIVATE KEY" => Self::RsaPrivateKey,
            "EC PRIVATE KEY" => Self::EcPrivateKey,
            "PUBLIC KEY" => Self::PublicKey,
            "RSA PUBLIC KEY" => Self::RsaPublicKey,
            "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => Self::CertificateRequest,
            "X509 CRL" => Self::X509Crl,
            _ => Self::Custom,
        }
    }
}

/// PEM parsing/encoding errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PemError {
    /// Missing BEGIN marker
    MissingBegin,
    /// Missing END marker
    MissingEnd,
    /// Mismatched labels
    MismatchedLabels { begin: String, end: String },
    /// Invalid Base64 content
    InvalidBase64(String),
    /// No PEM blocks found
    NoPemFound,
}

impl std::fmt::Display for PemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingBegin => write!(f, "Missing PEM BEGIN marker"),
            Self::MissingEnd => write!(f, "Missing PEM END marker"),
            Self::MismatchedLabels { begin, end } => {
                write!(f, "Mismatched PEM labels: BEGIN {} / END {}", begin, end)
            }
            Self::InvalidBase64(msg) => write!(f, "Invalid Base64: {}", msg),
            Self::NoPemFound => write!(f, "No PEM block found"),
        }
    }
}

impl std::error::Error for PemError {}

/// A single PEM block
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    /// The label (e.g., "CERTIFICATE", "PRIVATE KEY")
    pub label: String,
    /// The decoded binary data
    pub data: Vec<u8>,
}

impl PemBlock {
    /// Create new PEM block with standard label
    pub fn new(label: PemLabel, data: Vec<u8>) -> Self {
        Self {
            label: label.as_str().to_string(),
            data,
        }
    }

    /// Create new PEM block with custom label
    pub fn with_label(label: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            label: label.into(),
            data,
        }
    }

    /// Get the label type
    pub fn label_type(&self) -> PemLabel {
        PemLabel::from_str(&self.label)
    }

    /// Check if this is a certificate
    pub fn is_certificate(&self) -> bool {
        self.label_type() == PemLabel::Certificate
    }

    /// Check if this is a private key
    pub fn is_private_key(&self) -> bool {
        matches!(
            self.label_type(),
            PemLabel::PrivateKey | PemLabel::RsaPrivateKey | PemLabel::EcPrivateKey
        )
    }

    /// Check if this is a public key
    pub fn is_public_key(&self) -> bool {
        matches!(
            self.label_type(),
            PemLabel::PublicKey | PemLabel::RsaPublicKey
        )
    }

    /// Encode to PEM format
    pub fn encode(&self) -> String {
        let mut result = String::new();
        result.push_str("-----BEGIN ");
        result.push_str(&self.label);
        result.push_str("-----\n");
        result.push_str(&base64_encode_wrapped(&self.data, 64));
        if !result.ends_with('\n') {
            result.push('\n');
        }
        result.push_str("-----END ");
        result.push_str(&self.label);
        result.push_str("-----\n");
        result
    }

    /// Decode single PEM block from string
    pub fn decode(pem: &str) -> Result<Self, PemError> {
        let blocks = decode_all(pem)?;
        blocks.into_iter().next().ok_or(PemError::NoPemFound)
    }

    /// Decode first PEM block of specific type
    pub fn decode_first(pem: &str, label: PemLabel) -> Result<Self, PemError> {
        let blocks = decode_all(pem)?;
        blocks
            .into_iter()
            .find(|b| b.label_type() == label)
            .ok_or(PemError::NoPemFound)
    }
}

/// Decode all PEM blocks from a string
pub fn decode_all(pem: &str) -> Result<Vec<PemBlock>, PemError> {
    let mut blocks = Vec::new();
    let mut remaining = pem;

    while let Some(begin_pos) = remaining.find("-----BEGIN ") {
        remaining = &remaining[begin_pos..];

        // Find the label
        let label_start = "-----BEGIN ".len();
        let label_end = remaining[label_start..]
            .find("-----")
            .ok_or(PemError::MissingBegin)?;
        let begin_label = remaining[label_start..label_start + label_end].trim();

        // Find content start (after the BEGIN line)
        let content_start = remaining
            .find('\n')
            .map(|p| p + 1)
            .unwrap_or(label_start + label_end + 5);

        // Find END marker
        let end_marker = format!("-----END {}-----", begin_label);
        let end_pos = remaining.find(&end_marker).ok_or(PemError::MissingEnd)?;

        // Extract Base64 content
        let base64_content: String = remaining[content_start..end_pos]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        // Decode Base64
        let data = base64_decode(&base64_content)
            .map_err(|e| PemError::InvalidBase64(e.to_string()))?;

        blocks.push(PemBlock {
            label: begin_label.to_string(),
            data,
        });

        // Move past this block
        remaining = &remaining[end_pos + end_marker.len()..];
    }

    if blocks.is_empty() && pem.contains("-----") {
        return Err(PemError::MissingBegin);
    }

    Ok(blocks)
}

/// Encode multiple PEM blocks
pub fn encode_all(blocks: &[PemBlock]) -> String {
    blocks.iter().map(|b| b.encode()).collect::<Vec<_>>().join("")
}

/// Quick check if string contains PEM data
pub fn is_pem(data: &str) -> bool {
    data.contains("-----BEGIN ")
}

/// Quick check if bytes look like DER (starts with SEQUENCE tag)
pub fn is_der(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == 0x30
}

/// Convert DER to PEM
pub fn der_to_pem(der: &[u8], label: PemLabel) -> String {
    PemBlock::new(label, der.to_vec()).encode()
}

/// Convert PEM to DER (first block)
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, PemError> {
    Ok(PemBlock::decode(pem)?.data)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDK7CDRcWG7Ih9VvJfFhJRF
YDvE2GQKH1dZ5aTfD0vEcxBNHEewfzEwIDALBgNVHQ8EBAMCAQYwDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAANBAEfTHR7XG2hNJM3p0h1aNxpRa9rY9VvX
Kn4lL1hBCdcL6+J3Bq9g5Z7Y2VFJ2H8HiHR7K3JL5A==
-----END CERTIFICATE-----
"#;

    #[test]
    fn test_decode_single() {
        let block = PemBlock::decode(TEST_CERT_PEM).unwrap();
        assert_eq!(block.label, "CERTIFICATE");
        assert!(block.is_certificate());
        assert!(!block.data.is_empty());
        // DER starts with SEQUENCE tag
        assert_eq!(block.data[0], 0x30);
    }

    #[test]
    fn test_encode_roundtrip() {
        let original = PemBlock::decode(TEST_CERT_PEM).unwrap();
        let encoded = original.encode();
        let decoded = PemBlock::decode(&encoded).unwrap();

        assert_eq!(original.label, decoded.label);
        assert_eq!(original.data, decoded.data);
    }

    #[test]
    fn test_decode_multiple() {
        let multi_pem = format!(
            "{}{}",
            TEST_CERT_PEM,
            r#"-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAyuwg0XFhuyIfVbyX
-----END PRIVATE KEY-----
"#
        );

        let blocks = decode_all(&multi_pem).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[1].label, "PRIVATE KEY");
    }

    #[test]
    fn test_label_types() {
        assert_eq!(PemLabel::from_str("CERTIFICATE"), PemLabel::Certificate);
        assert_eq!(PemLabel::from_str("PRIVATE KEY"), PemLabel::PrivateKey);
        assert_eq!(PemLabel::from_str("RSA PRIVATE KEY"), PemLabel::RsaPrivateKey);
        assert_eq!(PemLabel::from_str("PUBLIC KEY"), PemLabel::PublicKey);
        assert_eq!(PemLabel::from_str("unknown"), PemLabel::Custom);
    }

    #[test]
    fn test_is_pem() {
        assert!(is_pem(TEST_CERT_PEM));
        assert!(!is_pem("not pem data"));
    }

    #[test]
    fn test_missing_end() {
        let bad_pem = "-----BEGIN CERTIFICATE-----\nYWJj\n";
        let result = PemBlock::decode(bad_pem);
        assert!(matches!(result, Err(PemError::MissingEnd)));
    }

    #[test]
    fn test_der_pem_conversion() {
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x00]; // Simple SEQUENCE
        let pem = der_to_pem(&der, PemLabel::Certificate);
        let recovered = pem_to_der(&pem).unwrap();
        assert_eq!(der, recovered);
    }
}
