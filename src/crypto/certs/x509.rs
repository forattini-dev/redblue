//! X.509 Certificate Parsing and Generation
//!
//! Implements X.509 v3 certificates as specified in RFC 5280.
//!
//! # Certificate Structure
//!
//! ```text
//! Certificate  ::=  SEQUENCE  {
//!     tbsCertificate       TBSCertificate,
//!     signatureAlgorithm   AlgorithmIdentifier,
//!     signatureValue       BIT STRING
//! }
//!
//! TBSCertificate  ::=  SEQUENCE  {
//!     version         [0]  EXPLICIT Version DEFAULT v1,
//!     serialNumber         CertificateSerialNumber,
//!     signature            AlgorithmIdentifier,
//!     issuer               Name,
//!     validity             Validity,
//!     subject              Name,
//!     subjectPublicKeyInfo SubjectPublicKeyInfo,
//!     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//!     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//!     extensions      [3]  EXPLICIT Extensions OPTIONAL
//! }
//! ```

use crate::crypto::encoding::asn1::{Asn1Error, Asn1Value};
use crate::crypto::encoding::oid::Oid;
use crate::crypto::encoding::pem::{PemBlock, PemError};
use std::net::IpAddr;

/// X.509 Certificate
#[derive(Debug, Clone)]
pub struct Certificate {
    /// To-Be-Signed certificate data
    pub tbs_certificate: TbsCertificate,
    /// Signature algorithm
    pub signature_algorithm: AlgorithmIdentifier,
    /// Signature value (DER-encoded)
    pub signature: Vec<u8>,
    /// Original DER encoding (for verification)
    raw_der: Vec<u8>,
}

/// TBS (To-Be-Signed) Certificate
#[derive(Debug, Clone)]
pub struct TbsCertificate {
    /// Certificate version (0 = v1, 1 = v2, 2 = v3)
    pub version: u8,
    /// Serial number (big-endian bytes)
    pub serial_number: Vec<u8>,
    /// Signature algorithm
    pub signature: AlgorithmIdentifier,
    /// Issuer distinguished name
    pub issuer: Name,
    /// Validity period
    pub validity: Validity,
    /// Subject distinguished name
    pub subject: Name,
    /// Subject public key info
    pub subject_public_key_info: SubjectPublicKeyInfo,
    /// Extensions (X.509 v3)
    pub extensions: Vec<Extension>,
    /// Raw TBS DER (for signing)
    raw_tbs: Vec<u8>,
}

/// Algorithm identifier with optional parameters
#[derive(Debug, Clone, PartialEq)]
pub struct AlgorithmIdentifier {
    /// Algorithm OID
    pub algorithm: Oid,
    /// Optional parameters
    pub parameters: Option<Vec<u8>>,
}

/// Distinguished Name (sequence of RDNs)
#[derive(Debug, Clone, PartialEq)]
pub struct Name {
    /// Relative Distinguished Names
    pub rdns: Vec<RelativeDistinguishedName>,
}

/// Relative Distinguished Name (set of attribute-value pairs)
#[derive(Debug, Clone, PartialEq)]
pub struct RelativeDistinguishedName {
    pub attributes: Vec<AttributeTypeAndValue>,
}

/// Attribute type and value pair
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeTypeAndValue {
    pub oid: Oid,
    pub value: String,
}

/// Certificate validity period
#[derive(Debug, Clone)]
pub struct Validity {
    /// Not valid before (Unix timestamp)
    pub not_before: i64,
    /// Not valid after (Unix timestamp)
    pub not_after: i64,
}

/// Subject Public Key Info
#[derive(Debug, Clone)]
pub struct SubjectPublicKeyInfo {
    /// Algorithm identifier
    pub algorithm: AlgorithmIdentifier,
    /// Public key bits
    pub public_key: Vec<u8>,
}

/// X.509 v3 Extension
#[derive(Debug, Clone)]
pub struct Extension {
    /// Extension OID
    pub oid: Oid,
    /// Critical flag
    pub critical: bool,
    /// Extension value (DER-encoded)
    pub value: Vec<u8>,
}

/// Subject Alternative Name types
#[derive(Debug, Clone, PartialEq)]
pub enum GeneralName {
    DnsName(String),
    IpAddress(IpAddr),
    Email(String),
    Uri(String),
}

/// Certificate parsing/generation errors
#[derive(Debug)]
pub enum CertError {
    Asn1(Asn1Error),
    Pem(PemError),
    InvalidFormat(String),
    InvalidSignature,
    Expired,
    NotYetValid,
    InvalidHostname,
    MissingExtension(String),
}

impl From<Asn1Error> for CertError {
    fn from(e: Asn1Error) -> Self {
        CertError::Asn1(e)
    }
}

impl From<PemError> for CertError {
    fn from(e: PemError) -> Self {
        CertError::Pem(e)
    }
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertError::Asn1(e) => write!(f, "ASN.1 error: {:?}", e),
            CertError::Pem(e) => write!(f, "PEM error: {:?}", e),
            CertError::InvalidFormat(s) => write!(f, "Invalid format: {}", s),
            CertError::InvalidSignature => write!(f, "Invalid signature"),
            CertError::Expired => write!(f, "Certificate expired"),
            CertError::NotYetValid => write!(f, "Certificate not yet valid"),
            CertError::InvalidHostname => write!(f, "Invalid hostname"),
            CertError::MissingExtension(s) => write!(f, "Missing extension: {}", s),
        }
    }
}

impl Certificate {
    /// Parse certificate from PEM format
    pub fn from_pem(pem: &str) -> Result<Self, CertError> {
        let block = PemBlock::decode(pem)?;
        if block.label != "CERTIFICATE" {
            return Err(CertError::InvalidFormat(format!(
                "Expected CERTIFICATE, got {}",
                block.label
            )));
        }
        Self::from_der(&block.data)
    }

    /// Parse certificate from DER format
    pub fn from_der(der: &[u8]) -> Result<Self, CertError> {
        let (value, _) = Asn1Value::decode_der(der)?;

        let seq = match value {
            Asn1Value::Sequence(s) => s,
            _ => return Err(CertError::InvalidFormat("Expected SEQUENCE".into())),
        };

        if seq.len() < 3 {
            return Err(CertError::InvalidFormat(
                "Certificate SEQUENCE too short".into(),
            ));
        }

        // Parse TBSCertificate
        let tbs_der = seq[0].encode_der();
        let tbs_certificate = Self::parse_tbs_certificate(&seq[0], tbs_der.clone())?;

        // Parse signature algorithm
        let signature_algorithm = Self::parse_algorithm_identifier(&seq[1])?;

        // Parse signature value
        let signature = match &seq[2] {
            Asn1Value::BitString(data, _unused) => data.clone(),
            _ => {
                return Err(CertError::InvalidFormat(
                    "Expected BIT STRING for signature".into(),
                ))
            }
        };

        Ok(Certificate {
            tbs_certificate,
            signature_algorithm,
            signature,
            raw_der: der.to_vec(),
        })
    }

    /// Export certificate to PEM format
    pub fn to_pem(&self) -> String {
        let block = PemBlock {
            label: "CERTIFICATE".to_string(),
            data: self.raw_der.clone(),
        };
        block.encode()
    }

    /// Export certificate to DER format
    pub fn to_der(&self) -> Vec<u8> {
        self.raw_der.clone()
    }

    /// Get subject common name (CN)
    pub fn subject_cn(&self) -> Option<&str> {
        self.tbs_certificate.subject.get_cn()
    }

    /// Get issuer common name (CN)
    pub fn issuer_cn(&self) -> Option<&str> {
        self.tbs_certificate.issuer.get_cn()
    }

    /// Get serial number as hex string
    pub fn serial_hex(&self) -> String {
        self.tbs_certificate
            .serial_number
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Get Subject Alternative Names (DNS)
    pub fn san_dns_names(&self) -> Vec<String> {
        self.get_san()
            .into_iter()
            .filter_map(|gn| match gn {
                GeneralName::DnsName(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    /// Get Subject Alternative Names (IP)
    pub fn san_ip_addresses(&self) -> Vec<IpAddr> {
        self.get_san()
            .into_iter()
            .filter_map(|gn| match gn {
                GeneralName::IpAddress(ip) => Some(ip),
                _ => None,
            })
            .collect()
    }

    /// Get all Subject Alternative Names
    pub fn get_san(&self) -> Vec<GeneralName> {
        // OID for Subject Alternative Name: 2.5.29.17
        let san_oid = Oid::new(&[2, 5, 29, 17]);

        for ext in &self.tbs_certificate.extensions {
            if ext.oid == san_oid {
                return Self::parse_san_extension(&ext.value);
            }
        }
        Vec::new()
    }

    /// Parse SAN extension value
    fn parse_san_extension(data: &[u8]) -> Vec<GeneralName> {
        let mut names = Vec::new();

        if let Ok((value, _)) = Asn1Value::decode_der(data) {
            if let Asn1Value::Sequence(items) = value {
                for item in items {
                    if let Asn1Value::ContextSpecific { tag, value, .. } = item {
                        match tag {
                            2 => {
                                // dNSName [2] IA5String
                                if let Asn1Value::Raw(_, data) = value.as_ref() {
                                    if let Ok(s) = String::from_utf8(data.clone()) {
                                        names.push(GeneralName::DnsName(s));
                                    }
                                }
                            }
                            7 => {
                                // iPAddress [7] OCTET STRING
                                if let Asn1Value::Raw(_, data) = value.as_ref() {
                                    if data.len() == 4 {
                                        let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                                            data[0], data[1], data[2], data[3],
                                        ));
                                        names.push(GeneralName::IpAddress(ip));
                                    } else if data.len() == 16 {
                                        let mut octets = [0u8; 16];
                                        octets.copy_from_slice(data);
                                        let ip = IpAddr::V6(std::net::Ipv6Addr::from(octets));
                                        names.push(GeneralName::IpAddress(ip));
                                    }
                                }
                            }
                            1 => {
                                // rfc822Name [1] IA5String (email)
                                if let Asn1Value::Raw(_, data) = value.as_ref() {
                                    if let Ok(s) = String::from_utf8(data.clone()) {
                                        names.push(GeneralName::Email(s));
                                    }
                                }
                            }
                            6 => {
                                // uniformResourceIdentifier [6] IA5String
                                if let Asn1Value::Raw(_, data) = value.as_ref() {
                                    if let Ok(s) = String::from_utf8(data.clone()) {
                                        names.push(GeneralName::Uri(s));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        names
    }

    /// Check if certificate is valid for hostname
    pub fn is_valid_for_hostname(&self, hostname: &str) -> bool {
        let hostname_lower = hostname.to_lowercase();

        // Check SANs first (preferred)
        for name in self.san_dns_names() {
            if Self::matches_hostname(&name.to_lowercase(), &hostname_lower) {
                return true;
            }
        }

        // Fall back to CN if no SANs
        if self.san_dns_names().is_empty() {
            if let Some(cn) = self.subject_cn() {
                if Self::matches_hostname(&cn.to_lowercase(), &hostname_lower) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if pattern matches hostname (with wildcard support)
    fn matches_hostname(pattern: &str, hostname: &str) -> bool {
        if pattern == hostname {
            return true;
        }

        // Wildcard matching (*.example.com)
        if let Some(suffix) = pattern.strip_prefix("*.") {
            // Hostname must have at least one label before the suffix
            if let Some(pos) = hostname.find('.') {
                let host_suffix = &hostname[pos + 1..];
                return host_suffix == suffix;
            }
        }

        false
    }

    /// Check if certificate is self-signed
    pub fn is_self_signed(&self) -> bool {
        self.tbs_certificate.subject == self.tbs_certificate.issuer
    }

    /// Check if certificate is a CA
    pub fn is_ca(&self) -> bool {
        // OID for Basic Constraints: 2.5.29.19
        let bc_oid = Oid::new(&[2, 5, 29, 19]);

        for ext in &self.tbs_certificate.extensions {
            if ext.oid == bc_oid {
                // Parse Basic Constraints
                if let Ok((value, _)) = Asn1Value::decode_der(&ext.value) {
                    if let Asn1Value::Sequence(items) = value {
                        if !items.is_empty() {
                            if let Asn1Value::Boolean(is_ca) = items[0] {
                                return is_ca;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if certificate is currently valid
    pub fn is_valid_now(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        now >= self.tbs_certificate.validity.not_before
            && now <= self.tbs_certificate.validity.not_after
    }

    /// Get certificate fingerprint (SHA-256)
    pub fn fingerprint_sha256(&self) -> String {
        use crate::crypto::sha256::sha256;
        let hash = sha256(&self.raw_der);
        hash.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Parse TBSCertificate from ASN.1
    fn parse_tbs_certificate(
        value: &Asn1Value,
        raw_tbs: Vec<u8>,
    ) -> Result<TbsCertificate, CertError> {
        let seq = match value {
            Asn1Value::Sequence(s) => s,
            _ => return Err(CertError::InvalidFormat("TBS: Expected SEQUENCE".into())),
        };

        let mut idx = 0;

        // Version (optional, explicit tag [0])
        let version = if let Some(Asn1Value::ContextSpecific { tag: 0, value, .. }) = seq.get(idx) {
            idx += 1;
            match value.as_ref() {
                Asn1Value::Integer(bytes) => {
                    if bytes.is_empty() {
                        0
                    } else {
                        bytes[0]
                    }
                }
                _ => 0,
            }
        } else {
            0 // Default to v1
        };

        // Serial number
        let serial_number = match seq.get(idx) {
            Some(Asn1Value::Integer(bytes)) => {
                idx += 1;
                bytes.clone()
            }
            _ => return Err(CertError::InvalidFormat("Missing serial number".into())),
        };

        // Signature algorithm
        let signature = Self::parse_algorithm_identifier(
            seq.get(idx)
                .ok_or_else(|| CertError::InvalidFormat("Missing signature algorithm".into()))?,
        )?;
        idx += 1;

        // Issuer
        let issuer = Self::parse_name(
            seq.get(idx)
                .ok_or_else(|| CertError::InvalidFormat("Missing issuer".into()))?,
        )?;
        idx += 1;

        // Validity
        let validity = Self::parse_validity(
            seq.get(idx)
                .ok_or_else(|| CertError::InvalidFormat("Missing validity".into()))?,
        )?;
        idx += 1;

        // Subject
        let subject = Self::parse_name(
            seq.get(idx)
                .ok_or_else(|| CertError::InvalidFormat("Missing subject".into()))?,
        )?;
        idx += 1;

        // Subject Public Key Info
        let subject_public_key_info = Self::parse_spki(
            seq.get(idx)
                .ok_or_else(|| CertError::InvalidFormat("Missing SPKI".into()))?,
        )?;
        idx += 1;

        // Extensions (optional, explicit tag [3])
        let mut extensions = Vec::new();
        while idx < seq.len() {
            if let Asn1Value::ContextSpecific { tag: 3, value, .. } = &seq[idx] {
                if let Asn1Value::Sequence(exts) = value.as_ref() {
                    for ext_value in exts {
                        if let Ok(ext) = Self::parse_extension(ext_value) {
                            extensions.push(ext);
                        }
                    }
                }
            }
            idx += 1;
        }

        Ok(TbsCertificate {
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            extensions,
            raw_tbs,
        })
    }

    /// Parse AlgorithmIdentifier
    fn parse_algorithm_identifier(value: &Asn1Value) -> Result<AlgorithmIdentifier, CertError> {
        let seq = match value {
            Asn1Value::Sequence(s) => s,
            _ => return Err(CertError::InvalidFormat("AlgId: Expected SEQUENCE".into())),
        };

        let algorithm = match seq.first() {
            Some(Asn1Value::ObjectIdentifier(oid)) => Oid::new(oid),
            _ => return Err(CertError::InvalidFormat("AlgId: Missing OID".into())),
        };

        let parameters = seq.get(1).map(|v| v.encode_der());

        Ok(AlgorithmIdentifier {
            algorithm,
            parameters,
        })
    }

    /// Parse Name (Distinguished Name)
    fn parse_name(value: &Asn1Value) -> Result<Name, CertError> {
        let seq = match value {
            Asn1Value::Sequence(s) => s,
            _ => return Err(CertError::InvalidFormat("Name: Expected SEQUENCE".into())),
        };

        let mut rdns = Vec::new();
        for rdn_value in seq {
            if let Asn1Value::Set(attrs) = rdn_value {
                let mut attributes = Vec::new();
                for attr_value in attrs {
                    if let Asn1Value::Sequence(attr_seq) = attr_value {
                        if attr_seq.len() >= 2 {
                            if let Asn1Value::ObjectIdentifier(oid) = &attr_seq[0] {
                                let value_str = match &attr_seq[1] {
                                    Asn1Value::Utf8String(s) => s.clone(),
                                    Asn1Value::PrintableString(s) => s.clone(),
                                    Asn1Value::Ia5String(s) => s.clone(),
                                    _ => continue,
                                };
                                attributes.push(AttributeTypeAndValue {
                                    oid: Oid::new(oid),
                                    value: value_str,
                                });
                            }
                        }
                    }
                }
                rdns.push(RelativeDistinguishedName { attributes });
            }
        }

        Ok(Name { rdns })
    }

    /// Parse Validity
    fn parse_validity(value: &Asn1Value) -> Result<Validity, CertError> {
        let seq = match value {
            Asn1Value::Sequence(s) => s,
            _ => {
                return Err(CertError::InvalidFormat(
                    "Validity: Expected SEQUENCE".into(),
                ))
            }
        };

        if seq.len() < 2 {
            return Err(CertError::InvalidFormat("Validity: Need 2 times".into()));
        }

        let not_before = Self::parse_time(&seq[0])?;
        let not_after = Self::parse_time(&seq[1])?;

        Ok(Validity {
            not_before,
            not_after,
        })
    }

    /// Parse UTCTime or GeneralizedTime to Unix timestamp
    fn parse_time(value: &Asn1Value) -> Result<i64, CertError> {
        match value {
            Asn1Value::UtcTime(s) => Self::parse_utc_time(s),
            Asn1Value::GeneralizedTime(s) => Self::parse_generalized_time(s),
            _ => Err(CertError::InvalidFormat("Expected time value".into())),
        }
    }

    /// Parse UTCTime string (YYMMDDHHMMSSZ) to Unix timestamp
    fn parse_utc_time(s: &str) -> Result<i64, CertError> {
        // Format: YYMMDDHHMMSSZ
        if s.len() < 12 {
            return Err(CertError::InvalidFormat("UTCTime too short".into()));
        }

        let year: i32 = s[0..2]
            .parse()
            .map_err(|_| CertError::InvalidFormat("Invalid year".into()))?;
        let month: u32 = s[2..4]
            .parse()
            .map_err(|_| CertError::InvalidFormat("Invalid month".into()))?;
        let day: u32 = s[4..6]
            .parse()
            .map_err(|_| CertError::InvalidFormat("Invalid day".into()))?;
        let hour: u32 = s[6..8]
            .parse()
            .map_err(|_| CertError::InvalidFormat("Invalid hour".into()))?;
        let min: u32 = s[8..10]
            .parse()
            .map_err(|_| CertError::InvalidFormat("Invalid minute".into()))?;
        let sec: u32 = s[10..12]
            .parse()
            .map_err(|_| CertError::InvalidFormat("Invalid second".into()))?;

        // RFC 5280: YY >= 50 means 19YY, YY < 50 means 20YY
        let full_year = if year >= 50 { 1900 + year } else { 2000 + year };

        Self::datetime_to_timestamp(full_year, month, day, hour, min, sec)
    }

    /// Parse GeneralizedTime string (YYYYMMDDHHMMSSZ) to Unix timestamp
    fn parse_generalized_time(s: &str) -> Result<i64, CertError> {
        // Format: YYYYMMDDHHMMSSZ
        if s.len() < 14 {
            return Err(CertError::InvalidFormat("GeneralizedTime too short".into()));
        }

        let year: i32 = s[0..4]
            .parse()
            .map_err(|_| CertError::InvalidFormat("Invalid year".into()))?;
        let month: u32 = s[4..6]
            .parse()
            .map_err(|_| CertError::InvalidFormat("Invalid month".into()))?;
        let day: u32 = s[6..8]
            .parse()
            .map_err(|_| CertError::InvalidFormat("Invalid day".into()))?;
        let hour: u32 = s[8..10]
            .parse()
            .map_err(|_| CertError::InvalidFormat("Invalid hour".into()))?;
        let min: u32 = s[10..12]
            .parse()
            .map_err(|_| CertError::InvalidFormat("Invalid minute".into()))?;
        let sec: u32 = s[12..14]
            .parse()
            .map_err(|_| CertError::InvalidFormat("Invalid second".into()))?;

        Self::datetime_to_timestamp(year, month, day, hour, min, sec)
    }

    /// Convert datetime components to Unix timestamp
    fn datetime_to_timestamp(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        min: u32,
        sec: u32,
    ) -> Result<i64, CertError> {
        // Days in each month (non-leap year)
        const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

        fn is_leap_year(y: i32) -> bool {
            (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
        }

        // Calculate days since Unix epoch (1970-01-01)
        let mut days: i64 = 0;

        // Add days for complete years
        for y in 1970..year {
            days += if is_leap_year(y) { 366 } else { 365 };
        }

        // Add days for complete months in the current year
        for m in 1..month {
            days += DAYS_IN_MONTH[(m - 1) as usize] as i64;
            if m == 2 && is_leap_year(year) {
                days += 1;
            }
        }

        // Add days in current month
        days += (day - 1) as i64;

        // Convert to seconds and add time components
        let timestamp = days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64);

        Ok(timestamp)
    }

    /// Parse SubjectPublicKeyInfo
    fn parse_spki(value: &Asn1Value) -> Result<SubjectPublicKeyInfo, CertError> {
        let seq = match value {
            Asn1Value::Sequence(s) => s,
            _ => return Err(CertError::InvalidFormat("SPKI: Expected SEQUENCE".into())),
        };

        if seq.len() < 2 {
            return Err(CertError::InvalidFormat(
                "SPKI: Need algorithm and key".into(),
            ));
        }

        let algorithm = Self::parse_algorithm_identifier(&seq[0])?;

        let public_key = match &seq[1] {
            Asn1Value::BitString(data, _) => data.clone(),
            _ => return Err(CertError::InvalidFormat("SPKI: Expected BIT STRING".into())),
        };

        Ok(SubjectPublicKeyInfo {
            algorithm,
            public_key,
        })
    }

    /// Parse Extension
    fn parse_extension(value: &Asn1Value) -> Result<Extension, CertError> {
        let seq = match value {
            Asn1Value::Sequence(s) => s,
            _ => return Err(CertError::InvalidFormat("Ext: Expected SEQUENCE".into())),
        };

        if seq.is_empty() {
            return Err(CertError::InvalidFormat("Ext: Empty sequence".into()));
        }

        let oid = match &seq[0] {
            Asn1Value::ObjectIdentifier(o) => Oid::new(o),
            _ => return Err(CertError::InvalidFormat("Ext: Missing OID".into())),
        };

        let mut idx = 1;
        let critical = if let Some(Asn1Value::Boolean(b)) = seq.get(idx) {
            idx += 1;
            *b
        } else {
            false
        };

        let value = match seq.get(idx) {
            Some(Asn1Value::OctetString(data)) => data.clone(),
            _ => return Err(CertError::InvalidFormat("Ext: Missing value".into())),
        };

        Ok(Extension {
            oid,
            critical,
            value,
        })
    }
}

impl Name {
    /// Create new Name from string (e.g., "CN=example.com,O=Example Inc")
    pub fn from_string(s: &str) -> Result<Self, CertError> {
        let mut rdns = Vec::new();

        for part in s.split(',') {
            let part = part.trim();
            if let Some(eq_pos) = part.find('=') {
                let attr_type = &part[..eq_pos].trim().to_uppercase();
                let attr_value = part[eq_pos + 1..].trim().to_string();

                let oid = match attr_type.as_str() {
                    "CN" => Oid::common_name(),
                    "O" => Oid::organization(),
                    "OU" => Oid::organizational_unit(),
                    "C" => Oid::country(),
                    "ST" | "S" => Oid::state(),
                    "L" => Oid::locality(),
                    "E" | "EMAIL" => Oid::email(),
                    _ => continue,
                };

                rdns.push(RelativeDistinguishedName {
                    attributes: vec![AttributeTypeAndValue {
                        oid,
                        value: attr_value,
                    }],
                });
            }
        }

        if rdns.is_empty() {
            return Err(CertError::InvalidFormat("Empty name".into()));
        }

        Ok(Name { rdns })
    }

    /// Get Common Name (CN)
    pub fn get_cn(&self) -> Option<&str> {
        for rdn in &self.rdns {
            for attr in &rdn.attributes {
                if attr.oid == Oid::common_name() {
                    return Some(&attr.value);
                }
            }
        }
        None
    }

    /// Get Organization (O)
    pub fn get_organization(&self) -> Option<&str> {
        for rdn in &self.rdns {
            for attr in &rdn.attributes {
                if attr.oid == Oid::organization() {
                    return Some(&attr.value);
                }
            }
        }
        None
    }

    /// Convert to string representation
    pub fn to_string_repr(&self) -> String {
        self.rdns
            .iter()
            .flat_map(|rdn| &rdn.attributes)
            .map(|attr| {
                let type_name = match &attr.oid {
                    o if *o == Oid::common_name() => "CN",
                    o if *o == Oid::organization() => "O",
                    o if *o == Oid::organizational_unit() => "OU",
                    o if *o == Oid::country() => "C",
                    o if *o == Oid::state() => "ST",
                    o if *o == Oid::locality() => "L",
                    _ => "?",
                };
                format!("{}={}", type_name, attr.value)
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Encode to ASN.1 DER
    pub fn to_der(&self) -> Vec<u8> {
        let rdns: Vec<Asn1Value> = self
            .rdns
            .iter()
            .map(|rdn| {
                let attrs: Vec<Asn1Value> = rdn
                    .attributes
                    .iter()
                    .map(|attr| {
                        Asn1Value::Sequence(vec![
                            attr.oid.to_asn1(),
                            Asn1Value::Utf8String(attr.value.clone()),
                        ])
                    })
                    .collect();
                Asn1Value::Set(attrs)
            })
            .collect();

        Asn1Value::Sequence(rdns).encode_der()
    }
}

impl Validity {
    /// Create validity period from now + days
    pub fn from_days(days: u32) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Validity {
            not_before: now,
            not_after: now + (days as i64 * 24 * 60 * 60),
        }
    }

    /// Get remaining days until expiration
    pub fn days_until_expiry(&self) -> i64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        (self.not_after - now) / (24 * 60 * 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_from_string() {
        let name = Name::from_string("CN=example.com, O=Example Inc, C=US").unwrap();
        assert_eq!(name.get_cn(), Some("example.com"));
        assert_eq!(name.get_organization(), Some("Example Inc"));
    }

    #[test]
    fn test_hostname_matching() {
        assert!(Certificate::matches_hostname("example.com", "example.com"));
        assert!(Certificate::matches_hostname(
            "*.example.com",
            "www.example.com"
        ));
        assert!(Certificate::matches_hostname(
            "*.example.com",
            "api.example.com"
        ));
        assert!(!Certificate::matches_hostname(
            "*.example.com",
            "example.com"
        ));
        assert!(!Certificate::matches_hostname(
            "*.example.com",
            "sub.www.example.com"
        ));
    }

    #[test]
    fn test_validity_from_days() {
        let validity = Validity::from_days(365);
        assert!(validity.days_until_expiry() >= 364);
        assert!(validity.days_until_expiry() <= 366);
    }
}
