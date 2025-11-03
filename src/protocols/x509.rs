// X.509 Certificate Parser - RFC 5280
// Parses X.509 v3 certificates using ASN.1/DER encoding
//
// Certificate structure (simplified):
// Certificate ::= SEQUENCE {
//     tbsCertificate       TBSCertificate,
//     signatureAlgorithm   AlgorithmIdentifier,
//     signatureValue       BIT STRING
// }

use super::asn1::{Asn1Object, Asn1Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// X.509 Certificate
#[derive(Debug, Clone)]
pub struct X509Certificate {
    pub version: u8,
    pub serial_number: Vec<u8>,
    pub signature_algorithm: AlgorithmIdentifier,
    pub issuer: DistinguishedName,
    pub validity: Validity,
    pub subject: DistinguishedName,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub extensions: Vec<Extension>,
}

/// Algorithm Identifier
#[derive(Debug, Clone)]
pub struct AlgorithmIdentifier {
    pub algorithm: String, // OID as string
    pub parameters: Option<Vec<u8>>,
    pub parameters_oid: Option<String>,
}

/// Distinguished Name
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistinguishedName {
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub locality: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub email: Option<String>,
}

impl std::fmt::Display for DistinguishedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();

        if let Some(ref cn) = self.common_name {
            parts.push(format!("CN={}", cn));
        }
        if let Some(ref o) = self.organization {
            parts.push(format!("O={}", o));
        }
        if let Some(ref ou) = self.organizational_unit {
            parts.push(format!("OU={}", ou));
        }
        if let Some(ref l) = self.locality {
            parts.push(format!("L={}", l));
        }
        if let Some(ref st) = self.state {
            parts.push(format!("ST={}", st));
        }
        if let Some(ref c) = self.country {
            parts.push(format!("C={}", c));
        }

        write!(f, "{}", parts.join(", "))
    }
}

/// Certificate Validity Period
#[derive(Debug, Clone)]
pub struct Validity {
    pub not_before: String,
    pub not_after: String,
}

/// Subject Public Key Info
#[derive(Debug, Clone)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub public_key: Vec<u8>,
}

/// X.509 Extension
#[derive(Debug, Clone)]
pub struct Extension {
    pub oid: String,
    pub critical: bool,
    pub value: Vec<u8>,
}

impl X509Certificate {
    /// Parse DER-encoded X.509 certificate
    pub fn from_der(data: &[u8]) -> Result<Self, String> {
        let (cert_obj, _) = Asn1Object::from_der(data)?;

        // Certificate is a SEQUENCE
        let cert_seq = cert_obj.as_sequence()?;
        if cert_seq.len() < 3 {
            return Err("Invalid certificate structure".to_string());
        }

        // TBSCertificate (To Be Signed)
        let tbs = &cert_seq[0];
        let tbs_seq = tbs.as_sequence()?;

        let mut idx = 0;

        // Version (optional, default v1=0)
        // X.509 version is [0] EXPLICIT INTEGER (context-specific tag 0)
        let version = if tbs_seq[idx].is_context_specific(0) {
            let version_data = tbs_seq[idx].as_context_specific()?;
            // Parse the wrapped INTEGER
            let (version_obj, _) = Asn1Object::from_der(version_data)?;
            let version_bytes = version_obj.as_integer()?;
            idx += 1;
            if version_bytes.is_empty() {
                0
            } else {
                version_bytes[0]
            }
        } else {
            0 // v1
        };

        // Serial Number
        let serial_number = tbs_seq[idx].as_integer()?.clone();
        idx += 1;

        // Signature Algorithm
        let signature_algorithm = parse_algorithm_identifier(&tbs_seq[idx])?;
        idx += 1;

        // Issuer
        let issuer = parse_distinguished_name(&tbs_seq[idx])?;
        idx += 1;

        // Validity
        let validity = parse_validity(&tbs_seq[idx])?;
        idx += 1;

        // Subject
        let subject = parse_distinguished_name(&tbs_seq[idx])?;
        idx += 1;

        // SubjectPublicKeyInfo
        let subject_public_key_info = parse_subject_public_key_info(&tbs_seq[idx])?;
        idx += 1;

        // Extensions (optional, [3] tag)
        let mut extensions = Vec::new();
        while idx < tbs_seq.len() {
            if tbs_seq[idx].is_context_specific(3) {
                let ext_data = tbs_seq[idx].as_context_specific()?;
                let (ext_seq_obj, _) = Asn1Object::from_der(ext_data)?;
                let ext_seq = ext_seq_obj.as_sequence()?;
                extensions = parse_extensions(ext_seq)?;
            }
            idx += 1;
        }

        Ok(X509Certificate {
            version,
            serial_number,
            signature_algorithm,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            extensions,
        })
    }

    /// Get certificate serial number as hex string
    pub fn serial_number_hex(&self) -> String {
        self.serial_number
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Get Subject Alternative Names (SAN) from extensions
    pub fn get_subject_alt_names(&self) -> Vec<String> {
        for ext in &self.extensions {
            // subjectAltName OID: 2.5.29.17
            if ext.oid == "2.5.29.17" {
                if let Ok(sans) = parse_subject_alt_name(&ext.value) {
                    return sans;
                }
            }
        }
        Vec::new()
    }

    /// Check if certificate is self-signed
    pub fn is_self_signed(&self) -> bool {
        self.issuer.common_name == self.subject.common_name
            && self.issuer.organization == self.subject.organization
    }

    /// Get certificate subject as string
    pub fn subject_string(&self) -> String {
        format_distinguished_name(&self.subject)
    }

    /// Get certificate issuer as string
    pub fn issuer_string(&self) -> String {
        format_distinguished_name(&self.issuer)
    }
}

impl SubjectPublicKeyInfo {
    /// Extract RSA modulus and exponent from the subject public key info
    pub fn rsa_components(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        if self.algorithm.algorithm != "1.2.840.113549.1.1.1" {
            return Err("Unsupported public key algorithm for RSA components".to_string());
        }

        let (key_obj, _) = Asn1Object::from_der(&self.public_key)?;
        let seq = key_obj.as_sequence()?;
        if seq.len() < 2 {
            return Err("Invalid RSA public key structure".to_string());
        }

        let modulus = seq[0]
            .as_integer()
            .map_err(|e| format!("Invalid RSA modulus: {}", e))?
            .clone();
        let exponent = seq[1]
            .as_integer()
            .map_err(|e| format!("Invalid RSA exponent: {}", e))?
            .clone();

        Ok((modulus, exponent))
    }
}

/// Parse AlgorithmIdentifier
fn parse_algorithm_identifier(obj: &Asn1Object) -> Result<AlgorithmIdentifier, String> {
    let seq = obj.as_sequence()?;
    if seq.is_empty() {
        return Err("Empty AlgorithmIdentifier".to_string());
    }

    let algorithm = seq[0].as_oid()?;

    let mut parameters = None;
    let mut parameters_oid = None;
    if seq.len() > 1 {
        match &seq[1].value {
            Asn1Value::Null => {}
            Asn1Value::OctetString(bytes) => {
                parameters = Some(bytes.clone());
            }
            Asn1Value::ObjectIdentifier(_) => {
                parameters_oid = Some(seq[1].as_oid()?);
            }
            _ => {}
        }
    }

    Ok(AlgorithmIdentifier {
        algorithm,
        parameters,
        parameters_oid,
    })
}

/// Parse Distinguished Name (DN)
fn parse_distinguished_name(obj: &Asn1Object) -> Result<DistinguishedName, String> {
    let seq = obj.as_sequence()?;

    let mut dn = DistinguishedName {
        common_name: None,
        organization: None,
        organizational_unit: None,
        locality: None,
        state: None,
        country: None,
        email: None,
    };

    for rdn_obj in seq {
        let rdn_set = rdn_obj.as_sequence()?;

        for attr_obj in rdn_set {
            let attr_seq = attr_obj.as_sequence()?;
            if attr_seq.len() < 2 {
                continue;
            }

            let oid = attr_seq[0].as_oid()?;
            let value = attr_seq[1].as_string()?;

            match oid.as_str() {
                "2.5.4.3" => dn.common_name = Some(value),
                "2.5.4.10" => dn.organization = Some(value),
                "2.5.4.11" => dn.organizational_unit = Some(value),
                "2.5.4.7" => dn.locality = Some(value),
                "2.5.4.8" => dn.state = Some(value),
                "2.5.4.6" => dn.country = Some(value),
                "1.2.840.113549.1.9.1" => dn.email = Some(value),
                _ => (),
            }
        }
    }

    Ok(dn)
}

/// Parse Validity
fn parse_validity(obj: &Asn1Object) -> Result<Validity, String> {
    let seq = obj.as_sequence()?;
    if seq.len() < 2 {
        return Err("Invalid Validity structure".to_string());
    }

    let not_before = seq[0].as_string()?;
    let not_after = seq[1].as_string()?;

    Ok(Validity {
        not_before,
        not_after,
    })
}

/// Parse SubjectPublicKeyInfo
fn parse_subject_public_key_info(obj: &Asn1Object) -> Result<SubjectPublicKeyInfo, String> {
    let seq = obj.as_sequence()?;
    if seq.len() < 2 {
        return Err("Invalid SubjectPublicKeyInfo".to_string());
    }

    let algorithm = parse_algorithm_identifier(&seq[0])?;
    let (public_key, _unused_bits) = seq[1].as_bit_string()?;

    Ok(SubjectPublicKeyInfo {
        algorithm,
        public_key: public_key.clone(),
    })
}

/// Parse Extensions
fn parse_extensions(ext_seq: &[Asn1Object]) -> Result<Vec<Extension>, String> {
    let mut extensions = Vec::new();

    for ext_obj in ext_seq {
        let ext_parts = ext_obj.as_sequence()?;
        if ext_parts.is_empty() {
            continue;
        }

        let oid = ext_parts[0].as_oid()?;

        let mut critical = false;
        let mut value_idx = 1;

        if ext_parts.len() > 2 {
            if let Asn1Value::Boolean(crit) = &ext_parts[1].value {
                critical = *crit;
                value_idx = 2;
            }
        }

        let value = if value_idx < ext_parts.len() {
            ext_parts[value_idx].as_octet_string()?.clone()
        } else {
            Vec::new()
        };

        extensions.push(Extension {
            oid,
            critical,
            value,
        });
    }

    Ok(extensions)
}

/// Parse Subject Alternative Name
fn parse_subject_alt_name(data: &[u8]) -> Result<Vec<String>, String> {
    let (san_obj, _) = Asn1Object::from_der(data)?;
    let san_seq = san_obj.as_sequence()?;

    let mut names = Vec::new();

    for name_obj in san_seq {
        if let Asn1Value::ContextSpecific(tag, name_data) = &name_obj.value {
            match tag {
                2 => {
                    if let Ok(dns_name) = String::from_utf8(name_data.clone()) {
                        names.push(dns_name);
                    }
                }
                1 => {
                    if let Ok(email) = String::from_utf8(name_data.clone()) {
                        names.push(format!("email:{}", email));
                    }
                }
                6 => {
                    if let Ok(uri) = String::from_utf8(name_data.clone()) {
                        names.push(format!("URI:{}", uri));
                    }
                }
                _ => (),
            }
        }
    }

    Ok(names)
}

/// Format Distinguished Name as string
fn format_distinguished_name(dn: &DistinguishedName) -> String {
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
    if let Some(email) = &dn.email {
        parts.push(format!("emailAddress={}", email));
    }

    if parts.is_empty() {
        "(empty)".to_string()
    } else {
        parts.join(", ")
    }
}

/// Get human-readable algorithm name from OID
pub fn algorithm_name_from_oid(oid: &str) -> &str {
    match oid {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.113549.1.1.5" => "SHA-1 with RSA",
        "1.2.840.113549.1.1.11" => "SHA-256 with RSA",
        "1.2.840.113549.1.1.12" => "SHA-384 with RSA",
        "1.2.840.113549.1.1.13" => "SHA-512 with RSA",
        "1.2.840.10045.2.1" => "EC Public Key",
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256",
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384",
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512",
        _ => oid,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if is_leap_year(year) { 29 } else { 28 }),
        _ => None,
    }
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if month < 1 || month > 12 {
        return None;
    }
    if day == 0 || day > days_in_month(year, month)? {
        return None;
    }

    let mut y = year;
    let mut m = month as i32;
    y -= (m <= 2) as i32;
    m += if m > 2 { -3 } else { 9 };

    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era as i64 * 146_097 + doe as i64 - 719_468)
}

fn system_time_from_components(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<SystemTime> {
    if hour >= 24 || minute >= 60 || second >= 60 {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    let seconds_since_midnight = (hour as i64) * 3600 + (minute as i64) * 60 + second as i64;
    let total_seconds = days * 86_400 + seconds_since_midnight;

    if total_seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(total_seconds as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs((-total_seconds) as u64))
    }
}

fn parse_u32(slice: &str) -> Option<u32> {
    slice.parse().ok()
}

fn parse_utc_time(body: &str) -> Option<SystemTime> {
    if body.len() != 12 && body.len() != 10 {
        return None;
    }

    let year = parse_u32(&body[0..2])? as i32;
    let month = parse_u32(&body[2..4])?;
    let day = parse_u32(&body[4..6])?;
    let hour = parse_u32(&body[6..8])?;
    let minute = parse_u32(&body[8..10])?;
    let second = if body.len() == 12 {
        parse_u32(&body[10..12])?
    } else {
        0
    };

    let full_year = if year >= 50 { 1900 + year } else { 2000 + year };
    system_time_from_components(full_year, month, day, hour, minute, second)
}

fn parse_generalized_time(body: &str) -> Option<SystemTime> {
    if body.len() != 14 && body.len() != 12 {
        return None;
    }

    let year = parse_u32(&body[0..4])? as i32;
    let month = parse_u32(&body[4..6])?;
    let day = parse_u32(&body[6..8])?;
    let hour = parse_u32(&body[8..10])?;
    let minute = parse_u32(&body[10..12])?;
    let second = if body.len() == 14 {
        parse_u32(&body[12..14])?
    } else {
        0
    };

    system_time_from_components(year, month, day, hour, minute, second)
}

/// Parse X.509 time string (UTCTime or GeneralizedTime) into `SystemTime`.
pub fn parse_x509_time(value: &str) -> Option<SystemTime> {
    if !value.ends_with('Z') {
        return None;
    }
    let body = &value[..value.len() - 1];

    if body.len() == 12 || body.len() == 10 {
        parse_utc_time(body)
    } else if body.len() == 14 {
        parse_generalized_time(body)
    } else {
        None
    }
}

/// Backward-compatible helper used by legacy TLS stacks.
pub fn parse_x509_certificate(data: &[u8]) -> Result<X509Certificate, String> {
    X509Certificate::from_der(data)
}
