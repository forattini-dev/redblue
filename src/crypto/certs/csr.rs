//! Certificate Signing Request (CSR) Operations
//!
//! Implements CSR generation and parsing as per RFC 2986.

use super::x509::{Name, AlgorithmIdentifier, Extension, CertError};
use crate::crypto::encoding::asn1::{Asn1Value, Asn1Error};
use crate::crypto::encoding::pem::PemBlock;
use crate::crypto::encoding::oid::Oid;
use std::net::IpAddr;

/// Certificate Signing Request (PKCS#10)
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    /// Subject distinguished name
    pub subject: Name,
    /// Public key (DER-encoded)
    pub public_key: Vec<u8>,
    /// Key algorithm
    pub key_algorithm: AlgorithmIdentifier,
    /// Requested extensions
    pub extensions: Vec<Extension>,
    /// DNS SANs
    pub san_dns: Vec<String>,
    /// IP SANs
    pub san_ip: Vec<IpAddr>,
    /// Email SANs
    pub san_email: Vec<String>,
}

impl CertificateRequest {
    /// Create new CSR builder
    pub fn builder(subject: &str) -> CsrBuilder {
        CsrBuilder::new(subject)
    }

    /// Parse CSR from PEM format
    pub fn from_pem(pem: &str) -> Result<Self, CertError> {
        let block = PemBlock::decode(pem)?;
        if block.label != "CERTIFICATE REQUEST" {
            return Err(CertError::InvalidFormat(format!(
                "Expected CERTIFICATE REQUEST, got {}",
                block.label
            )));
        }
        Self::from_der(&block.data)
    }

    /// Parse CSR from DER format
    pub fn from_der(der: &[u8]) -> Result<Self, CertError> {
        let (value, _) = Asn1Value::decode_der(der)?;

        let seq = match value {
            Asn1Value::Sequence(s) => s,
            _ => return Err(CertError::InvalidFormat("CSR: Expected SEQUENCE".into())),
        };

        if seq.len() < 3 {
            return Err(CertError::InvalidFormat("CSR: Sequence too short".into()));
        }

        // Parse CertificationRequestInfo
        let cri_seq = match &seq[0] {
            Asn1Value::Sequence(s) => s,
            _ => return Err(CertError::InvalidFormat("CSR: Expected CRI SEQUENCE".into())),
        };

        if cri_seq.len() < 4 {
            return Err(CertError::InvalidFormat("CSR: CRI too short".into()));
        }

        // Version (should be 0)
        let _version = match &cri_seq[0] {
            Asn1Value::Integer(_) => {},
            _ => return Err(CertError::InvalidFormat("CSR: Expected version".into())),
        };

        // Subject
        let subject = Self::parse_name(&cri_seq[1])?;

        // SubjectPublicKeyInfo
        let (key_algorithm, public_key) = Self::parse_spki(&cri_seq[2])?;

        // Attributes (optional, tag [0])
        let mut extensions = Vec::new();
        let mut san_dns = Vec::new();
        let mut san_ip = Vec::new();
        let mut san_email = Vec::new();

        if let Some(Asn1Value::ContextSpecific { tag: 0, value: attrs, .. }) = cri_seq.get(3) {
            // Parse extension request attribute if present
            if let Asn1Value::Sequence(attr_seq) = attrs.as_ref() {
                for attr in attr_seq {
                    if let Asn1Value::Sequence(inner) = attr {
                        if inner.len() >= 2 {
                            if let Asn1Value::ObjectIdentifier(oid) = &inner[0] {
                                // Extension request OID: 1.2.840.113549.1.9.14
                                if oid == &[1, 2, 840, 113549, 1, 9, 14] {
                                    // Parse extension request
                                    if let Some(Asn1Value::Set(values)) = inner.get(1) {
                                        for val in values {
                                            if let Asn1Value::Sequence(exts) = val {
                                                for ext in exts {
                                                    if let Ok((e, dns, ip, email)) = Self::parse_extension(ext) {
                                                        extensions.push(e);
                                                        san_dns.extend(dns);
                                                        san_ip.extend(ip);
                                                        san_email.extend(email);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(CertificateRequest {
            subject,
            public_key,
            key_algorithm,
            extensions,
            san_dns,
            san_ip,
            san_email,
        })
    }

    /// Get subject common name
    pub fn subject_cn(&self) -> Option<&str> {
        self.subject.get_cn()
    }

    /// Parse Name from ASN.1
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
                                attributes.push(super::x509::AttributeTypeAndValue {
                                    oid: Oid::new(oid),
                                    value: value_str,
                                });
                            }
                        }
                    }
                }
                rdns.push(super::x509::RelativeDistinguishedName { attributes });
            }
        }

        Ok(Name { rdns })
    }

    /// Parse SubjectPublicKeyInfo
    fn parse_spki(value: &Asn1Value) -> Result<(AlgorithmIdentifier, Vec<u8>), CertError> {
        let seq = match value {
            Asn1Value::Sequence(s) => s,
            _ => return Err(CertError::InvalidFormat("SPKI: Expected SEQUENCE".into())),
        };

        if seq.len() < 2 {
            return Err(CertError::InvalidFormat("SPKI: Need algorithm and key".into()));
        }

        // Parse algorithm
        let alg_seq = match &seq[0] {
            Asn1Value::Sequence(s) => s,
            _ => return Err(CertError::InvalidFormat("SPKI: Expected alg SEQUENCE".into())),
        };

        let algorithm = match alg_seq.first() {
            Some(Asn1Value::ObjectIdentifier(oid)) => Oid::new(oid),
            _ => return Err(CertError::InvalidFormat("SPKI: Missing OID".into())),
        };

        let parameters = alg_seq.get(1).map(|v| v.encode_der());

        let key_algorithm = AlgorithmIdentifier { algorithm, parameters };

        // Parse public key
        let public_key = match &seq[1] {
            Asn1Value::BitString(data, _) => data.clone(),
            _ => return Err(CertError::InvalidFormat("SPKI: Expected BIT STRING".into())),
        };

        Ok((key_algorithm, public_key))
    }

    /// Parse extension and extract SANs
    fn parse_extension(value: &Asn1Value) -> Result<(Extension, Vec<String>, Vec<IpAddr>, Vec<String>), CertError> {
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

        let value_data = match seq.get(idx) {
            Some(Asn1Value::OctetString(data)) => data.clone(),
            _ => return Err(CertError::InvalidFormat("Ext: Missing value".into())),
        };

        // Parse SANs if this is the SAN extension
        let mut san_dns = Vec::new();
        let mut san_ip = Vec::new();
        let mut san_email = Vec::new();

        if oid == Oid::new(&[2, 5, 29, 17]) {
            // Subject Alternative Name
            if let Ok((Asn1Value::Sequence(items), _)) = Asn1Value::decode_der(&value_data) {
                for item in items {
                    if let Asn1Value::ContextSpecific { tag, value: inner, .. } = item {
                        match tag {
                            2 => {
                                // dNSName
                                if let Asn1Value::Raw(_, data) = inner.as_ref() {
                                    if let Ok(s) = String::from_utf8(data.clone()) {
                                        san_dns.push(s);
                                    }
                                }
                            }
                            7 => {
                                // iPAddress
                                if let Asn1Value::Raw(_, data) = inner.as_ref() {
                                    if data.len() == 4 {
                                        san_ip.push(IpAddr::V4(std::net::Ipv4Addr::new(
                                            data[0], data[1], data[2], data[3],
                                        )));
                                    }
                                }
                            }
                            1 => {
                                // rfc822Name
                                if let Asn1Value::Raw(_, data) = inner.as_ref() {
                                    if let Ok(s) = String::from_utf8(data.clone()) {
                                        san_email.push(s);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok((Extension { oid, critical, value: value_data }, san_dns, san_ip, san_email))
    }
}

/// CSR Builder
pub struct CsrBuilder {
    subject: String,
    san_dns: Vec<String>,
    san_ip: Vec<IpAddr>,
    san_email: Vec<String>,
}

impl CsrBuilder {
    /// Create new CSR builder
    pub fn new(subject: &str) -> Self {
        CsrBuilder {
            subject: subject.to_string(),
            san_dns: Vec::new(),
            san_ip: Vec::new(),
            san_email: Vec::new(),
        }
    }

    /// Add DNS SAN
    pub fn add_san_dns(mut self, dns: &str) -> Self {
        self.san_dns.push(dns.to_string());
        self
    }

    /// Add IP SAN
    pub fn add_san_ip(mut self, ip: IpAddr) -> Self {
        self.san_ip.push(ip);
        self
    }

    /// Add email SAN
    pub fn add_san_email(mut self, email: &str) -> Self {
        self.san_email.push(email.to_string());
        self
    }

    /// Build CSR using OpenSSL
    pub fn build(self, key_pem: &str) -> Result<String, CertError> {
        use boring::pkey::PKey;
        use boring::x509::X509ReqBuilder;
        use boring::x509::X509NameBuilder;
        use boring::x509::extension::SubjectAlternativeName;
        use boring::nid::Nid;
        use boring::hash::MessageDigest;
        use boring::stack::Stack;

        // Load private key
        let pkey = PKey::private_key_from_pem(key_pem.as_bytes())
            .map_err(|e| CertError::InvalidFormat(format!("Load key failed: {}", e)))?;

        // Parse subject
        let parsed_name = Name::from_string(&self.subject)?;
        let mut name_builder = X509NameBuilder::new()
            .map_err(|e| CertError::InvalidFormat(format!("Name builder failed: {}", e)))?;

        for rdn in &parsed_name.rdns {
            for attr in &rdn.attributes {
                let nid = if attr.oid == Oid::common_name() {
                    Nid::COMMONNAME
                } else if attr.oid == Oid::organization() {
                    Nid::ORGANIZATIONNAME
                } else if attr.oid == Oid::country() {
                    Nid::COUNTRYNAME
                } else {
                    continue;
                };

                name_builder
                    .append_entry_by_nid(nid, &attr.value)
                    .map_err(|e| CertError::InvalidFormat(format!("Name entry failed: {}", e)))?;
            }
        }

        let x509_name = name_builder.build();

        // Build CSR
        let mut builder = X509ReqBuilder::new()
            .map_err(|e| CertError::InvalidFormat(format!("CSR builder failed: {}", e)))?;

        builder.set_subject_name(&x509_name)
            .map_err(|e| CertError::InvalidFormat(format!("Set subject failed: {}", e)))?;

        builder.set_pubkey(&pkey)
            .map_err(|e| CertError::InvalidFormat(format!("Set pubkey failed: {}", e)))?;

        // Add SANs if any
        if !self.san_dns.is_empty() || !self.san_ip.is_empty() || !self.san_email.is_empty() {
            let mut extensions = Stack::new()
                .map_err(|e| CertError::InvalidFormat(format!("Stack new failed: {}", e)))?;

            let mut san_builder = SubjectAlternativeName::new();

            for dns in &self.san_dns {
                san_builder.dns(dns);
            }

            for ip in &self.san_ip {
                san_builder.ip(&ip.to_string());
            }

            for email in &self.san_email {
                san_builder.email(email);
            }

            let san = san_builder.build(&builder.x509v3_context(None))
                .map_err(|e| CertError::InvalidFormat(format!("SAN build failed: {}", e)))?;
            extensions.push(san)
                .map_err(|e| CertError::InvalidFormat(format!("Push SAN failed: {}", e)))?;

            builder.add_extensions(&extensions)
                .map_err(|e| CertError::InvalidFormat(format!("Add extensions failed: {}", e)))?;
        }

        // Sign CSR
        builder.sign(&pkey, MessageDigest::sha256())
            .map_err(|e| CertError::InvalidFormat(format!("Sign failed: {}", e)))?;

        let csr = builder.build();
        let csr_pem = csr.to_pem()
            .map_err(|e| CertError::InvalidFormat(format!("To PEM failed: {}", e)))?;

        Ok(String::from_utf8(csr_pem).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csr_builder() {
        // Generate a key first
        use boring::pkey::PKey;
        use boring::ec::{EcKey, EcGroup};
        use boring::nid::Nid;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec).unwrap();
        let key_pem = String::from_utf8(pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();

        let csr_pem = CertificateRequest::builder("CN=test.example.com")
            .add_san_dns("test.example.com")
            .add_san_dns("*.test.example.com")
            .build(&key_pem)
            .expect("CSR build should succeed");

        assert!(csr_pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(csr_pem.contains("-----END CERTIFICATE REQUEST-----"));
    }
}
