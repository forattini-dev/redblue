//! Certificate Authority (CA) Operations
//!
//! This module provides CA functionality for:
//! - Generating self-signed CA certificates
//! - Signing certificates for MITM interception
//! - Managing certificate serial numbers

use super::x509::{
    AlgorithmIdentifier, CertError, Certificate, Extension, Name, SubjectPublicKeyInfo,
    TbsCertificate, Validity,
};
use crate::crypto::encoding::asn1::Asn1Value;
use crate::crypto::encoding::oid::Oid;
use crate::crypto::sha256::sha256;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Certificate Authority
pub struct CertificateAuthority {
    /// CA certificate
    pub cert: Certificate,
    /// CA private key (DER-encoded)
    pub private_key: Vec<u8>,
    /// Key algorithm
    pub key_algorithm: KeyAlgorithm,
    /// Serial number counter
    serial_counter: AtomicU64,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("cert", &self.cert)
            .field("key_algorithm", &self.key_algorithm)
            .field(
                "private_key",
                &format!("[{} bytes]", self.private_key.len()),
            )
            .finish()
    }
}

/// Supported key algorithms
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyAlgorithm {
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
}

impl CertificateAuthority {
    /// Create new self-signed CA using OpenSSL
    ///
    /// # Arguments
    /// * `subject` - CA subject (e.g., "CN=My CA, O=My Org")
    /// * `key_algorithm` - Key algorithm to use
    /// * `validity_days` - Number of days the CA cert is valid
    pub fn new(
        subject: &str,
        key_algorithm: KeyAlgorithm,
        validity_days: u32,
    ) -> Result<Self, CertError> {
        use boring::bn::BigNum;
        use boring::ec::{EcGroup, EcKey};
        use boring::hash::MessageDigest;
        use boring::nid::Nid;
        use boring::pkey::PKey;
        use boring::rsa::Rsa;
        use boring::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
        use boring::x509::{X509Builder, X509NameBuilder};

        // Generate key pair
        let pkey = match key_algorithm {
            KeyAlgorithm::Rsa2048 => {
                let rsa = Rsa::generate(2048)
                    .map_err(|e| CertError::InvalidFormat(format!("RSA gen failed: {}", e)))?;
                PKey::from_rsa(rsa)
                    .map_err(|e| CertError::InvalidFormat(format!("PKey failed: {}", e)))?
            }
            KeyAlgorithm::Rsa4096 => {
                let rsa = Rsa::generate(4096)
                    .map_err(|e| CertError::InvalidFormat(format!("RSA gen failed: {}", e)))?;
                PKey::from_rsa(rsa)
                    .map_err(|e| CertError::InvalidFormat(format!("PKey failed: {}", e)))?
            }
            KeyAlgorithm::EcdsaP256 => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                    .map_err(|e| CertError::InvalidFormat(format!("EC group failed: {}", e)))?;
                let ec = EcKey::generate(&group)
                    .map_err(|e| CertError::InvalidFormat(format!("EC gen failed: {}", e)))?;
                PKey::from_ec_key(ec)
                    .map_err(|e| CertError::InvalidFormat(format!("PKey failed: {}", e)))?
            }
            KeyAlgorithm::EcdsaP384 => {
                let group = EcGroup::from_curve_name(Nid::SECP384R1)
                    .map_err(|e| CertError::InvalidFormat(format!("EC group failed: {}", e)))?;
                let ec = EcKey::generate(&group)
                    .map_err(|e| CertError::InvalidFormat(format!("EC gen failed: {}", e)))?;
                PKey::from_ec_key(ec)
                    .map_err(|e| CertError::InvalidFormat(format!("PKey failed: {}", e)))?
            }
        };

        // Parse subject
        let parsed_name = Name::from_string(subject)?;
        let mut name_builder = X509NameBuilder::new()
            .map_err(|e| CertError::InvalidFormat(format!("Name builder failed: {}", e)))?;

        for rdn in &parsed_name.rdns {
            for attr in &rdn.attributes {
                let nid = if attr.oid == Oid::common_name() {
                    Nid::COMMONNAME
                } else if attr.oid == Oid::organization() {
                    Nid::ORGANIZATIONNAME
                } else if attr.oid == Oid::organizational_unit() {
                    Nid::ORGANIZATIONALUNITNAME
                } else if attr.oid == Oid::country() {
                    Nid::COUNTRYNAME
                } else if attr.oid == Oid::state() {
                    Nid::STATEORPROVINCENAME
                } else if attr.oid == Oid::locality() {
                    Nid::LOCALITYNAME
                } else {
                    continue;
                };

                name_builder
                    .append_entry_by_nid(nid, &attr.value)
                    .map_err(|e| CertError::InvalidFormat(format!("Name entry failed: {}", e)))?;
            }
        }

        let x509_name = name_builder.build();

        // Build certificate
        let mut builder = X509Builder::new()
            .map_err(|e| CertError::InvalidFormat(format!("X509 builder failed: {}", e)))?;

        builder
            .set_version(2) // X.509 v3
            .map_err(|e| CertError::InvalidFormat(format!("Set version failed: {}", e)))?;

        // Random serial number
        let serial = BigNum::from_u32(rand_u32())
            .map_err(|e| CertError::InvalidFormat(format!("BigNum failed: {}", e)))?;
        let serial_asn1 = serial
            .to_asn1_integer()
            .map_err(|e| CertError::InvalidFormat(format!("ASN1 integer failed: {}", e)))?;
        builder
            .set_serial_number(&serial_asn1)
            .map_err(|e| CertError::InvalidFormat(format!("Set serial failed: {}", e)))?;

        builder
            .set_subject_name(&x509_name)
            .map_err(|e| CertError::InvalidFormat(format!("Set subject failed: {}", e)))?;

        builder
            .set_issuer_name(&x509_name) // Self-signed
            .map_err(|e| CertError::InvalidFormat(format!("Set issuer failed: {}", e)))?;

        builder
            .set_pubkey(&pkey)
            .map_err(|e| CertError::InvalidFormat(format!("Set pubkey failed: {}", e)))?;

        // Validity
        let not_before = boring::asn1::Asn1Time::days_from_now(0)
            .map_err(|e| CertError::InvalidFormat(format!("Not before failed: {}", e)))?;
        let not_after = boring::asn1::Asn1Time::days_from_now(validity_days)
            .map_err(|e| CertError::InvalidFormat(format!("Not after failed: {}", e)))?;

        builder
            .set_not_before(&not_before)
            .map_err(|e| CertError::InvalidFormat(format!("Set not before failed: {}", e)))?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| CertError::InvalidFormat(format!("Set not after failed: {}", e)))?;

        // Extensions for CA
        let bc = BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .map_err(|e| CertError::InvalidFormat(format!("BC extension failed: {}", e)))?;
        builder
            .append_extension(bc)
            .map_err(|e| CertError::InvalidFormat(format!("Append BC failed: {}", e)))?;

        let ku = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .map_err(|e| CertError::InvalidFormat(format!("KU extension failed: {}", e)))?;
        builder
            .append_extension(ku)
            .map_err(|e| CertError::InvalidFormat(format!("Append KU failed: {}", e)))?;

        let ctx = builder.x509v3_context(None, None);
        let ski = SubjectKeyIdentifier::new()
            .build(&ctx)
            .map_err(|e| CertError::InvalidFormat(format!("SKI extension failed: {}", e)))?;
        builder
            .append_extension(ski)
            .map_err(|e| CertError::InvalidFormat(format!("Append SKI failed: {}", e)))?;

        // Sign
        let digest = match key_algorithm {
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => MessageDigest::sha256(),
            KeyAlgorithm::EcdsaP256 => MessageDigest::sha256(),
            KeyAlgorithm::EcdsaP384 => MessageDigest::sha384(),
        };

        builder
            .sign(&pkey, digest)
            .map_err(|e| CertError::InvalidFormat(format!("Sign failed: {}", e)))?;

        let x509 = builder.build();

        // Convert to our types
        let cert_der = x509
            .to_der()
            .map_err(|e| CertError::InvalidFormat(format!("To DER failed: {}", e)))?;
        let cert = Certificate::from_der(&cert_der)?;

        let private_key = pkey
            .private_key_to_der()
            .map_err(|e| CertError::InvalidFormat(format!("Private key to DER failed: {}", e)))?;

        Ok(CertificateAuthority {
            cert,
            private_key,
            key_algorithm,
            serial_counter: AtomicU64::new(1),
        })
    }

    /// Load existing CA from PEM files
    pub fn load(cert_pem: &str, key_pem: &str) -> Result<Self, CertError> {
        use boring::pkey::PKey;
        use boring::x509::X509;

        let x509 = X509::from_pem(cert_pem.as_bytes())
            .map_err(|e| CertError::InvalidFormat(format!("Parse cert failed: {}", e)))?;

        let pkey = PKey::private_key_from_pem(key_pem.as_bytes())
            .map_err(|e| CertError::InvalidFormat(format!("Parse key failed: {}", e)))?;

        let cert_der = x509
            .to_der()
            .map_err(|e| CertError::InvalidFormat(format!("To DER failed: {}", e)))?;
        let cert = Certificate::from_der(&cert_der)?;

        let private_key = pkey
            .private_key_to_der()
            .map_err(|e| CertError::InvalidFormat(format!("Key to DER failed: {}", e)))?;

        // Detect key algorithm
        let key_algorithm = if pkey.rsa().is_ok() {
            let rsa = pkey.rsa().unwrap();
            if rsa.size() <= 256 {
                KeyAlgorithm::Rsa2048
            } else {
                KeyAlgorithm::Rsa4096
            }
        } else if pkey.ec_key().is_ok() {
            KeyAlgorithm::EcdsaP256 // Default to P-256
        } else {
            KeyAlgorithm::Rsa2048
        };

        Ok(CertificateAuthority {
            cert,
            private_key,
            key_algorithm,
            serial_counter: AtomicU64::new(1),
        })
    }

    /// Generate certificate for hostname (MITM interception)
    pub fn generate_cert(&self, hostname: &str) -> Result<(Certificate, Vec<u8>), CertError> {
        self.generate_cert_with_sans(hostname, &[hostname], &[])
    }

    /// Generate certificate with Subject Alternative Names
    pub fn generate_cert_with_sans(
        &self,
        common_name: &str,
        dns_names: &[&str],
        ip_addresses: &[IpAddr],
    ) -> Result<(Certificate, Vec<u8>), CertError> {
        use boring::bn::BigNum;
        use boring::ec::{EcGroup, EcKey};
        use boring::hash::MessageDigest;
        use boring::nid::Nid;
        use boring::pkey::PKey;
        use boring::rsa::Rsa;
        use boring::x509::extension::{
            BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
        };
        use boring::x509::{X509Builder, X509NameBuilder, X509};

        // Load CA private key
        let ca_pkey = PKey::private_key_from_der(&self.private_key)
            .map_err(|e| CertError::InvalidFormat(format!("Load CA key failed: {}", e)))?;

        let ca_cert = X509::from_der(&self.cert.to_der())
            .map_err(|e| CertError::InvalidFormat(format!("Load CA cert failed: {}", e)))?;

        // Generate new key pair for the certificate
        let pkey = match self.key_algorithm {
            KeyAlgorithm::Rsa2048 => {
                let rsa = Rsa::generate(2048)
                    .map_err(|e| CertError::InvalidFormat(format!("RSA gen failed: {}", e)))?;
                PKey::from_rsa(rsa)
                    .map_err(|e| CertError::InvalidFormat(format!("PKey failed: {}", e)))?
            }
            KeyAlgorithm::Rsa4096 => {
                let rsa = Rsa::generate(4096)
                    .map_err(|e| CertError::InvalidFormat(format!("RSA gen failed: {}", e)))?;
                PKey::from_rsa(rsa)
                    .map_err(|e| CertError::InvalidFormat(format!("PKey failed: {}", e)))?
            }
            KeyAlgorithm::EcdsaP256 => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                    .map_err(|e| CertError::InvalidFormat(format!("EC group failed: {}", e)))?;
                let ec = EcKey::generate(&group)
                    .map_err(|e| CertError::InvalidFormat(format!("EC gen failed: {}", e)))?;
                PKey::from_ec_key(ec)
                    .map_err(|e| CertError::InvalidFormat(format!("PKey failed: {}", e)))?
            }
            KeyAlgorithm::EcdsaP384 => {
                let group = EcGroup::from_curve_name(Nid::SECP384R1)
                    .map_err(|e| CertError::InvalidFormat(format!("EC group failed: {}", e)))?;
                let ec = EcKey::generate(&group)
                    .map_err(|e| CertError::InvalidFormat(format!("EC gen failed: {}", e)))?;
                PKey::from_ec_key(ec)
                    .map_err(|e| CertError::InvalidFormat(format!("PKey failed: {}", e)))?
            }
        };

        // Build subject name
        let mut name_builder = X509NameBuilder::new()
            .map_err(|e| CertError::InvalidFormat(format!("Name builder failed: {}", e)))?;
        name_builder
            .append_entry_by_nid(Nid::COMMONNAME, common_name)
            .map_err(|e| CertError::InvalidFormat(format!("CN failed: {}", e)))?;
        let subject_name = name_builder.build();

        // Build certificate
        let mut builder = X509Builder::new()
            .map_err(|e| CertError::InvalidFormat(format!("X509 builder failed: {}", e)))?;

        builder
            .set_version(2) // X.509 v3
            .map_err(|e| CertError::InvalidFormat(format!("Set version failed: {}", e)))?;

        // Serial number
        let serial_num = self.serial_counter.fetch_add(1, Ordering::SeqCst);
        let serial = BigNum::from_u32(serial_num as u32)
            .map_err(|e| CertError::InvalidFormat(format!("BigNum failed: {}", e)))?;
        let serial_asn1 = serial
            .to_asn1_integer()
            .map_err(|e| CertError::InvalidFormat(format!("ASN1 integer failed: {}", e)))?;
        builder
            .set_serial_number(&serial_asn1)
            .map_err(|e| CertError::InvalidFormat(format!("Set serial failed: {}", e)))?;

        builder
            .set_subject_name(&subject_name)
            .map_err(|e| CertError::InvalidFormat(format!("Set subject failed: {}", e)))?;

        builder
            .set_issuer_name(ca_cert.subject_name())
            .map_err(|e| CertError::InvalidFormat(format!("Set issuer failed: {}", e)))?;

        builder
            .set_pubkey(&pkey)
            .map_err(|e| CertError::InvalidFormat(format!("Set pubkey failed: {}", e)))?;

        // Validity (1 year)
        let not_before = boring::asn1::Asn1Time::days_from_now(0)
            .map_err(|e| CertError::InvalidFormat(format!("Not before failed: {}", e)))?;
        let not_after = boring::asn1::Asn1Time::days_from_now(365)
            .map_err(|e| CertError::InvalidFormat(format!("Not after failed: {}", e)))?;

        builder
            .set_not_before(&not_before)
            .map_err(|e| CertError::InvalidFormat(format!("Set not before failed: {}", e)))?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| CertError::InvalidFormat(format!("Set not after failed: {}", e)))?;

        // Extensions
        let bc = BasicConstraints::new()
            .build()
            .map_err(|e| CertError::InvalidFormat(format!("BC extension failed: {}", e)))?;
        builder
            .append_extension(bc)
            .map_err(|e| CertError::InvalidFormat(format!("Append BC failed: {}", e)))?;

        let ku = KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()
            .map_err(|e| CertError::InvalidFormat(format!("KU extension failed: {}", e)))?;
        builder
            .append_extension(ku)
            .map_err(|e| CertError::InvalidFormat(format!("Append KU failed: {}", e)))?;

        let eku = ExtendedKeyUsage::new()
            .server_auth()
            .client_auth()
            .build()
            .map_err(|e| CertError::InvalidFormat(format!("EKU extension failed: {}", e)))?;
        builder
            .append_extension(eku)
            .map_err(|e| CertError::InvalidFormat(format!("Append EKU failed: {}", e)))?;

        // Subject Alternative Names
        let ctx = builder.x509v3_context(Some(&ca_cert), None);
        let mut san_builder = SubjectAlternativeName::new();

        for dns in dns_names {
            san_builder.dns(dns);
        }

        for ip in ip_addresses {
            san_builder.ip(&ip.to_string());
        }

        let san = san_builder
            .build(&ctx)
            .map_err(|e| CertError::InvalidFormat(format!("SAN extension failed: {}", e)))?;
        builder
            .append_extension(san)
            .map_err(|e| CertError::InvalidFormat(format!("Append SAN failed: {}", e)))?;

        // Sign with CA key
        let digest = match self.key_algorithm {
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => MessageDigest::sha256(),
            KeyAlgorithm::EcdsaP256 => MessageDigest::sha256(),
            KeyAlgorithm::EcdsaP384 => MessageDigest::sha384(),
        };

        builder
            .sign(&ca_pkey, digest)
            .map_err(|e| CertError::InvalidFormat(format!("Sign failed: {}", e)))?;

        let x509 = builder.build();

        // Convert to our types
        let cert_der = x509
            .to_der()
            .map_err(|e| CertError::InvalidFormat(format!("To DER failed: {}", e)))?;
        let cert = Certificate::from_der(&cert_der)?;

        let private_key_der = pkey
            .private_key_to_der()
            .map_err(|e| CertError::InvalidFormat(format!("Key to DER failed: {}", e)))?;

        Ok((cert, private_key_der))
    }

    /// Load CA from PEM-encoded certificate and key
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, CertError> {
        use boring::pkey::PKey;
        use boring::x509::X509;

        // Parse certificate
        let x509 = X509::from_pem(cert_pem.as_bytes())
            .map_err(|e| CertError::InvalidFormat(format!("Failed to parse CA cert: {}", e)))?;

        // Parse private key
        let pkey = PKey::private_key_from_pem(key_pem.as_bytes())
            .map_err(|e| CertError::InvalidFormat(format!("Failed to parse CA key: {}", e)))?;

        // Determine key algorithm
        let key_algorithm = if pkey.rsa().is_ok() {
            let rsa = pkey.rsa().unwrap();
            if rsa.size() * 8 >= 4096 {
                KeyAlgorithm::Rsa4096
            } else {
                KeyAlgorithm::Rsa2048
            }
        } else if pkey.ec_key().is_ok() {
            let ec = pkey.ec_key().unwrap();
            let group = ec.group();
            let nid = group.curve_name();
            if nid == Some(boring::nid::Nid::SECP384R1) {
                KeyAlgorithm::EcdsaP384
            } else {
                KeyAlgorithm::EcdsaP256
            }
        } else {
            return Err(CertError::InvalidFormat("Unknown key algorithm".into()));
        };

        // Get private key DER
        let private_key = pkey
            .private_key_to_der()
            .map_err(|e| CertError::InvalidFormat(format!("Failed to encode key: {}", e)))?;

        // Parse X.509 into our Certificate structure
        let cert_der = x509
            .to_der()
            .map_err(|e| CertError::InvalidFormat(format!("Failed to encode cert: {}", e)))?;

        let cert = Certificate::from_der(&cert_der)?;

        Ok(Self {
            cert,
            private_key,
            key_algorithm,
            serial_counter: AtomicU64::new(rand_u32() as u64),
        })
    }

    /// Export CA certificate as PEM
    pub fn export_ca_pem(&self) -> String {
        self.cert.to_pem()
    }

    /// Export CA certificate as DER
    pub fn export_ca_der(&self) -> Vec<u8> {
        self.cert.to_der()
    }

    /// Export CA private key as PEM
    pub fn export_key_pem(&self) -> String {
        use crate::crypto::encoding::pem::PemBlock;

        let block = PemBlock {
            label: "PRIVATE KEY".to_string(),
            data: self.private_key.clone(),
        };
        block.encode()
    }

    /// Get CA subject
    pub fn subject(&self) -> String {
        self.cert.tbs_certificate.subject.to_string_repr()
    }

    /// Get CA fingerprint
    pub fn fingerprint(&self) -> String {
        self.cert.fingerprint_sha256()
    }
}

/// Simple random u32 using system entropy
fn rand_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    // Mix with process ID for uniqueness
    let pid = std::process::id();

    ((now as u64 ^ (pid as u64).wrapping_mul(0x9e3779b97f4a7c15)) & 0xFFFFFFFF) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_generation() {
        let ca = CertificateAuthority::new("CN=Test CA, O=Test Org", KeyAlgorithm::EcdsaP256, 365)
            .expect("CA generation should succeed");

        assert!(ca.cert.is_self_signed());
        assert!(ca.cert.is_ca());
        assert!(ca.cert.is_valid_now());
        assert_eq!(ca.cert.subject_cn(), Some("Test CA"));
    }

    #[test]
    fn test_cert_generation() {
        let ca = CertificateAuthority::new("CN=Test CA", KeyAlgorithm::EcdsaP256, 365)
            .expect("CA generation should succeed");

        let (cert, _key) = ca
            .generate_cert("example.com")
            .expect("Cert generation should succeed");

        assert!(!cert.is_self_signed());
        assert!(!cert.is_ca());
        assert!(cert.is_valid_now());
        assert!(cert.is_valid_for_hostname("example.com"));
        assert_eq!(cert.subject_cn(), Some("example.com"));
    }

    #[test]
    fn test_cert_with_sans() {
        let ca = CertificateAuthority::new("CN=Test CA", KeyAlgorithm::EcdsaP256, 365)
            .expect("CA generation should succeed");

        let (cert, _key) = ca
            .generate_cert_with_sans(
                "example.com",
                &["example.com", "*.example.com", "api.example.com"],
                &["192.168.1.1".parse().unwrap()],
            )
            .expect("Cert generation should succeed");

        assert!(cert.is_valid_for_hostname("example.com"));
        assert!(cert.is_valid_for_hostname("www.example.com"));
        assert!(cert.is_valid_for_hostname("api.example.com"));

        let san_dns = cert.san_dns_names();
        assert!(san_dns.contains(&"example.com".to_string()));
        assert!(san_dns.contains(&"*.example.com".to_string()));

        let san_ips = cert.san_ip_addresses();
        assert!(san_ips.contains(&"192.168.1.1".parse().unwrap()));
    }
}
