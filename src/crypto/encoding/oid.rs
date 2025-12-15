//! Object Identifiers (OID) Constants
//!
//! Common OIDs used in X.509 certificates, PKCS formats, and cryptographic algorithms.

use super::asn1::Asn1Value;

/// Object Identifier wrapper
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Oid {
    /// OID components
    pub components: Vec<u32>,
}

impl Oid {
    //=========================================================================
    // X.500 Distinguished Name OIDs (as functions for Rust const limitations)
    //=========================================================================

    /// Common Name (CN) - 2.5.4.3
    pub fn common_name() -> Self {
        Self::new(OID_COMMON_NAME)
    }
    /// Organization (O) - 2.5.4.10
    pub fn organization() -> Self {
        Self::new(OID_ORGANIZATION_NAME)
    }
    /// Organizational Unit (OU) - 2.5.4.11
    pub fn organizational_unit() -> Self {
        Self::new(OID_ORGANIZATIONAL_UNIT)
    }
    /// Country (C) - 2.5.4.6
    pub fn country() -> Self {
        Self::new(OID_COUNTRY_NAME)
    }
    /// State or Province (ST) - 2.5.4.8
    pub fn state() -> Self {
        Self::new(OID_STATE_OR_PROVINCE)
    }
    /// Locality (L) - 2.5.4.7
    pub fn locality() -> Self {
        Self::new(OID_LOCALITY_NAME)
    }
    /// Email Address - 1.2.840.113549.1.9.1
    pub fn email() -> Self {
        Self::new(OID_EMAIL_ADDRESS)
    }

    // Associated constants using OID slices (for comparison)
    pub const COMMON_NAME: &'static [u32] = OID_COMMON_NAME;
    pub const ORGANIZATION: &'static [u32] = OID_ORGANIZATION_NAME;
    pub const ORGANIZATIONAL_UNIT: &'static [u32] = OID_ORGANIZATIONAL_UNIT;
    pub const COUNTRY: &'static [u32] = OID_COUNTRY_NAME;
    pub const STATE: &'static [u32] = OID_STATE_OR_PROVINCE;
    pub const LOCALITY: &'static [u32] = OID_LOCALITY_NAME;
    pub const EMAIL: &'static [u32] = OID_EMAIL_ADDRESS;

    /// Create OID from components
    pub fn new(components: &[u32]) -> Self {
        Self {
            components: components.to_vec(),
        }
    }

    /// Create OID from slice
    pub fn from_slice(components: &[u32]) -> Self {
        Self {
            components: components.to_vec(),
        }
    }

    /// Parse OID from dotted string
    pub fn from_str(s: &str) -> Option<Self> {
        let components: Result<Vec<u32>, _> = s.split('.').map(|p| p.parse()).collect();
        components.ok().map(|c| Self { components: c })
    }

    /// Convert to ASN.1 value
    pub fn to_asn1(&self) -> Asn1Value {
        Asn1Value::ObjectIdentifier(self.components.clone())
    }

    /// Get human-readable name if known
    pub fn name(&self) -> Option<&'static str> {
        KNOWN_OIDS
            .iter()
            .find(|(_, oid)| *oid == self.components.as_slice())
            .map(|(name, _)| *name)
    }
}

impl std::fmt::Display for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self
            .components
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(".");
        write!(f, "{}", s)
    }
}

impl From<&[u32]> for Oid {
    fn from(components: &[u32]) -> Self {
        Self::from_slice(components)
    }
}

//=============================================================================
// WELL-KNOWN OIDs
//=============================================================================

/// Known OID mappings (name, components)
pub const KNOWN_OIDS: &[(&str, &[u32])] = &[
    // =========================================================================
    // SIGNATURE ALGORITHMS
    // =========================================================================
    ("md5WithRSAEncryption", &[1, 2, 840, 113549, 1, 1, 4]),
    ("sha1WithRSAEncryption", &[1, 2, 840, 113549, 1, 1, 5]),
    ("sha256WithRSAEncryption", &[1, 2, 840, 113549, 1, 1, 11]),
    ("sha384WithRSAEncryption", &[1, 2, 840, 113549, 1, 1, 12]),
    ("sha512WithRSAEncryption", &[1, 2, 840, 113549, 1, 1, 13]),
    ("rsaEncryption", &[1, 2, 840, 113549, 1, 1, 1]),
    ("rsaesOaep", &[1, 2, 840, 113549, 1, 1, 7]),
    ("rsassaPss", &[1, 2, 840, 113549, 1, 1, 10]),
    ("ecdsaWithSHA256", &[1, 2, 840, 10045, 4, 3, 2]),
    ("ecdsaWithSHA384", &[1, 2, 840, 10045, 4, 3, 3]),
    ("ecdsaWithSHA512", &[1, 2, 840, 10045, 4, 3, 4]),
    ("ed25519", &[1, 3, 101, 112]),
    ("ed448", &[1, 3, 101, 113]),
    // =========================================================================
    // PUBLIC KEY ALGORITHMS
    // =========================================================================
    ("ecPublicKey", &[1, 2, 840, 10045, 2, 1]),
    ("x25519", &[1, 3, 101, 110]),
    ("x448", &[1, 3, 101, 111]),
    // =========================================================================
    // ELLIPTIC CURVES
    // =========================================================================
    ("secp256r1", &[1, 2, 840, 10045, 3, 1, 7]), // P-256 / prime256v1
    ("secp384r1", &[1, 3, 132, 0, 34]),          // P-384
    ("secp521r1", &[1, 3, 132, 0, 35]),          // P-521
    ("secp256k1", &[1, 3, 132, 0, 10]),          // Bitcoin curve
    // =========================================================================
    // HASH ALGORITHMS
    // =========================================================================
    ("md5", &[1, 2, 840, 113549, 2, 5]),
    ("sha1", &[1, 3, 14, 3, 2, 26]),
    ("sha256", &[2, 16, 840, 1, 101, 3, 4, 2, 1]),
    ("sha384", &[2, 16, 840, 1, 101, 3, 4, 2, 2]),
    ("sha512", &[2, 16, 840, 1, 101, 3, 4, 2, 3]),
    ("sha224", &[2, 16, 840, 1, 101, 3, 4, 2, 4]),
    ("sha512-224", &[2, 16, 840, 1, 101, 3, 4, 2, 5]),
    ("sha512-256", &[2, 16, 840, 1, 101, 3, 4, 2, 6]),
    ("sha3-256", &[2, 16, 840, 1, 101, 3, 4, 2, 8]),
    ("sha3-384", &[2, 16, 840, 1, 101, 3, 4, 2, 9]),
    ("sha3-512", &[2, 16, 840, 1, 101, 3, 4, 2, 10]),
    // =========================================================================
    // X.500 DISTINGUISHED NAME ATTRIBUTES
    // =========================================================================
    ("commonName", &[2, 5, 4, 3]),
    ("surname", &[2, 5, 4, 4]),
    ("serialNumber", &[2, 5, 4, 5]),
    ("countryName", &[2, 5, 4, 6]),
    ("localityName", &[2, 5, 4, 7]),
    ("stateOrProvinceName", &[2, 5, 4, 8]),
    ("streetAddress", &[2, 5, 4, 9]),
    ("organizationName", &[2, 5, 4, 10]),
    ("organizationalUnitName", &[2, 5, 4, 11]),
    ("title", &[2, 5, 4, 12]),
    ("description", &[2, 5, 4, 13]),
    ("postalCode", &[2, 5, 4, 17]),
    ("givenName", &[2, 5, 4, 42]),
    ("initials", &[2, 5, 4, 43]),
    ("generationQualifier", &[2, 5, 4, 44]),
    ("dnQualifier", &[2, 5, 4, 46]),
    ("pseudonym", &[2, 5, 4, 65]),
    ("emailAddress", &[1, 2, 840, 113549, 1, 9, 1]),
    ("domainComponent", &[0, 9, 2342, 19200300, 100, 1, 25]),
    ("userId", &[0, 9, 2342, 19200300, 100, 1, 1]),
    // =========================================================================
    // X.509 CERTIFICATE EXTENSIONS
    // =========================================================================
    ("subjectKeyIdentifier", &[2, 5, 29, 14]),
    ("keyUsage", &[2, 5, 29, 15]),
    ("subjectAltName", &[2, 5, 29, 17]),
    ("issuerAltName", &[2, 5, 29, 18]),
    ("basicConstraints", &[2, 5, 29, 19]),
    ("nameConstraints", &[2, 5, 29, 30]),
    ("cRLDistributionPoints", &[2, 5, 29, 31]),
    ("certificatePolicies", &[2, 5, 29, 32]),
    ("authorityKeyIdentifier", &[2, 5, 29, 35]),
    ("extKeyUsage", &[2, 5, 29, 37]),
    ("authorityInfoAccess", &[1, 3, 6, 1, 5, 5, 7, 1, 1]),
    ("subjectInfoAccess", &[1, 3, 6, 1, 5, 5, 7, 1, 11]),
    // =========================================================================
    // EXTENDED KEY USAGE
    // =========================================================================
    ("serverAuth", &[1, 3, 6, 1, 5, 5, 7, 3, 1]),
    ("clientAuth", &[1, 3, 6, 1, 5, 5, 7, 3, 2]),
    ("codeSigning", &[1, 3, 6, 1, 5, 5, 7, 3, 3]),
    ("emailProtection", &[1, 3, 6, 1, 5, 5, 7, 3, 4]),
    ("timeStamping", &[1, 3, 6, 1, 5, 5, 7, 3, 8]),
    ("ocspSigning", &[1, 3, 6, 1, 5, 5, 7, 3, 9]),
    // =========================================================================
    // PKCS#7 / CMS
    // =========================================================================
    ("data", &[1, 2, 840, 113549, 1, 7, 1]),
    ("signedData", &[1, 2, 840, 113549, 1, 7, 2]),
    ("envelopedData", &[1, 2, 840, 113549, 1, 7, 3]),
    ("signedAndEnvelopedData", &[1, 2, 840, 113549, 1, 7, 4]),
    ("digestedData", &[1, 2, 840, 113549, 1, 7, 5]),
    ("encryptedData", &[1, 2, 840, 113549, 1, 7, 6]),
    // =========================================================================
    // PKCS#9 ATTRIBUTES
    // =========================================================================
    ("contentType", &[1, 2, 840, 113549, 1, 9, 3]),
    ("messageDigest", &[1, 2, 840, 113549, 1, 9, 4]),
    ("signingTime", &[1, 2, 840, 113549, 1, 9, 5]),
    ("challengePassword", &[1, 2, 840, 113549, 1, 9, 7]),
    ("extensionRequest", &[1, 2, 840, 113549, 1, 9, 14]),
    // =========================================================================
    // ENCRYPTION ALGORITHMS
    // =========================================================================
    ("aes128-CBC", &[2, 16, 840, 1, 101, 3, 4, 1, 2]),
    ("aes192-CBC", &[2, 16, 840, 1, 101, 3, 4, 1, 22]),
    ("aes256-CBC", &[2, 16, 840, 1, 101, 3, 4, 1, 42]),
    ("aes128-GCM", &[2, 16, 840, 1, 101, 3, 4, 1, 6]),
    ("aes192-GCM", &[2, 16, 840, 1, 101, 3, 4, 1, 26]),
    ("aes256-GCM", &[2, 16, 840, 1, 101, 3, 4, 1, 46]),
    ("des-CBC", &[1, 3, 14, 3, 2, 7]),
    ("des-EDE3-CBC", &[1, 2, 840, 113549, 3, 7]),
    // =========================================================================
    // PKCS#5 / PKCS#12
    // =========================================================================
    ("pbeWithMD5AndDES-CBC", &[1, 2, 840, 113549, 1, 5, 3]),
    ("pbeWithSHA1AndDES-CBC", &[1, 2, 840, 113549, 1, 5, 10]),
    (
        "pbeWithSHA1And3-KeyTripleDES-CBC",
        &[1, 2, 840, 113549, 1, 12, 1, 3],
    ),
    ("pbeWithSHA1And128BitRC4", &[1, 2, 840, 113549, 1, 12, 1, 1]),
    ("pbkdf2", &[1, 2, 840, 113549, 1, 5, 12]),
    ("pbes2", &[1, 2, 840, 113549, 1, 5, 13]),
];

//=============================================================================
// OID CONSTANTS (for convenience)
//=============================================================================

/// RSA encryption OID
pub const OID_RSA_ENCRYPTION: &[u32] = &[1, 2, 840, 113549, 1, 1, 1];

/// SHA-256 with RSA encryption OID
pub const OID_SHA256_WITH_RSA: &[u32] = &[1, 2, 840, 113549, 1, 1, 11];

/// SHA-384 with RSA encryption OID
pub const OID_SHA384_WITH_RSA: &[u32] = &[1, 2, 840, 113549, 1, 1, 12];

/// SHA-512 with RSA encryption OID
pub const OID_SHA512_WITH_RSA: &[u32] = &[1, 2, 840, 113549, 1, 1, 13];

/// EC public key OID
pub const OID_EC_PUBLIC_KEY: &[u32] = &[1, 2, 840, 10045, 2, 1];

/// ECDSA with SHA-256 OID
pub const OID_ECDSA_WITH_SHA256: &[u32] = &[1, 2, 840, 10045, 4, 3, 2];

/// Ed25519 OID
pub const OID_ED25519: &[u32] = &[1, 3, 101, 112];

/// X25519 OID
pub const OID_X25519: &[u32] = &[1, 3, 101, 110];

/// P-256 curve OID (secp256r1/prime256v1)
pub const OID_SECP256R1: &[u32] = &[1, 2, 840, 10045, 3, 1, 7];

/// P-384 curve OID (secp384r1)
pub const OID_SECP384R1: &[u32] = &[1, 3, 132, 0, 34];

/// secp256k1 curve OID (Bitcoin)
pub const OID_SECP256K1: &[u32] = &[1, 3, 132, 0, 10];

/// Common Name OID
pub const OID_COMMON_NAME: &[u32] = &[2, 5, 4, 3];

/// Organization Name OID
pub const OID_ORGANIZATION_NAME: &[u32] = &[2, 5, 4, 10];

/// Organizational Unit OID
pub const OID_ORGANIZATIONAL_UNIT: &[u32] = &[2, 5, 4, 11];

/// Country Name OID
pub const OID_COUNTRY_NAME: &[u32] = &[2, 5, 4, 6];

/// State/Province OID
pub const OID_STATE_OR_PROVINCE: &[u32] = &[2, 5, 4, 8];

/// Locality OID
pub const OID_LOCALITY_NAME: &[u32] = &[2, 5, 4, 7];

/// Email Address OID
pub const OID_EMAIL_ADDRESS: &[u32] = &[1, 2, 840, 113549, 1, 9, 1];

/// Basic Constraints extension OID
pub const OID_BASIC_CONSTRAINTS: &[u32] = &[2, 5, 29, 19];

/// Key Usage extension OID
pub const OID_KEY_USAGE: &[u32] = &[2, 5, 29, 15];

/// Extended Key Usage extension OID
pub const OID_EXT_KEY_USAGE: &[u32] = &[2, 5, 29, 37];

/// Subject Alternative Name extension OID
pub const OID_SUBJECT_ALT_NAME: &[u32] = &[2, 5, 29, 17];

/// Subject Key Identifier extension OID
pub const OID_SUBJECT_KEY_IDENTIFIER: &[u32] = &[2, 5, 29, 14];

/// Authority Key Identifier extension OID
pub const OID_AUTHORITY_KEY_IDENTIFIER: &[u32] = &[2, 5, 29, 35];

/// Server Authentication EKU OID
pub const OID_SERVER_AUTH: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];

/// Client Authentication EKU OID
pub const OID_CLIENT_AUTH: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 3, 2];

//=============================================================================
// HELPER FUNCTIONS
//=============================================================================

/// Look up OID name from components
pub fn oid_name(components: &[u32]) -> Option<&'static str> {
    KNOWN_OIDS
        .iter()
        .find(|(_, oid)| *oid == components)
        .map(|(name, _)| *name)
}

/// Look up OID components from name
pub fn oid_by_name(name: &str) -> Option<&'static [u32]> {
    KNOWN_OIDS
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, oid)| *oid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_from_str() {
        let oid = Oid::from_str("1.2.840.113549.1.1.1").unwrap();
        assert_eq!(oid.components, vec![1, 2, 840, 113549, 1, 1, 1]);
    }

    #[test]
    fn test_oid_to_string() {
        let oid = Oid::from_slice(&[1, 2, 840, 113549, 1, 1, 1]);
        assert_eq!(oid.to_string(), "1.2.840.113549.1.1.1");
    }

    #[test]
    fn test_oid_name_lookup() {
        assert_eq!(oid_name(OID_RSA_ENCRYPTION), Some("rsaEncryption"));
        assert_eq!(oid_name(OID_COMMON_NAME), Some("commonName"));
        assert_eq!(oid_name(OID_ED25519), Some("ed25519"));
    }

    #[test]
    fn test_oid_by_name() {
        assert_eq!(oid_by_name("rsaEncryption"), Some(OID_RSA_ENCRYPTION));
        assert_eq!(oid_by_name("commonName"), Some(OID_COMMON_NAME));
        assert_eq!(oid_by_name("RSAENCRYPTION"), Some(OID_RSA_ENCRYPTION)); // case insensitive
    }

    #[test]
    fn test_oid_asn1() {
        let oid = Oid::from_slice(OID_RSA_ENCRYPTION);
        let asn1 = oid.to_asn1();

        if let Asn1Value::ObjectIdentifier(comps) = asn1 {
            assert_eq!(comps, OID_RSA_ENCRYPTION);
        } else {
            panic!("Expected ObjectIdentifier");
        }
    }
}
