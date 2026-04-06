//! Kerberos Protocol Types (RFC 4120)
//!
//! ASN.1 structures for Kerberos 5 authentication protocol.
//! Used for PKINIT, S4U, and other Active Directory attacks.
//!
//! # References
//! - RFC 4120: The Kerberos Network Authentication Service (V5)
//! - MS-KILE: Kerberos Protocol Extensions
//! - MS-SFU: Kerberos Protocol Extensions: S4U and PAC

mod ap;
mod encoding;
mod enums;
mod error;
mod flags;
mod messages;
mod primitives;

// Re-export all public types
pub use ap::*;
pub use encoding::*;
pub use enums::*;
pub use error::*;
pub use flags::*;
pub use messages::*;
pub use primitives::*;

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

/// Kerberos version number
pub const KERBEROS_VERSION: u32 = 5;

// ═══════════════════════════════════════════════════════════════════════════
// Traits
// ═══════════════════════════════════════════════════════════════════════════

/// Trait for DER encoding
pub trait DerEncodable {
  fn encode_der(&self) -> Vec<u8>;
}

impl DerEncodable for AsReq {
  fn encode_der(&self) -> Vec<u8> {
    AsReq::encode_der(self)
  }
}

impl DerEncodable for TgsReq {
  fn encode_der(&self) -> Vec<u8> {
    TgsReq::encode_der(self)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_principal_name() {
    let user = PrincipalName::user("administrator");
    assert_eq!(user.name_type, NameType::Principal);
    assert_eq!(user.name_string, vec!["administrator"]);

    let service = PrincipalName::service("ldap", "dc01.corp.local");
    assert_eq!(service.name_type, NameType::SrvInst);
    assert_eq!(service.name_string, vec!["ldap", "dc01.corp.local"]);
  }

  #[test]
  fn test_kerberos_time() {
    let now = KerberosTime::now();
    assert!(now.0.ends_with('Z'));
    assert_eq!(now.0.len(), 15); // YYYYMMDDHHMMSSZ
  }

  #[test]
  fn test_kdc_options() {
    let opts = KdcOptions::new()
      .with(KdcOptions::FORWARDABLE)
      .with(KdcOptions::RENEWABLE);

    assert!(opts.has(KdcOptions::FORWARDABLE));
    assert!(opts.has(KdcOptions::RENEWABLE));
    assert!(!opts.has(KdcOptions::PROXIABLE));
  }

  #[test]
  fn test_as_req_encode() {
    let realm = Realm::new("CORP.LOCAL");
    let cname = PrincipalName::user("testuser");
    let body = KdcReqBody::for_as_req(cname, realm, 12345678);
    let as_req = AsReq::new(body);

    let der = as_req.encode_der();

    // Should start with APPLICATION 10 tag
    assert_eq!(der[0], 0x6A); // 0x60 | 10
    assert!(der.len() > 50); // Reasonable size
  }

  #[test]
  fn test_encryption_type_properties() {
    assert_eq!(EncryptionType::Aes256CtsHmacSha1.key_size(), 32);
    assert_eq!(EncryptionType::Rc4Hmac.key_size(), 16);
    assert_eq!(EncryptionType::Aes256CtsHmacSha1.block_size(), 16);
  }
}
