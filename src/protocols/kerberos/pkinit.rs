//! PKINIT - Public Key Cryptography for Initial Authentication (RFC 4556)
//!
//! PKINIT allows using X.509 certificates instead of passwords for Kerberos
//! authentication. This is commonly used in Active Directory with:
//! - Smart cards
//! - Certificates issued by AD CS
//! - Shadow credentials attacks
//!
//! # Attack Vectors
//!
//! 1. **Certificate abuse**: Use stolen/forged certificates to get TGTs
//! 2. **Shadow credentials**: Add KeyCredential to user, use for auth
//! 3. **Certificate theft**: Extract certificates from DPAPI
//!
//! # Protocol Flow
//!
//! ```text
//! Client                                          KDC
//!   |                                              |
//!   |  AS-REQ (PA-PK-AS-REQ with signed AuthPack)  |
//!   |--------------------------------------------->|
//!   |                                              |
//!   |  AS-REP (PA-PK-AS-REP with encrypted key)    |
//!   |<---------------------------------------------|
//!   |                                              |
//! ```

use super::types::{
  AsReq, EncryptionKey, EncryptionType, KdcReqBody, KerberosTime, PaData, PaDataType,
  PrincipalName, Realm,
};
use crate::protocols::ecdh;

// ═══════════════════════════════════════════════════════════════════════════
// PKINIT OIDs
// ═══════════════════════════════════════════════════════════════════════════

/// OID: id-pkinit-authData (1.3.6.1.5.2.3.1)
const OID_PKINIT_AUTH_DATA: &[u64] = &[1, 3, 6, 1, 5, 2, 3, 1];

/// OID: id-pkinit-DHKeyData (1.3.6.1.5.2.3.2)
const OID_PKINIT_DH_KEY_DATA: &[u64] = &[1, 3, 6, 1, 5, 2, 3, 2];

/// OID: id-pkinit-rkeyData (1.3.6.1.5.2.3.3)
const OID_PKINIT_RKEY_DATA: &[u64] = &[1, 3, 6, 1, 5, 2, 3, 3];

/// OID: szOID_NT_PRINCIPAL_NAME (1.3.6.1.4.1.311.20.2.3)
const OID_MS_UPN: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 20, 2, 3];

/// OID: id-dh-sig-hmac-sha1 (1.3.6.1.5.2.3.4)
const OID_DH_SIG_HMAC_SHA1: &[u64] = &[1, 3, 6, 1, 5, 2, 3, 4];

// ═══════════════════════════════════════════════════════════════════════════
// AuthPack - The signed data in PA-PK-AS-REQ
// ═══════════════════════════════════════════════════════════════════════════

/// PKAuthenticator - authenticator in AuthPack
#[derive(Debug, Clone)]
pub struct PkAuthenticator {
  /// Current client time
  pub cusec: u32,
  /// Microseconds
  pub ctime: KerberosTime,
  /// Random nonce
  pub nonce: u32,
  /// Hash of KDC-REQ-BODY (for binding)
  pub pa_checksum: Option<Vec<u8>>,
}

impl PkAuthenticator {
  pub fn new(nonce: u32) -> Self {
    Self {
      cusec: 0,
      ctime: KerberosTime::now(),
      nonce,
      pa_checksum: None,
    }
  }

  pub fn with_checksum(mut self, checksum: Vec<u8>) -> Self {
    self.pa_checksum = Some(checksum);
    self
  }

  /// Encode as DER
  pub fn encode_der(&self) -> Vec<u8> {
    // PKAuthenticator ::= SEQUENCE {
    //     cusec        [0] INTEGER,
    //     ctime        [1] KerberosTime,
    //     nonce        [2] INTEGER,
    //     paChecksum   [3] OCTET STRING OPTIONAL
    // }
    let mut body = Vec::new();

    // cusec [0]
    body.extend_from_slice(&encode_tagged(0, &encode_integer(self.cusec as i32)));

    // ctime [1]
    body.extend_from_slice(&encode_tagged(1, &self.ctime.encode_der()));

    // nonce [2]
    body.extend_from_slice(&encode_tagged(2, &encode_integer(self.nonce as i32)));

    // paChecksum [3] OPTIONAL
    if let Some(ref checksum) = self.pa_checksum {
      body.extend_from_slice(&encode_tagged(3, &encode_octet_string(checksum)));
    }

    encode_sequence(&body)
  }
}

/// AuthPack - the content of SignedData in PA-PK-AS-REQ
#[derive(Debug, Clone)]
pub struct AuthPack {
  /// PKAuthenticator
  pub pk_authenticator: PkAuthenticator,
  /// Client's Diffie-Hellman public value (for DH key agreement)
  pub client_public_value: Option<Vec<u8>>,
  /// Supported CMS algorithms (for encryption of reply key)
  pub supported_cms_types: Vec<Vec<u64>>,
  /// Client DH nonce (for key derivation)
  pub client_dh_nonce: Option<Vec<u8>>,
}

impl AuthPack {
  pub fn new(pk_authenticator: PkAuthenticator) -> Self {
    Self {
      pk_authenticator,
      client_public_value: None,
      supported_cms_types: Vec::new(),
      client_dh_nonce: None,
    }
  }

  pub fn with_dh_public_value(mut self, public_value: Vec<u8>, dh_nonce: Vec<u8>) -> Self {
    self.client_public_value = Some(public_value);
    self.client_dh_nonce = Some(dh_nonce);
    self
  }

  /// Encode as DER
  pub fn encode_der(&self) -> Vec<u8> {
    // AuthPack ::= SEQUENCE {
    //     pkAuthenticator    [0] PKAuthenticator,
    //     clientPublicValue  [1] SubjectPublicKeyInfo OPTIONAL,
    //     supportedCMSTypes  [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
    //     clientDHNonce      [3] DHNonce OPTIONAL
    // }
    let mut body = Vec::new();

    // pkAuthenticator [0]
    body.extend_from_slice(&encode_tagged(0, &self.pk_authenticator.encode_der()));

    // clientPublicValue [1] OPTIONAL
    if let Some(ref public_value) = self.client_public_value {
      body.extend_from_slice(&encode_tagged(1, public_value));
    }

    // supportedCMSTypes [2] OPTIONAL - typically omit for simplicity

    // clientDHNonce [3] OPTIONAL
    if let Some(ref dh_nonce) = self.client_dh_nonce {
      body.extend_from_slice(&encode_tagged(3, &encode_octet_string(dh_nonce)));
    }

    encode_sequence(&body)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// PA-PK-AS-REQ - The pre-authentication data for PKINIT
// ═══════════════════════════════════════════════════════════════════════════

/// PA-PK-AS-REQ - PKINIT request
#[derive(Debug, Clone)]
pub struct PaPkAsReq {
  /// SignedData containing AuthPack (CMS SignedData)
  pub signed_auth_pack: Vec<u8>,
  /// Trusted CA certificates (for cert path validation hints)
  pub trusted_certifiers: Option<Vec<Vec<u8>>>,
  /// KDC certificate issuer and serial (for cert selection)
  pub kdc_pk_id: Option<Vec<u8>>,
}

impl PaPkAsReq {
  /// Create a new PA-PK-AS-REQ from signed auth pack
  pub fn new(signed_auth_pack: Vec<u8>) -> Self {
    Self {
      signed_auth_pack,
      trusted_certifiers: None,
      kdc_pk_id: None,
    }
  }

  /// Encode as DER
  pub fn encode_der(&self) -> Vec<u8> {
    // PA-PK-AS-REQ ::= SEQUENCE {
    //     signedAuthPack     [0] IMPLICIT OCTET STRING,
    //     trustedCertifiers  [1] SEQUENCE OF ExternalPrincipalIdentifier OPTIONAL,
    //     kdcPkId            [2] IMPLICIT OCTET STRING OPTIONAL
    // }
    let mut body = Vec::new();

    // signedAuthPack [0] IMPLICIT
    body.extend_from_slice(&encode_implicit_tagged(0, &self.signed_auth_pack));

    // trustedCertifiers [1] OPTIONAL - skip for now

    // kdcPkId [2] OPTIONAL - skip for now

    encode_sequence(&body)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// PA-PK-AS-REP - The pre-authentication reply
// ═══════════════════════════════════════════════════════════════════════════

/// PA-PK-AS-REP - PKINIT reply
#[derive(Debug)]
pub struct PaPkAsRep {
  /// DH key agreement reply (when using DH)
  pub dh_rep_info: Option<DhRepInfo>,
  /// Encrypted reply key (when using RSA key transport)
  pub enc_key_pack: Option<Vec<u8>>,
}

impl PaPkAsRep {
  /// Parse from DER bytes
  pub fn decode_der(data: &[u8]) -> Result<Self, String> {
    use crate::protocols::asn1::{Asn1Object, Asn1Value};

    let (obj, _) = Asn1Object::from_der(data)?;

    match obj.value {
      Asn1Value::ContextSpecific(0, bytes) => {
        // DH key agreement
        let dh_rep_info = DhRepInfo::decode_der(&bytes)?;
        Ok(Self {
          dh_rep_info: Some(dh_rep_info),
          enc_key_pack: None,
        })
      }
      Asn1Value::ContextSpecific(1, bytes) => {
        // RSA key transport (encKeyPack)
        Ok(Self {
          dh_rep_info: None,
          enc_key_pack: Some(bytes),
        })
      }
      _ => Err("Invalid PA-PK-AS-REP structure".to_string()),
    }
  }
}

/// DHRepInfo - DH key agreement reply info
#[derive(Debug)]
pub struct DhRepInfo {
  /// SignedData containing KDCDHKeyInfo
  pub dh_signed_data: Vec<u8>,
  /// KDC's nonce for key derivation
  pub server_dh_nonce: Option<Vec<u8>>,
}

impl DhRepInfo {
  pub fn decode_der(data: &[u8]) -> Result<Self, String> {
    use crate::protocols::asn1::{Asn1Object, Asn1Value};

    let (obj, _) = Asn1Object::from_der(data)?;

    match obj.value {
      Asn1Value::Sequence(fields) => {
        let mut dh_signed_data = None;
        let mut server_dh_nonce = None;

        for field in fields {
          if let Asn1Value::ContextSpecific(tag, bytes) = field.value {
            match tag {
              0 => dh_signed_data = Some(bytes),
              1 => {
                let (inner, _) = Asn1Object::from_der(&bytes)?;
                if let Asn1Value::OctetString(nonce) = inner.value {
                  server_dh_nonce = Some(nonce);
                }
              }
              _ => {}
            }
          }
        }

        Ok(Self {
          dh_signed_data: dh_signed_data.ok_or("Missing dhSignedData")?,
          server_dh_nonce,
        })
      }
      _ => Err("Expected SEQUENCE".to_string()),
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CMS SignedData (simplified)
// ═══════════════════════════════════════════════════════════════════════════

/// Create CMS SignedData structure
///
/// This is a simplified implementation for PKINIT.
/// A full CMS implementation would be much more complex.
pub struct SignedData;

impl SignedData {
  /// Create SignedData for AuthPack
  ///
  /// # Arguments
  /// * `content` - The AuthPack to sign
  /// * `cert` - The signing certificate (DER-encoded)
  /// * `private_key` - The private key for signing
  pub fn create(content: &[u8], cert: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
    // ContentInfo OID for SignedData: 1.2.840.113549.1.7.2
    let signed_data_oid = encode_oid(&[1, 2, 840, 113549, 1, 7, 2]);

    // Create SignerInfo
    let digest = crate::crypto::sha256::sha256(content);
    let signature = sign_with_key(private_key, &digest)?;

    let signer_info = Self::build_signer_info(&signature, cert)?;

    // Build SignedData
    let signed_data = Self::build_signed_data(content, cert, &signer_info);

    // Wrap in ContentInfo
    let mut result = Vec::new();
    result.extend_from_slice(&encode_sequence(
      &[signed_data_oid, encode_tagged(0, &signed_data)].concat(),
    ));

    Ok(result)
  }

  fn build_signer_info(signature: &[u8], _cert: &[u8]) -> Result<Vec<u8>, String> {
    // SignerInfo ::= SEQUENCE {
    //     version CMSVersion,
    //     sid SignerIdentifier,
    //     digestAlgorithm DigestAlgorithmIdentifier,
    //     signatureAlgorithm SignatureAlgorithmIdentifier,
    //     signature SignatureValue
    // }

    let version = encode_integer(1); // CMSVersion

    // SHA-256 OID: 2.16.840.1.101.3.4.2.1
    let sha256_oid = encode_oid(&[2, 16, 840, 1, 101, 3, 4, 2, 1]);
    let digest_algo = encode_sequence(&[sha256_oid, vec![0x05, 0x00]].concat()); // with NULL

    // RSA with SHA-256 OID: 1.2.840.113549.1.1.11
    let sig_algo_oid = encode_oid(&[1, 2, 840, 113549, 1, 1, 11]);
    let sig_algo = encode_sequence(&[sig_algo_oid, vec![0x05, 0x00]].concat());

    // SignerIdentifier - use issuerAndSerialNumber (simplified)
    let sid = encode_sequence(&[]); // Placeholder

    let sig_value = encode_octet_string(signature);

    Ok(encode_sequence(
      &[version, sid, digest_algo, sig_algo, sig_value].concat(),
    ))
  }

  fn build_signed_data(content: &[u8], cert: &[u8], signer_info: &[u8]) -> Vec<u8> {
    // SignedData ::= SEQUENCE {
    //     version CMSVersion,
    //     digestAlgorithms SET OF DigestAlgorithmIdentifier,
    //     encapContentInfo EncapsulatedContentInfo,
    //     certificates [0] IMPLICIT CertificateSet OPTIONAL,
    //     signerInfos SET OF SignerInfo
    // }

    let version = encode_integer(3); // CMSVersion

    // digestAlgorithms - SHA-256
    let sha256_oid = encode_oid(&[2, 16, 840, 1, 101, 3, 4, 2, 1]);
    let digest_algos = encode_set(&encode_sequence(&[sha256_oid, vec![0x05, 0x00]].concat()));

    // encapContentInfo
    let content_type = encode_oid(OID_PKINIT_AUTH_DATA);
    let content_wrapped = encode_tagged(0, &encode_octet_string(content));
    let encap_content = encode_sequence(&[content_type, content_wrapped].concat());

    // certificates [0] IMPLICIT
    let certs = encode_implicit_tagged(0, cert);

    // signerInfos
    let signer_infos = encode_set(signer_info);

    encode_sequence(&[version, digest_algos, encap_content, certs, signer_infos].concat())
  }
}

/// Sign data with private key (placeholder - would use RSA/ECDSA)
fn sign_with_key(private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
  // This is a placeholder. Real implementation would:
  // 1. Parse the private key (PKCS#8 or PKCS#1)
  // 2. Sign using RSA-SHA256 or ECDSA

  // For now, create a dummy signature
  let mut signature = Vec::with_capacity(256);
  signature.extend_from_slice(&data[..data.len().min(128)]);
  signature.extend_from_slice(private_key);
  signature.truncate(256);

  Ok(signature)
}

// ═══════════════════════════════════════════════════════════════════════════
// PKINIT Client
// ═══════════════════════════════════════════════════════════════════════════

/// PKINIT client for certificate-based authentication
pub struct PkinitClient {
  /// User's certificate (DER-encoded)
  pub certificate: Vec<u8>,
  /// User's private key (DER-encoded)
  pub private_key: Vec<u8>,
  /// Target realm
  pub realm: Realm,
  /// Target user principal
  pub cname: PrincipalName,
}

impl PkinitClient {
  /// Create a new PKINIT client
  pub fn new(certificate: Vec<u8>, private_key: Vec<u8>, realm: &str, username: &str) -> Self {
    Self {
      certificate,
      private_key,
      realm: Realm::new(realm),
      cname: PrincipalName::user(username),
    }
  }

  /// Build AS-REQ with PKINIT pre-authentication
  pub fn build_as_req(&self, nonce: u32) -> Result<AsReq, String> {
    // Build KDC-REQ-BODY
    let req_body = KdcReqBody::for_as_req(self.cname.clone(), self.realm.clone(), nonce);

    // Calculate paChecksum (SHA1 hash of req_body DER)
    let req_body_der = req_body.encode_der();
    let pa_checksum = crate::crypto::sha1::sha1(&req_body_der).to_vec();

    // Build PKAuthenticator
    let pk_authenticator = PkAuthenticator::new(nonce).with_checksum(pa_checksum);

    // Build AuthPack (without DH for RSA key transport)
    let auth_pack = AuthPack::new(pk_authenticator);
    let auth_pack_der = auth_pack.encode_der();

    // Sign AuthPack using CMS SignedData
    let signed_auth_pack =
      SignedData::create(&auth_pack_der, &self.certificate, &self.private_key)?;

    // Build PA-PK-AS-REQ
    let pa_pk_as_req = PaPkAsReq::new(signed_auth_pack);
    let pa_pk_as_req_der = pa_pk_as_req.encode_der();

    // Build PA-DATA
    let padata = vec![
      PaData::new(PaDataType::PkAsReq, pa_pk_as_req_der),
      PaData::pac_request(true),
    ];

    // Build AS-REQ
    let as_req = AsReq::new(req_body).with_padata(padata);

    Ok(as_req)
  }

  /// Build AS-REQ with DH key agreement
  pub fn build_as_req_dh(&self, nonce: u32) -> Result<(AsReq, [u8; 32]), String> {
    // Generate ECDH keypair for DH key agreement
    let keypair = ecdh::EcdhKeyPair::generate()?;
    let public_dh = keypair.public_key_bytes();

    // Build KDC-REQ-BODY
    let req_body = KdcReqBody::for_as_req(self.cname.clone(), self.realm.clone(), nonce);

    // Calculate paChecksum
    let req_body_der = req_body.encode_der();
    let pa_checksum = crate::crypto::sha1::sha1(&req_body_der).to_vec();

    // Build PKAuthenticator
    let pk_authenticator = PkAuthenticator::new(nonce).with_checksum(pa_checksum);

    // Generate DH nonce
    let dh_nonce = generate_random_bytes(32);

    // Build SubjectPublicKeyInfo for our DH public value
    let spki = encode_subject_public_key_info(&public_dh);

    // Build AuthPack with DH
    let auth_pack = AuthPack::new(pk_authenticator).with_dh_public_value(spki, dh_nonce);
    let auth_pack_der = auth_pack.encode_der();

    // Sign AuthPack
    let signed_auth_pack =
      SignedData::create(&auth_pack_der, &self.certificate, &self.private_key)?;

    // Build PA-PK-AS-REQ
    let pa_pk_as_req = PaPkAsReq::new(signed_auth_pack);
    let pa_pk_as_req_der = pa_pk_as_req.encode_der();

    // Build PA-DATA
    let padata = vec![
      PaData::new(PaDataType::PkAsReq, pa_pk_as_req_der),
      PaData::pac_request(true),
    ];

    // Build AS-REQ
    let as_req = AsReq::new(req_body).with_padata(padata);

    // Return private key bytes for shared secret computation
    // Note: We need to extract private key from keypair for later use
    let private_bytes = extract_private_key_bytes(&keypair);
    Ok((as_req, private_bytes))
  }

  /// Process AS-REP and extract session key
  pub fn process_as_rep_dh(
    &self,
    as_rep: &super::types::AsRep,
    _private_dh: &[u8; 32],
  ) -> Result<EncryptionKey, String> {
    // Find PA-PK-AS-REP in padata
    let pa_pk_as_rep = as_rep
      .padata
      .iter()
      .find(|p| p.padata_type == PaDataType::PkAsRep)
      .ok_or("Missing PA-PK-AS-REP in response")?;

    // Parse PA-PK-AS-REP
    let pk_as_rep = PaPkAsRep::decode_der(&pa_pk_as_rep.padata_value)?;

    if let Some(dh_rep_info) = pk_as_rep.dh_rep_info {
      // Extract KDC's DH public value from the signed data
      // (This is simplified - real implementation would verify signature)
      let _kdc_public = extract_dh_public_value(&dh_rep_info.dh_signed_data)?;

      // Note: For proper implementation, we'd need to:
      // 1. Reconstruct the keypair from private_dh
      // 2. Parse kdc_public into P256Point
      // 3. Compute shared secret
      // For now, derive from the nonce as a placeholder
      let session_key = derive_session_key(&[0u8; 32], &dh_rep_info.server_dh_nonce);

      Ok(EncryptionKey::new(
        EncryptionType::Aes256CtsHmacSha1,
        session_key.to_vec(),
      ))
    } else {
      // RSA key transport case
      Err("RSA key transport not implemented - use DH mode".to_string())
    }
  }
}

/// Extract private key bytes from ECDH keypair (placeholder implementation)
fn extract_private_key_bytes(_keypair: &ecdh::EcdhKeyPair) -> [u8; 32] {
  // The EcdhKeyPair struct keeps private key internal
  // For now, return zeros - real implementation would need access to private key
  // This is a limitation of the current ecdh module design
  [0u8; 32]
}

/// Extract DH public value from signed data (simplified)
fn extract_dh_public_value(signed_data: &[u8]) -> Result<[u8; 32], String> {
  // This is a placeholder. Real implementation would:
  // 1. Parse CMS SignedData
  // 2. Verify signature
  // 3. Extract KDCDHKeyInfo
  // 4. Extract subjectPublicKey

  // For now, assume the public key is at the end of the data
  if signed_data.len() < 32 {
    return Err("Signed data too short".to_string());
  }

  let mut key = [0u8; 32];
  key.copy_from_slice(&signed_data[signed_data.len() - 32..]);
  Ok(key)
}

/// Derive session key from DH shared secret
fn derive_session_key(shared_secret: &[u8; 32], server_nonce: &Option<Vec<u8>>) -> [u8; 32] {
  // Per RFC 4556, the key derivation uses:
  // K = SHA-1(DHSharedKey || "pkinit" || nonces)

  let mut input = shared_secret.to_vec();
  input.extend_from_slice(b"pkinit");
  if let Some(nonce) = server_nonce {
    input.extend_from_slice(nonce);
  }

  // Use SHA-256 for 32-byte key output
  crate::crypto::sha256::sha256(&input)
}

/// Generate random bytes
fn generate_random_bytes(len: usize) -> Vec<u8> {
  use std::time::{SystemTime, UNIX_EPOCH};
  let seed = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_nanos() as u64;

  let mut state = seed;
  let mut result = Vec::with_capacity(len);

  for _ in 0..len {
    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    result.push((state >> 56) as u8);
  }

  result
}

// ═══════════════════════════════════════════════════════════════════════════
// ASN.1 Encoding Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn encode_length(len: usize) -> Vec<u8> {
  if len < 128 {
    vec![len as u8]
  } else if len < 256 {
    vec![0x81, len as u8]
  } else if len < 65536 {
    vec![0x82, (len >> 8) as u8, len as u8]
  } else {
    vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
  }
}

fn encode_sequence(content: &[u8]) -> Vec<u8> {
  let mut result = vec![0x30];
  result.extend_from_slice(&encode_length(content.len()));
  result.extend_from_slice(content);
  result
}

fn encode_set(content: &[u8]) -> Vec<u8> {
  let mut result = vec![0x31];
  result.extend_from_slice(&encode_length(content.len()));
  result.extend_from_slice(content);
  result
}

fn encode_tagged(tag: u8, content: &[u8]) -> Vec<u8> {
  let mut result = vec![0xA0 | tag];
  result.extend_from_slice(&encode_length(content.len()));
  result.extend_from_slice(content);
  result
}

fn encode_implicit_tagged(tag: u8, content: &[u8]) -> Vec<u8> {
  let mut result = vec![0x80 | tag];
  result.extend_from_slice(&encode_length(content.len()));
  result.extend_from_slice(content);
  result
}

fn encode_integer(value: i32) -> Vec<u8> {
  let bytes = value.to_be_bytes();
  let mut start = 0;
  while start < 3 && bytes[start] == 0 && (bytes[start + 1] & 0x80) == 0 {
    start += 1;
  }

  if value >= 0 && (bytes[start] & 0x80) != 0 {
    let len = 4 - start + 1;
    let mut result = vec![0x02, len as u8, 0x00];
    result.extend_from_slice(&bytes[start..]);
    return result;
  }

  let len = 4 - start;
  let mut result = vec![0x02, len as u8];
  result.extend_from_slice(&bytes[start..]);
  result
}

fn encode_octet_string(data: &[u8]) -> Vec<u8> {
  let mut result = vec![0x04];
  result.extend_from_slice(&encode_length(data.len()));
  result.extend_from_slice(data);
  result
}

fn encode_oid(oid: &[u64]) -> Vec<u8> {
  if oid.len() < 2 {
    return vec![0x06, 0x00];
  }

  let mut content = Vec::new();

  // First two components encoded together
  content.push((oid[0] * 40 + oid[1]) as u8);

  // Remaining components use base-128 encoding
  for &component in &oid[2..] {
    if component == 0 {
      content.push(0);
    } else {
      let mut bytes = Vec::new();
      let mut val = component;
      while val > 0 {
        bytes.push((val & 0x7f) as u8);
        val >>= 7;
      }
      bytes.reverse();
      for (i, byte) in bytes.iter().enumerate() {
        if i < bytes.len() - 1 {
          content.push(byte | 0x80);
        } else {
          content.push(*byte);
        }
      }
    }
  }

  let mut result = vec![0x06];
  result.extend_from_slice(&encode_length(content.len()));
  result.extend_from_slice(&content);
  result
}

fn encode_subject_public_key_info(public_key: &[u8]) -> Vec<u8> {
  // SubjectPublicKeyInfo for X25519 (simplified)
  // OID for X25519: 1.3.101.110
  let algo_oid = encode_oid(&[1, 3, 101, 110]);
  let algo_id = encode_sequence(&algo_oid);

  // BIT STRING containing the public key
  let mut bit_string = vec![0x03];
  bit_string.extend_from_slice(&encode_length(public_key.len() + 1));
  bit_string.push(0x00); // unused bits
  bit_string.extend_from_slice(public_key);

  encode_sequence(&[algo_id, bit_string].concat())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_pk_authenticator_encode() {
    let pk_auth = PkAuthenticator::new(12345);
    let der = pk_auth.encode_der();

    // Should be a valid SEQUENCE
    assert_eq!(der[0], 0x30);
    assert!(der.len() > 10);
  }

  #[test]
  fn test_auth_pack_encode() {
    let pk_auth = PkAuthenticator::new(12345);
    let auth_pack = AuthPack::new(pk_auth);
    let der = auth_pack.encode_der();

    assert_eq!(der[0], 0x30);
    assert!(der.len() > 20);
  }

  #[test]
  fn test_pa_pk_as_req_encode() {
    let signed_data = vec![0x01, 0x02, 0x03];
    let pa_pk_as_req = PaPkAsReq::new(signed_data);
    let der = pa_pk_as_req.encode_der();

    assert_eq!(der[0], 0x30);
  }

  #[test]
  fn test_pkinit_client_build_as_req() {
    let cert = vec![0x30, 0x82, 0x01, 0x00]; // Dummy cert
    let private_key = vec![0x30, 0x82, 0x01, 0x00]; // Dummy key

    let client = PkinitClient::new(cert, private_key, "CORP.LOCAL", "testuser");

    let as_req = client.build_as_req(12345678).unwrap();

    // Should have PA-DATA
    assert!(!as_req.padata.is_empty());

    // Should have PKINIT PA-DATA
    assert!(as_req
      .padata
      .iter()
      .any(|p| p.padata_type == PaDataType::PkAsReq));
  }

  #[test]
  fn test_oid_encoding() {
    // OID 1.2.840.113549.1.7.2
    let oid = encode_oid(&[1, 2, 840, 113549, 1, 7, 2]);
    assert_eq!(oid[0], 0x06); // OID tag
    assert!(oid.len() > 2);
  }
}
