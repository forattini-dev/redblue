//! Kerberos AP (Application Protocol) Types
//!
//! AP-REQ, AP-REP, Authenticator, and KDC-REP structures.

use super::encoding::*;
use super::enums::*;
use super::flags::ApOptions;
use super::primitives::*;

/// AP-REQ message (RFC 4120 5.5.1)
#[derive(Debug, Clone)]
pub struct ApReq {
  pub pvno: u32,
  pub msg_type: MessageType,
  pub ap_options: ApOptions,
  pub ticket: Ticket,
  pub authenticator: EncryptedData,
}

impl ApReq {
  pub fn encode(&self) -> Vec<u8> {
    self.encode_der()
  }

  pub fn encode_der(&self) -> Vec<u8> {
    let pvno = encode_tagged(0, &encode_integer(self.pvno as i32));
    let msg_type = encode_tagged(1, &encode_integer(self.msg_type as i32));
    let ap_options = encode_tagged(2, &self.ap_options.encode_der());
    let ticket = encode_tagged(3, &self.ticket.encode_der());
    let authenticator = encode_tagged(4, &self.authenticator.encode_der());

    let mut body = pvno;
    body.extend_from_slice(&msg_type);
    body.extend_from_slice(&ap_options);
    body.extend_from_slice(&ticket);
    body.extend_from_slice(&authenticator);

    encode_application(14, &encode_sequence(&body))
  }
}

/// AP-REP message (RFC 4120 5.5.2)
#[derive(Debug, Clone)]
pub struct ApRep {
  pub pvno: u32,
  pub msg_type: MessageType,
  pub enc_part: EncryptedData,
}

impl ApRep {
  pub fn decode(der: &[u8]) -> Result<Self, String> {
    // Parse APPLICATION 15
    if der.is_empty() || (der[0] & 0x1f) != 15 {
      return Err("Not an AP-REP".to_string());
    }
    // Simplified decoding
    Ok(Self {
      pvno: 5,
      msg_type: MessageType::ApRep,
      enc_part: EncryptedData {
        etype: EncryptionType::Aes256CtsHmacSha1,
        kvno: None,
        cipher: vec![],
      },
    })
  }
}

/// KDC-REP common structure (used internally)
#[derive(Debug, Clone)]
pub struct KdcRep {
  pub pvno: u32,
  pub msg_type: MessageType,
  pub padata: Vec<PaData>,
  pub crealm: Realm,
  pub cname: PrincipalName,
  pub ticket: Ticket,
  pub enc_part: EncryptedData,
}

/// Authenticator (RFC 4120 5.5.1)
#[derive(Debug, Clone)]
pub struct Authenticator {
  pub authenticator_vno: u32,
  pub crealm: Realm,
  pub cname: PrincipalName,
  pub cksum: Option<Checksum>,
  pub cusec: u32,
  pub ctime: KerberosTime,
  pub subkey: Option<EncryptionKey>,
  pub seq_number: Option<u32>,
  pub authorization_data: Option<Vec<u8>>,
}

impl Authenticator {
  pub fn encode(&self) -> Vec<u8> {
    self.encode_der()
  }

  pub fn encode_der(&self) -> Vec<u8> {
    let vno = encode_tagged(0, &encode_integer(self.authenticator_vno as i32));
    let crealm = encode_tagged(1, &self.crealm.encode_der());
    let cname = encode_tagged(2, &self.cname.encode_der());

    let mut body = vno;
    body.extend_from_slice(&crealm);
    body.extend_from_slice(&cname);

    if let Some(ref cksum) = self.cksum {
      body.extend_from_slice(&encode_tagged(3, &cksum.encode_der()));
    }

    body.extend_from_slice(&encode_tagged(4, &encode_integer(self.cusec as i32)));
    body.extend_from_slice(&encode_tagged(5, &self.ctime.encode_der()));

    if let Some(ref subkey) = self.subkey {
      body.extend_from_slice(&encode_tagged(6, &subkey.encode_der()));
    }

    if let Some(seq) = self.seq_number {
      body.extend_from_slice(&encode_tagged(7, &encode_integer(seq as i32)));
    }

    encode_application(2, &encode_sequence(&body))
  }
}
