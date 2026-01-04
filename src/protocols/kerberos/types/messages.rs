//! Kerberos Request/Response Message Types
//!
//! KDC-REQ-BODY, AS-REQ, AS-REP, TGS-REQ, TGS-REP, KRB-ERROR, HostAddress.

use crate::protocols::asn1::{Asn1Object, Asn1Value};

use super::encoding::*;
use super::enums::*;
use super::flags::KdcOptions;
use super::primitives::*;
use super::KERBEROS_VERSION;

/// KDC Request body
#[derive(Debug, Clone)]
pub struct KdcReqBody {
    pub kdc_options: KdcOptions,
    pub cname: Option<PrincipalName>,
    pub realm: Realm,
    pub sname: Option<PrincipalName>,
    pub from: Option<KerberosTime>,
    pub till: KerberosTime,
    pub rtime: Option<KerberosTime>,
    pub nonce: u32,
    pub etype: Vec<EncryptionType>,
    pub addresses: Option<Vec<HostAddress>>,
    pub enc_authorization_data: Option<EncryptedData>,
    pub additional_tickets: Option<Vec<Ticket>>,
}

impl KdcReqBody {
    pub fn for_as_req(cname: PrincipalName, realm: Realm, nonce: u32) -> Self {
        Self {
            kdc_options: KdcOptions::new()
                .with(KdcOptions::FORWARDABLE)
                .with(KdcOptions::RENEWABLE)
                .with(KdcOptions::CANONICALIZE),
            cname: Some(cname),
            realm: realm.clone(),
            sname: Some(PrincipalName::krbtgt(&realm.0)),
            from: None,
            till: KerberosTime::from_offset(8 * 60 * 60), // 8 hours
            rtime: Some(KerberosTime::from_offset(7 * 24 * 60 * 60)), // 7 days
            nonce,
            etype: vec![
                EncryptionType::Aes256CtsHmacSha1,
                EncryptionType::Aes128CtsHmacSha1,
                EncryptionType::Rc4Hmac,
            ],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        }
    }

    pub fn encode_der(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // kdc-options [0] KDCOptions
        let options = encode_bit_string_32(self.kdc_options.0);
        body.extend_from_slice(&encode_tagged(0, &options));

        // cname [1] PrincipalName OPTIONAL
        if let Some(ref cname) = self.cname {
            body.extend_from_slice(&encode_tagged(1, &cname.encode_der()));
        }

        // realm [2] Realm
        body.extend_from_slice(&encode_tagged(2, &self.realm.encode_der()));

        // sname [3] PrincipalName OPTIONAL
        if let Some(ref sname) = self.sname {
            body.extend_from_slice(&encode_tagged(3, &sname.encode_der()));
        }

        // from [4] KerberosTime OPTIONAL
        if let Some(ref from) = self.from {
            body.extend_from_slice(&encode_tagged(4, &from.encode_der()));
        }

        // till [5] KerberosTime
        body.extend_from_slice(&encode_tagged(5, &self.till.encode_der()));

        // rtime [6] KerberosTime OPTIONAL
        if let Some(ref rtime) = self.rtime {
            body.extend_from_slice(&encode_tagged(6, &rtime.encode_der()));
        }

        // nonce [7] UInt32
        body.extend_from_slice(&encode_tagged(7, &encode_integer(self.nonce as i32)));

        // etype [8] SEQUENCE OF Int32
        let etype_seq: Vec<u8> = self
            .etype
            .iter()
            .flat_map(|e| encode_integer(*e as i32))
            .collect();
        body.extend_from_slice(&encode_tagged(8, &encode_sequence(&etype_seq)));

        // addresses [9] HostAddresses OPTIONAL - skipped for now

        // enc-authorization-data [10] EncryptedData OPTIONAL
        if let Some(ref enc_authz) = self.enc_authorization_data {
            body.extend_from_slice(&encode_tagged(10, &enc_authz.encode_der()));
        }

        // additional-tickets [11] SEQUENCE OF Ticket OPTIONAL
        if let Some(ref tickets) = self.additional_tickets {
            let tickets_seq: Vec<u8> = tickets.iter().flat_map(|t| t.encode_der()).collect();
            body.extend_from_slice(&encode_tagged(11, &encode_sequence(&tickets_seq)));
        }

        encode_sequence(&body)
    }
}

/// AS-REQ message
#[derive(Debug, Clone)]
pub struct AsReq {
    pub pvno: u32,
    pub msg_type: MessageType,
    pub padata: Vec<PaData>,
    pub req_body: KdcReqBody,
}

impl AsReq {
    pub fn new(req_body: KdcReqBody) -> Self {
        Self {
            pvno: KERBEROS_VERSION,
            msg_type: MessageType::AsReq,
            padata: vec![PaData::pac_request(true)],
            req_body,
        }
    }

    pub fn with_padata(mut self, padata: Vec<PaData>) -> Self {
        self.padata = padata;
        self
    }

    /// Encode to DER bytes (alias for encode_der)
    pub fn encode(&self) -> Vec<u8> {
        self.encode_der()
    }

    pub fn encode_der(&self) -> Vec<u8> {
        let pvno = encode_tagged(1, &encode_integer(self.pvno as i32));
        let msg_type = encode_tagged(2, &encode_integer(self.msg_type as i32 as i32));

        let padata = if !self.padata.is_empty() {
            let padata_seq: Vec<u8> = self.padata.iter().flat_map(|p| p.encode_der()).collect();
            encode_tagged(3, &encode_sequence(&padata_seq))
        } else {
            Vec::new()
        };

        let req_body = encode_tagged(4, &self.req_body.encode_der());

        let mut body = pvno;
        body.extend_from_slice(&msg_type);
        body.extend_from_slice(&padata);
        body.extend_from_slice(&req_body);

        let seq = encode_sequence(&body);
        encode_application(10, &seq)
    }
}

/// AS-REP message
#[derive(Debug, Clone)]
pub struct AsRep {
    pub pvno: u32,
    pub msg_type: MessageType,
    pub padata: Vec<PaData>,
    pub crealm: Realm,
    pub cname: PrincipalName,
    pub ticket: Ticket,
    pub enc_part: EncryptedData,
}

impl AsRep {
    /// Decode from DER bytes (alias for decode_der)
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        Self::decode_der(data)
    }

    pub fn decode_der(data: &[u8]) -> Result<Self, String> {
        let (obj, _) = Asn1Object::from_der(data)?;

        // Should be APPLICATION 11
        if obj.tag != (0x60 | 11) {
            return Err(format!(
                "Expected APPLICATION 11 (AS-REP), got tag 0x{:02x}",
                obj.tag
            ));
        }

        match obj.value {
            Asn1Value::Sequence(fields) => {
                let mut pvno = None;
                let mut msg_type = None;
                let padata = Vec::new();
                let mut crealm = None;
                let mut cname = None;
                let mut ticket = None;
                let mut enc_part = None;

                for field in fields {
                    if let Asn1Value::ContextSpecific(tag, bytes) = field.value {
                        match tag {
                            1 => {
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::Integer(v) = inner.value {
                                    pvno = Some(der_integer_to_i32(&v) as u32);
                                }
                            }
                            2 => {
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::Integer(v) = inner.value {
                                    msg_type = MessageType::from_u32(der_integer_to_i32(&v) as u32);
                                }
                            }
                            3 => {
                                // PA-DATA sequence - parse each element
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::Sequence(_pa_fields) = inner.value {
                                    // Parse individual PA-DATA entries
                                    // For simplicity, skip detailed parsing
                                }
                            }
                            4 => {
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::PrintableString(s) | Asn1Value::IA5String(s) =
                                    inner.value
                                {
                                    crealm = Some(Realm(s));
                                }
                            }
                            5 => {
                                // Parse PrincipalName
                                cname = Some(PrincipalName::user("parsed"));
                            }
                            6 => {
                                ticket = Some(Ticket::decode_der(&bytes)?);
                            }
                            7 => {
                                enc_part = Some(EncryptedData::decode_der(&bytes)?);
                            }
                            _ => {}
                        }
                    }
                }

                Ok(Self {
                    pvno: pvno.ok_or("Missing pvno")?,
                    msg_type: msg_type.ok_or("Missing msg-type")?,
                    padata,
                    crealm: crealm.ok_or("Missing crealm")?,
                    cname: cname.ok_or("Missing cname")?,
                    ticket: ticket.ok_or("Missing ticket")?,
                    enc_part: enc_part.ok_or("Missing enc-part")?,
                })
            }
            _ => Err("Expected SEQUENCE".to_string()),
        }
    }
}

/// TGS-REQ message
#[derive(Debug, Clone)]
pub struct TgsReq {
    pub pvno: u32,
    pub msg_type: MessageType,
    pub padata: Vec<PaData>,
    pub req_body: KdcReqBody,
}

impl TgsReq {
    pub fn new(req_body: KdcReqBody) -> Self {
        Self {
            pvno: KERBEROS_VERSION,
            msg_type: MessageType::TgsReq,
            padata: Vec::new(),
            req_body,
        }
    }

    pub fn with_padata(mut self, padata: Vec<PaData>) -> Self {
        self.padata = padata;
        self
    }

    /// Encode to DER bytes (alias for encode_der)
    pub fn encode(&self) -> Vec<u8> {
        self.encode_der()
    }

    pub fn encode_der(&self) -> Vec<u8> {
        let pvno = encode_tagged(1, &encode_integer(self.pvno as i32));
        let msg_type = encode_tagged(2, &encode_integer(self.msg_type as i32 as i32));

        let padata = if !self.padata.is_empty() {
            let padata_seq: Vec<u8> = self.padata.iter().flat_map(|p| p.encode_der()).collect();
            encode_tagged(3, &encode_sequence(&padata_seq))
        } else {
            Vec::new()
        };

        let req_body = encode_tagged(4, &self.req_body.encode_der());

        let mut body = pvno;
        body.extend_from_slice(&msg_type);
        body.extend_from_slice(&padata);
        body.extend_from_slice(&req_body);

        let seq = encode_sequence(&body);
        encode_application(12, &seq)
    }
}

/// TGS-REP message (RFC 4120 5.4.2)
#[derive(Debug, Clone)]
pub struct TgsRep {
    pub pvno: u32,
    pub msg_type: MessageType,
    pub padata: Vec<PaData>,
    pub crealm: Realm,
    pub cname: PrincipalName,
    pub ticket: Ticket,
    pub enc_part: EncryptedData,
}

impl TgsRep {
    pub fn decode(der: &[u8]) -> Result<Self, String> {
        // Similar to AsRep decoding, just different message type
        AsRep::decode(der).map(|as_rep| TgsRep {
            pvno: as_rep.pvno,
            msg_type: MessageType::TgsRep,
            padata: as_rep.padata,
            crealm: as_rep.crealm,
            cname: as_rep.cname,
            ticket: as_rep.ticket,
            enc_part: as_rep.enc_part,
        })
    }
}

/// KRB-ERROR message
#[derive(Debug, Clone)]
pub struct KrbError {
    pub pvno: u32,
    pub msg_type: MessageType,
    pub ctime: Option<KerberosTime>,
    pub cusec: Option<u32>,
    pub stime: KerberosTime,
    pub susec: u32,
    pub error_code: i32,
    pub crealm: Option<Realm>,
    pub cname: Option<PrincipalName>,
    pub realm: Realm,
    pub sname: PrincipalName,
    pub e_text: Option<String>,
    pub e_data: Option<Vec<u8>>,
}

impl KrbError {
    /// Decode from DER bytes (alias for decode_der)
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        Self::decode_der(data)
    }

    pub fn decode_der(data: &[u8]) -> Result<Self, String> {
        let (obj, _) = Asn1Object::from_der(data)?;

        // Should be APPLICATION 30
        if obj.tag != (0x60 | 30) {
            return Err(format!(
                "Expected APPLICATION 30 (KRB-ERROR), got tag 0x{:02x}",
                obj.tag
            ));
        }

        match obj.value {
            Asn1Value::Sequence(fields) => {
                let mut error = KrbError {
                    pvno: KERBEROS_VERSION,
                    msg_type: MessageType::KrbError,
                    ctime: None,
                    cusec: None,
                    stime: KerberosTime::now(),
                    susec: 0,
                    error_code: 0,
                    crealm: None,
                    cname: None,
                    realm: Realm("UNKNOWN".to_string()),
                    sname: PrincipalName::user("unknown"),
                    e_text: None,
                    e_data: None,
                };

                for field in fields {
                    if let Asn1Value::ContextSpecific(tag, bytes) = field.value {
                        match tag {
                            6 => {
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::Integer(v) = inner.value {
                                    error.error_code = der_integer_to_i32(&v);
                                }
                            }
                            12 => {
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::UTF8String(s) = inner.value {
                                    error.e_text = Some(s);
                                }
                            }
                            13 => {
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::OctetString(v) = inner.value {
                                    error.e_data = Some(v);
                                }
                            }
                            _ => {}
                        }
                    }
                }

                Ok(error)
            }
            _ => Err("Expected SEQUENCE".to_string()),
        }
    }

    /// Get error name
    pub fn error_name(&self) -> &'static str {
        match self.error_code {
            0 => "KDC_ERR_NONE",
            1 => "KDC_ERR_NAME_EXP",
            2 => "KDC_ERR_SERVICE_EXP",
            3 => "KDC_ERR_BAD_PVNO",
            4 => "KDC_ERR_C_OLD_MAST_KVNO",
            5 => "KDC_ERR_S_OLD_MAST_KVNO",
            6 => "KDC_ERR_C_PRINCIPAL_UNKNOWN",
            7 => "KDC_ERR_S_PRINCIPAL_UNKNOWN",
            8 => "KDC_ERR_PRINCIPAL_NOT_UNIQUE",
            9 => "KDC_ERR_NULL_KEY",
            10 => "KDC_ERR_CANNOT_POSTDATE",
            11 => "KDC_ERR_NEVER_VALID",
            12 => "KDC_ERR_POLICY",
            13 => "KDC_ERR_BADOPTION",
            14 => "KDC_ERR_ETYPE_NOSUPP",
            15 => "KDC_ERR_SUMTYPE_NOSUPP",
            16 => "KDC_ERR_PADATA_TYPE_NOSUPP",
            17 => "KDC_ERR_TRTYPE_NOSUPP",
            18 => "KDC_ERR_CLIENT_REVOKED",
            19 => "KDC_ERR_SERVICE_REVOKED",
            20 => "KDC_ERR_TGT_REVOKED",
            21 => "KDC_ERR_CLIENT_NOTYET",
            22 => "KDC_ERR_SERVICE_NOTYET",
            23 => "KDC_ERR_KEY_EXPIRED",
            24 => "KDC_ERR_PREAUTH_FAILED",
            25 => "KDC_ERR_PREAUTH_REQUIRED",
            26 => "KDC_ERR_SERVER_NOMATCH",
            27 => "KDC_ERR_MUST_USE_USER2USER",
            28 => "KDC_ERR_PATH_NOT_ACCEPTED",
            29 => "KDC_ERR_SVC_UNAVAILABLE",
            31 => "KRB_AP_ERR_BAD_INTEGRITY",
            32 => "KRB_AP_ERR_TKT_EXPIRED",
            33 => "KRB_AP_ERR_TKT_NYV",
            34 => "KRB_AP_ERR_REPEAT",
            35 => "KRB_AP_ERR_NOT_US",
            36 => "KRB_AP_ERR_BADMATCH",
            37 => "KRB_AP_ERR_SKEW",
            38 => "KRB_AP_ERR_BADADDR",
            39 => "KRB_AP_ERR_BADVERSION",
            40 => "KRB_AP_ERR_MSG_TYPE",
            41 => "KRB_AP_ERR_MODIFIED",
            42 => "KRB_AP_ERR_BADORDER",
            44 => "KRB_AP_ERR_BADKEYVER",
            45 => "KRB_AP_ERR_NOKEY",
            46 => "KRB_AP_ERR_MUT_FAIL",
            47 => "KRB_AP_ERR_BADDIRECTION",
            48 => "KRB_AP_ERR_METHOD",
            49 => "KRB_AP_ERR_BADSEQ",
            50 => "KRB_AP_ERR_INAPP_CKSUM",
            60 => "KRB_ERR_GENERIC",
            61 => "KRB_ERR_FIELD_TOOLONG",
            62 => "KDC_ERR_CLIENT_NOT_TRUSTED",
            63 => "KDC_ERR_KDC_NOT_TRUSTED",
            64 => "KDC_ERR_INVALID_SIG",
            65 => "KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED",
            68 => "KDC_ERR_WRONG_REALM",
            69 => "KRB_AP_ERR_USER_TO_USER_REQUIRED",
            70 => "KDC_ERR_CANT_VERIFY_CERTIFICATE",
            71 => "KDC_ERR_INVALID_CERTIFICATE",
            72 => "KDC_ERR_REVOKED_CERTIFICATE",
            73 => "KDC_ERR_REVOCATION_STATUS_UNKNOWN",
            74 => "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE",
            75 => "KDC_ERR_CLIENT_NAME_MISMATCH",
            76 => "KDC_ERR_KDC_NAME_MISMATCH",
            _ => "UNKNOWN_ERROR",
        }
    }
}

/// Host address
#[derive(Debug, Clone)]
pub struct HostAddress {
    pub addr_type: i32,
    pub address: Vec<u8>,
}

impl HostAddress {
    pub const NETBIOS: i32 = 20;
    pub const IPV4: i32 = 2;
    pub const IPV6: i32 = 24;

    pub fn ipv4(addr: [u8; 4]) -> Self {
        Self {
            addr_type: Self::IPV4,
            address: addr.to_vec(),
        }
    }

    pub fn encode_der(&self) -> Vec<u8> {
        let addr_type = encode_tagged(0, &encode_integer(self.addr_type));
        let address = encode_tagged(1, &encode_octet_string(&self.address));

        let mut body = addr_type;
        body.extend_from_slice(&address);
        encode_sequence(&body)
    }
}
