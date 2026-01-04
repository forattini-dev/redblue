//! Core Kerberos Primitive Types
//!
//! KerberosTime, Realm, PrincipalName, EncryptionKey, EncryptedData, Checksum, PaData, Ticket.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocols::asn1::{Asn1Object, Asn1Value};

use super::encoding::*;
use super::enums::*;

/// KerberosTime - GeneralizedTime format: YYYYMMDDHHMMSSZ
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosTime(pub String);

impl KerberosTime {
    /// Create a KerberosTime from current time
    pub fn now() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let secs_per_day = 86400u64;
        let days = now / secs_per_day;
        let time_of_day = now % secs_per_day;

        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;

        let mut year = 1970;
        let mut remaining_days = days;

        loop {
            let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                366
            } else {
                365
            };
            if remaining_days < days_in_year {
                break;
            }
            remaining_days -= days_in_year;
            year += 1;
        }

        let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let days_in_month = [
            31,
            if is_leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];

        let mut month = 0;
        while month < 12 && remaining_days >= days_in_month[month] {
            remaining_days -= days_in_month[month];
            month += 1;
        }
        let day = remaining_days + 1;

        Self(format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            year,
            month + 1,
            day,
            hours,
            minutes,
            seconds
        ))
    }

    /// Create a KerberosTime from offset seconds from now
    pub fn from_offset(offset_secs: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + offset_secs;

        let secs_per_day = 86400u64;
        let days = now / secs_per_day;
        let time_of_day = now % secs_per_day;

        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;

        let mut year = 1970;
        let mut remaining_days = days;

        loop {
            let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                366
            } else {
                365
            };
            if remaining_days < days_in_year {
                break;
            }
            remaining_days -= days_in_year;
            year += 1;
        }

        let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let days_in_month = [
            31,
            if is_leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];

        let mut month = 0;
        while month < 12 && remaining_days >= days_in_month[month] {
            remaining_days -= days_in_month[month];
            month += 1;
        }
        let day = remaining_days + 1;

        Self(format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            year,
            month + 1,
            day,
            hours,
            minutes,
            seconds
        ))
    }

    /// Create a KerberosTime from unix timestamp (seconds since epoch)
    pub fn from_unix(timestamp: u64) -> Self {
        let secs_per_day = 86400u64;
        let days = timestamp / secs_per_day;
        let time_of_day = timestamp % secs_per_day;

        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;

        let mut year = 1970;
        let mut remaining_days = days;

        loop {
            let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                366
            } else {
                365
            };
            if remaining_days < days_in_year {
                break;
            }
            remaining_days -= days_in_year;
            year += 1;
        }

        let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let days_in_month = [
            31,
            if is_leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];

        let mut month = 0;
        while month < 12 && remaining_days >= days_in_month[month] {
            remaining_days -= days_in_month[month];
            month += 1;
        }
        let day = remaining_days + 1;

        Self(format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            year,
            month + 1,
            day,
            hours,
            minutes,
            seconds
        ))
    }

    /// Encode as DER GeneralizedTime
    pub fn encode_der(&self) -> Vec<u8> {
        let bytes = self.0.as_bytes();
        let mut result = vec![0x18]; // GeneralizedTime tag
        result.extend_from_slice(&encode_length(bytes.len()));
        result.extend_from_slice(bytes);
        result
    }
}

/// Realm - Kerberos realm (domain name)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Realm(pub String);

impl Realm {
    pub fn new(realm: &str) -> Self {
        Self(realm.to_uppercase())
    }

    pub fn encode_der(&self) -> Vec<u8> {
        encode_general_string(&self.0)
    }
}

impl fmt::Display for Realm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// PrincipalName - Kerberos principal (user or service)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalName {
    pub name_type: NameType,
    pub name_string: Vec<String>,
}

impl PrincipalName {
    /// Create a new PrincipalName with given type and name components
    pub fn new(name_type: NameType, name_string: Vec<String>) -> Self {
        Self {
            name_type,
            name_string,
        }
    }

    /// Create a user principal (name-type = NT-PRINCIPAL)
    pub fn user(username: &str) -> Self {
        Self {
            name_type: NameType::Principal,
            name_string: vec![username.to_string()],
        }
    }

    /// Create a service principal (name-type = NT-SRV-INST)
    pub fn service(service: &str, host: &str) -> Self {
        Self {
            name_type: NameType::SrvInst,
            name_string: vec![service.to_string(), host.to_string()],
        }
    }

    /// Create krbtgt principal for realm
    pub fn krbtgt(realm: &str) -> Self {
        Self {
            name_type: NameType::SrvInst,
            name_string: vec!["krbtgt".to_string(), realm.to_uppercase()],
        }
    }

    /// Encode as DER SEQUENCE
    pub fn encode_der(&self) -> Vec<u8> {
        let name_type = encode_tagged(0, &encode_integer(self.name_type as i32));

        let name_strings: Vec<u8> = self
            .name_string
            .iter()
            .flat_map(|s| encode_general_string(s))
            .collect();
        let name_string_seq = encode_sequence(&name_strings);
        let name_string = encode_tagged(1, &name_string_seq);

        let mut body = name_type;
        body.extend_from_slice(&name_string);
        encode_sequence(&body)
    }
}

impl fmt::Display for PrincipalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name_string.join("/"))
    }
}

/// EncryptionKey - Symmetric encryption key
#[derive(Debug, Clone)]
pub struct EncryptionKey {
    pub keytype: EncryptionType,
    pub keyvalue: Vec<u8>,
}

impl EncryptionKey {
    pub fn new(keytype: EncryptionType, keyvalue: Vec<u8>) -> Self {
        Self { keytype, keyvalue }
    }

    /// Encode as DER SEQUENCE
    pub fn encode_der(&self) -> Vec<u8> {
        let keytype = encode_tagged(0, &encode_integer(self.keytype as i32));
        let keyvalue = encode_tagged(1, &encode_octet_string(&self.keyvalue));

        let mut body = keytype;
        body.extend_from_slice(&keyvalue);
        encode_sequence(&body)
    }

    /// Decode from DER bytes
    pub fn decode_der(data: &[u8]) -> Result<Self, String> {
        let (obj, _) = Asn1Object::from_der(data)?;
        match obj.value {
            Asn1Value::Sequence(fields) => {
                let mut keytype = None;
                let mut keyvalue = None;

                for field in fields {
                    if let Asn1Value::ContextSpecific(tag, bytes) = field.value {
                        match tag {
                            0 => {
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::Integer(v) = inner.value {
                                    let val = der_integer_to_i32(&v);
                                    keytype = EncryptionType::from_i32(val);
                                }
                            }
                            1 => {
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::OctetString(v) = inner.value {
                                    keyvalue = Some(v);
                                }
                            }
                            _ => {}
                        }
                    }
                }

                Ok(Self {
                    keytype: keytype.ok_or("Missing keytype")?,
                    keyvalue: keyvalue.ok_or("Missing keyvalue")?,
                })
            }
            _ => Err("Expected SEQUENCE".to_string()),
        }
    }
}

/// EncryptedData - Encrypted payload
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub etype: EncryptionType,
    pub kvno: Option<u32>,
    pub cipher: Vec<u8>,
}

impl EncryptedData {
    pub fn new(etype: EncryptionType, cipher: Vec<u8>) -> Self {
        Self {
            etype,
            kvno: None,
            cipher,
        }
    }

    pub fn with_kvno(mut self, kvno: u32) -> Self {
        self.kvno = Some(kvno);
        self
    }

    /// Encode as DER SEQUENCE
    pub fn encode_der(&self) -> Vec<u8> {
        let etype = encode_tagged(0, &encode_integer(self.etype as i32));

        let kvno = if let Some(v) = self.kvno {
            encode_tagged(1, &encode_integer(v as i32))
        } else {
            Vec::new()
        };

        let cipher = encode_tagged(2, &encode_octet_string(&self.cipher));

        let mut body = etype;
        body.extend_from_slice(&kvno);
        body.extend_from_slice(&cipher);
        encode_sequence(&body)
    }

    /// Decode from DER bytes
    pub fn decode_der(data: &[u8]) -> Result<Self, String> {
        let (obj, _) = Asn1Object::from_der(data)?;
        match obj.value {
            Asn1Value::Sequence(fields) => {
                let mut etype = None;
                let mut kvno = None;
                let mut cipher = None;

                for field in fields {
                    if let Asn1Value::ContextSpecific(tag, bytes) = field.value {
                        match tag {
                            0 => {
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::Integer(v) = inner.value {
                                    let val = der_integer_to_i32(&v);
                                    etype = EncryptionType::from_i32(val);
                                }
                            }
                            1 => {
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::Integer(v) = inner.value {
                                    kvno = Some(der_integer_to_i32(&v) as u32);
                                }
                            }
                            2 => {
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::OctetString(v) = inner.value {
                                    cipher = Some(v);
                                }
                            }
                            _ => {}
                        }
                    }
                }

                Ok(Self {
                    etype: etype.ok_or("Missing etype")?,
                    kvno,
                    cipher: cipher.ok_or("Missing cipher")?,
                })
            }
            _ => Err("Expected SEQUENCE".to_string()),
        }
    }
}

/// Checksum
#[derive(Debug, Clone)]
pub struct Checksum {
    pub cksumtype: ChecksumType,
    pub checksum: Vec<u8>,
}

impl Checksum {
    pub fn new(cksumtype: ChecksumType, checksum: Vec<u8>) -> Self {
        Self {
            cksumtype,
            checksum,
        }
    }

    pub fn encode_der(&self) -> Vec<u8> {
        let cksumtype = encode_tagged(0, &encode_integer(self.cksumtype as i32));
        let checksum = encode_tagged(1, &encode_octet_string(&self.checksum));

        let mut body = cksumtype;
        body.extend_from_slice(&checksum);
        encode_sequence(&body)
    }
}

/// Pre-authentication data
#[derive(Debug, Clone)]
pub struct PaData {
    pub padata_type: PaDataType,
    pub padata_value: Vec<u8>,
}

impl PaData {
    pub fn new(padata_type: PaDataType, padata_value: Vec<u8>) -> Self {
        Self {
            padata_type,
            padata_value,
        }
    }

    /// Create PA-PAC-REQUEST
    pub fn pac_request(include_pac: bool) -> Self {
        let include_pac_der = encode_tagged(0, &encode_boolean(include_pac));
        let value = encode_sequence(&include_pac_der);
        Self::new(PaDataType::PacRequest, value)
    }

    pub fn encode_der(&self) -> Vec<u8> {
        let padata_type = encode_tagged(1, &encode_integer(self.padata_type as i32));
        let padata_value = encode_tagged(2, &encode_octet_string(&self.padata_value));

        let mut body = padata_type;
        body.extend_from_slice(&padata_value);
        encode_sequence(&body)
    }
}

/// Ticket
#[derive(Debug, Clone)]
pub struct Ticket {
    pub tkt_vno: u32,
    pub realm: Realm,
    pub sname: PrincipalName,
    pub enc_part: EncryptedData,
}

impl Ticket {
    pub fn encode_der(&self) -> Vec<u8> {
        let tkt_vno = encode_tagged(0, &encode_integer(self.tkt_vno as i32));
        let realm = encode_tagged(1, &self.realm.encode_der());
        let sname = encode_tagged(2, &self.sname.encode_der());
        let enc_part = encode_tagged(3, &self.enc_part.encode_der());

        let mut body = tkt_vno;
        body.extend_from_slice(&realm);
        body.extend_from_slice(&sname);
        body.extend_from_slice(&enc_part);

        let seq = encode_sequence(&body);
        encode_application(1, &seq)
    }

    pub fn decode_der(data: &[u8]) -> Result<Self, String> {
        let (obj, _) = Asn1Object::from_der(data)?;

        // Should be APPLICATION 1
        if obj.tag != (0x60 | 1) {
            return Err(format!("Expected APPLICATION 1, got tag 0x{:02x}", obj.tag));
        }

        // Inner SEQUENCE
        match obj.value {
            Asn1Value::Sequence(fields) => {
                let mut tkt_vno = None;
                let mut realm = None;
                let mut sname = None;
                let mut enc_part = None;

                for field in fields {
                    if let Asn1Value::ContextSpecific(tag, bytes) = field.value {
                        match tag {
                            0 => {
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::Integer(v) = inner.value {
                                    tkt_vno = Some(der_integer_to_i32(&v) as u32);
                                }
                            }
                            1 => {
                                let (inner, _) = Asn1Object::from_der(&bytes)?;
                                if let Asn1Value::PrintableString(s) | Asn1Value::IA5String(s) =
                                    inner.value
                                {
                                    realm = Some(Realm(s));
                                }
                            }
                            2 => {
                                // PrincipalName parsing would go here
                                // For now, create a placeholder
                                sname = Some(PrincipalName::user("parsed"));
                            }
                            3 => {
                                enc_part = Some(EncryptedData::decode_der(&bytes)?);
                            }
                            _ => {}
                        }
                    }
                }

                Ok(Self {
                    tkt_vno: tkt_vno.ok_or("Missing tkt-vno")?,
                    realm: realm.ok_or("Missing realm")?,
                    sname: sname.ok_or("Missing sname")?,
                    enc_part: enc_part.ok_or("Missing enc-part")?,
                })
            }
            _ => Err("Expected SEQUENCE".to_string()),
        }
    }
}
