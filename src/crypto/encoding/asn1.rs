//! ASN.1 DER (Distinguished Encoding Rules) Encoder/Decoder
//!
//! Implements ASN.1 DER encoding as specified in X.690.
//! This is the foundation for X.509 certificates and PKCS formats.
//!
//! # ASN.1 Tag Structure
//!
//! ```text
//! +--------+--------+--------+
//! | Class  | P/C    | Number |
//! | 2 bits | 1 bit  | 5 bits |
//! +--------+--------+--------+
//!
//! Class:
//!   00 = Universal
//!   01 = Application
//!   10 = Context-specific
//!   11 = Private
//!
//! P/C:
//!   0 = Primitive
//!   1 = Constructed
//! ```
//!
//! # Example
//!
//! ```rust
//! use redblue::crypto::encoding::asn1::{Asn1Value, Asn1Tag};
//!
//! // Create a SEQUENCE
//! let seq = Asn1Value::Sequence(vec![
//!     Asn1Value::Integer(vec![0x01]),
//!     Asn1Value::Utf8String("Hello".to_string()),
//! ]);
//!
//! // Encode to DER
//! let der = seq.encode_der();
//!
//! // Decode back
//! let (decoded, _) = Asn1Value::decode_der(&der).unwrap();
//! ```

use std::fmt;

/// ASN.1 Tag numbers (Universal class)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Asn1Tag {
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    ObjectIdentifier = 0x06,
    ObjectDescriptor = 0x07,
    External = 0x08,
    Real = 0x09,
    Enumerated = 0x0A,
    EmbeddedPdv = 0x0B,
    Utf8String = 0x0C,
    RelativeOid = 0x0D,
    Time = 0x0E,
    // 0x0F reserved
    Sequence = 0x10,
    Set = 0x11,
    NumericString = 0x12,
    PrintableString = 0x13,
    T61String = 0x14,
    VideotexString = 0x15,
    Ia5String = 0x16,
    UtcTime = 0x17,
    GeneralizedTime = 0x18,
    GraphicString = 0x19,
    VisibleString = 0x1A,
    GeneralString = 0x1B,
    UniversalString = 0x1C,
    CharacterString = 0x1D,
    BmpString = 0x1E,
    Date = 0x1F,
}

impl Asn1Tag {
    /// Get the tag value
    pub fn value(self) -> u8 {
        self as u8
    }

    /// Create from raw tag byte (universal class only)
    pub fn from_byte(byte: u8) -> Option<Self> {
        let tag_number = byte & 0x1F;
        match tag_number {
            0x01 => Some(Self::Boolean),
            0x02 => Some(Self::Integer),
            0x03 => Some(Self::BitString),
            0x04 => Some(Self::OctetString),
            0x05 => Some(Self::Null),
            0x06 => Some(Self::ObjectIdentifier),
            0x0C => Some(Self::Utf8String),
            0x10 => Some(Self::Sequence),
            0x11 => Some(Self::Set),
            0x13 => Some(Self::PrintableString),
            0x16 => Some(Self::Ia5String),
            0x17 => Some(Self::UtcTime),
            0x18 => Some(Self::GeneralizedTime),
            _ => None,
        }
    }
}

/// ASN.1 parsing/encoding errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asn1Error {
    /// Unexpected end of data
    UnexpectedEof,
    /// Invalid tag
    InvalidTag(u8),
    /// Invalid length encoding
    InvalidLength,
    /// Length too large
    LengthTooLarge(usize),
    /// Invalid content for type
    InvalidContent(String),
    /// Invalid OID encoding
    InvalidOid,
    /// Invalid string encoding
    InvalidString,
    /// Invalid time format
    InvalidTime,
    /// Trailing data after value
    TrailingData,
}

impl fmt::Display for Asn1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "Unexpected end of data"),
            Self::InvalidTag(tag) => write!(f, "Invalid tag: {:#04x}", tag),
            Self::InvalidLength => write!(f, "Invalid length encoding"),
            Self::LengthTooLarge(len) => write!(f, "Length too large: {}", len),
            Self::InvalidContent(msg) => write!(f, "Invalid content: {}", msg),
            Self::InvalidOid => write!(f, "Invalid OID encoding"),
            Self::InvalidString => write!(f, "Invalid string encoding"),
            Self::InvalidTime => write!(f, "Invalid time format"),
            Self::TrailingData => write!(f, "Trailing data after value"),
        }
    }
}

impl std::error::Error for Asn1Error {}

/// ASN.1 Value types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asn1Value {
    /// BOOLEAN
    Boolean(bool),
    /// INTEGER (big-endian, two's complement)
    Integer(Vec<u8>),
    /// BIT STRING (data, unused_bits)
    BitString(Vec<u8>, u8),
    /// OCTET STRING
    OctetString(Vec<u8>),
    /// NULL
    Null,
    /// OBJECT IDENTIFIER (components)
    ObjectIdentifier(Vec<u32>),
    /// UTF8String
    Utf8String(String),
    /// PrintableString
    PrintableString(String),
    /// IA5String (ASCII)
    Ia5String(String),
    /// UTCTime (YYMMDDHHMMSSZ)
    UtcTime(String),
    /// GeneralizedTime (YYYYMMDDHHMMSSZ)
    GeneralizedTime(String),
    /// SEQUENCE (ordered)
    Sequence(Vec<Asn1Value>),
    /// SET (unordered)
    Set(Vec<Asn1Value>),
    /// Context-specific tagged value [N]
    ContextSpecific {
        tag: u8,
        constructed: bool,
        value: Box<Asn1Value>,
    },
    /// Context-specific tagged raw bytes [N] IMPLICIT
    ContextSpecificRaw {
        tag: u8,
        data: Vec<u8>,
    },
    /// Raw/unknown value (tag, data)
    Raw(u8, Vec<u8>),
}

impl Asn1Value {
    //=========================================================================
    // CONSTRUCTORS
    //=========================================================================

    /// Create INTEGER from u64
    pub fn integer_from_u64(n: u64) -> Self {
        if n == 0 {
            return Self::Integer(vec![0x00]);
        }

        let mut bytes = Vec::new();
        let mut val = n;
        while val > 0 {
            bytes.push((val & 0xFF) as u8);
            val >>= 8;
        }
        bytes.reverse();

        // Add leading zero if high bit is set (to keep positive)
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0x00);
        }

        Self::Integer(bytes)
    }

    /// Create INTEGER from big-endian bytes
    pub fn integer_from_bytes(bytes: &[u8]) -> Self {
        let mut result = bytes.to_vec();

        // Remove leading zeros but keep at least one byte
        while result.len() > 1 && result[0] == 0 && (result[1] & 0x80) == 0 {
            result.remove(0);
        }

        Self::Integer(result)
    }

    /// Create INTEGER from signed i64
    pub fn integer_from_i64(n: i64) -> Self {
        if n == 0 {
            return Self::Integer(vec![0x00]);
        }

        let bytes = n.to_be_bytes();
        let mut result = Vec::new();
        let mut started = false;

        for (i, &byte) in bytes.iter().enumerate() {
            if !started {
                if n >= 0 {
                    // Positive: skip leading 0x00, but keep if next byte has high bit set
                    if byte == 0x00 && i + 1 < bytes.len() && (bytes[i + 1] & 0x80) == 0 {
                        continue;
                    }
                } else {
                    // Negative: skip leading 0xFF, but keep if next byte doesn't have high bit set
                    if byte == 0xFF && i + 1 < bytes.len() && (bytes[i + 1] & 0x80) != 0 {
                        continue;
                    }
                }
                started = true;
            }
            result.push(byte);
        }

        if result.is_empty() {
            result.push(0x00);
        }

        Self::Integer(result)
    }

    /// Create OBJECT IDENTIFIER from components
    pub fn oid(components: &[u32]) -> Self {
        Self::ObjectIdentifier(components.to_vec())
    }

    /// Create OBJECT IDENTIFIER from dotted string (e.g., "1.2.840.113549")
    pub fn oid_from_str(s: &str) -> Result<Self, Asn1Error> {
        let components: Result<Vec<u32>, _> = s
            .split('.')
            .map(|part| part.parse::<u32>())
            .collect();

        match components {
            Ok(comps) if comps.len() >= 2 => Ok(Self::ObjectIdentifier(comps)),
            _ => Err(Asn1Error::InvalidOid),
        }
    }

    /// Create SEQUENCE from values
    pub fn sequence(items: Vec<Asn1Value>) -> Self {
        Self::Sequence(items)
    }

    /// Create SET from values
    pub fn set(items: Vec<Asn1Value>) -> Self {
        Self::Set(items)
    }

    /// Create BIT STRING from bytes (all bits used)
    pub fn bit_string(data: Vec<u8>) -> Self {
        Self::BitString(data, 0)
    }

    /// Create BIT STRING with unused bits specified
    pub fn bit_string_with_unused(data: Vec<u8>, unused_bits: u8) -> Self {
        Self::BitString(data, unused_bits)
    }

    /// Create context-specific tagged value [N]
    pub fn context_specific(tag: u8, value: Asn1Value) -> Self {
        Self::ContextSpecific {
            tag,
            constructed: matches!(value, Asn1Value::Sequence(_) | Asn1Value::Set(_)),
            value: Box::new(value),
        }
    }

    /// Create explicit context-specific tagged value [N] EXPLICIT
    pub fn context_explicit(tag: u8, value: Asn1Value) -> Self {
        Self::ContextSpecific {
            tag,
            constructed: true,
            value: Box::new(value),
        }
    }

    //=========================================================================
    // ACCESSORS
    //=========================================================================

    /// Get as integer bytes
    pub fn as_integer(&self) -> Option<&[u8]> {
        match self {
            Self::Integer(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// Get integer as u64 (if it fits)
    pub fn as_u64(&self) -> Option<u64> {
        let bytes = self.as_integer()?;
        if bytes.len() > 8 || (bytes.len() == 8 && bytes[0] & 0x80 != 0) {
            return None;
        }

        let mut result = 0u64;
        for &byte in bytes {
            result = result << 8 | byte as u64;
        }
        Some(result)
    }

    /// Get as OID components
    pub fn as_oid(&self) -> Option<&[u32]> {
        match self {
            Self::ObjectIdentifier(comps) => Some(comps),
            _ => None,
        }
    }

    /// Get OID as dotted string
    pub fn oid_to_string(&self) -> Option<String> {
        let comps = self.as_oid()?;
        Some(
            comps
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join("."),
        )
    }

    /// Get as sequence of values
    pub fn as_sequence(&self) -> Option<&[Asn1Value]> {
        match self {
            Self::Sequence(items) => Some(items),
            _ => None,
        }
    }

    /// Get as bytes (OctetString or BitString)
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::OctetString(data) => Some(data),
            Self::BitString(data, _) => Some(data),
            _ => None,
        }
    }

    /// Get as string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Utf8String(s) | Self::PrintableString(s) | Self::Ia5String(s) => Some(s),
            _ => None,
        }
    }

    //=========================================================================
    // DER ENCODING
    //=========================================================================

    /// Encode value to DER format
    pub fn encode_der(&self) -> Vec<u8> {
        let mut result = Vec::new();
        self.encode_der_into(&mut result);
        result
    }

    /// Encode value into existing buffer
    fn encode_der_into(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Boolean(val) => {
                buf.push(Asn1Tag::Boolean.value());
                buf.push(0x01);
                buf.push(if *val { 0xFF } else { 0x00 });
            }

            Self::Integer(bytes) => {
                buf.push(Asn1Tag::Integer.value());
                encode_length(bytes.len(), buf);
                buf.extend_from_slice(bytes);
            }

            Self::BitString(data, unused_bits) => {
                buf.push(Asn1Tag::BitString.value());
                encode_length(data.len() + 1, buf);
                buf.push(*unused_bits);
                buf.extend_from_slice(data);
            }

            Self::OctetString(data) => {
                buf.push(Asn1Tag::OctetString.value());
                encode_length(data.len(), buf);
                buf.extend_from_slice(data);
            }

            Self::Null => {
                buf.push(Asn1Tag::Null.value());
                buf.push(0x00);
            }

            Self::ObjectIdentifier(components) => {
                buf.push(Asn1Tag::ObjectIdentifier.value());
                let oid_bytes = encode_oid(components);
                encode_length(oid_bytes.len(), buf);
                buf.extend_from_slice(&oid_bytes);
            }

            Self::Utf8String(s) => {
                buf.push(Asn1Tag::Utf8String.value());
                let bytes = s.as_bytes();
                encode_length(bytes.len(), buf);
                buf.extend_from_slice(bytes);
            }

            Self::PrintableString(s) => {
                buf.push(Asn1Tag::PrintableString.value());
                let bytes = s.as_bytes();
                encode_length(bytes.len(), buf);
                buf.extend_from_slice(bytes);
            }

            Self::Ia5String(s) => {
                buf.push(Asn1Tag::Ia5String.value());
                let bytes = s.as_bytes();
                encode_length(bytes.len(), buf);
                buf.extend_from_slice(bytes);
            }

            Self::UtcTime(s) => {
                buf.push(Asn1Tag::UtcTime.value());
                let bytes = s.as_bytes();
                encode_length(bytes.len(), buf);
                buf.extend_from_slice(bytes);
            }

            Self::GeneralizedTime(s) => {
                buf.push(Asn1Tag::GeneralizedTime.value());
                let bytes = s.as_bytes();
                encode_length(bytes.len(), buf);
                buf.extend_from_slice(bytes);
            }

            Self::Sequence(items) => {
                buf.push(Asn1Tag::Sequence.value() | 0x20); // Constructed
                let content = encode_sequence_content(items);
                encode_length(content.len(), buf);
                buf.extend_from_slice(&content);
            }

            Self::Set(items) => {
                buf.push(Asn1Tag::Set.value() | 0x20); // Constructed
                let content = encode_sequence_content(items);
                encode_length(content.len(), buf);
                buf.extend_from_slice(&content);
            }

            Self::ContextSpecific { tag, constructed, value } => {
                let tag_byte = 0xA0 | (*tag & 0x1F);
                let tag_byte = if *constructed { tag_byte } else { tag_byte & !0x20 };
                buf.push(tag_byte);
                let content = value.encode_der();
                encode_length(content.len(), buf);
                buf.extend_from_slice(&content);
            }

            Self::ContextSpecificRaw { tag, data } => {
                let tag_byte = 0x80 | (*tag & 0x1F);
                buf.push(tag_byte);
                encode_length(data.len(), buf);
                buf.extend_from_slice(data);
            }

            Self::Raw(tag, data) => {
                buf.push(*tag);
                encode_length(data.len(), buf);
                buf.extend_from_slice(data);
            }
        }
    }

    //=========================================================================
    // DER DECODING
    //=========================================================================

    /// Decode DER data to ASN.1 value
    /// Returns the value and number of bytes consumed
    pub fn decode_der(data: &[u8]) -> Result<(Self, usize), Asn1Error> {
        if data.is_empty() {
            return Err(Asn1Error::UnexpectedEof);
        }

        let tag = data[0];
        let (length, length_size) = decode_length(&data[1..])?;
        let content_start = 1 + length_size;
        let content_end = content_start + length;

        if data.len() < content_end {
            return Err(Asn1Error::UnexpectedEof);
        }

        let content = &data[content_start..content_end];
        let total_consumed = content_end;

        // Check tag class
        let class = (tag >> 6) & 0x03;
        let constructed = (tag & 0x20) != 0;
        let tag_number = tag & 0x1F;

        let value = if class == 2 {
            // Context-specific [N]
            if constructed {
                let (inner, _) = Self::decode_der(content)?;
                Self::ContextSpecific {
                    tag: tag_number,
                    constructed: true,
                    value: Box::new(inner),
                }
            } else {
                Self::ContextSpecificRaw {
                    tag: tag_number,
                    data: content.to_vec(),
                }
            }
        } else if class == 0 {
            // Universal
            match tag_number {
                0x01 => {
                    // BOOLEAN
                    if content.len() != 1 {
                        return Err(Asn1Error::InvalidContent("Boolean must be 1 byte".into()));
                    }
                    Self::Boolean(content[0] != 0)
                }

                0x02 => {
                    // INTEGER
                    Self::Integer(content.to_vec())
                }

                0x03 => {
                    // BIT STRING
                    if content.is_empty() {
                        return Err(Asn1Error::InvalidContent("BitString empty".into()));
                    }
                    let unused_bits = content[0];
                    if unused_bits > 7 {
                        return Err(Asn1Error::InvalidContent("Invalid unused bits".into()));
                    }
                    Self::BitString(content[1..].to_vec(), unused_bits)
                }

                0x04 => {
                    // OCTET STRING
                    Self::OctetString(content.to_vec())
                }

                0x05 => {
                    // NULL
                    if !content.is_empty() {
                        return Err(Asn1Error::InvalidContent("NULL must be empty".into()));
                    }
                    Self::Null
                }

                0x06 => {
                    // OBJECT IDENTIFIER
                    let components = decode_oid(content)?;
                    Self::ObjectIdentifier(components)
                }

                0x0C => {
                    // UTF8String
                    let s = String::from_utf8(content.to_vec())
                        .map_err(|_| Asn1Error::InvalidString)?;
                    Self::Utf8String(s)
                }

                0x13 => {
                    // PrintableString
                    let s = String::from_utf8(content.to_vec())
                        .map_err(|_| Asn1Error::InvalidString)?;
                    Self::PrintableString(s)
                }

                0x16 => {
                    // IA5String
                    let s = String::from_utf8(content.to_vec())
                        .map_err(|_| Asn1Error::InvalidString)?;
                    Self::Ia5String(s)
                }

                0x17 => {
                    // UTCTime
                    let s = String::from_utf8(content.to_vec())
                        .map_err(|_| Asn1Error::InvalidTime)?;
                    Self::UtcTime(s)
                }

                0x18 => {
                    // GeneralizedTime
                    let s = String::from_utf8(content.to_vec())
                        .map_err(|_| Asn1Error::InvalidTime)?;
                    Self::GeneralizedTime(s)
                }

                0x10 | 0x11 => {
                    // SEQUENCE or SET (constructed)
                    let items = decode_sequence_content(content)?;
                    if tag_number == 0x10 {
                        Self::Sequence(items)
                    } else {
                        Self::Set(items)
                    }
                }

                _ => {
                    // Unknown universal tag
                    Self::Raw(tag, content.to_vec())
                }
            }
        } else {
            // Application or Private class
            Self::Raw(tag, content.to_vec())
        };

        Ok((value, total_consumed))
    }

    /// Decode DER and expect no trailing data
    pub fn decode_der_exact(data: &[u8]) -> Result<Self, Asn1Error> {
        let (value, consumed) = Self::decode_der(data)?;
        if consumed != data.len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(value)
    }
}

//=============================================================================
// HELPER FUNCTIONS
//=============================================================================

/// Encode length in DER format
fn encode_length(len: usize, buf: &mut Vec<u8>) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 65536 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else if len < 16777216 {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x84);
        buf.push((len >> 24) as u8);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Decode length from DER format
fn decode_length(data: &[u8]) -> Result<(usize, usize), Asn1Error> {
    if data.is_empty() {
        return Err(Asn1Error::UnexpectedEof);
    }

    let first = data[0];
    if first < 128 {
        // Short form
        Ok((first as usize, 1))
    } else {
        // Long form
        let num_octets = (first & 0x7F) as usize;
        if num_octets == 0 {
            return Err(Asn1Error::InvalidLength);
        }
        if num_octets > 4 {
            return Err(Asn1Error::LengthTooLarge(num_octets));
        }
        if data.len() < 1 + num_octets {
            return Err(Asn1Error::UnexpectedEof);
        }

        let mut length = 0usize;
        for i in 0..num_octets {
            length = length << 8 | data[1 + i] as usize;
        }

        Ok((length, 1 + num_octets))
    }
}

/// Encode OID components
fn encode_oid(components: &[u32]) -> Vec<u8> {
    let mut result = Vec::new();

    if components.len() >= 2 {
        // First two components are encoded specially
        let first_byte = components[0] * 40 + components[1];
        encode_oid_component(first_byte, &mut result);

        for &comp in &components[2..] {
            encode_oid_component(comp, &mut result);
        }
    }

    result
}

/// Encode single OID component using base-128
fn encode_oid_component(value: u32, buf: &mut Vec<u8>) {
    if value < 128 {
        buf.push(value as u8);
    } else {
        let mut bytes = Vec::new();
        let mut val = value;
        bytes.push((val & 0x7F) as u8);
        val >>= 7;
        while val > 0 {
            bytes.push(0x80 | (val & 0x7F) as u8);
            val >>= 7;
        }
        bytes.reverse();
        buf.extend_from_slice(&bytes);
    }
}

/// Decode OID from bytes
fn decode_oid(data: &[u8]) -> Result<Vec<u32>, Asn1Error> {
    if data.is_empty() {
        return Err(Asn1Error::InvalidOid);
    }

    let mut components = Vec::new();

    // First byte encodes first two components
    let first_byte = data[0] as u32;
    components.push(first_byte / 40);
    components.push(first_byte % 40);

    // Decode remaining components
    let mut i = 1;
    while i < data.len() {
        let mut value = 0u32;
        loop {
            if i >= data.len() {
                return Err(Asn1Error::InvalidOid);
            }
            let byte = data[i];
            i += 1;
            value = value << 7 | (byte & 0x7F) as u32;
            if byte & 0x80 == 0 {
                break;
            }
        }
        components.push(value);
    }

    Ok(components)
}

/// Encode sequence/set content
fn encode_sequence_content(items: &[Asn1Value]) -> Vec<u8> {
    let mut result = Vec::new();
    for item in items {
        item.encode_der_into(&mut result);
    }
    result
}

/// Decode sequence/set content
fn decode_sequence_content(data: &[u8]) -> Result<Vec<Asn1Value>, Asn1Error> {
    let mut items = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let (value, consumed) = Asn1Value::decode_der(&data[offset..])?;
        items.push(value);
        offset += consumed;
    }

    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integer_encoding() {
        // Small positive
        let val = Asn1Value::integer_from_u64(127);
        let encoded = val.encode_der();
        assert_eq!(encoded, vec![0x02, 0x01, 0x7F]);

        // Needs leading zero
        let val = Asn1Value::integer_from_u64(128);
        let encoded = val.encode_der();
        assert_eq!(encoded, vec![0x02, 0x02, 0x00, 0x80]);

        // Roundtrip
        let (decoded, _) = Asn1Value::decode_der(&encoded).unwrap();
        assert_eq!(decoded.as_u64(), Some(128));
    }

    #[test]
    fn test_oid_encoding() {
        // RSA OID: 1.2.840.113549.1.1.1
        let oid = Asn1Value::oid(&[1, 2, 840, 113549, 1, 1, 1]);
        let encoded = oid.encode_der();

        // Decode and verify
        let (decoded, _) = Asn1Value::decode_der(&encoded).unwrap();
        assert_eq!(decoded.oid_to_string(), Some("1.2.840.113549.1.1.1".to_string()));
    }

    #[test]
    fn test_sequence_encoding() {
        let seq = Asn1Value::sequence(vec![
            Asn1Value::integer_from_u64(1),
            Asn1Value::Utf8String("test".to_string()),
        ]);

        let encoded = seq.encode_der();
        let (decoded, _) = Asn1Value::decode_der(&encoded).unwrap();

        if let Asn1Value::Sequence(items) = decoded {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].as_u64(), Some(1));
            assert_eq!(items[1].as_str(), Some("test"));
        } else {
            panic!("Expected Sequence");
        }
    }

    #[test]
    fn test_bit_string() {
        let bits = Asn1Value::bit_string(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let encoded = bits.encode_der();

        let (decoded, _) = Asn1Value::decode_der(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    }

    #[test]
    fn test_boolean() {
        let t = Asn1Value::Boolean(true);
        let f = Asn1Value::Boolean(false);

        let encoded_t = t.encode_der();
        let encoded_f = f.encode_der();

        assert_eq!(encoded_t, vec![0x01, 0x01, 0xFF]);
        assert_eq!(encoded_f, vec![0x01, 0x01, 0x00]);

        let (decoded_t, _) = Asn1Value::decode_der(&encoded_t).unwrap();
        let (decoded_f, _) = Asn1Value::decode_der(&encoded_f).unwrap();

        assert_eq!(decoded_t, Asn1Value::Boolean(true));
        assert_eq!(decoded_f, Asn1Value::Boolean(false));
    }

    #[test]
    fn test_null() {
        let null = Asn1Value::Null;
        let encoded = null.encode_der();
        assert_eq!(encoded, vec![0x05, 0x00]);

        let (decoded, _) = Asn1Value::decode_der(&encoded).unwrap();
        assert_eq!(decoded, Asn1Value::Null);
    }

    #[test]
    fn test_length_encoding() {
        let mut buf = Vec::new();

        // Short form
        encode_length(100, &mut buf);
        assert_eq!(buf, vec![100]);

        // Long form (1 byte)
        buf.clear();
        encode_length(200, &mut buf);
        assert_eq!(buf, vec![0x81, 200]);

        // Long form (2 bytes)
        buf.clear();
        encode_length(1000, &mut buf);
        assert_eq!(buf, vec![0x82, 0x03, 0xE8]);
    }
}
