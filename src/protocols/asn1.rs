// ASN.1/DER Parser - RFC 2459 (X.509), RFC 5280
// Distinguished Encoding Rules (DER) for parsing certificates and TLS messages
//
// ASN.1 is the data structure format used in X.509 certificates and TLS handshakes.
// DER is the binary encoding of ASN.1 (deterministic, canonical representation).

use std::fmt;

/// ASN.1 Tag Classes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TagClass {
    Universal = 0x00,
    Application = 0x01,
    ContextSpecific = 0x02,
    Private = 0x03,
}

/// ASN.1 Universal Tag Numbers
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tag {
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    ObjectIdentifier = 0x06,
    UTF8String = 0x0C,
    Sequence = 0x10,
    Set = 0x11,
    PrintableString = 0x13,
    IA5String = 0x16,
    UTCTime = 0x17,
    GeneralizedTime = 0x18,
}

/// ASN.1 Value Types
#[derive(Debug, Clone)]
pub enum Asn1Value {
    Boolean(bool),
    Integer(Vec<u8>),
    BitString(Vec<u8>, u8), // data, unused_bits
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(Vec<u64>),
    UTF8String(String),
    Sequence(Vec<Asn1Object>),
    Set(Vec<Asn1Object>),
    PrintableString(String),
    IA5String(String),
    UTCTime(String),
    GeneralizedTime(String),
    ContextSpecific(u8, Vec<u8>), // tag_number, raw_data
}

/// ASN.1 Object (Type-Length-Value)
#[derive(Debug, Clone)]
pub struct Asn1Object {
    pub tag: u8,
    pub constructed: bool,
    pub value: Asn1Value,
}

impl Asn1Object {
    /// Parse DER-encoded bytes into ASN.1 object
    pub fn from_der(data: &[u8]) -> Result<(Self, usize), String> {
        if data.is_empty() {
            return Err("Empty DER data".to_string());
        }

        let mut offset = 0;

        // Parse tag
        let tag_byte = data[offset];
        offset += 1;

        let constructed = (tag_byte & 0x20) != 0;
        let tag_class = (tag_byte >> 6) & 0x03; // 0=Universal, 2=Context-specific
        let tag_number = tag_byte & 0x1F;

        // Parse length
        if offset >= data.len() {
            return Err("Unexpected end of data (length)".to_string());
        }

        let (length, length_bytes) = parse_length(&data[offset..])?;
        offset += length_bytes;

        // Parse value
        if offset + length > data.len() {
            return Err(format!(
                "Invalid length: offset={}, length={}, data.len()={}",
                offset,
                length,
                data.len()
            ));
        }

        let value_bytes = &data[offset..offset + length];
        // Pass full tag_byte so parse_value can detect context-specific tags
        let value = parse_value(tag_byte, constructed, value_bytes)?;

        let obj = Asn1Object {
            tag: tag_byte, // Store full tag byte to preserve class info
            constructed,
            value,
        };

        Ok((obj, offset + length))
    }

    /// Get sequence contents (if this is a SEQUENCE)
    pub fn as_sequence(&self) -> Result<&Vec<Asn1Object>, String> {
        match &self.value {
            Asn1Value::Sequence(seq) => Ok(seq),
            _ => Err(format!("Expected SEQUENCE, got {:?}", self.value)),
        }
    }

    /// Get set contents (if this is a SET)
    pub fn as_set(&self) -> Result<&Vec<Asn1Object>, String> {
        match &self.value {
            Asn1Value::Set(set) => Ok(set),
            _ => Err(format!("Expected SET, got {:?}", self.value)),
        }
    }

    /// Get sequence OR set contents (for structures like X.509 Name where SET is used)
    pub fn as_sequence_or_set(&self) -> Result<&Vec<Asn1Object>, String> {
        match &self.value {
            Asn1Value::Sequence(items) => Ok(items),
            Asn1Value::Set(items) => Ok(items),
            _ => Err(format!("Expected SEQUENCE or SET, got {:?}", self.value)),
        }
    }

    /// Get integer as bytes
    pub fn as_integer(&self) -> Result<&Vec<u8>, String> {
        match &self.value {
            Asn1Value::Integer(bytes) => Ok(bytes),
            _ => Err(format!("Expected INTEGER, got {:?}", self.value)),
        }
    }

    /// Get OID as string (e.g., "1.2.840.113549.1.1.1")
    pub fn as_oid(&self) -> Result<String, String> {
        match &self.value {
            Asn1Value::ObjectIdentifier(components) => Ok(components
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(".")),
            _ => Err(format!("Expected OID, got {:?}", self.value)),
        }
    }

    /// Get octet string
    pub fn as_octet_string(&self) -> Result<&Vec<u8>, String> {
        match &self.value {
            Asn1Value::OctetString(bytes) => Ok(bytes),
            _ => Err(format!("Expected OCTET STRING, got {:?}", self.value)),
        }
    }

    /// Get bit string
    pub fn as_bit_string(&self) -> Result<(&Vec<u8>, u8), String> {
        match &self.value {
            Asn1Value::BitString(bytes, unused_bits) => Ok((bytes, *unused_bits)),
            _ => Err(format!("Expected BIT STRING, got {:?}", self.value)),
        }
    }

    /// Get string value (UTF8String, PrintableString, IA5String)
    pub fn as_string(&self) -> Result<String, String> {
        match &self.value {
            Asn1Value::UTF8String(s) => Ok(s.clone()),
            Asn1Value::PrintableString(s) => Ok(s.clone()),
            Asn1Value::IA5String(s) => Ok(s.clone()),
            Asn1Value::UTCTime(s) => Ok(s.clone()),
            Asn1Value::GeneralizedTime(s) => Ok(s.clone()),
            _ => Err(format!("Expected STRING, got {:?}", self.value)),
        }
    }

    /// Check if this is a context-specific tag with the given tag number
    /// Context-specific tags have class bits = 10 (0x80)
    /// tag_num is the tag number (0-30)
    pub fn is_context_specific(&self, tag_num: u8) -> bool {
        // Check via value type (most reliable)
        match &self.value {
            Asn1Value::ContextSpecific(n, _) => *n == tag_num,
            _ => {
                // Fallback: check tag byte class bits (10 = context-specific)
                let tag_class = (self.tag >> 6) & 0x03;
                tag_class == 0x02 && (self.tag & 0x1F) == tag_num
            }
        }
    }

    /// Get context-specific data
    pub fn as_context_specific(&self) -> Result<&Vec<u8>, String> {
        match &self.value {
            Asn1Value::ContextSpecific(_, data) => Ok(data),
            _ => Err(format!("Expected context-specific, got {:?}", self.value)),
        }
    }
}

/// Parse DER length encoding
///
/// DER length can be:
/// - Short form (0-127): 1 byte
/// - Long form (128+): first byte = 0x80 | number_of_length_bytes, followed by length bytes
fn parse_length(data: &[u8]) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("Empty data for length".to_string());
    }

    let first_byte = data[0];

    if first_byte & 0x80 == 0 {
        // Short form: length is in the first byte
        Ok((first_byte as usize, 1))
    } else {
        // Long form: first byte tells us how many bytes encode the length
        let num_length_bytes = (first_byte & 0x7F) as usize;

        if num_length_bytes == 0 {
            return Err("Indefinite length not supported in DER".to_string());
        }

        if num_length_bytes > 4 {
            return Err(format!("Length too long: {} bytes", num_length_bytes));
        }

        if 1 + num_length_bytes > data.len() {
            return Err("Not enough data for length".to_string());
        }

        let mut length: usize = 0;
        for i in 0..num_length_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }

        Ok((length, 1 + num_length_bytes))
    }
}

/// Parse ASN.1 value based on tag
fn parse_value(tag_byte: u8, constructed: bool, data: &[u8]) -> Result<Asn1Value, String> {
    // Extract tag class and number from the full tag byte
    let tag_class = (tag_byte >> 6) & 0x03; // 0=Universal, 1=Application, 2=Context-specific, 3=Private
    let tag_number = tag_byte & 0x1F;

    // Handle context-specific tags (class 2 = 0x80-0xBF range)
    if tag_class == 2 {
        return Ok(Asn1Value::ContextSpecific(tag_number, data.to_vec()));
    }

    // For universal tags, match on the tag number (not the full byte)
    match tag_number {
        0x00 => {
            // Tag [0] - context-specific tag (used in EXPLICIT/IMPLICIT tagging)
            // Store as ContextSpecific so X.509 parser can handle it
            Ok(Asn1Value::ContextSpecific(0, data.to_vec()))
        }
        0x01 => {
            // BOOLEAN
            if data.len() != 1 {
                return Err("Invalid BOOLEAN length".to_string());
            }
            Ok(Asn1Value::Boolean(data[0] != 0))
        }
        0x02 => {
            // INTEGER
            Ok(Asn1Value::Integer(data.to_vec()))
        }
        0x03 => {
            // BIT STRING
            if data.is_empty() {
                return Err("Empty BIT STRING".to_string());
            }
            let unused_bits = data[0];
            Ok(Asn1Value::BitString(data[1..].to_vec(), unused_bits))
        }
        0x04 => {
            // OCTET STRING
            Ok(Asn1Value::OctetString(data.to_vec()))
        }
        0x05 => {
            // NULL
            if !data.is_empty() {
                return Err("NULL must have zero length".to_string());
            }
            Ok(Asn1Value::Null)
        }
        0x06 => {
            // OBJECT IDENTIFIER
            parse_oid(data)
        }
        0x0C => {
            // UTF8String
            let s = String::from_utf8(data.to_vec())
                .map_err(|e| format!("Invalid UTF8String: {}", e))?;
            Ok(Asn1Value::UTF8String(s))
        }
        0x10 => {
            // SEQUENCE
            if !constructed {
                return Err("SEQUENCE must be constructed".to_string());
            }
            parse_sequence(data)
        }
        0x11 => {
            // SET
            if !constructed {
                return Err("SET must be constructed".to_string());
            }
            parse_sequence(data) // Same parsing as SEQUENCE
                .map(|v| match v {
                    Asn1Value::Sequence(items) => Asn1Value::Set(items),
                    _ => unreachable!(),
                })
        }
        0x13 => {
            // PrintableString
            let s = String::from_utf8(data.to_vec())
                .map_err(|e| format!("Invalid PrintableString: {}", e))?;
            Ok(Asn1Value::PrintableString(s))
        }
        0x16 => {
            // IA5String
            let s = String::from_utf8(data.to_vec())
                .map_err(|e| format!("Invalid IA5String: {}", e))?;
            Ok(Asn1Value::IA5String(s))
        }
        0x17 => {
            // UTCTime (YYMMDDHHMMSSZ)
            let s =
                String::from_utf8(data.to_vec()).map_err(|e| format!("Invalid UTCTime: {}", e))?;
            Ok(Asn1Value::UTCTime(s))
        }
        0x18 => {
            // GeneralizedTime (YYYYMMDDHHMMSSZ)
            let s = String::from_utf8(data.to_vec())
                .map_err(|e| format!("Invalid GeneralizedTime: {}", e))?;
            Ok(Asn1Value::GeneralizedTime(s))
        }
        _ => Err(format!(
            "Unsupported tag: 0x{:02X} (class={}, number={})",
            tag_byte, tag_class, tag_number
        )),
    }
}

/// Parse SEQUENCE or SET (list of ASN.1 objects)
fn parse_sequence(data: &[u8]) -> Result<Asn1Value, String> {
    let mut objects = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let (obj, consumed) = Asn1Object::from_der(&data[offset..])?;
        objects.push(obj);
        offset += consumed;
    }

    Ok(Asn1Value::Sequence(objects))
}

/// Parse Object Identifier (OID)
///
/// OID encoding:
/// - First byte encodes first two components: 40*first + second
/// - Subsequent bytes use base-128 encoding (high bit = continuation)
fn parse_oid(data: &[u8]) -> Result<Asn1Value, String> {
    if data.is_empty() {
        return Err("Empty OID".to_string());
    }

    let mut components = Vec::new();

    // First byte encodes first two components
    let first_byte = data[0];
    components.push((first_byte / 40) as u64);
    components.push((first_byte % 40) as u64);

    // Parse remaining components
    let mut i = 1;
    while i < data.len() {
        let mut value: u64 = 0;

        loop {
            if i >= data.len() {
                return Err("Incomplete OID component".to_string());
            }

            let byte = data[i];
            i += 1;

            value = (value << 7) | ((byte & 0x7F) as u64);

            // If high bit is 0, this is the last byte of the component
            if byte & 0x80 == 0 {
                break;
            }
        }

        components.push(value);
    }

    Ok(Asn1Value::ObjectIdentifier(components))
}

impl fmt::Display for Asn1Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Asn1Value::Boolean(b) => write!(f, "BOOLEAN: {}", b),
            Asn1Value::Integer(bytes) => {
                write!(f, "INTEGER: ")?;
                for (i, byte) in bytes.iter().enumerate() {
                    if i > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{:02X}", byte)?;
                }
                Ok(())
            }
            Asn1Value::BitString(bytes, unused) => {
                write!(
                    f,
                    "BIT STRING ({} unused bits): {} bytes",
                    unused,
                    bytes.len()
                )
            }
            Asn1Value::OctetString(bytes) => write!(f, "OCTET STRING: {} bytes", bytes.len()),
            Asn1Value::Null => write!(f, "NULL"),
            Asn1Value::ObjectIdentifier(components) => {
                write!(f, "OID: ")?;
                write!(
                    f,
                    "{}",
                    components
                        .iter()
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(".")
                )
            }
            Asn1Value::UTF8String(s) => write!(f, "UTF8String: {}", s),
            Asn1Value::Sequence(objects) => {
                write!(f, "SEQUENCE ({} items)", objects.len())
            }
            Asn1Value::Set(objects) => {
                write!(f, "SET ({} items)", objects.len())
            }
            Asn1Value::PrintableString(s) => write!(f, "PrintableString: {}", s),
            Asn1Value::IA5String(s) => write!(f, "IA5String: {}", s),
            Asn1Value::UTCTime(s) => write!(f, "UTCTime: {}", s),
            Asn1Value::GeneralizedTime(s) => write!(f, "GeneralizedTime: {}", s),
            Asn1Value::ContextSpecific(tag, data) => {
                write!(f, "ContextSpecific[{}]: {} bytes", tag, data.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_integer() {
        // INTEGER 42 (0x2A)
        let data = vec![0x02, 0x01, 0x2A];
        let (obj, consumed) = Asn1Object::from_der(&data).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(obj.tag, 0x02);
        let int_bytes = obj.as_integer().unwrap();
        assert_eq!(int_bytes, &vec![0x2A]);
    }

    #[test]
    fn test_parse_boolean() {
        // BOOLEAN true
        let data = vec![0x01, 0x01, 0xFF];
        let (obj, _) = Asn1Object::from_der(&data).unwrap();
        match obj.value {
            Asn1Value::Boolean(b) => assert!(b),
            _ => panic!("Expected boolean"),
        }
    }

    #[test]
    fn test_parse_null() {
        // NULL
        let data = vec![0x05, 0x00];
        let (obj, consumed) = Asn1Object::from_der(&data).unwrap();
        assert_eq!(consumed, 2);
        match obj.value {
            Asn1Value::Null => (),
            _ => panic!("Expected NULL"),
        }
    }

    #[test]
    fn test_parse_oid() {
        // OID 1.2.840.113549 (RSA)
        let data = vec![0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D];
        let (obj, _) = Asn1Object::from_der(&data).unwrap();
        let oid_str = obj.as_oid().unwrap();
        assert_eq!(oid_str, "1.2.840.113549");
    }

    #[test]
    fn test_parse_sequence() {
        // SEQUENCE { INTEGER 1, INTEGER 2 }
        let data = vec![
            0x30, 0x06, // SEQUENCE, length 6
            0x02, 0x01, 0x01, // INTEGER 1
            0x02, 0x01, 0x02, // INTEGER 2
        ];
        let (obj, _) = Asn1Object::from_der(&data).unwrap();
        let seq = obj.as_sequence().unwrap();
        assert_eq!(seq.len(), 2);
    }

    #[test]
    fn test_parse_utf8_string() {
        // UTF8String "hello"
        let data = vec![0x0C, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let (obj, _) = Asn1Object::from_der(&data).unwrap();
        let s = obj.as_string().unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_parse_long_length() {
        // INTEGER with long form length
        // Tag: 0x02, Length: 0x81 0x80 (128 bytes), Value: 128 bytes of 0x00
        let mut data = vec![0x02, 0x81, 0x80];
        data.extend(vec![0x00; 128]);
        let (obj, consumed) = Asn1Object::from_der(&data).unwrap();
        assert_eq!(consumed, 3 + 128);
        let int_bytes = obj.as_integer().unwrap();
        assert_eq!(int_bytes.len(), 128);
    }
}
