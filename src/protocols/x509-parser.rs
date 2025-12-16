//! Minimal X.509 Certificate Parser from Scratch
//!
//! This implements JUST ENOUGH DER/ASN.1 parsing to extract RSA public keys
//! from X.509 certificates for TLS handshakes.
//!
//! References:
//! - RFC 5280 (X.509): https://www.rfc-editor.org/rfc/rfc5280
//! - ITU-T X.690 (DER): https://www.itu.int/rec/T-REC-X.690
//!
//! Status: Minimal implementation - enough for TLS 1.2

/// DER tag types
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_SEQUENCE: u8 = 0x30;

/// Parse DER length field
fn parse_der_length(data: &[u8], offset: &mut usize) -> Result<usize, String> {
    if *offset >= data.len() {
        return Err("Unexpected end of data".to_string());
    }

    let first_byte = data[*offset];
    *offset += 1;

    if first_byte & 0x80 == 0 {
        // Short form: length is in the first byte
        Ok(first_byte as usize)
    } else {
        // Long form: first byte indicates how many following bytes contain the length
        let num_bytes = (first_byte & 0x7F) as usize;
        if num_bytes > 4 {
            return Err("Length too long".to_string());
        }

        if *offset + num_bytes > data.len() {
            return Err("Unexpected end of data".to_string());
        }

        let mut length = 0usize;
        for _ in 0..num_bytes {
            length = (length << 8) | (data[*offset] as usize);
            *offset += 1;
        }

        Ok(length)
    }
}

/// Skip a DER element
fn skip_der_element(data: &[u8], offset: &mut usize) -> Result<(), String> {
    if *offset >= data.len() {
        return Err("Unexpected end of data".to_string());
    }

    // Skip tag
    *offset += 1;

    // Parse and skip length
    let length = parse_der_length(data, offset)?;

    // Skip content
    *offset += length;

    if *offset > data.len() {
        return Err("Invalid length".to_string());
    }

    Ok(())
}

/// Parse DER SEQUENCE and return content
fn parse_der_sequence<'a>(data: &'a [u8], offset: &mut usize) -> Result<&'a [u8], String> {
    if *offset >= data.len() {
        return Err("Unexpected end of data".to_string());
    }

    let tag = data[*offset];
    if tag != TAG_SEQUENCE {
        return Err(format!("Expected SEQUENCE tag, got 0x{:02X}", tag));
    }
    *offset += 1;

    let length = parse_der_length(data, offset)?;
    let content_start = *offset;

    if *offset + length > data.len() {
        return Err("SEQUENCE length exceeds data".to_string());
    }

    *offset += length;

    Ok(&data[content_start..content_start + length])
}

/// Parse DER INTEGER and return content bytes
fn parse_der_integer(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, String> {
    if *offset >= data.len() {
        return Err("Unexpected end of data".to_string());
    }

    let tag = data[*offset];
    if tag != TAG_INTEGER {
        return Err(format!("Expected INTEGER tag, got 0x{:02X}", tag));
    }
    *offset += 1;

    let length = parse_der_length(data, offset)?;
    let content_start = *offset;

    if *offset + length > data.len() {
        return Err("INTEGER length exceeds data".to_string());
    }

    *offset += length;

    let mut content = data[content_start..content_start + length].to_vec();

    // Remove leading zero byte if present (used for positive numbers in DER)
    if content.len() > 1 && content[0] == 0x00 {
        content.remove(0);
    }

    Ok(content)
}

/// Parse DER BIT STRING and return content bytes
fn parse_der_bit_string(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, String> {
    if *offset >= data.len() {
        return Err("Unexpected end of data".to_string());
    }

    let tag = data[*offset];
    if tag != TAG_BIT_STRING {
        return Err(format!("Expected BIT STRING tag, got 0x{:02X}", tag));
    }
    *offset += 1;

    let length = parse_der_length(data, offset)?;

    if *offset + length > data.len() {
        return Err("BIT STRING length exceeds data".to_string());
    }

    // First byte is number of unused bits (should be 0 for our use case)
    *offset += 1;

    let content_start = *offset;
    *offset += length - 1;

    Ok(data[content_start..content_start + length - 1].to_vec())
}

/// Extract RSA public key (n, e) from X.509 DER certificate
pub fn extract_rsa_public_key(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut offset = 0;

    // Certificate ::= SEQUENCE
    let cert_seq = parse_der_sequence(cert_der, &mut offset)?;

    let mut cert_offset = 0;

    // TBSCertificate ::= SEQUENCE
    let tbs_cert = parse_der_sequence(cert_seq, &mut cert_offset)?;

    let mut tbs_offset = 0;

    // Skip version [0] EXPLICIT (optional)
    if tbs_offset < tbs_cert.len() && tbs_cert[tbs_offset] == 0xA0 {
        skip_der_element(tbs_cert, &mut tbs_offset)?;
    }

    // Skip serialNumber INTEGER
    skip_der_element(tbs_cert, &mut tbs_offset)?;

    // Skip signature AlgorithmIdentifier SEQUENCE
    skip_der_element(tbs_cert, &mut tbs_offset)?;

    // Skip issuer Name SEQUENCE
    skip_der_element(tbs_cert, &mut tbs_offset)?;

    // Skip validity Validity SEQUENCE
    skip_der_element(tbs_cert, &mut tbs_offset)?;

    // Skip subject Name SEQUENCE
    skip_der_element(tbs_cert, &mut tbs_offset)?;

    // subjectPublicKeyInfo SubjectPublicKeyInfo ::= SEQUENCE
    let spki = parse_der_sequence(tbs_cert, &mut tbs_offset)?;

    let mut spki_offset = 0;

    // algorithm AlgorithmIdentifier ::= SEQUENCE (skip)
    skip_der_element(spki, &mut spki_offset)?;

    // subjectPublicKey BIT STRING
    let public_key_bits = parse_der_bit_string(spki, &mut spki_offset)?;

    // Parse RSA public key: SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    let mut pk_offset = 0;
    let rsa_seq = parse_der_sequence(&public_key_bits, &mut pk_offset)?;

    let mut rsa_offset = 0;

    // modulus n
    let n = parse_der_integer(rsa_seq, &mut rsa_offset)?;

    // publicExponent e
    let e = parse_der_integer(rsa_seq, &mut rsa_offset)?;

    Ok((n, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_der_length_short() {
        let data = [0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mut offset = 0;
        let length = parse_der_length(&data, &mut offset).unwrap();
        assert_eq!(length, 5);
        assert_eq!(offset, 1);
    }

    #[test]
    fn test_parse_der_length_long() {
        let data = [0x82, 0x01, 0x00]; // Length = 256 (2 bytes)
        let mut offset = 0;
        let length = parse_der_length(&data, &mut offset).unwrap();
        assert_eq!(length, 256);
        assert_eq!(offset, 3);
    }

    #[test]
    fn test_parse_der_integer() {
        // INTEGER 42 (0x2A)
        let data = [0x02, 0x01, 0x2A];
        let mut offset = 0;
        let value = parse_der_integer(&data, &mut offset).unwrap();
        assert_eq!(value, vec![0x2A]);
        assert_eq!(offset, 3);
    }
}
