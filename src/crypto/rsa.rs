/// RSA encryption implementation from scratch
/// Implements RSA public-key cryptography using only Rust std library
///
/// Supports:
/// - RSA encryption with PKCS#1 v1.5 padding
/// - Public key operations (encryption)
/// - Key extraction from X.509 certificates
///
/// Note: This implements ONLY public key encryption (for TLS ClientKeyExchange)
/// We don't need RSA signature verification or private key operations
///
/// Replaces: OpenSSL RSA, ring, rustls crypto
use super::bigint::BigInt;
use std::io::Read;

/// RSA public key
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    /// Modulus (n)
    pub n: BigInt,
    /// Public exponent (e) - typically 65537 (0x10001)
    pub e: BigInt,
    /// Key size in bits
    pub bits: usize,
}

impl RsaPublicKey {
    /// Create a new RSA public key
    pub fn new(n: BigInt, e: BigInt) -> Self {
        let bits = n.bit_length();
        Self { n, e, bits }
    }

    /// Encrypt data with PKCS#1 v1.5 padding
    /// Used for TLS ClientKeyExchange to encrypt the pre-master secret
    pub fn encrypt_pkcs1v15(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let k = (self.bits + 7) / 8; // modulus size in bytes

        // PKCS#1 v1.5 padding: EM = 0x00 || 0x02 || PS || 0x00 || M
        // where PS is random non-zero padding, at least 8 bytes
        if plaintext.len() > k - 11 {
            return Err("Plaintext too long for RSA encryption".to_string());
        }

        let ps_len = k - plaintext.len() - 3;
        if ps_len < 8 {
            return Err("Insufficient space for padding".to_string());
        }

        // Build padded message
        let mut em = Vec::with_capacity(k);
        em.push(0x00);
        em.push(0x02);

        // Generate random non-zero padding
        let ps = generate_random_nonzero(ps_len);
        em.extend_from_slice(&ps);

        em.push(0x00);
        em.extend_from_slice(plaintext);

        // Convert to BigInt
        let m = BigInt::from_bytes_be(&em);

        // RSA encryption: c = m^e mod n
        let c = m.mod_exp(&self.e, &self.n);

        // Convert to bytes, ensuring it's exactly k bytes
        let mut ciphertext = c.to_bytes_be();

        // Pad with leading zeros if necessary
        while ciphertext.len() < k {
            ciphertext.insert(0, 0);
        }

        Ok(ciphertext)
    }

    /// Get key size in bytes
    pub fn size(&self) -> usize {
        (self.bits + 7) / 8
    }
}

/// Generate n bytes of random non-zero data
fn generate_random_nonzero(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];

    // Read from /dev/urandom on Unix systems
    #[cfg(unix)]
    {
        let mut file = std::fs::File::open("/dev/urandom").expect("Failed to open /dev/urandom");
        file.read_exact(&mut buf)
            .expect("Failed to read random data");
    }

    // Fallback: use a simple PRNG based on current time
    #[cfg(not(unix))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        for byte in &mut buf {
            // Linear congruential generator
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (seed >> 32) as u8;
        }
    }

    // Ensure no zeros (PKCS#1 v1.5 requirement)
    for byte in &mut buf {
        if *byte == 0 {
            *byte = 1; // Replace zeros with 1
        }
    }

    buf
}

/// ASN.1 DER parser (minimal implementation for X.509 certificates)
pub mod asn1 {
    use super::BigInt;

    /// ASN.1 tag types
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum Tag {
        Integer = 0x02,
        BitString = 0x03,
        OctetString = 0x04,
        Null = 0x05,
        ObjectIdentifier = 0x06,
        Sequence = 0x30,
    }

    /// Parse ASN.1 DER length
    pub fn parse_length(data: &[u8], offset: &mut usize) -> Result<usize, String> {
        if *offset >= data.len() {
            return Err("Unexpected end of data".to_string());
        }

        let first = data[*offset];
        *offset += 1;

        if first & 0x80 == 0 {
            // Short form: length is in the first byte
            Ok(first as usize)
        } else {
            // Long form: first byte indicates number of length bytes
            let num_bytes = (first & 0x7F) as usize;
            if num_bytes > 4 {
                return Err("Length too large".to_string());
            }

            if *offset + num_bytes > data.len() {
                return Err("Unexpected end of data".to_string());
            }

            let mut length = 0usize;
            for _ in 0..num_bytes {
                length = (length << 8) | data[*offset] as usize;
                *offset += 1;
            }

            Ok(length)
        }
    }

    /// Parse an ASN.1 SEQUENCE
    pub fn parse_sequence(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, String> {
        if *offset >= data.len() {
            return Err("Unexpected end of data".to_string());
        }

        let tag = data[*offset];
        *offset += 1;

        if tag != Tag::Sequence as u8 {
            return Err(format!("Expected SEQUENCE, got tag 0x{:02x}", tag));
        }

        let length = parse_length(data, offset)?;

        if *offset + length > data.len() {
            return Err("Sequence extends beyond data".to_string());
        }

        let seq_data = data[*offset..*offset + length].to_vec();
        *offset += length;

        Ok(seq_data)
    }

    /// Parse an ASN.1 INTEGER and return as BigInt
    pub fn parse_integer(data: &[u8], offset: &mut usize) -> Result<BigInt, String> {
        if *offset >= data.len() {
            return Err("Unexpected end of data".to_string());
        }

        let tag = data[*offset];
        *offset += 1;

        if tag != Tag::Integer as u8 {
            return Err(format!("Expected INTEGER, got tag 0x{:02x}", tag));
        }

        let length = parse_length(data, offset)?;

        if *offset + length > data.len() {
            return Err("Integer extends beyond data".to_string());
        }

        let int_bytes = &data[*offset..*offset + length];
        *offset += length;

        // Remove leading zero byte if present (ASN.1 uses it for sign)
        let int_bytes = if int_bytes[0] == 0 && int_bytes.len() > 1 {
            &int_bytes[1..]
        } else {
            int_bytes
        };

        Ok(BigInt::from_bytes_be(int_bytes))
    }

    /// Parse an ASN.1 BIT STRING
    pub fn parse_bit_string(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, String> {
        if *offset >= data.len() {
            return Err("Unexpected end of data".to_string());
        }

        let tag = data[*offset];
        *offset += 1;

        if tag != Tag::BitString as u8 {
            return Err(format!("Expected BIT STRING, got tag 0x{:02x}", tag));
        }

        let length = parse_length(data, offset)?;

        if *offset + length > data.len() {
            return Err("Bit string extends beyond data".to_string());
        }

        // First byte is number of unused bits (should be 0 for our use case)
        let _unused_bits = data[*offset];
        *offset += 1;

        let bit_string = data[*offset..*offset + length - 1].to_vec();
        *offset += length - 1;

        Ok(bit_string)
    }

    /// Skip an ASN.1 element (any type)
    pub fn skip_element(data: &[u8], offset: &mut usize) -> Result<(), String> {
        if *offset >= data.len() {
            return Err("Unexpected end of data".to_string());
        }

        let _tag = data[*offset];
        *offset += 1;

        let length = parse_length(data, offset)?;

        if *offset + length > data.len() {
            return Err("Element extends beyond data".to_string());
        }

        *offset += length;
        Ok(())
    }
}

/// Extract RSA public key from X.509 certificate (DER format)
pub fn extract_public_key_from_cert(cert_der: &[u8]) -> Result<RsaPublicKey, String> {
    let mut offset = 0;

    // Certificate ::= SEQUENCE {
    //     tbsCertificate       TBSCertificate,
    //     signatureAlgorithm   AlgorithmIdentifier,
    //     signature            BIT STRING }

    let _cert_seq = asn1::parse_sequence(cert_der, &mut offset)?;
    offset = 0; // Reset to parse the contents

    // Parse outer SEQUENCE tag
    if cert_der[offset] != asn1::Tag::Sequence as u8 {
        return Err("Invalid certificate: not a SEQUENCE".to_string());
    }
    offset += 1;
    let _cert_len = asn1::parse_length(cert_der, &mut offset)?;

    // TBSCertificate ::= SEQUENCE
    let tbs_cert = asn1::parse_sequence(cert_der, &mut offset)?;
    let mut tbs_offset = 0;

    // Skip version [0] EXPLICIT (optional)
    if tbs_cert[tbs_offset] == 0xa0 {
        asn1::skip_element(&tbs_cert, &mut tbs_offset)?;
    }

    // Skip serialNumber
    asn1::skip_element(&tbs_cert, &mut tbs_offset)?;

    // Skip signature algorithm
    asn1::skip_element(&tbs_cert, &mut tbs_offset)?;

    // Skip issuer
    asn1::skip_element(&tbs_cert, &mut tbs_offset)?;

    // Skip validity
    asn1::skip_element(&tbs_cert, &mut tbs_offset)?;

    // Skip subject
    asn1::skip_element(&tbs_cert, &mut tbs_offset)?;

    // SubjectPublicKeyInfo ::= SEQUENCE {
    //     algorithm       AlgorithmIdentifier,
    //     subjectPublicKey BIT STRING }

    let spki = asn1::parse_sequence(&tbs_cert, &mut tbs_offset)?;
    let mut spki_offset = 0;

    // Skip algorithm identifier (SEQUENCE containing OID)
    asn1::skip_element(&spki, &mut spki_offset)?;

    // Parse subjectPublicKey BIT STRING
    let public_key_bits = asn1::parse_bit_string(&spki, &mut spki_offset)?;

    // RSAPublicKey ::= SEQUENCE {
    //     modulus         INTEGER,
    //     publicExponent  INTEGER }

    let mut pk_offset = 0;
    let _rsa_seq = asn1::parse_sequence(&public_key_bits, &mut pk_offset)?;
    pk_offset = 0; // Reset

    // Skip SEQUENCE tag
    if public_key_bits[pk_offset] != asn1::Tag::Sequence as u8 {
        return Err("Invalid RSA public key: not a SEQUENCE".to_string());
    }
    pk_offset += 1;
    let _rsa_len = asn1::parse_length(&public_key_bits, &mut pk_offset)?;

    // Parse modulus (n)
    let n = asn1::parse_integer(&public_key_bits, &mut pk_offset)?;

    // Parse public exponent (e)
    let e = asn1::parse_integer(&public_key_bits, &mut pk_offset)?;

    Ok(RsaPublicKey::new(n, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_public_key() {
        // Small RSA key for testing: n = 3233, e = 17
        // (from RSA paper example)
        let n = BigInt::from_u64(3233);
        let e = BigInt::from_u64(17);
        let key = RsaPublicKey::new(n, e);

        assert_eq!(key.bits, 12); // 3233 = 0xCA1, 12 bits
    }

    #[test]
    fn test_pkcs1v15_padding() {
        // Test that padding works correctly
        let n = BigInt::from_bytes_be(&[0xFF; 128]); // 1024-bit key
        let e = BigInt::from_u64(65537);
        let key = RsaPublicKey::new(n, e);

        let plaintext = b"Hello, World!";
        let result = key.encrypt_pkcs1v15(plaintext);

        assert!(result.is_ok());
        let ciphertext = result.unwrap();
        assert_eq!(ciphertext.len(), 128); // 1024 bits = 128 bytes
    }

    #[test]
    fn test_asn1_parse_integer() {
        // ASN.1 encoding of integer 42: 02 01 2A
        let data = vec![0x02, 0x01, 0x2A];
        let mut offset = 0;
        let result = asn1::parse_integer(&data, &mut offset);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), BigInt::from_u64(42));
    }

    #[test]
    fn test_asn1_parse_sequence() {
        // ASN.1 encoding of SEQUENCE containing two integers
        // SEQUENCE { INTEGER 1, INTEGER 2 }
        // 30 06 02 01 01 02 01 02
        let data = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let mut offset = 0;
        let result = asn1::parse_sequence(&data, &mut offset);

        assert!(result.is_ok());
        let seq = result.unwrap();
        assert_eq!(seq.len(), 6);
    }
}
