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
use super::{sha256, sha384};
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

    /// Get key size in bits
    pub fn modulus_bits(&self) -> usize {
        self.bits
    }

    fn decrypt_signature(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        let k = self.size();
        if signature.len() > k {
            return Err("Signature length larger than modulus size".to_string());
        }

        let sig = BigInt::from_bytes_be(signature);
        let decrypted = sig.mod_exp(&self.e, &self.n);
        let mut em = decrypted.to_bytes_be();
        if em.len() < k {
            let mut padded = vec![0u8; k - em.len()];
            padded.extend_from_slice(&em);
            em = padded;
        }
        Ok(em)
    }

    /// Verify a PKCS#1 v1.5 signature against the provided DigestInfo.
    pub fn verify_pkcs1_v15(
        &self,
        expected_digest_info: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        let em = self.decrypt_signature(signature)?;
        if em.len() < expected_digest_info.len() + 11 {
            return Err("Decrypted signature too short".to_string());
        }

        if em[0] != 0x00 || em[1] != 0x01 {
            return Err("Invalid PKCS#1 padding header".to_string());
        }

        let mut idx = 2;
        while idx < em.len() && em[idx] == 0xFF {
            idx += 1;
        }

        if idx >= em.len() || em[idx] != 0x00 {
            return Err("Invalid PKCS#1 separator".to_string());
        }
        idx += 1;

        let digest_region = &em[idx..];
        if digest_region != expected_digest_info {
            return Err("DigestInfo mismatch".to_string());
        }

        Ok(())
    }

    fn verify_pss_internal(
        &self,
        message_hash: &[u8],
        signature: &[u8],
        hash_len: usize,
        hash_fn: fn(&[u8]) -> Vec<u8>,
    ) -> Result<(), String> {
        if message_hash.len() != hash_len {
            return Err("Message hash length does not match signature scheme".to_string());
        }

        let em = self.decrypt_signature(signature)?;
        if em.is_empty() {
            return Err("Decrypted signature empty".to_string());
        }
        if *em.last().unwrap() != 0xBC {
            return Err("RSA-PSS trailer field mismatch".to_string());
        }

        let em_len = em.len();
        if em_len < hash_len + 2 {
            return Err("RSA-PSS encoded message too short".to_string());
        }

        let db_len = em_len - hash_len - 1;
        let (masked_db, h) = em.split_at(db_len);
        let h = &h[..hash_len];

        let db_mask = mgf1(hash_fn, h, db_len);
        let mut db = masked_db.to_vec();
        for (byte, mask) in db.iter_mut().zip(db_mask.iter()) {
            *byte ^= *mask;
        }

        let em_bits = self.modulus_bits();
        let leading_bits = 8 * em_len - em_bits;
        if leading_bits > 8 {
            return Err("RSA modulus too small for signature".to_string());
        }
        if leading_bits > 0 {
            db[0] &= 0xFF >> leading_bits;
        }

        let salt_len = hash_len;
        if db_len < salt_len + 1 {
            return Err("RSA-PSS encoded message malformed".to_string());
        }

        let ps_len = db_len - salt_len - 1;
        if !db[..ps_len].iter().all(|b| *b == 0) {
            return Err("RSA-PSS padding not zeroed".to_string());
        }
        if db[ps_len] != 0x01 {
            return Err("RSA-PSS separator missing".to_string());
        }

        let salt = &db[ps_len + 1..];
        if salt.len() != salt_len {
            return Err("RSA-PSS salt length mismatch".to_string());
        }

        let mut m_prime = Vec::with_capacity(8 + hash_len + salt_len);
        m_prime.extend_from_slice(&[0u8; 8]);
        m_prime.extend_from_slice(message_hash);
        m_prime.extend_from_slice(salt);
        let h_prime = hash_fn(&m_prime);
        if h_prime.len() != hash_len {
            return Err("Hash function output length mismatch".to_string());
        }

        if h != h_prime.as_slice() {
            return Err("RSA-PSS signature verification failed".to_string());
        }

        Ok(())
    }

    /// Verify an RSA-PSS signature using SHA-256.
    pub fn verify_pss_sha256(&self, message_hash: &[u8], signature: &[u8]) -> Result<(), String> {
        self.verify_pss_internal(message_hash, signature, 32, sha256_hash)
    }

    /// Verify an RSA-PSS signature using SHA-384.
    pub fn verify_pss_sha384(&self, message_hash: &[u8], signature: &[u8]) -> Result<(), String> {
        self.verify_pss_internal(message_hash, signature, 48, sha384_hash)
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

fn mgf1(hash_fn: fn(&[u8]) -> Vec<u8>, seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(mask_len);
    let mut counter = 0u32;

    while mask.len() < mask_len {
        let mut data = Vec::with_capacity(seed.len() + 4);
        data.extend_from_slice(seed);
        data.extend_from_slice(&counter.to_be_bytes());

        let digest = hash_fn(&data);
        let take = std::cmp::min(mask_len - mask.len(), digest.len());
        mask.extend_from_slice(&digest[..take]);
        counter = counter
            .checked_add(1)
            .expect("MGF1 counter overflow (mask_len too large)");
    }

    mask
}

fn sha256_hash(data: &[u8]) -> Vec<u8> {
    sha256::sha256(data).to_vec()
}

fn sha384_hash(data: &[u8]) -> Vec<u8> {
    sha384::sha384(data).to_vec()
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
