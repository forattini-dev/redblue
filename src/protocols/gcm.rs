/// AES-GCM (Galois/Counter Mode) Implementation from Scratch
///
/// Reference: NIST SP 800-38D
/// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
///
/// This implements AES-GCM authenticated encryption WITHOUT external dependencies.
/// Only uses Rust std library and our own AES implementation.
// use super::crypto::Aes128; // FIXME: Old stub, use crate::crypto instead

/// GHASH function for GCM mode
/// Implements multiplication in GF(2^128)
fn ghash(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];

    // Process data in 16-byte blocks
    for chunk in data.chunks(16) {
        let mut x = [0u8; 16];
        x[..chunk.len()].copy_from_slice(chunk);

        // XOR with current Y
        for i in 0..16 {
            y[i] ^= x[i];
        }

        // Multiply in GF(2^128)
        y = gf128_mul(&y, h);
    }

    y
}

/// Multiplication in GF(2^128) using the polynomial x^128 + x^7 + x^2 + x + 1
fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;

    for i in 0..128 {
        // Get bit i of x (big-endian bit order)
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);
        let bit = (x[byte_idx] >> bit_idx) & 1;

        if bit == 1 {
            // z = z XOR v
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }

        // Check LSB of v
        let lsb = v[15] & 1;

        // v = v >> 1 (shift right by 1 bit)
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;

        // If LSB was 1, XOR with R = 0xE1 << 120
        if lsb == 1 {
            v[0] ^= 0xE1;
        }
    }

    z
}

/// Increment a 128-bit counter (big-endian, increment rightmost 32 bits)
fn gcm_incr(counter: &mut [u8; 16]) {
    for i in (12..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// AES-128-GCM encryption
///
/// # Arguments
/// * `key` - 16-byte encryption key
/// * `iv` - 12-byte initialization vector (nonce)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (can be empty)
///
/// # Returns
/// Ciphertext with 16-byte authentication tag appended
pub fn aes128_gcm_encrypt(key: &[u8; 16], iv: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key);

    // Compute H = AES(K, 0^128)
    let h = cipher.encrypt_block(&[0u8; 16]);

    // Initialize counter: IV || 0^31 || 1
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(iv);
    counter[15] = 1;

    // Encrypt plaintext using CTR mode
    let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);
    for chunk in plaintext.chunks(16) {
        gcm_incr(&mut counter);

        let keystream = cipher.encrypt_block(&counter);
        for (i, &byte) in chunk.iter().enumerate() {
            ciphertext.push(byte ^ keystream[i]);
        }
    }

    // Compute authentication tag using GHASH
    let mut ghash_input = Vec::new();

    // Add AAD with padding
    ghash_input.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    ghash_input.extend(vec![0u8; aad_pad]);

    // Add ciphertext with padding
    ghash_input.extend_from_slice(&ciphertext);
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    ghash_input.extend(vec![0u8; ct_pad]);

    // Add lengths (in bits)
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    ghash_input.extend_from_slice(&aad_bits.to_be_bytes());
    ghash_input.extend_from_slice(&ct_bits.to_be_bytes());

    let mut tag = ghash(&h, &ghash_input);

    // Encrypt tag with J0 = IV || 0^31 || 1
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;

    let j0_encrypted = cipher.encrypt_block(&j0);

    for i in 0..16 {
        tag[i] ^= j0_encrypted[i];
    }

    // Append tag to ciphertext
    ciphertext.extend_from_slice(&tag);
    ciphertext
}

/// AES-128-GCM decryption
///
/// # Arguments
/// * `key` - 16-byte encryption key
/// * `iv` - 12-byte initialization vector (nonce)
/// * `ciphertext_with_tag` - Encrypted data with 16-byte tag appended
/// * `aad` - Additional authenticated data (must match encryption)
///
/// # Returns
/// Decrypted plaintext or error if authentication fails
pub fn aes128_gcm_decrypt(
    key: &[u8; 16],
    iv: &[u8; 12],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if ciphertext_with_tag.len() < 16 {
        return Err("Ciphertext too short (missing tag)".to_string());
    }

    let tag_start = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..tag_start];
    let received_tag = &ciphertext_with_tag[tag_start..];

    let cipher = Aes128::new(key);

    // Compute H = AES(K, 0^128)
    let h = cipher.encrypt_block(&[0u8; 16]);

    // Verify authentication tag
    let mut ghash_input = Vec::new();

    // Add AAD with padding
    ghash_input.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    ghash_input.extend(vec![0u8; aad_pad]);

    // Add ciphertext with padding
    ghash_input.extend_from_slice(ciphertext);
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    ghash_input.extend(vec![0u8; ct_pad]);

    // Add lengths (in bits)
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    ghash_input.extend_from_slice(&aad_bits.to_be_bytes());
    ghash_input.extend_from_slice(&ct_bits.to_be_bytes());

    let mut computed_tag = ghash(&h, &ghash_input);

    // Encrypt tag with J0
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;

    let j0_encrypted = cipher.encrypt_block(&j0);

    for i in 0..16 {
        computed_tag[i] ^= j0_encrypted[i];
    }

    // Constant-time comparison
    let mut tag_match = true;
    for i in 0..16 {
        if computed_tag[i] != received_tag[i] {
            tag_match = false;
        }
    }

    if !tag_match {
        return Err("Authentication tag verification failed".to_string());
    }

    // Decrypt ciphertext using CTR mode
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(iv);
    counter[15] = 1;

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        gcm_incr(&mut counter);

        let keystream = cipher.encrypt_block(&counter);
        for (i, &byte) in chunk.iter().enumerate() {
            plaintext.push(byte ^ keystream[i]);
        }
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcm_encrypt_decrypt() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let plaintext = b"Hello, GCM!";
        let aad = b"additional data";

        let ciphertext = aes128_gcm_encrypt(&key, &iv, plaintext, aad);
        let decrypted = aes128_gcm_decrypt(&key, &iv, &ciphertext, aad).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_gcm_authentication_failure() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let plaintext = b"Hello, GCM!";
        let aad = b"additional data";

        let mut ciphertext = aes128_gcm_encrypt(&key, &iv, plaintext, aad);

        // Tamper with ciphertext
        ciphertext[0] ^= 1;

        let result = aes128_gcm_decrypt(&key, &iv, &ciphertext, aad);
        assert!(result.is_err());
    }
}
