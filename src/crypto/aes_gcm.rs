/// AES-256-GCM (Galois/Counter Mode) AEAD Cipher
/// NIST SP 800-38D - Galois/Counter Mode (GCM)
///
/// AES-GCM is an AEAD cipher used in TLS 1.3
///
/// Implements:
/// - AES-256 encryption (extension of AES-128)
/// - CTR mode encryption
/// - GHASH authentication
/// - GCM AEAD construction
///
/// ✅ ZERO DEPENDENCIES - Pure Rust implementation
/// Replaces: aes-gcm crate, ring, openssl

// S-box for SubBytes transformation (same as AES-128)
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Galois field multiplication (for MixColumns)
fn gmul(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut a = a;
    let mut b = b;

    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }

        let hi_bit_set = a & 0x80 != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1b; // AES irreducible polynomial
        }
        b >>= 1;
    }

    p
}

/// ShiftRows transformation
fn shift_rows(state: &mut [u8; 16]) {
    // Row 1: shift left by 1
    let temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 2: shift left by 2
    let temp1 = state[2];
    let temp2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = temp1;
    state[14] = temp2;

    // Row 3: shift left by 3
    let temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

/// MixColumns transformation
fn mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let s0 = state[i * 4];
        let s1 = state[i * 4 + 1];
        let s2 = state[i * 4 + 2];
        let s3 = state[i * 4 + 3];

        state[i * 4] = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3;
        state[i * 4 + 1] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3;
        state[i * 4 + 2] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3);
        state[i * 4 + 3] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2);
    }
}

/// AES-256 key expansion
/// Extends 256-bit key (32 bytes) to 15 round keys (240 bytes)
fn aes256_key_expansion(key: &[u8; 32]) -> Vec<u8> {
    let mut expanded = vec![0u8; 240]; // 15 rounds * 16 bytes

    // Copy original key (first 2 round keys)
    expanded[..32].copy_from_slice(key);

    let mut rcon = 1u8;

    for i in 2..15 {
        let prev_offset = (i - 1) * 16;
        let curr_offset = i * 16;

        if i % 2 == 0 {
            // Every even round: use SubWord + RotWord + Rcon
            let mut temp = [
                expanded[prev_offset + 13],
                expanded[prev_offset + 14],
                expanded[prev_offset + 15],
                expanded[prev_offset + 12],
            ];

            // SubWord
            for byte in &mut temp {
                *byte = SBOX[*byte as usize];
            }

            // XOR with previous round key and Rcon
            for j in 0..4 {
                expanded[curr_offset + j] = expanded[curr_offset - 32 + j] ^ temp[j];
                if j == 0 {
                    expanded[curr_offset + j] ^= rcon;
                }
            }

            rcon = gmul(rcon, 0x02);
        } else {
            // Odd rounds: use SubWord only
            let mut temp = [
                expanded[prev_offset + 12],
                expanded[prev_offset + 13],
                expanded[prev_offset + 14],
                expanded[prev_offset + 15],
            ];

            // SubWord
            for byte in &mut temp {
                *byte = SBOX[*byte as usize];
            }

            for j in 0..4 {
                expanded[curr_offset + j] = expanded[curr_offset - 32 + j] ^ temp[j];
            }
        }

        // Fill remaining bytes
        for j in 4..16 {
            expanded[curr_offset + j] = expanded[curr_offset + j - 4] ^ expanded[prev_offset + j];
        }
    }

    expanded
}

/// AES-256 block encryption
fn aes256_encrypt_block(plaintext: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let expanded_key = aes256_key_expansion(key);
    let mut state = *plaintext;

    // Initial round key addition
    for i in 0..16 {
        state[i] ^= expanded_key[i];
    }

    // 13 main rounds (AES-256 uses 14 rounds total)
    for round in 1..14 {
        // SubBytes
        for byte in &mut state {
            *byte = SBOX[*byte as usize];
        }

        // ShiftRows
        shift_rows(&mut state);

        // MixColumns (not in final round)
        if round < 13 {
            mix_columns(&mut state);
        }

        // AddRoundKey
        let round_key_offset = round * 16;
        for i in 0..16 {
            state[i] ^= expanded_key[round_key_offset + i];
        }
    }

    // Final round (no MixColumns)
    for byte in &mut state {
        *byte = SBOX[*byte as usize];
    }
    shift_rows(&mut state);
    for i in 0..16 {
        state[i] ^= expanded_key[224 + i]; // Round 14
    }

    state
}

/// Increment a 128-bit counter (little-endian)
fn increment_counter(counter: &mut [u8; 16]) {
    for i in (0..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// CTR mode encryption/decryption
fn aes256_ctr(key: &[u8; 32], iv: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut counter = [0u8; 16];

    // Initialize counter with IV (first 12 bytes) and counter value (last 4 bytes)
    counter[..12].copy_from_slice(iv);
    counter[12..].copy_from_slice(&[0, 0, 0, 1]); // Counter starts at 1

    let mut offset = 0;
    while offset < data.len() {
        // Encrypt counter
        let keystream = aes256_encrypt_block(&counter, key);

        // XOR with data
        let chunk_len = std::cmp::min(16, data.len() - offset);
        for i in 0..chunk_len {
            result.push(data[offset + i] ^ keystream[i]);
        }

        offset += chunk_len;
        increment_counter(&mut counter);
    }

    result
}

/// GHASH function for GCM authentication
///
/// GHASH is a universal hash function used in GCM mode.
/// It computes: GHASH(H, X) where H is the hash key and X is the input.
fn ghash(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];

    // Process data in 16-byte blocks
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);

        // Y_i = (Y_{i-1} XOR X_i) * H
        for i in 0..16 {
            y[i] ^= block[i];
        }
        y = gmul_block(&y, h);
    }

    y
}

/// Galois field multiplication of two 128-bit blocks
/// Multiplies two polynomials in GF(2^128)
fn gmul_block(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;

    for i in 0..16 {
        for bit in (0..8).rev() {
            if (x[i] & (1 << bit)) != 0 {
                // z = z XOR v
                for j in 0..16 {
                    z[j] ^= v[j];
                }
            }

            // Check if LSB of v is 1
            let lsb = v[15] & 1;

            // Right shift v by 1 bit
            for j in (1..16).rev() {
                v[j] = (v[j] >> 1) | (v[j - 1] << 7);
            }
            v[0] >>= 1;

            // If LSB was 1, XOR with R (reduction polynomial)
            if lsb == 1 {
                v[0] ^= 0xe1; // R = 11100001 || 0^120
            }
        }
    }

    z
}

/// AES-256-GCM encryption
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `iv` - 12-byte initialization vector (nonce)
/// * `aad` - Additional authenticated data
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// Ciphertext || 16-byte authentication tag
pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    // Derive hash key H = AES(K, 0^128)
    let h = aes256_encrypt_block(&[0u8; 16], key);

    // Encrypt plaintext using CTR mode
    let ciphertext = aes256_ctr(key, iv, plaintext);

    // Construct GHASH input: AAD || 0* || C || 0* || len(AAD) || len(C)
    let mut ghash_input = Vec::new();

    // Add AAD with padding
    ghash_input.extend_from_slice(aad);
    let aad_pad_len = (16 - (aad.len() % 16)) % 16;
    ghash_input.extend(vec![0u8; aad_pad_len]);

    // Add ciphertext with padding
    ghash_input.extend_from_slice(&ciphertext);
    let ct_pad_len = (16 - (ciphertext.len() % 16)) % 16;
    ghash_input.extend(vec![0u8; ct_pad_len]);

    // Add lengths (in bits, big-endian)
    let aad_bits = (aad.len() * 8) as u64;
    let ct_bits = (ciphertext.len() * 8) as u64;
    ghash_input.extend_from_slice(&aad_bits.to_be_bytes());
    ghash_input.extend_from_slice(&ct_bits.to_be_bytes());

    // Compute GHASH
    let ghash_result = ghash(&h, &ghash_input);

    // Compute authentication tag: GHASH XOR AES(K, IV || 0^31 || 1)
    let mut counter_block = [0u8; 16];
    counter_block[..12].copy_from_slice(iv);
    counter_block[15] = 1;
    let tag_mask = aes256_encrypt_block(&counter_block, key);

    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = ghash_result[i] ^ tag_mask[i];
    }

    // Return ciphertext || tag
    let mut result = ciphertext;
    result.extend_from_slice(&tag);
    result
}

/// AES-256-GCM decryption
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `iv` - 12-byte initialization vector (nonce)
/// * `aad` - Additional authenticated data
/// * `ciphertext_and_tag` - Ciphertext with 16-byte tag appended
///
/// # Returns
/// Plaintext if tag verification succeeds, Err otherwise
pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, String> {
    if ciphertext_and_tag.len() < 16 {
        return Err("Ciphertext too short".to_string());
    }

    // Split ciphertext and tag
    let ciphertext = &ciphertext_and_tag[..ciphertext_and_tag.len() - 16];
    let received_tag = &ciphertext_and_tag[ciphertext_and_tag.len() - 16..];

    // Derive hash key H = AES(K, 0^128)
    let h = aes256_encrypt_block(&[0u8; 16], key);

    // Construct GHASH input
    let mut ghash_input = Vec::new();
    ghash_input.extend_from_slice(aad);
    let aad_pad_len = (16 - (aad.len() % 16)) % 16;
    ghash_input.extend(vec![0u8; aad_pad_len]);
    ghash_input.extend_from_slice(ciphertext);
    let ct_pad_len = (16 - (ciphertext.len() % 16)) % 16;
    ghash_input.extend(vec![0u8; ct_pad_len]);
    let aad_bits = (aad.len() * 8) as u64;
    let ct_bits = (ciphertext.len() * 8) as u64;
    ghash_input.extend_from_slice(&aad_bits.to_be_bytes());
    ghash_input.extend_from_slice(&ct_bits.to_be_bytes());

    // Compute GHASH
    let ghash_result = ghash(&h, &ghash_input);

    // Compute expected tag
    let mut counter_block = [0u8; 16];
    counter_block[..12].copy_from_slice(iv);
    counter_block[15] = 1;
    let tag_mask = aes256_encrypt_block(&counter_block, key);

    let mut computed_tag = [0u8; 16];
    for i in 0..16 {
        computed_tag[i] = ghash_result[i] ^ tag_mask[i];
    }

    // Constant-time tag comparison
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= received_tag[i] ^ computed_tag[i];
    }

    if diff != 0 {
        return Err("Authentication tag verification failed".to_string());
    }

    // Decrypt ciphertext
    let plaintext = aes256_ctr(key, iv, ciphertext);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_gcm_basic() {
        // Basic test with known values
        let key = [0x42u8; 32];
        let iv = [0x12u8; 12];
        let aad = b"additional data";
        let plaintext = b"Hello, AES-256-GCM!";

        let ciphertext_with_tag = aes256_gcm_encrypt(&key, &iv, aad, plaintext);

        // Should be plaintext.len() + 16 (tag)
        assert_eq!(ciphertext_with_tag.len(), plaintext.len() + 16);

        // Decrypt should succeed
        let decrypted = aes256_gcm_decrypt(&key, &iv, aad, &ciphertext_with_tag)
            .expect("Decryption failed");
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_aes256_gcm_empty_plaintext() {
        let key = [0x00u8; 32];
        let iv = [0x00u8; 12];
        let aad = b"";
        let plaintext = b"";

        let ciphertext_with_tag = aes256_gcm_encrypt(&key, &iv, aad, plaintext);

        // Should be just the tag (16 bytes)
        assert_eq!(ciphertext_with_tag.len(), 16);

        let decrypted = aes256_gcm_decrypt(&key, &iv, aad, &ciphertext_with_tag)
            .expect("Decryption failed");
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_aes256_gcm_modified_ciphertext() {
        let key = [0x42u8; 32];
        let iv = [0x12u8; 12];
        let aad = b"additional data";
        let plaintext = b"Hello, World!";

        let mut ciphertext_with_tag = aes256_gcm_encrypt(&key, &iv, aad, plaintext);

        // Modify ciphertext
        ciphertext_with_tag[0] ^= 1;

        // Decryption should fail
        assert!(aes256_gcm_decrypt(&key, &iv, aad, &ciphertext_with_tag).is_err());
    }

    #[test]
    fn test_aes256_gcm_modified_tag() {
        let key = [0x42u8; 32];
        let iv = [0x12u8; 12];
        let aad = b"additional data";
        let plaintext = b"Hello, World!";

        let mut ciphertext_with_tag = aes256_gcm_encrypt(&key, &iv, aad, plaintext);

        // Modify tag
        let len = ciphertext_with_tag.len();
        ciphertext_with_tag[len - 1] ^= 1;

        // Decryption should fail
        assert!(aes256_gcm_decrypt(&key, &iv, aad, &ciphertext_with_tag).is_err());
    }

    #[test]
    fn test_aes256_gcm_different_aad() {
        let key = [0x42u8; 32];
        let iv = [0x12u8; 12];
        let aad = b"additional data";
        let plaintext = b"Hello, World!";

        let ciphertext_with_tag = aes256_gcm_encrypt(&key, &iv, aad, plaintext);

        // Decrypt with different AAD should fail
        let wrong_aad = b"wrong data";
        assert!(aes256_gcm_decrypt(&key, &iv, wrong_aad, &ciphertext_with_tag).is_err());
    }

    #[test]
    fn test_aes256_gcm_deterministic() {
        let key = [0x42u8; 32];
        let iv = [0x12u8; 12];
        let aad = b"additional data";
        let plaintext = b"Hello, World!";

        let ct1 = aes256_gcm_encrypt(&key, &iv, aad, plaintext);
        let ct2 = aes256_gcm_encrypt(&key, &iv, aad, plaintext);

        // Same inputs should produce same output (deterministic)
        assert_eq!(ct1, ct2);
    }
}
