/// AES-GCM (Galois/Counter Mode) Implementation using OpenSSL
///
/// This replaces our custom AES-GCM implementation with OpenSSL's battle-tested implementation.
/// OpenSSL provides optimized, constant-time cryptography with hardware acceleration when available.
use boring::symm::{Cipher, Crypter, Mode};

/// AES-128-GCM encryption using OpenSSL
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
    let cipher = Cipher::aes_128_gcm();

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))
        .expect("Failed to create AES-128-GCM encrypter");

    // Set AAD (Additional Authenticated Data)
    if !aad.is_empty() {
        crypter.aad_update(aad).expect("Failed to set AAD");
    }

    // Encrypt plaintext
    let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];
    let mut count = crypter
        .update(plaintext, &mut ciphertext)
        .expect("Failed to encrypt");
    count += crypter
        .finalize(&mut ciphertext[count..])
        .expect("Failed to finalize encryption");
    ciphertext.truncate(count);

    // Get authentication tag (16 bytes for GCM)
    let mut tag = vec![0u8; 16];
    crypter.get_tag(&mut tag).expect("Failed to get GCM tag");

    // Append tag to ciphertext
    ciphertext.extend_from_slice(&tag);
    ciphertext
}

/// AES-128-GCM decryption using OpenSSL
///
/// # Arguments
/// * `key` - 16-byte encryption key
/// * `iv` - 12-byte initialization vector (nonce)
/// * `ciphertext_with_tag` - Ciphertext with 16-byte tag appended
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
        return Err("ciphertext too short (must include 16-byte tag)".to_string());
    }

    let cipher = Cipher::aes_128_gcm();

    // Split ciphertext and tag
    let ciphertext_len = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..ciphertext_len];
    let tag = &ciphertext_with_tag[ciphertext_len..];

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))
        .map_err(|e| format!("Failed to create AES-128-GCM decrypter: {}", e))?;

    // Set tag for verification
    crypter
        .set_tag(tag)
        .map_err(|e| format!("Failed to set GCM tag: {}", e))?;

    // Set AAD (Additional Authenticated Data)
    if !aad.is_empty() {
        crypter
            .aad_update(aad)
            .map_err(|e| format!("Failed to set AAD: {}", e))?;
    }

    // Decrypt ciphertext
    let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];
    let mut count = crypter
        .update(ciphertext, &mut plaintext)
        .map_err(|e| format!("Failed to decrypt: {}", e))?;
    count += crypter
        .finalize(&mut plaintext[count..])
        .map_err(|_| "GCM tag verification failed (authentication error)".to_string())?;
    plaintext.truncate(count);

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_gcm_roundtrip() {
        let key = [0x00; 16];
        let iv = [0x00; 12];
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let ciphertext = aes128_gcm_encrypt(&key, &iv, plaintext, aad);
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // plaintext + 16-byte tag

        let decrypted = aes128_gcm_decrypt(&key, &iv, &ciphertext, aad).expect("Decryption failed");
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_aes128_gcm_wrong_tag() {
        let key = [0x00; 16];
        let iv = [0x00; 12];
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let mut ciphertext = aes128_gcm_encrypt(&key, &iv, plaintext, aad);

        // Corrupt the tag
        let tag_idx = ciphertext.len() - 1;
        ciphertext[tag_idx] ^= 0x01;

        let result = aes128_gcm_decrypt(&key, &iv, &ciphertext, aad);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authentication error"));
    }

    #[test]
    fn test_aes128_gcm_wrong_aad() {
        let key = [0x00; 16];
        let iv = [0x00; 12];
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let ciphertext = aes128_gcm_encrypt(&key, &iv, plaintext, aad);

        // Try to decrypt with different AAD
        let wrong_aad = b"wrong aad";
        let result = aes128_gcm_decrypt(&key, &iv, &ciphertext, wrong_aad);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authentication error"));
    }
}
