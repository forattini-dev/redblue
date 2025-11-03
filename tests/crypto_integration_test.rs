/// Integration test for the complete crypto stack
///
/// This test demonstrates that all crypto components work together
/// to perform a complete TLS key derivation flow.

#[cfg(test)]
mod crypto_integration_tests {
    use redblue::crypto::{aes, hmac, prf, sha256};

    #[test]
    fn test_complete_tls_crypto_flow() {
        // Simulate a TLS 1.2 handshake key derivation

        // 1. Generate client and server randoms (normally random, fixed for test)
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        // 2. Pre-master secret (48 bytes: version + random)
        let mut pre_master = [0u8; 48];
        pre_master[0] = 0x03; // TLS 1.2 major
        pre_master[1] = 0x03; // TLS 1.2 minor
        for i in 2..48 {
            pre_master[i] = (i % 256) as u8;
        }

        // 3. Derive master secret using PRF
        let master_secret = prf::derive_master_secret(&pre_master, &client_random, &server_random);

        // Verify master secret is 48 bytes
        assert_eq!(master_secret.len(), 48);

        // 4. Derive key material (104 bytes for AES-128-CBC-SHA256)
        let key_material = prf::derive_keys(&master_secret, &server_random, &client_random, 104);

        // Verify key material is correct length
        assert_eq!(key_material.len(), 104);

        // 5. Extract keys from key_block
        let client_write_mac = &key_material[0..32];
        let server_write_mac = &key_material[32..64];
        let client_write_key = &key_material[64..80];
        let server_write_key = &key_material[80..96];
        let client_write_iv = &key_material[96..112]; // Only need 16 bytes

        // Verify all keys are non-zero (properly derived)
        assert_ne!(client_write_mac, &[0u8; 32]);
        assert_ne!(server_write_mac, &[0u8; 32]);
        assert_ne!(client_write_key, &[0u8; 16]);
        assert_ne!(server_write_key, &[0u8; 16]);
        assert_ne!(client_write_iv, &[0u8; 16]);

        // 6. Test encryption/decryption with derived keys
        let plaintext = b"Hello, TLS 1.2 from pure Rust!";

        // Encrypt
        let key: [u8; 16] = client_write_key.try_into().unwrap();
        let iv: [u8; 16] = client_write_iv.try_into().unwrap();
        let ciphertext = aes::aes128_cbc_encrypt(&key, &iv, plaintext);

        // Verify ciphertext is different from plaintext
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);

        // Decrypt
        let decrypted = aes::aes128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();

        // Verify round-trip
        assert_eq!(&decrypted[..], plaintext);

        // 7. Test HMAC computation
        let mac_key: [u8; 32] = client_write_mac.try_into().unwrap();
        let mac = hmac::hmac_sha256(&mac_key, plaintext);

        // Verify MAC is 32 bytes
        assert_eq!(mac.len(), 32);

        // Verify MAC is deterministic
        let mac2 = hmac::hmac_sha256(&mac_key, plaintext);
        assert_eq!(mac, mac2);

        println!("✅ Complete TLS crypto flow test passed!");
        println!("   - Master secret derived: {} bytes", master_secret.len());
        println!("   - Key material derived: {} bytes", key_material.len());
        println!("   - AES encryption/decryption: OK");
        println!("   - HMAC computation: OK");
    }

    #[test]
    fn test_sha256_basic() {
        let data = b"test";
        let hash = sha256::sha256(data);

        // SHA-256 should produce 32 bytes
        assert_eq!(hash.len(), 32);

        // Should be deterministic
        let hash2 = sha256::sha256(data);
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let hash3 = sha256::sha256(b"different");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_hmac_basic() {
        let key = b"secret_key";
        let message = b"message";

        let mac = hmac::hmac_sha256(key, message);

        // HMAC-SHA256 should produce 32 bytes
        assert_eq!(mac.len(), 32);

        // Should be deterministic
        let mac2 = hmac::hmac_sha256(key, message);
        assert_eq!(mac, mac2);

        // Different key should produce different MAC
        let mac3 = hmac::hmac_sha256(b"different_key", message);
        assert_ne!(mac, mac3);
    }

    #[test]
    fn test_aes_roundtrip() {
        let key = [0x2bu8; 16];
        let iv = [0x00u8; 16];
        let plaintext = b"This is a test message for AES-128-CBC!";

        // Encrypt
        let ciphertext = aes::aes128_cbc_encrypt(&key, &iv, plaintext);

        // Ciphertext should be longer (due to padding)
        assert!(ciphertext.len() >= plaintext.len());

        // Decrypt
        let decrypted = aes::aes128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();

        // Should match original
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_prf_deterministic() {
        let secret = b"secret";
        let label = b"test label";
        let seed = b"seed";

        let output1 = prf::prf_tls12(secret, label, seed, 64);
        let output2 = prf::prf_tls12(secret, label, seed, 64);

        // Should be deterministic
        assert_eq!(output1, output2);
        assert_eq!(output1.len(), 64);

        // Different seed should produce different output
        let output3 = prf::prf_tls12(secret, label, b"different", 64);
        assert_ne!(output1, output3);
    }

    #[test]
    fn test_tls_record_simulation() {
        // Simulate encrypting and decrypting a TLS record

        // Setup
        let key = [0x42u8; 16];
        let iv = [0x13u8; 16];
        let mac_key = [0x99u8; 32];
        let sequence_number: u64 = 0;

        // Application data
        let plaintext = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        // 1. Compute MAC (as TLS does)
        let mut mac_data = Vec::new();
        mac_data.extend_from_slice(&sequence_number.to_be_bytes());
        mac_data.push(23); // ApplicationData
        mac_data.push(0x03); // TLS 1.2
        mac_data.push(0x03);
        let data_len = plaintext.len() as u16;
        mac_data.extend_from_slice(&data_len.to_be_bytes());
        mac_data.extend_from_slice(plaintext);

        let mac = hmac::hmac_sha256(&mac_key, &mac_data);

        // 2. Combine plaintext + MAC
        let mut plaintext_with_mac = Vec::new();
        plaintext_with_mac.extend_from_slice(plaintext);
        plaintext_with_mac.extend_from_slice(&mac);

        // 3. Encrypt
        let encrypted = aes::aes128_cbc_encrypt(&key, &iv, &plaintext_with_mac);

        // 4. Decrypt
        let decrypted = aes::aes128_cbc_decrypt(&key, &iv, &encrypted).unwrap();

        // 5. Extract plaintext and MAC
        let recovered_plaintext = &decrypted[..plaintext.len()];
        let recovered_mac = &decrypted[plaintext.len()..];

        // 6. Verify
        assert_eq!(recovered_plaintext, plaintext);
        assert_eq!(recovered_mac, &mac[..]);

        println!("✅ TLS record encryption/decryption simulation passed!");
    }
}
