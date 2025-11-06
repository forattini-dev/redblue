/// Test AES-256-GCM with TLS 1.3 style AAD and nonce
use redblue::crypto::aes_gcm::aes256_gcm_decrypt;
use redblue::crypto::aes_gcm::aes256_gcm_encrypt;

#[test]
fn test_aes256_gcm_tls13_style() {
    // Simulate TLS 1.3 scenario
    let key = [0x42u8; 32]; // Server key
    let base_iv = [0x13u8; 12]; // Server IV

    // Sequence number 0
    let seq = 0u64;

    // Construct nonce (IV XOR sequence_number)
    let mut nonce = base_iv.clone();
    for i in 0..8 {
        nonce[12 - 8 + i] ^= ((seq >> (56 - i * 8)) & 0xff) as u8;
    }

    // Plaintext: handshake message + content type
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(b"ServerHandshakeMessage");
    plaintext.push(0x16); // ContentType::Handshake

    println!("Plaintext len: {}", plaintext.len());
    println!("Plaintext: {:02x?}", &plaintext[..plaintext.len().min(32)]);

    // AAD: TLS 1.3 style
    // opaque_type (0x17) || legacy_version (0x0303) || length
    let ciphertext_len = (plaintext.len() + 16) as u16; // + 16 for tag
    let mut aad = Vec::new();
    aad.push(0x17); // ApplicationData
    aad.push(0x03); // TLS 1.2
    aad.push(0x03);
    aad.push((ciphertext_len >> 8) as u8);
    aad.push(ciphertext_len as u8);

    println!("AAD: {:02x?}", aad);
    println!("Nonce: {:02x?}", nonce);
    println!("Key: {:02x?}", &key[..16]);

    // Encrypt
    let ciphertext = aes256_gcm_encrypt(&key, &nonce, &aad, &plaintext);
    println!("Ciphertext len: {}", ciphertext.len());
    println!(
        "Ciphertext: {:02x?}",
        &ciphertext[..ciphertext.len().min(32)]
    );

    assert_eq!(ciphertext.len(), plaintext.len() + 16);

    // Now decrypt with same AAD
    let decrypted =
        aes256_gcm_decrypt(&key, &nonce, &aad, &ciphertext).expect("Decryption should succeed!");

    assert_eq!(decrypted, plaintext);
    println!("✅ TLS 1.3 style AES-256-GCM roundtrip PASSED!");
}

#[test]
fn test_aes256_gcm_wrong_aad_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x13u8; 12];
    let plaintext = b"test message";

    // Correct AAD
    let aad1 = vec![0x17, 0x03, 0x03, 0x00, 0x1c]; // length = 28 (12 + 16)

    // Wrong AAD (different length)
    let aad2 = vec![0x17, 0x03, 0x03, 0x00, 0x1d]; // length = 29

    let ciphertext = aes256_gcm_encrypt(&key, &nonce, &aad1, plaintext);

    // Try to decrypt with wrong AAD - should fail
    let result = aes256_gcm_decrypt(&key, &nonce, &aad2, &ciphertext);
    assert!(result.is_err(), "Should fail with wrong AAD!");

    println!("✅ Wrong AAD correctly rejected!");
}
