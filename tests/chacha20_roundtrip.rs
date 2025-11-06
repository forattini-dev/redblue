/// Test ChaCha20-Poly1305 roundtrip with TLS-like AAD
use redblue::crypto::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let nonce = [0x13u8; 12];
    let plaintext = b"Hello, TLS 1.3!";

    // TLS 1.3 style AAD
    let aad = vec![
        0x17, // ApplicationData
        0x03, 0x03, // TLS 1.2
        0x00, 0x1f, // length (31 = 15 + 16)
    ];

    // Encrypt
    let ciphertext = chacha20poly1305_encrypt(&key, &nonce, &aad, plaintext);

    println!("Plaintext len: {}", plaintext.len());
    println!("Ciphertext len: {}", ciphertext.len());
    assert_eq!(ciphertext.len(), plaintext.len() + 16);

    // Decrypt
    let decrypted =
        chacha20poly1305_decrypt(&key, &nonce, &aad, &ciphertext).expect("Decryption failed!");

    assert_eq!(decrypted, plaintext);
    println!("✅ Roundtrip test PASSED!");
}

#[test]
fn test_wrong_aad_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x13u8; 12];
    let plaintext = b"Secret message";

    let aad1 = vec![0x17, 0x03, 0x03, 0x00, 0x1e];
    let aad2 = vec![0x17, 0x03, 0x03, 0x00, 0x1f]; // Different!

    let ciphertext = chacha20poly1305_encrypt(&key, &nonce, &aad1, plaintext);

    // Try to decrypt with wrong AAD - should fail
    let result = chacha20poly1305_decrypt(&key, &nonce, &aad2, &ciphertext);
    assert!(result.is_err(), "Should fail with wrong AAD!");

    println!("✅ Wrong AAD correctly rejected!");
}
