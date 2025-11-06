/// RFC 8439 Test Vectors for ChaCha20-Poly1305
/// Section 2.8.2: Test Vector for the ChaCha20-Poly1305 AEAD
use redblue::crypto::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};

#[test]
fn test_rfc8439_chacha20poly1305_aead() {
    // RFC 8439 Section 2.8.2
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();

    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];

    let nonce: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];

    // Expected ciphertext + tag from RFC 8439
    let expected = hex::decode(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
    ).unwrap();

    // Encrypt
    let ciphertext = chacha20poly1305_encrypt(&key, &nonce, &aad, plaintext);

    // Should match expected
    assert_eq!(
        ciphertext,
        expected,
        "ChaCha20-Poly1305 encryption mismatch!\nGot:      {:02x?}\nExpected: {:02x?}",
        &ciphertext[..32],
        &expected[..32]
    );

    // Decrypt
    let decrypted =
        chacha20poly1305_decrypt(&key, &nonce, &aad, &ciphertext).expect("Decryption failed!");

    assert_eq!(
        decrypted, plaintext,
        "ChaCha20-Poly1305 decryption mismatch!"
    );

    println!("✅ RFC 8439 ChaCha20-Poly1305 test vector PASSED!");
}

#[test]
fn test_chacha20poly1305_empty_aad() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"test message";

    // Encrypt with empty AAD
    let ciphertext = chacha20poly1305_encrypt(&key, &nonce, &[], plaintext);

    // Should be able to decrypt
    let decrypted = chacha20poly1305_decrypt(&key, &nonce, &[], &ciphertext)
        .expect("Decryption with empty AAD failed!");

    assert_eq!(decrypted, plaintext);
    println!("✅ ChaCha20-Poly1305 empty AAD test PASSED!");
}

#[test]
fn test_chacha20poly1305_tls13_aad() {
    // Simulate TLS 1.3 AAD format
    let key = [1u8; 32];
    let nonce = [2u8; 12];
    let plaintext = b"TLS 1.3 application data";

    // TLS 1.3 AAD: type (1) + version (2) + length (2)
    let aad = vec![
        0x17, // ApplicationData
        0x03, 0x03, // TLS 1.2
        0x00, 0x28, // length (40 = 24 plaintext + 16 tag)
    ];

    let ciphertext = chacha20poly1305_encrypt(&key, &nonce, &aad, plaintext);
    assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for tag

    let decrypted = chacha20poly1305_decrypt(&key, &nonce, &aad, &ciphertext)
        .expect("TLS 1.3 AAD decryption failed!");

    assert_eq!(decrypted, plaintext);
    println!("✅ ChaCha20-Poly1305 TLS 1.3 AAD test PASSED!");
}

// Hex decoding helper (simple implementation)
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("Hex string must have even length".to_string());
        }

        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("Invalid hex: {}", e))
            })
            .collect()
    }
}
