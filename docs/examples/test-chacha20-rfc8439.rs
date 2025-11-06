/// RFC 8439 Test Vector for ChaCha20-Poly1305
use redblue::crypto::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    println!("🧪 Testing ChaCha20-Poly1305 with RFC 8439 test vectors...\n");

    // RFC 8439 Section 2.8.2
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let aad = hex_decode("50515253c0c1c2c3c4c5c6c7");

    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];

    let nonce: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];

    // Expected ciphertext + tag from RFC 8439
    let expected = hex_decode(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
    );

    println!("Plaintext: {} bytes", plaintext.len());
    println!("AAD: {} bytes", aad.len());
    println!("Expected ciphertext+tag: {} bytes\n", expected.len());

    // Encrypt
    println!("→ Encrypting...");
    let ciphertext = chacha20poly1305_encrypt(&key, &nonce, &aad, plaintext);

    println!("✓ Got ciphertext: {} bytes", ciphertext.len());
    println!("\nFirst 32 bytes:");
    println!("  Got:      {:02x?}", &ciphertext[..32]);
    println!("  Expected: {:02x?}", &expected[..32]);

    if ciphertext == expected {
        println!("\n✅ ENCRYPT PASSED! Ciphertext matches RFC 8439!");
    } else {
        println!("\n❌ ENCRYPT FAILED! Ciphertext mismatch!");
        println!("\nLast 16 bytes (Poly1305 tag):");
        println!("  Got:      {:02x?}", &ciphertext[ciphertext.len() - 16..]);
        println!("  Expected: {:02x?}", &expected[expected.len() - 16..]);
        return;
    }

    // Decrypt
    println!("\n→ Decrypting...");
    match chacha20poly1305_decrypt(&key, &nonce, &aad, &ciphertext) {
        Ok(decrypted) => {
            if decrypted == plaintext {
                println!("✅ DECRYPT PASSED! Plaintext recovered!");
                println!("\n🎉 RFC 8439 ChaCha20-Poly1305 test vector PASSED!");
            } else {
                println!("❌ DECRYPT FAILED! Plaintext mismatch!");
            }
        }
        Err(e) => {
            println!("❌ DECRYPT FAILED! Error: {}", e);
        }
    }
}
