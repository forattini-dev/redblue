/// RFC 8448 Section 3 - Test Decrypting EncryptedExtensions
///
/// This tests decryption of the SPECIFIC EncryptedExtensions message
/// from RFC 8448 Section 3 using AES-128-GCM-SHA256 (cipher 0x1301)
use redblue::crypto::aes_gcm::aes128_gcm_decrypt;
use redblue::crypto::hkdf::hkdf_expand_label;

fn hex_decode(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .flat_map(|s| {
            (0..s.len())
                .step_by(2)
                .map(move |i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        })
        .collect()
}

#[test]
fn test_decrypt_encrypted_extensions_rfc8448() {
    println!("\n🔐 RFC 8448 Section 3: EncryptedExtensions Decryption Test");
    println!("   Cipher: TLS_AES_128_GCM_SHA256 (0x1301)\n");

    // From RFC 8448 Section 3
    // Server handshake traffic secret (32 bytes for SHA-256)
    let server_hs_secret_hex = "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 \
                                 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38";
    let server_hs_secret_vec = hex_decode(server_hs_secret_hex);
    let mut server_hs_secret = [0u8; 32];
    server_hs_secret.copy_from_slice(&server_hs_secret_vec);

    println!("Server handshake traffic secret:");
    println!("  {:02x?}", &server_hs_secret);

    // Derive AES-128-GCM key (16 bytes) and IV (12 bytes)
    let server_key_vec = hkdf_expand_label(&server_hs_secret, b"key", b"", 16);
    let server_iv_vec = hkdf_expand_label(&server_hs_secret, b"iv", b"", 12);

    let mut server_key = [0u8; 16];
    let mut server_iv = [0u8; 12];
    server_key.copy_from_slice(&server_key_vec);
    server_iv.copy_from_slice(&server_iv_vec);

    println!("\nDerived keys:");
    println!("  Write key (16 bytes): {:02x?}", server_key);
    println!("  Write IV (12 bytes):  {:02x?}", server_iv);

    // Expected key and IV from RFC 8448
    let expected_key = hex_decode("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc");
    let expected_iv = hex_decode("5d 31 3e b2 67 12 76 ee 13 00 0b 30");

    assert_eq!(
        &server_key[..],
        &expected_key[..],
        "Key mismatch! Our HKDF is broken"
    );
    assert_eq!(
        &server_iv[..],
        &expected_iv[..],
        "IV mismatch! Our HKDF is broken"
    );
    println!("  ✓ Keys match RFC 8448 expected values");

    // Encrypted EncryptedExtensions record from RFC 8448
    // Record header: 17 03 03 00 61
    // Encrypted payload: 97 bytes (including 16-byte tag)
    let encrypted_record_hex = "17 03 03 00 61 \
        dc 48 23 7b 4b 87 9f 50 d0 d4 d2 \
        62 ea 8b 47 16 eb 40 dd c1 eb 95 7e 11 12 6e 8a \
        71 49 c2 d0 12 d3 7a 71 15 95 7e 64 ce 30 00 8b \
        9e 03 23 f2 c0 5a 9c 1c 77 b4 f3 78 49 a6 95 ab \
        25 50 60 a3 3f ee 77 0c a9 5c b8 48 6b fd 08 43 \
        b8 70 24 86 5c a3 5c c4 1c 4e 51 5c 64 dc b1 36 \
        9f 98 63 5b c7 a5";

    let full_record = hex_decode(encrypted_record_hex);
    let header = &full_record[0..5];
    let ciphertext = &full_record[5..];

    println!("\nEncrypted record:");
    println!("  Header (AAD): {:02x?}", header);
    println!(
        "  Ciphertext: {} bytes (should be {} plaintext + 16 tag = {})",
        ciphertext.len(),
        ciphertext.len() - 16,
        ciphertext.len()
    );

    // Construct nonce: IV XOR sequence number
    // This is the FIRST encrypted handshake record, so sequence = 0
    let seq = 0u64;
    let mut nonce = server_iv;
    for i in 0..8 {
        nonce[12 - 8 + i] ^= ((seq >> (56 - i * 8)) & 0xff) as u8;
    }

    println!("\nDecryption parameters:");
    println!("  Sequence: {}", seq);
    println!("  Nonce: {:02x?}", nonce);
    println!("  AAD: {:02x?}", header);

    // Expected plaintext from RFC 8448 (including content type byte)
    let expected_plaintext_hex = "08 00 00 24 00 22 00 0a 00 14 00 12 00 1d 00 17 \
                                  00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c \
                                  00 02 40 01 00 00 00 00 16";
    let expected_plaintext = hex_decode(expected_plaintext_hex);

    println!("\nExpected plaintext ({} bytes):", expected_plaintext.len());
    println!("  {:02x?}", expected_plaintext);
    println!(
        "  Last byte: 0x{:02x} (should be 0x16 = Handshake)",
        expected_plaintext.last().unwrap()
    );

    // DECRYPT!
    println!("\n📦 Attempting decryption with AES-128-GCM...");
    match aes128_gcm_decrypt(&server_key, &nonce, header, ciphertext) {
        Ok(plaintext) => {
            println!("✅ DECRYPTION SUCCESS!");
            println!("\nDecrypted plaintext ({} bytes):", plaintext.len());
            println!("  {:02x?}", plaintext);

            if let Some(&content_type) = plaintext.last() {
                println!("\nContent type (last byte): 0x{:02x}", content_type);
                match content_type {
                    0x16 => println!("  → Handshake (0x16) ✓"),
                    0x17 => println!("  → ApplicationData (0x17)"),
                    _ => println!("  → Unknown content type!"),
                }
            }

            // Compare with expected plaintext
            if plaintext == expected_plaintext {
                println!("\n✅✅✅ PLAINTEXT MATCHES RFC 8448 EXACTLY! ✅✅✅");
                println!("Our AES-128-GCM implementation is CORRECT!");
            } else {
                println!("\n❌ PLAINTEXT MISMATCH!");
                println!("Expected: {:02x?}", expected_plaintext);
                println!("Got:      {:02x?}", plaintext);
                panic!("Plaintext does not match RFC 8448!");
            }

            assert_eq!(plaintext, expected_plaintext, "Plaintext mismatch!");
        }
        Err(e) => {
            println!("❌ DECRYPTION FAILED: {}", e);
            println!("\nThis means either:");
            println!("  1. Our AES-128-GCM implementation is broken");
            println!("  2. Our HKDF implementation is broken (but it passed key check)");
            println!("  3. Our nonce construction is broken");
            println!("  4. Our AAD handling is broken");
            panic!("Failed to decrypt RFC 8448 EncryptedExtensions!");
        }
    }
}
