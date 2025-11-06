/// Test decrypting actual TLS 1.3 encrypted handshake from RFC 8448
///
/// This is the REAL test - decrypt the actual encrypted server handshake
/// from RFC 8448 using our AES-128-GCM implementation
use redblue::crypto::hkdf::hkdf_expand_label;
use redblue::protocols::gcm::aes128_gcm_decrypt;

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
fn test_decrypt_server_handshake_rfc8448() {
    println!("\n🔐 Testing TLS 1.3 Decryption with RFC 8448 Server Handshake\n");

    // Server handshake traffic secret from RFC 8448
    let server_hs_secret_hex = "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38";
    let server_hs_secret_vec = hex_decode(server_hs_secret_hex);
    assert_eq!(
        server_hs_secret_vec.len(),
        32,
        "Server HS secret should be 32 bytes"
    );
    let mut server_hs_secret = [0u8; 32];
    server_hs_secret.copy_from_slice(&server_hs_secret_vec);

    println!("Server HS secret: {:02x?}", &server_hs_secret[..16]);

    // Derive server handshake key and IV
    // RFC 8446: key length for AES-256-GCM is 32 bytes
    // TLS_AES_128_GCM_SHA256 uses 16-byte AES key
    let server_key_vec = hkdf_expand_label(&server_hs_secret, b"key", b"", 16);
    let server_iv_vec = hkdf_expand_label(&server_hs_secret, b"iv", b"", 12);

    let mut server_key = [0u8; 16];
    let mut server_iv = [0u8; 12];
    server_key.copy_from_slice(&server_key_vec);
    server_iv.copy_from_slice(&server_iv_vec);

    println!("Server HS key: {:02x?}", server_key);
    println!("Server HS IV: {:02x?}", server_iv);

    // RFC 8448 encrypted server handshake record
    // This is the "complete record" starting with 17 03 03 02 a2
    // Header: 17 03 03 02 a2 (5 bytes)
    // Payload: encrypted data (674 bytes ciphertext + 16 bytes tag = 690 bytes)
    let encrypted_record_hex = "17 03 03 02 a2 d1 ff 33 4a 56 f5 bf \
        f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3 5e df \
        78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61 2e f9 f9 45 \
        cb 96 0b 40 68 90 51 23 ea 78 b1 11 b4 29 ba 91 91 cd 05 d2 a3 \
        89 28 0f 52 61 34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b \
        d9 ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79 02 07 16 cf b9 \
        b1 18 3e f3 ab 20 e3 7d 57 a6 b9 d7 47 76 09 ae e6 e1 22 a4 cf \
        51 42 73 25 25 0c 7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d \
        2e d6 5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb b3 60 98 72 55 \
        cc 74 41 10 c4 53 ba a4 fc d6 10 92 8d 80 98 10 e4 b7 ed 1a 8f \
        d9 91 f0 6a a6 24 82 04 79 7e 36 a6 a7 3b 70 a2 55 9c 09 ea d6 \
        86 94 5b a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 a8 94 41 ac \
        66 27 2f d8 fb 33 0e f8 19 05 79 b3 68 45 96 c9 60 bd 59 6e ea \
        52 0a 56 a8 d6 50 f5 63 aa d2 74 09 96 0d ca 63 d3 e6 88 61 1e \
        a5 e2 2f 44 15 cf 95 38 d5 1a 20 0c 27 03 42 72 96 8a 26 4e d6 \
        54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26 f5 9e ca ba 9a cb bb \
        31 7b 66 d9 02 f4 f2 92 a3 6a c1 b6 39 c6 37 ce 34 31 17 b6 59 \
        62 22 45 31 7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64 7e \
        92 ea 33 0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e 1b 7a 6c 71 78 af \
        36 87 90 18 e3 f2 52 10 7f 24 3d 24 3d c7 33 9d 56 84 c8 b0 37 \
        8b f3 02 44 da 8c 87 c8 43 f5 e5 6e b4 c5 e8 28 0a 2b 48 05 2c \
        f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4 61 e6 6f 99 88 \
        2b d8 9f c5 08 00 be cc a6 2d 6c 74 11 6d bd 29 72 fd a1 fa 80 \
        f8 5d f8 81 ed be 5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69 \
        18 a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb 99 2f 2b 99 \
        2f 67 f8 af e6 7f 76 91 3f a3 88 cb 56 30 c8 ca 01 e0 c6 5d 11 \
        c6 6a 1e 2a c4 c8 59 77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5 51 \
        56 14 63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38 eb ba 42 \
        f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97 8c 31 7f c9 fa 66 a7 3f \
        60 f0 50 4d e9 3b 5b 84 5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd \
        d5 02 78 40 16 e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5 d2 af \
        93 98 28 fd 4a e3 79 4e 44 f9 4d f5 a6 31 ed e4 2c 17 19 bf da \
        bf 02 53 fe 51 75 be 89 8e 75 0e dc 53 37 0d 2b";

    let full_record = hex_decode(encrypted_record_hex);

    // Split header and payload
    let header = &full_record[0..5]; // 17 03 03 02 a2
    let ciphertext = &full_record[5..]; // Remaining 690 bytes

    println!("\nRecord header (AAD): {:02x?}", header);
    println!("Ciphertext length: {} bytes", ciphertext.len());
    println!("Expected: 674 bytes plaintext + 16 bytes tag = 690 bytes");

    // Construct nonce: IV XOR sequence_number
    // Sequence number = 0 for first record
    let seq = 0u64;
    let mut nonce = server_iv;
    for i in 0..8 {
        nonce[12 - 8 + i] ^= ((seq >> (56 - i * 8)) & 0xff) as u8;
    }

    println!("Nonce: {:02x?}", nonce);

    // AAD is the record header
    let aad = header;

    println!("\n📦 Attempting decryption...");

    // Decrypt!
    // Use AES-128-GCM since the RFC vector negotiates TLS_AES_128_GCM_SHA256
    match aes128_gcm_decrypt(&server_key, &nonce, ciphertext, aad) {
        Ok(plaintext) => {
            println!("✅ DECRYPTION SUCCESS!");
            println!("Plaintext length: {} bytes", plaintext.len());
            println!(
                "First 64 bytes: {:02x?}",
                &plaintext[..64.min(plaintext.len())]
            );

            // The plaintext should end with ContentType byte
            if let Some(&content_type) = plaintext.last() {
                println!("Content type (last byte): 0x{:02x}", content_type);
                match content_type {
                    0x16 => println!("  → Handshake (0x16) ✓"),
                    0x17 => println!("  → ApplicationData (0x17)"),
                    _ => println!("  → Unknown content type!"),
                }
            }

            // RFC 8448 says this should decrypt to multiple handshake messages:
            // - EncryptedExtensions
            // - Certificate
            // - CertificateVerify
            // - Finished
            assert!(plaintext.len() > 0, "Plaintext should not be empty!");
        }
        Err(e) => {
            println!("❌ DECRYPTION FAILED: {}", e);
            panic!("Failed to decrypt RFC 8448 server handshake!");
        }
    }
}
