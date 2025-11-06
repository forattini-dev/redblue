/// Test decrypting Google's ACTUAL ciphertext with our AES-GCM implementation
use redblue::crypto::aes_gcm::aes256_gcm_decrypt;
use std::convert::TryInto;
use std::fs;

fn main() {
    println!("🔍 Testing Google's Actual TLS 1.3 Encrypted Handshake\n");

    // From /tmp/google_decrypt_params.txt
    let key = vec![
        0xdc, 0xe4, 0x19, 0x57, 0x45, 0x70, 0x45, 0xe7, 0xd5, 0x60, 0x7a, 0x24, 0x63, 0x2d, 0x94,
        0x6c, 0x8a, 0x8c, 0x92, 0x35, 0x6f, 0x80, 0xe1, 0xa4, 0x0a, 0x7b, 0x0b, 0xa9, 0xf3, 0xd7,
        0xa9, 0xdd,
    ];
    let iv = vec![
        0x90, 0x9e, 0x17, 0x0e, 0xa1, 0xd2, 0x1e, 0x50, 0xe2, 0xd4, 0xd8, 0x49,
    ];
    let nonce = vec![
        0x90, 0x9e, 0x17, 0x0e, 0xa1, 0xd2, 0x1e, 0x50, 0xe2, 0xd4, 0xd8, 0x49,
    ];
    let aad = vec![0x17, 0x03, 0x03, 0x19, 0x72];

    // Read ciphertext from file
    let ciphertext =
        fs::read("/tmp/google_ciphertext.bin").expect("Failed to read ciphertext file");

    println!("Parameters:");
    println!("  Key length: {} bytes", key.len());
    println!("  IV length: {} bytes", iv.len());
    println!("  Nonce length: {} bytes", nonce.len());
    println!("  AAD: {:02x?}", aad);
    println!("  Ciphertext length: {} bytes", ciphertext.len());
    println!();

    // Verify nonce == IV (for seq=0)
    if nonce == iv {
        println!("✓ Nonce equals IV (correct for sequence 0)");
    } else {
        println!("✗ Nonce != IV (should be equal for seq=0!)");
    }
    println!();

    // Try to decrypt
    let key_arr: [u8; 32] = key.clone().try_into().expect("key length");
    let nonce_arr: [u8; 12] = nonce.clone().try_into().expect("nonce length");

    println!("🔓 Attempting decryption with in-house AES-GCM...");
    match aes256_gcm_decrypt(&key_arr, &nonce_arr, &aad, &ciphertext) {
        Ok(plaintext) => {
            println!("✅ DECRYPTION SUCCEEDED!");
            println!("   Plaintext length: {} bytes", plaintext.len());
            println!(
                "   First 64 bytes: {:02x?}",
                &plaintext[..64.min(plaintext.len())]
            );

            // Check content type (last byte)
            if let Some(&content_type) = plaintext.last() {
                println!("   Content type (last byte): 0x{:02x}", content_type);
                match content_type {
                    0x16 => println!("     → Handshake (0x16) ✓"),
                    0x17 => println!("     → ApplicationData (0x17)"),
                    _ => println!("     → Unknown!"),
                }
            }
        }
        Err(err) => {
            println!("❌ DECRYPTION FAILED!");
            println!("   Error: {}", err);
            println!();
            println!("This means the problem is in our input data:");
            println!("  - Wrong key derivation?");
            println!("  - Wrong nonce construction?");
            println!("  - Wrong AAD?");
            println!("  - Corrupted ciphertext?");
        }
    }
}
