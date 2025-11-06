// Test AES-256-GCM round-trip with exact values from TLS 1.3 handshake

use redblue::crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    // Use the exact key and IV from our debug output
    let key_hex = "3d02abc9818af904dd0ea4c0b7ed43e1ff4b22809c42f854f2a8a5236f2e7579";
    let iv_hex = "d4291f83fb1cd804575a90ae";

    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = u8::from_str_radix(&key_hex[i*2..i*2+2], 16).unwrap();
    }

    let mut iv = [0u8; 12];
    for i in 0..12 {
        iv[i] = u8::from_str_radix(&iv_hex[i*2..i*2+2], 16).unwrap();
    }

    // AAD from our debug: 1703031973
    let aad = vec![0x17, 0x03, 0x03, 0x19, 0x73];

    // Test with simple plaintext
    let plaintext = b"Hello, TLS 1.3!";

    println!("Key: {}", to_hex(&key));
    println!("IV:  {}", to_hex(&iv));
    println!("AAD: {}", to_hex(&aad));
    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));

    // Encrypt
    let ciphertext = aes256_gcm_encrypt(&key, &iv, &aad, plaintext);
    println!("\nCiphertext+Tag: {}", to_hex(&ciphertext));

    // Decrypt
    match aes256_gcm_decrypt(&key, &iv, &aad, &ciphertext) {
        Ok(decrypted) => {
            println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
            if decrypted == plaintext {
                println!("\n✅ Round-trip SUCCESS!");
            } else {
                println!("\n❌ Round-trip FAILED - plaintext mismatch");
            }
        }
        Err(e) => {
            println!("\n❌ Decryption FAILED: {}", e);
        }
    }
}
