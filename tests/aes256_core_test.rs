/// Test AES-256 core encryption with NIST test vectors
/// This isolates the AES block cipher from GCM mode
use redblue::crypto::aes_gcm::aes256_encrypt_block;

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
fn test_aes256_block_encryption() {
    println!("\n🔐 AES-256 Block Cipher Test");
    println!("   FIPS-197 test vectors\n");

    // FIPS-197 Appendix C.3: AES-256 test
    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let plaintext_hex = "00112233445566778899aabbccddeeff";
    let expected_ciphertext_hex = "8ea2b7ca516745bfeafc49904b496089";

    let key_vec = hex_decode(key_hex);
    let plaintext_vec = hex_decode(plaintext_hex);
    let expected = hex_decode(expected_ciphertext_hex);

    let mut key = [0u8; 32];
    let mut plaintext = [0u8; 16];
    key.copy_from_slice(&key_vec);
    plaintext.copy_from_slice(&plaintext_vec);

    println!("Key:       {}", key_hex);
    println!("Plaintext: {}", plaintext_hex);
    println!("Expected:  {}", expected_ciphertext_hex);

    let ciphertext = aes256_encrypt_block(&plaintext, &key);

    let computed_hex: String = ciphertext.iter().map(|b| format!("{:02x}", b)).collect();
    println!("Computed:  {}", computed_hex);

    if ciphertext == expected.as_slice() {
        println!("\n✅ AES-256 block encryption is CORRECT!");
    } else {
        println!("\n❌ AES-256 block encryption is WRONG!");
        println!("\nByte-by-byte comparison:");
        for (i, (exp, got)) in expected.iter().zip(ciphertext.iter()).enumerate() {
            let marker = if exp == got { " " } else { "❌" };
            println!(
                "  Byte {}: expected {:02x}, got {:02x} {}",
                i, exp, got, marker
            );
        }
        panic!("AES-256 core implementation is broken!");
    }
}

#[test]
fn test_aes256_all_zeros() {
    println!("\n🔐 AES-256 All Zeros Test");
    println!("   Key and plaintext both all zeros\n");

    // Simple test: all zeros
    let key = [0u8; 32];
    let plaintext = [0u8; 16];

    // Expected output from reference implementation
    // This is what OpenSSL produces for AES-256-ECB with all-zero key and plaintext
    let expected_hex = "dc95c078a2408989ad48a21492842087";
    let expected = hex_decode(expected_hex);

    println!("Key:       00000000000000000000000000000000");
    println!("Plaintext: 00000000000000000000000000000000");
    println!("Expected:  {}", expected_hex);

    let ciphertext = aes256_encrypt_block(&plaintext, &key);

    let computed_hex: String = ciphertext.iter().map(|b| format!("{:02x}", b)).collect();
    println!("Computed:  {}", computed_hex);

    if ciphertext == expected.as_slice() {
        println!("\n✅ All-zeros test PASSED!");
    } else {
        println!("\n❌ All-zeros test FAILED!");
        panic!("AES-256 all-zeros test failed!");
    }
}
