/// NIST AES-256-GCM test vectors
/// Source: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES
///
/// This test uses official NIST test vectors to validate our GCM implementation
use redblue::crypto::aes_gcm::{aes256_gcm_decrypt, aes256_gcm_encrypt};

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
fn test_aes256_gcm_nist_case1() {
    println!("\n🔐 NIST AES-256-GCM Test Case 1");
    println!("   Validating against official test vectors\n");

    // NIST Test Case 1: Simple encryption with small data
    let key_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    let iv_hex = "000000000000000000000000";
    let plaintext_hex = "";
    let aad_hex = "";
    let expected_ciphertext_hex = "";
    let expected_tag_hex = "530f8afbc74536b9a963b4f1c4cb738b";

    let key_vec = hex_decode(key_hex);
    let iv_vec = hex_decode(iv_hex);
    let plaintext = hex_decode(plaintext_hex);
    let aad = hex_decode(aad_hex);
    let expected_tag = hex_decode(expected_tag_hex);

    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    key.copy_from_slice(&key_vec);
    iv.copy_from_slice(&iv_vec);

    println!("Key:       {}", key_hex);
    println!("IV:        {}", iv_hex);
    println!("Plaintext: {} (empty)", plaintext_hex);
    println!("AAD:       {} (empty)", aad_hex);
    println!("Expected tag: {}", expected_tag_hex);

    // Encrypt
    let ciphertext_with_tag = aes256_gcm_encrypt(&key, &iv, &aad, &plaintext);

    println!("\nEncryption result:");
    println!("  Ciphertext + Tag length: {}", ciphertext_with_tag.len());

    let computed_tag = &ciphertext_with_tag[ciphertext_with_tag.len() - 16..];
    println!(
        "  Computed tag: {}",
        computed_tag
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    // Check tag
    if computed_tag == &expected_tag[..] {
        println!("\n✅ Tag matches NIST test vector!");
    } else {
        println!("\n❌ Tag MISMATCH!");
        println!("   Expected: {}", expected_tag_hex);
        println!(
            "   Got:      {}",
            computed_tag
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        panic!("AES-256-GCM tag does not match NIST test vector!");
    }

    // Decrypt
    match aes256_gcm_decrypt(&key, &iv, &aad, &ciphertext_with_tag) {
        Ok(decrypted) => {
            println!("✅ Decryption successful");
            assert_eq!(decrypted, plaintext, "Decrypted plaintext mismatch");
        }
        Err(e) => {
            panic!("Decryption failed: {}", e);
        }
    }
}

#[test]
fn test_aes256_gcm_nist_case2() {
    println!("\n🔐 NIST AES-256-GCM Test Case 2");
    println!("   With plaintext and AAD\n");

    // NIST Test Case 2: With actual data
    let key_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    let iv_hex = "000000000000000000000000";
    let plaintext_hex = "00000000000000000000000000000000";
    let aad_hex = "";
    let expected_ciphertext_hex = "cea7403d4d606b6e074ec5d3baf39d18";
    let expected_tag_hex = "d0d1c8a799996bf0265b98b5d48ab919";

    let key_vec = hex_decode(key_hex);
    let iv_vec = hex_decode(iv_hex);
    let plaintext = hex_decode(plaintext_hex);
    let aad = hex_decode(aad_hex);
    let expected_ciphertext = hex_decode(expected_ciphertext_hex);
    let expected_tag = hex_decode(expected_tag_hex);

    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    key.copy_from_slice(&key_vec);
    iv.copy_from_slice(&iv_vec);

    println!("Key:       {}", key_hex);
    println!("IV:        {}", iv_hex);
    println!("Plaintext: {}", plaintext_hex);
    println!("AAD:       {} (empty)", aad_hex);
    println!("Expected ciphertext: {}", expected_ciphertext_hex);
    println!("Expected tag:        {}", expected_tag_hex);

    // Encrypt
    let result = aes256_gcm_encrypt(&key, &iv, &aad, &plaintext);

    let ciphertext = &result[..result.len() - 16];
    let computed_tag = &result[result.len() - 16..];

    println!("\nEncryption result:");
    println!(
        "  Computed ciphertext: {}",
        ciphertext
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!(
        "  Computed tag:        {}",
        computed_tag
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    // Check ciphertext
    if ciphertext == &expected_ciphertext[..] {
        println!("\n✅ Ciphertext matches NIST test vector!");
    } else {
        println!("\n❌ Ciphertext MISMATCH!");
        panic!("Ciphertext does not match NIST test vector!");
    }

    // Check tag
    if computed_tag == &expected_tag[..] {
        println!("✅ Tag matches NIST test vector!");
    } else {
        println!("❌ Tag MISMATCH!");
        panic!("Tag does not match NIST test vector!");
    }

    // Decrypt
    match aes256_gcm_decrypt(&key, &iv, &aad, &result) {
        Ok(decrypted) => {
            println!("✅ Decryption successful");
            assert_eq!(decrypted, plaintext, "Decrypted plaintext mismatch");
        }
        Err(e) => {
            panic!("Decryption failed: {}", e);
        }
    }
}
