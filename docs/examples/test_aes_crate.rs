use redblue::crypto::aes_gcm::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use std::convert::TryInto;

fn hex_decode(hex: &str) -> Vec<u8> {
    let hex_clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    (0..hex_clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_clean[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    println!("Testing in-house AES-256-GCM with NIST test vector...\n");
    let key_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    let iv_hex = "000000000000000000000000";
    let plaintext_hex = "00000000000000000000000000000000";
    let expected_ciphertext_hex = "cea7403d4d606b6e074ec5d3baf39d18";
    let expected_tag_hex = "d0d1c8a799996bf0265b98b5d48ab919";

    let key = hex_decode(key_hex);
    let iv = hex_decode(iv_hex);
    let plaintext = hex_decode(plaintext_hex);
    let expected_ciphertext = hex_decode(expected_ciphertext_hex);
    let expected_tag = hex_decode(expected_tag_hex);

    let key_arr: [u8; 32] = key.clone().try_into().expect("key length");
    let iv_arr: [u8; 12] = iv.clone().try_into().expect("iv length");
    let ciphertext_and_tag = aes256_gcm_encrypt(&key_arr, &iv_arr, &[], &plaintext);

    let mut expected = expected_ciphertext.clone();
    expected.extend_from_slice(&expected_tag);

    println!("Ciphertext+Tag: {:02x?}", ciphertext_and_tag);
    println!("Expected:       {:02x?}", expected);

    if ciphertext_and_tag == expected {
        println!("✅ Encryption MATCH!");
    } else {
        println!("❌ Encryption MISMATCH!");
        return;
    }
    let decrypted =
        aes256_gcm_decrypt(&key_arr, &iv_arr, &[], &ciphertext_and_tag).expect("Decryption failed");

    if decrypted == plaintext {
        println!("✅ Decryption MATCH! In-house AES-256-GCM works!\n");
        println!("🎉 Our AES-256-GCM implementation is correct!");
    }
}
