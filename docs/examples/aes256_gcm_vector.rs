#[allow(dead_code)]
mod aes_impl {
    #![allow(dead_code)]
    include!("../src/crypto/aes_gcm.rs");

    pub fn encrypt_block(block: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
        aes256_encrypt_block(block, key)
    }

    pub fn expanded_key(key: &[u8; 32]) -> [u8; 240] {
        aes256_key_expansion(key)
    }
}

use aes_impl::{aes256_gcm_encrypt, encrypt_block, expanded_key};

fn main() {
    let key = [0x00u8; 32];
    let iv = [0x00u8; 12];
    let aad: [u8; 0] = [];
    let plaintext = [
        0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    let result = aes256_gcm_encrypt(&key, &iv, &aad, &plaintext);
    let (ciphertext, tag) = result.split_at(plaintext.len());

    println!("ciphertext: {:02x?}", ciphertext);
    println!("tag:        {:02x?}", tag);

    // Debug: inspect first round key and AES block output
    let expanded = expanded_key(&key);
    for (idx, chunk) in expanded.chunks(16).enumerate().take(4) {
        println!("round key {}: {:02x?}", idx, chunk);
    }
    println!(
        "aes(0^128) with zero key: {:02x?}",
        encrypt_block(&[0u8; 16], &key)
    );
}
