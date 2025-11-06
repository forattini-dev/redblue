/// Basic AES-128-GCM roundtrip test
use redblue::crypto::aes_gcm::{aes128_gcm_decrypt, aes128_gcm_encrypt};

#[test]
fn test_aes128_roundtrip() {
    let key = [0x42u8; 16];
    let iv = [0x12u8; 12];
    let aad = b"test aad";
    let plaintext = b"Hello, AES-128-GCM!";

    println!("\n=== AES-128-GCM Roundtrip Test ===");
    println!("Key:       {:02x?}", key);
    println!("IV:        {:02x?}", iv);
    println!("AAD:       {:?}", std::str::from_utf8(aad).unwrap());
    println!("Plaintext: {:?}", std::str::from_utf8(plaintext).unwrap());

    let ciphertext = aes128_gcm_encrypt(&key, &iv, aad, plaintext);
    println!(
        "\nCiphertext len: {} (expected {})",
        ciphertext.len(),
        plaintext.len() + 16
    );
    println!(
        "Ciphertext: {:02x?}",
        &ciphertext[..ciphertext.len().min(32)]
    );

    let decrypted = aes128_gcm_decrypt(&key, &iv, aad, &ciphertext).expect("Decrypt failed");
    println!(
        "\nDecrypted: {:?}",
        std::str::from_utf8(&decrypted).unwrap()
    );

    assert_eq!(&decrypted[..], plaintext);
    println!("\n✅ AES-128-GCM roundtrip works!");
}

#[test]
fn test_aes128_empty() {
    let key = [0x00u8; 16];
    let iv = [0x00u8; 12];
    let aad: &[u8] = b"";
    let plaintext: &[u8] = b"";

    let ciphertext = aes128_gcm_encrypt(&key, &iv, aad, plaintext);
    assert_eq!(
        ciphertext.len(),
        16,
        "Empty plaintext should produce only tag"
    );

    let decrypted = aes128_gcm_decrypt(&key, &iv, aad, &ciphertext).expect("Decrypt failed");
    assert_eq!(&decrypted[..], plaintext);
}
