/// NIST SP 800-38D Test Vectors for AES-128-GCM
/// These are official test vectors that ANY correct AES-128-GCM implementation must pass
use redblue::crypto::aes_gcm::{aes128_gcm_decrypt, aes128_gcm_encrypt};

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
fn test_aes128_gcm_nist_case1() {
    // NIST SP 800-38D Test Case 1
    // K = 00000000000000000000000000000000
    // IV = 000000000000000000000000
    // P = (empty)
    // AAD = (empty)
    // Expected ciphertext = (empty)
    // Expected tag = 58e2fccefa7e3061367f1d57a4e7455a

    println!("\n=== NIST SP 800-38D Test Case 1 ===");

    let key = [0x00u8; 16];
    let iv = [0x00u8; 12];
    let aad: &[u8] = &[];
    let plaintext: &[u8] = &[];

    println!("Key:       {:02x?}", key);
    println!("IV:        {:02x?}", iv);
    println!("Plaintext: (empty)");
    println!("AAD:       (empty)");

    let ciphertext_and_tag = aes128_gcm_encrypt(&key, &iv, aad, plaintext);

    let expected_tag_hex = "58 e2 fc ce fa 7e 30 61 36 7f 1d 57 a4 e7 45 5a";
    let expected_tag = hex_decode(expected_tag_hex);

    println!("\nExpected tag: {:02x?}", expected_tag);
    println!("Got tag:      {:02x?}", ciphertext_and_tag);

    assert_eq!(ciphertext_and_tag.len(), 16, "Should be only tag");
    assert_eq!(&ciphertext_and_tag[..], &expected_tag[..], "Tag mismatch!");

    // Test decryption
    let decrypted =
        aes128_gcm_decrypt(&key, &iv, aad, &ciphertext_and_tag).expect("Decrypt failed");
    assert_eq!(&decrypted[..], plaintext);

    println!("✅ NIST Test Case 1 PASSED!");
}

#[test]
fn test_aes128_gcm_nist_case2() {
    // NIST SP 800-38D Test Case 2
    // K = 00000000000000000000000000000000
    // IV = 000000000000000000000000
    // P = 00000000000000000000000000000000
    // AAD = (empty)
    // Expected C = 0388dace60b6a392f328c2b971b2fe78
    // Expected T = ab6e47d42cec13bdf53a67b21257bddf

    println!("\n=== NIST SP 800-38D Test Case 2 ===");

    let key = [0x00u8; 16];
    let iv = [0x00u8; 12];
    let aad: &[u8] = &[];
    let plaintext = [0x00u8; 16];

    println!("Key:       {:02x?}", key);
    println!("IV:        {:02x?}", iv);
    println!("Plaintext: {:02x?}", plaintext);

    let ciphertext_and_tag = aes128_gcm_encrypt(&key, &iv, aad, &plaintext);

    let expected_ciphertext_hex = "03 88 da ce 60 b6 a3 92 f3 28 c2 b9 71 b2 fe 78";
    let expected_tag_hex = "ab 6e 47 d4 2c ec 13 bd f5 3a 67 b2 12 57 bd df";
    let expected_ciphertext = hex_decode(expected_ciphertext_hex);
    let expected_tag = hex_decode(expected_tag_hex);

    println!("\nExpected ciphertext: {:02x?}", expected_ciphertext);
    println!("Got ciphertext:      {:02x?}", &ciphertext_and_tag[..16]);
    println!("Expected tag:        {:02x?}", expected_tag);
    println!("Got tag:             {:02x?}", &ciphertext_and_tag[16..]);

    assert_eq!(ciphertext_and_tag.len(), 32);
    assert_eq!(
        &ciphertext_and_tag[..16],
        &expected_ciphertext[..],
        "Ciphertext mismatch!"
    );
    assert_eq!(
        &ciphertext_and_tag[16..],
        &expected_tag[..],
        "Tag mismatch!"
    );

    // Test decryption
    let decrypted =
        aes128_gcm_decrypt(&key, &iv, aad, &ciphertext_and_tag).expect("Decrypt failed");
    assert_eq!(&decrypted[..], &plaintext[..]);

    println!("✅ NIST Test Case 2 PASSED!");
}

#[test]
fn test_aes128_gcm_nist_case4_with_aad() {
    // NIST SP 800-38D Test Case 4 (with AAD)
    // K = feffe9928665731c6d6a8f9467308308
    // IV = cafebabefacedbaddecaf888
    // P = d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
    // AAD = feedfacedeadbeeffeedfacedeadbeefabaddad2

    println!("\n=== NIST SP 800-38D Test Case 4 (with AAD) ===");

    let key_hex = "fe ff e9 92 86 65 73 1c 6d 6a 8f 94 67 30 83 08";
    let iv_hex = "ca fe ba be fa ce db ad de ca f8 88";
    let plaintext_hex = "d9 31 32 25 f8 84 06 e5 a5 59 09 c5 af f5 26 9a \
                         86 a7 a9 53 15 34 f7 da 2e 4c 30 3d 8a 31 8a 72 \
                         1c 3c 0c 95 95 68 09 53 2f cf 0e 24 49 a6 b5 25 \
                         b1 6a ed f5 aa 0d e6 57 ba 63 7b 39";
    let aad_hex = "fe ed fa ce de ad be ef fe ed fa ce de ad be ef ab ad da d2";
    let expected_ciphertext_hex = "42 83 1e c2 21 77 74 24 4b 72 21 b7 84 d0 d4 9c \
                                    e3 aa 21 2f 2c 02 a4 e0 35 c1 7e 23 29 ac a1 2e \
                                    21 d5 14 b2 54 66 93 1c 7d 8f 6a 5a ac 84 aa 05 \
                                    1b a3 0b 39 6a 0a ac 97 3d 58 e0 91";
    let expected_tag_hex = "5b c9 4f bc 32 21 a5 db 94 fa e9 5a e7 12 1a 47";

    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    key.copy_from_slice(&hex_decode(key_hex));
    iv.copy_from_slice(&hex_decode(iv_hex));
    let plaintext = hex_decode(plaintext_hex);
    let aad = hex_decode(aad_hex);
    let expected_ciphertext = hex_decode(expected_ciphertext_hex);
    let expected_tag = hex_decode(expected_tag_hex);

    println!("Key:       {:02x?}...", &key[..8]);
    println!("IV:        {:02x?}...", &iv[..8]);
    println!("Plaintext: {} bytes", plaintext.len());
    println!("AAD:       {} bytes", aad.len());

    let ciphertext_and_tag = aes128_gcm_encrypt(&key, &iv, &aad, &plaintext);

    println!(
        "\nExpected ciphertext: {:02x?}...",
        &expected_ciphertext[..16]
    );
    println!("Got ciphertext:      {:02x?}...", &ciphertext_and_tag[..16]);
    println!("Expected tag:        {:02x?}", expected_tag);
    println!(
        "Got tag:             {:02x?}",
        &ciphertext_and_tag[ciphertext_and_tag.len() - 16..]
    );

    assert_eq!(ciphertext_and_tag.len(), plaintext.len() + 16);
    assert_eq!(
        &ciphertext_and_tag[..expected_ciphertext.len()],
        &expected_ciphertext[..],
        "Ciphertext mismatch!"
    );
    assert_eq!(
        &ciphertext_and_tag[expected_ciphertext.len()..],
        &expected_tag[..],
        "Tag mismatch!"
    );

    // Test decryption
    let decrypted =
        aes128_gcm_decrypt(&key, &iv, &aad, &ciphertext_and_tag).expect("Decrypt failed");
    assert_eq!(&decrypted[..], &plaintext[..]);

    println!("✅ NIST Test Case 4 PASSED!");
}
