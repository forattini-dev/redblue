/// Standalone Poly1305 test - RFC 8439 Section 2.5.2
/// This isolates the Poly1305 MAC to find the bug

#[test]
fn test_poly1305_rfc8439_section_2_5_2() {
    // RFC 8439 Section 2.5.2 - Poly1305 Example and Test Vector

    // Test key (from RFC)
    let key = hex_decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");

    // Message to authenticate
    let msg = b"Cryptographic Forum Research Group";

    // Expected tag from RFC
    let expected_tag = hex_decode("a8061dc1305136c6c22b8baf0c0127a9");

    // Compute Poly1305
    use redblue::crypto::chacha20::Poly1305;
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key);

    let mut poly = Poly1305::new(&key_array);
    poly.update(msg);
    let tag = poly.finalize();

    println!("Message: {:?}", std::str::from_utf8(msg));
    println!("Key:     {:02x?}", &key[..16]);
    println!("Got tag: {:02x?}", &tag);
    println!("Expected: {:02x?}", &expected_tag);

    assert_eq!(
        tag[..],
        expected_tag[..],
        "\nPoly1305 MAC mismatch!\nGot:      {:02x?}\nExpected: {:02x?}",
        tag,
        expected_tag
    );
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
