use redblue::crypto::chacha20::Poly1305;
use std::convert::TryInto;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .map(|chunk| u8::from_str_radix(chunk, 16).expect("invalid hex"))
        .collect()
}

#[test]
fn test_poly1305_empty_message_zero_key() {
    let key = [0u8; 32];
    let msg = b"";

    let mut poly = Poly1305::new(&key);
    poly.update(msg);
    let tag = poly.finalize();

    assert_eq!(tag, [0u8; 16]);
}

#[test]
fn test_poly1305_rfc8439_vector() {
    // RFC 8439 Section 2.5.2 test vector
    let key_bytes = hex_to_bytes(
        "85 d6 be 78 57 55 6d 33 7f 44 52 fe 42 d5 06 a8 \
         01 03 80 8a fb 0d b2 fd 4a bf f6 af 41 49 f5 1b",
    );
    let key: [u8; 32] = key_bytes.try_into().expect("key length");
    let msg = b"Cryptographic Forum Research Group";
    let expected_tag_bytes = hex_to_bytes("a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9");
    let expected_tag: [u8; 16] = expected_tag_bytes.try_into().expect("tag length");

    let mut poly = Poly1305::new(&key);
    poly.update(msg);
    let tag = poly.finalize();

    assert_eq!(tag, expected_tag);
}
