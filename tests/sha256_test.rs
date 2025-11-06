/// Test SHA-256 implementation
use redblue::crypto::sha256::sha256;

#[test]
fn test_sha256_empty() {
    let input = b"";
    let hash = sha256(input);
    let expected = hex_decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hash.to_vec(), expected);
}

#[test]
fn test_sha256_abc() {
    let input = b"abc";
    let hash = sha256(input);
    let expected = hex_decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(hash.to_vec(), expected);
}

#[test]
fn test_sha256_long() {
    let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let hash = sha256(input);
    let expected = hex_decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    assert_eq!(hash.to_vec(), expected);
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
