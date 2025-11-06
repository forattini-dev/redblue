/// Test HKDF implementation against RFC 5869 test vectors
use redblue::crypto::hkdf::{hkdf_expand, hkdf_extract};

#[test]
fn test_hkdf_extract_rfc5869_case1() {
    // RFC 5869 Test Case 1
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_decode("000102030405060708090a0b0c");
    let prk = hkdf_extract(Some(&salt), &ikm);

    let expected = hex_decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    assert_eq!(&prk[..], &expected[..]);
}

#[test]
fn test_hkdf_expand_rfc5869_case1() {
    // RFC 5869 Test Case 1
    let prk_vec = hex_decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&prk_vec);

    let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
    let okm = hkdf_expand(&prk, &info, 42);

    let expected = hex_decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
    assert_eq!(okm, expected);
}

#[test]
fn test_hkdf_extract_no_salt() {
    // RFC 5869 Test Case 2 - no salt
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let prk = hkdf_extract(None, &ikm);

    let expected = hex_decode("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
    assert_eq!(&prk[..], &expected[..]);
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
