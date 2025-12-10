//! Test that both HKDF implementations produce the same output
use redblue::crypto::hkdf as hkdf_external;
use redblue::crypto::tls13_hash::Tls13HashAlgorithm;

#[test]
fn test_hkdf_implementations_match() {
    let secret = [0x08, 0x01, 0x9a, 0xc4, 0xc4, 0x52, 0x41, 0x92, 
                  0xcb, 0x9c, 0x84, 0xf4, 0x15, 0x91, 0xeb, 0x3a, 
                  0x91, 0x59, 0xf9, 0xf4, 0x34, 0x57, 0x40, 0xcc, 
                  0x85, 0x0b, 0x8d, 0xe8, 0xd2, 0x68, 0x77, 0xd6u8];
    
    // Using external hkdf.rs
    let key1 = hkdf_external::hkdf_expand_label(&secret, b"quic key", &[], 16);
    println!("hkdf.rs result: {:02x?}", key1);
    
    // Using tls13_hash.rs  
    let hash_alg = Tls13HashAlgorithm::Sha256;
    let key2 = hash_alg.hkdf_expand_label(&secret, b"quic key", &[], 16).unwrap();
    println!("tls13_hash.rs result: {:02x?}", key2);
    
    assert_eq!(key1, key2, "HKDF implementations must produce identical output");
}
