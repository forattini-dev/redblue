pub mod aes;
pub mod aes_gcm;
pub mod bigint;
pub mod chacha20;
pub mod hkdf;
pub mod hmac;
pub mod md5;
pub mod prf;
pub mod rsa;
/// Cryptography primitives for TLS implementation
/// All implemented from scratch using only Rust std library
pub mod sha1;
pub mod sha256;
pub mod sha384;
pub mod tls13_hash;
pub mod tls13_keyschedule;
pub mod x25519;

// Re-exports
pub use aes_gcm::{aes256_gcm_decrypt, aes256_gcm_encrypt};
pub use bigint::BigInt;
pub use chacha20::{
    chacha20poly1305_decrypt, chacha20poly1305_encrypt, decode_base64, encode_base64, generate_key,
    generate_nonce, ChaCha20, Poly1305,
};
pub use hkdf::{derive_secret, hkdf, hkdf_expand, hkdf_expand_label, hkdf_extract};
pub use hmac::Hmac;
pub use md5::md5;
pub use prf::prf_tls12;
pub use rsa::{extract_public_key_from_cert, RsaPublicKey};
pub use sha256::sha256;
pub use sha384::{sha384, Sha384};
pub use tls13_hash::Tls13HashAlgorithm;
pub use tls13_keyschedule::Tls13KeySchedule;
pub use x25519::{x25519, x25519_public_key};
