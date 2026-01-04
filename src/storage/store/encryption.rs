//! Encryption support for Database storage
//!
//! Provides EncryptionState and helper methods for encrypted databases.

use crate::crypto::uuid::Uuid;
use crate::storage::encryption::{PageEncryptor, SecureKey};
use crate::storage::layout::ENCRYPTION_SALT_SIZE;

/// Encryption state for the database
pub struct EncryptionState {
    pub encryptor: PageEncryptor,
    pub salt: [u8; ENCRYPTION_SALT_SIZE],
    pub key_check: Vec<u8>,
}

impl std::fmt::Debug for EncryptionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionState")
            .field("salt", &"[REDACTED]")
            .field("key_check_len", &self.key_check.len())
            .finish()
    }
}

/// Generate a random salt for key derivation
pub fn generate_salt() -> [u8; ENCRYPTION_SALT_SIZE] {
    let mut salt = [0u8; ENCRYPTION_SALT_SIZE];
    let uuid1 = Uuid::new_v4();
    let uuid2 = Uuid::new_v4();
    salt[0..16].copy_from_slice(uuid1.as_bytes());
    salt[16..32].copy_from_slice(uuid2.as_bytes());
    salt
}

/// Generate key check blob using a known value
pub fn generate_key_check(encryptor: &PageEncryptor) -> Vec<u8> {
    let known_value = [0xAAu8; 32];
    encryptor.encrypt(u32::MAX, &known_value)
}

/// Validate key against stored key check
pub fn validate_key_check(encryptor: &PageEncryptor, key_check: &[u8]) -> bool {
    match encryptor.decrypt(u32::MAX, key_check) {
        Ok(plaintext) => {
            let expected = [0xAAu8; 32];
            plaintext == expected
        }
        Err(_) => false,
    }
}

/// Create an EncryptionState from password and salt
pub fn create_encryption_state(
    password: &str,
    salt: [u8; ENCRYPTION_SALT_SIZE],
) -> EncryptionState {
    let key = SecureKey::from_passphrase(password, &salt);
    let encryptor = PageEncryptor::new(key);
    let key_check = generate_key_check(&encryptor);
    EncryptionState {
        encryptor,
        salt,
        key_check,
    }
}

/// Create an EncryptionState for an existing database (with provided key_check)
pub fn create_encryption_state_with_check(
    password: &str,
    salt: [u8; ENCRYPTION_SALT_SIZE],
    key_check: Vec<u8>,
) -> EncryptionState {
    let key = SecureKey::from_passphrase(password, &salt);
    let encryptor = PageEncryptor::new(key);
    EncryptionState {
        encryptor,
        salt,
        key_check,
    }
}
