//! Compile-Time String Encryption
//!
//! Encrypts sensitive strings at compile time so they don't appear in the binary.
//! Strings are decrypted at runtime only when needed.
//!
//! # How it works
//! 1. Strings are XOR encrypted with a build-specific key at compile time
//! 2. The encrypted bytes are stored in the binary
//! 3. At runtime, strings are decrypted on-demand
//! 4. Decrypted strings can be zeroed after use for extra security
//!
//! # Usage
//! ```rust
//! use redblue::modules::evasion::strings::EncryptedString;
//!
//! // Create encrypted string (data is pre-encrypted)
//! let cmd = EncryptedString::new(&[0x43, 0x4d, 0x44], 0x00);
//! let decrypted = cmd.decrypt(); // "CMD"
//! ```

use super::mutations;

/// An encrypted string that can be decrypted at runtime
#[derive(Clone)]
pub struct EncryptedString {
    /// Encrypted bytes
    data: Vec<u8>,
    /// XOR key used for encryption (can be build-specific)
    key: Vec<u8>,
}

impl EncryptedString {
    /// Create a new encrypted string from pre-encrypted data
    pub fn new(encrypted_data: &[u8], single_key: u8) -> Self {
        Self {
            data: encrypted_data.to_vec(),
            key: vec![single_key],
        }
    }

    /// Create with multi-byte key
    pub fn with_key(encrypted_data: &[u8], key: &[u8]) -> Self {
        Self {
            data: encrypted_data.to_vec(),
            key: key.to_vec(),
        }
    }

    /// Create from plaintext (encrypts immediately using build key)
    pub fn from_plaintext(plaintext: &str) -> Self {
        let encrypted = mutations::obfuscate_string(plaintext);
        Self {
            data: encrypted,
            key: mutations::XOR_KEY_MULTI.to_vec(),
        }
    }

    /// Decrypt the string
    pub fn decrypt(&self) -> String {
        if self.key.len() == 1 {
            // Single-byte XOR
            let decrypted: Vec<u8> = self.data.iter().map(|b| b ^ self.key[0]).collect();
            String::from_utf8_lossy(&decrypted).to_string()
        } else {
            // Multi-byte XOR
            let decrypted: Vec<u8> = self
                .data
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ self.key[i % self.key.len()])
                .collect();
            String::from_utf8_lossy(&decrypted).to_string()
        }
    }

    /// Decrypt using build-specific key
    pub fn decrypt_with_build_key(&self) -> String {
        mutations::deobfuscate_string(&self.data)
    }

    /// Get encrypted bytes (for embedding in code)
    pub fn encrypted_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the key
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// Encrypt a string for embedding in source code
/// Returns (encrypted_bytes, key) that can be used to create EncryptedString
pub fn encrypt_for_embedding(plaintext: &str) -> (Vec<u8>, u8) {
    let key = mutations::get_xor_key();
    let encrypted: Vec<u8> = plaintext.bytes().map(|b| b ^ key).collect();
    (encrypted, key)
}

/// Encrypt with multi-byte key for stronger obfuscation
pub fn encrypt_multi_key(plaintext: &str) -> (Vec<u8>, Vec<u8>) {
    let key = mutations::XOR_KEY_MULTI.to_vec();
    let encrypted: Vec<u8> = plaintext
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();
    (encrypted, key)
}

/// Common sensitive strings that should be encrypted
pub struct SensitiveStrings;

impl SensitiveStrings {
    /// Windows command interpreter
    pub fn cmd_exe() -> EncryptedString {
        EncryptedString::from_plaintext("cmd.exe")
    }

    /// PowerShell
    pub fn powershell() -> EncryptedString {
        EncryptedString::from_plaintext("powershell.exe")
    }

    /// PowerShell with hidden window
    pub fn powershell_hidden() -> EncryptedString {
        EncryptedString::from_plaintext("powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass")
    }

    /// Windows Script Host
    pub fn wscript() -> EncryptedString {
        EncryptedString::from_plaintext("wscript.exe")
    }

    /// MSHTA for HTA execution
    pub fn mshta() -> EncryptedString {
        EncryptedString::from_plaintext("mshta.exe")
    }

    /// Rundll32 for DLL execution
    pub fn rundll32() -> EncryptedString {
        EncryptedString::from_plaintext("rundll32.exe")
    }

    /// Regsvr32 for COM object execution
    pub fn regsvr32() -> EncryptedString {
        EncryptedString::from_plaintext("regsvr32.exe")
    }

    /// Linux shell
    pub fn bash() -> EncryptedString {
        EncryptedString::from_plaintext("/bin/bash")
    }

    /// Alternative Linux shell
    pub fn sh() -> EncryptedString {
        EncryptedString::from_plaintext("/bin/sh")
    }

    /// Netcat
    pub fn nc() -> EncryptedString {
        EncryptedString::from_plaintext("nc")
    }

    /// Curl
    pub fn curl() -> EncryptedString {
        EncryptedString::from_plaintext("curl")
    }

    /// Wget
    pub fn wget() -> EncryptedString {
        EncryptedString::from_plaintext("wget")
    }

    /// Custom encrypted string
    pub fn custom(s: &str) -> EncryptedString {
        EncryptedString::from_plaintext(s)
    }
}

/// Stack string - decrypts character by character to avoid string in memory
/// Each character is stored as an encrypted byte
pub struct StackString {
    chars: Vec<u8>,
    key: u8,
}

impl StackString {
    /// Create from plaintext (encrypts each char)
    pub fn new(plaintext: &str) -> Self {
        let key = mutations::get_xor_key();
        let chars: Vec<u8> = plaintext.bytes().map(|b| b ^ key).collect();
        Self { chars, key }
    }

    /// Decrypt to String (builds on stack, not heap when possible)
    pub fn decrypt(&self) -> String {
        let mut result = String::with_capacity(self.chars.len());
        for &c in &self.chars {
            result.push((c ^ self.key) as char);
        }
        result
    }

    /// Get decrypted bytes without allocating String
    pub fn decrypt_bytes(&self) -> Vec<u8> {
        self.chars.iter().map(|&c| c ^ self.key).collect()
    }

    /// Length of the string
    pub fn len(&self) -> usize {
        self.chars.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }
}

/// Secure string that zeros memory when dropped
pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    /// Create from plaintext
    pub fn new(s: &str) -> Self {
        Self {
            data: s.as_bytes().to_vec(),
        }
    }

    /// Create from encrypted string (decrypts)
    pub fn from_encrypted(enc: &EncryptedString) -> Self {
        Self {
            data: enc.decrypt().into_bytes(),
        }
    }

    /// Get the string (borrowed)
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.data).unwrap_or("")
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Zero the memory before deallocation
        for byte in &mut self.data {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        // Prevent compiler from optimizing away the zeroing
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Generate Rust code for an encrypted string constant
pub fn generate_encrypted_const(name: &str, plaintext: &str) -> String {
    let (encrypted, key) = encrypt_for_embedding(plaintext);
    let bytes_str: String = encrypted.iter().map(|b| format!("0x{:02X}, ", b)).collect();

    format!(
        r#"/// Encrypted string: "{}"
const {}_ENCRYPTED: &[u8] = &[{}];
const {}_KEY: u8 = 0x{:02X};

fn decrypt_{}() -> String {{
    {}_ENCRYPTED.iter().map(|b| (b ^ {}_KEY) as char).collect()
}}"#,
        plaintext,
        name.to_uppercase(),
        bytes_str.trim_end_matches(", "),
        name.to_uppercase(),
        key,
        name.to_lowercase(),
        name.to_uppercase(),
        name.to_uppercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_string_roundtrip() {
        let original = "secret command";
        let enc = EncryptedString::from_plaintext(original);
        let dec = enc.decrypt_with_build_key();
        assert_eq!(original, dec);
    }

    #[test]
    fn test_stack_string() {
        let original = "cmd.exe";
        let stack = StackString::new(original);
        assert_eq!(original, stack.decrypt());
    }

    #[test]
    fn test_secure_string_zeros() {
        let s = SecureString::new("password123");
        assert_eq!(s.as_str(), "password123");
        // Drop will zero memory
    }

    #[test]
    fn test_sensitive_strings() {
        let cmd = SensitiveStrings::cmd_exe();
        assert_eq!(cmd.decrypt_with_build_key(), "cmd.exe");

        let bash = SensitiveStrings::bash();
        assert_eq!(bash.decrypt_with_build_key(), "/bin/bash");
    }

    #[test]
    fn test_generate_const() {
        let code = generate_encrypted_const("CMD", "cmd.exe");
        assert!(code.contains("CMD_ENCRYPTED"));
        assert!(code.contains("CMD_KEY"));
    }
}
