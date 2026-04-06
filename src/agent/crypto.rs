use crate::crypto::chacha20::{
  chacha20poly1305_decrypt, chacha20poly1305_encrypt, generate_key, generate_nonce,
};
use crate::crypto::x25519::{x25519, x25519_public_key};

pub struct AgentCrypto {
  pub private_key: [u8; 32],
  pub public_key: [u8; 32],
  pub session_key: Option<[u8; 32]>,
}

impl AgentCrypto {
  pub fn new() -> Self {
    let private_key = generate_key(); // Use existing RNG
    let public_key = x25519_public_key(&private_key);

    Self {
      private_key,
      public_key,
      session_key: None,
    }
  }

  pub fn derive_session_key(&mut self, server_public_key: &[u8; 32]) {
    self.session_key = Some(x25519(&self.private_key, server_public_key));
  }

  pub fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, [u8; 16], [u8; 12]), String> {
    let key = self.session_key.as_ref().ok_or("No session key")?;
    let nonce = generate_nonce();

    // Use empty AAD for now
    let aad = b"";

    let encrypted_with_tag = chacha20poly1305_encrypt(key, &nonce, aad, data);

    // Extract tag (last 16 bytes)
    if encrypted_with_tag.len() < 16 {
      return Err("Encryption failed".to_string());
    }

    let split_idx = encrypted_with_tag.len() - 16;
    let payload = encrypted_with_tag[..split_idx].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&encrypted_with_tag[split_idx..]);

    Ok((payload, tag, nonce))
  }

  pub fn decrypt(
    &self,
    ciphertext: &[u8],
    tag: &[u8; 16],
    nonce: &[u8; 12],
  ) -> Result<Vec<u8>, String> {
    let key = self.session_key.as_ref().ok_or("No session key")?;

    // Reconstruct ciphertext + tag for chacha20poly1305_decrypt
    let mut input = ciphertext.to_vec();
    input.extend_from_slice(tag);

    chacha20poly1305_decrypt(key, nonce, b"", &input)
  }

  // New method for encrypting with an explicit key (used by server for response)
  pub fn encrypt_with_key(
    &self,
    key: &[u8; 32],
    data: &[u8],
  ) -> Result<(Vec<u8>, [u8; 16], [u8; 12]), String> {
    let nonce = generate_nonce();
    let aad = b"";

    let encrypted_with_tag = chacha20poly1305_encrypt(key, &nonce, aad, data);

    if encrypted_with_tag.len() < 16 {
      return Err("Encryption failed".to_string());
    }

    let split_idx = encrypted_with_tag.len() - 16;
    let payload = encrypted_with_tag[..split_idx].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&encrypted_with_tag[split_idx..]);

    Ok((payload, tag, nonce))
  }

  pub fn decrypt_with_key(
    &self,
    key: &[u8; 32],
    ciphertext: &[u8],
    tag: &[u8; 16],
    nonce: &[u8; 12],
  ) -> Result<Vec<u8>, String> {
    // Reconstruct ciphertext + tag for chacha20poly1305_decrypt
    let mut input = ciphertext.to_vec();
    input.extend_from_slice(tag);

    chacha20poly1305_decrypt(key, nonce, b"", &input)
  }
}
