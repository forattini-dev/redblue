use crate::crypto::chacha20::{chacha20poly1305_encrypt, chacha20poly1305_decrypt, generate_key, generate_nonce};
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

    pub fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, [u8; 16]), String> {
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
        
        // We need to send nonce too! The BeaconMessage doesn't have a nonce field?
        // Let's check protocol.rs again.
        // BeaconMessage: magic, version, msg_type, flags, session_id, timestamp, payload, tag.
        // It's missing nonce!
        // RFC 8439 requires unique nonce.
        // We should prepend nonce to payload or add a field.
        // Prepending nonce to payload is common.
        
        // Let's re-package:
        // Return: nonce + ciphertext, tag
        
        let mut result_payload = nonce.to_vec();
        result_payload.extend_from_slice(&payload);
        
        Ok((result_payload, tag))
    }

    pub fn decrypt(&self, payload_with_nonce: &[u8], tag: &[u8; 16]) -> Result<Vec<u8>, String> {
        let key = self.session_key.as_ref().ok_or("No session key")?;
        
        if payload_with_nonce.len() < 12 {
            return Err("Payload too short (missing nonce)".to_string());
        }
        
        let nonce = &payload_with_nonce[..12];
        let ciphertext = &payload_with_nonce[12..];
        
        // Reconstruct ciphertext + tag for chacha20poly1305_decrypt
        let mut input = ciphertext.to_vec();
        input.extend_from_slice(tag);
        
        let nonce_arr: [u8; 12] = nonce.try_into().map_err(|_| "Invalid nonce".to_string())?;
        
        chacha20poly1305_decrypt(key, &nonce_arr, b"", &input)
    }

    // New method for encrypting with an explicit key (used by server for response)
    pub fn encrypt_with_key(&self, key: &[u8; 32], data: &[u8]) -> Result<(Vec<u8>, [u8; 16]), String> {
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
        
        let mut result_payload = nonce.to_vec();
        result_payload.extend_from_slice(&payload);
        
        Ok((result_payload, tag))
    }
}
