use crate::crypto::aes::Aes128;
use crate::crypto::aes_gcm::{aes128_gcm_decrypt, aes128_gcm_encrypt};
use crate::crypto::hkdf::{hkdf_expand, hkdf_extract};
use crate::crypto::sha256::sha256;

use super::constants::{
    LABEL_CLIENT_IN, LABEL_QUIC_HP, LABEL_QUIC_IV, LABEL_QUIC_KEY, LABEL_SERVER_IN, INITIAL_SALT_V1,
};

/// Length of QUIC AEAD keys (AES-128-GCM by default).
pub const PACKET_KEY_LEN: usize = 16;
/// Length of AEAD nonce (XOR of IV and packet number).
pub const PACKET_IV_LEN: usize = 12;
/// Length of header protection key sample.
pub const HEADER_SAMPLE_LEN: usize = 16;

/// Client-side initial keying material.
#[derive(Debug, Clone)]
pub struct ClientInitialKeys {
    pub secret: [u8; 32],
    pub packet: PacketKeySet,
}

/// Server-side initial keying material.
#[derive(Debug, Clone)]
pub struct ServerInitialKeys {
    pub secret: [u8; 32],
    pub packet: PacketKeySet,
}

/// Packet protection keys (AEAD + header protection).
#[derive(Debug, Clone)]
pub struct PacketKeySet {
    key: [u8; PACKET_KEY_LEN],
    iv: [u8; PACKET_IV_LEN],
    hp: [u8; PACKET_KEY_LEN],
}

impl PacketKeySet {
    pub fn new(key: [u8; PACKET_KEY_LEN], iv: [u8; PACKET_IV_LEN], hp: [u8; PACKET_KEY_LEN]) -> Self {
        Self { key, iv, hp }
    }

    /// Encrypt payload with AES-128-GCM and append authentication tag.
    pub fn encrypt(&self, packet_number: u64, header: &[u8], payload: &[u8]) -> Vec<u8> {
        let nonce = self.build_nonce(packet_number);
        // QUIC AEAD: encrypt payload (plaintext), authenticate header (AAD)
        aes128_gcm_encrypt(&self.key, &nonce, payload, header)
    }

    /// Decrypt payload with AES-128-GCM, returning plaintext.
    pub fn decrypt(
        &self,
        packet_number: u64,
        header: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let nonce = self.build_nonce(packet_number);
        // QUIC AEAD: decrypt ciphertext (payload), verify header (AAD)
        aes128_gcm_decrypt(&self.key, &nonce, ciphertext, header)
    }

    /// Apply header protection to the given header fields in-place.
    pub fn apply_header_protection(&self, first_byte: &mut u8, packet_number_bytes: &mut [u8], sample: &[u8]) {
        let mask = self.generate_hp_mask(sample);

        // Long header: mask lower 4 bits of first byte. Short header: lower 5 bits.
        if (*first_byte & 0x80) != 0 {
            *first_byte ^= mask[0] & 0x0f;
        } else {
            *first_byte ^= mask[0] & 0x1f;
        }

        for (pn_byte, mask_byte) in packet_number_bytes.iter_mut().zip(&mask[1..]) {
            *pn_byte ^= mask_byte;
        }
    }

    /// Remove header protection (inverse of apply).
    pub fn remove_header_protection(&self, first_byte: &mut u8, packet_number_bytes: &mut [u8], sample: &[u8]) {
        // Applying the same mask twice restores the original value.
        self.apply_header_protection(first_byte, packet_number_bytes, sample);
    }

    fn build_nonce(&self, packet_number: u64) -> [u8; PACKET_IV_LEN] {
        let mut nonce = self.iv;
        // XOR the packet number into the right-most bytes of the IV.
        for (i, byte) in nonce.iter_mut().rev().enumerate() {
            let pn_byte = ((packet_number >> (i * 8)) & 0xff) as u8;
            *byte ^= pn_byte;
            if i == 7 {
                break; // Packet numbers are at most 64 bits.
            }
        }
        nonce
    }

    pub fn generate_hp_mask(&self, sample_input: &[u8]) -> [u8; 5] {
        assert!(
            sample_input.len() >= HEADER_SAMPLE_LEN,
            "header protection sample must be at least {} bytes",
            HEADER_SAMPLE_LEN
        );
        let mut sample = [0u8; HEADER_SAMPLE_LEN];
        sample.copy_from_slice(&sample_input[..HEADER_SAMPLE_LEN]);

        let aes = Aes128::new(&self.hp);
        let block = aes.encrypt_block(&sample);

        let mut mask = [0u8; 5];
        mask.copy_from_slice(&block[..5]);
        mask
    }
}

/// Derive client/server initial key material for QUIC version 1.
pub fn derive_initial_keys(dcid: &[u8]) -> (ClientInitialKeys, ServerInitialKeys) {
    let initial_secret = hkdf_extract(Some(&INITIAL_SALT_V1), dcid);

    let client_secret_vec = quic_hkdf_expand_label(&initial_secret, LABEL_CLIENT_IN, &[], 32);
    let server_secret_vec = quic_hkdf_expand_label(&initial_secret, LABEL_SERVER_IN, &[], 32);

    let mut client_secret = [0u8; 32];
    let mut server_secret = [0u8; 32];
    client_secret.copy_from_slice(&client_secret_vec);
    server_secret.copy_from_slice(&server_secret_vec);

    let client_keys = derive_packet_keys(&client_secret);
    let server_keys = derive_packet_keys(&server_secret);

    (
        ClientInitialKeys {
            secret: client_secret,
            packet: client_keys,
        },
        ServerInitialKeys {
            secret: server_secret,
            packet: server_keys,
        },
)
}

fn derive_packet_keys(secret: &[u8; 32]) -> PacketKeySet {
    let key_vec = quic_hkdf_expand_label(secret, LABEL_QUIC_KEY, &[], PACKET_KEY_LEN);
    let iv_vec = quic_hkdf_expand_label(secret, LABEL_QUIC_IV, &[], PACKET_IV_LEN);
    let hp_vec = quic_hkdf_expand_label(secret, LABEL_QUIC_HP, &[], PACKET_KEY_LEN);

    let mut key = [0u8; PACKET_KEY_LEN];
    let mut iv = [0u8; PACKET_IV_LEN];
    let mut hp = [0u8; PACKET_KEY_LEN];

    key.copy_from_slice(&key_vec);
    iv.copy_from_slice(&iv_vec);
    hp.copy_from_slice(&hp_vec);

    PacketKeySet::new(key, iv, hp)
}

/// Derive packet protection keys from any QUIC traffic secret (Initial/Handshake/1-RTT).
pub fn derive_packet_keyset(secret: &[u8; 32]) -> PacketKeySet {
    derive_packet_keys(secret)
}

/// QUIC-specific HKDF-Expand-Label using the "quic " prefix instead of "tls13 ".
pub fn quic_hkdf_expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let mut hkdf_label = Vec::with_capacity(2 + 1 + 4 + label.len() + 1 + context.len());
    hkdf_label.push(((length >> 8) & 0xff) as u8);
    hkdf_label.push((length & 0xff) as u8);

    let full_label = [b"quic ".as_ref(), label].concat();
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(&full_label);

    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    hkdf_expand(secret, &hkdf_label, length)
}

/// Update traffic secrets when QUIC performs a key update (RFC 9001 §6).
pub fn update_traffic_secret(current_secret: &[u8; 32]) -> [u8; 32] {
    let next = quic_hkdf_expand_label(current_secret, b"quic ku", &[], 32);
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&next);
    secret
}

/// Compute the header protection sample offset for a packet payload.
pub fn sample_offset(packet_number_len: usize, payload_len: usize) -> usize {
    // QUIC samples start after packet number field.
    // Sample must be at least 16 bytes; if payload too short the caller must pad.
    (packet_number_len) + 4 // 4 bytes of packet number field in ciphertext before sample is taken.
        .min(payload_len.saturating_sub(HEADER_SAMPLE_LEN))
}

/// Derive Stateless Reset token from connection ID (RFC 9000 §5.6).
pub fn derive_stateless_reset_token(secret: &[u8; 32], cid: &[u8]) -> [u8; 16] {
    let context = sha256(cid);
    let expanded = quic_hkdf_expand_label(secret, b"stateless reset", &context, 16);
    let mut token = [0u8; 16];
    token.copy_from_slice(&expanded);
    token
}
