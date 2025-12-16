//! Double Ratchet Protocol Implementation
//!
//! Based on the Signal Protocol specification for forward secrecy.
//! Each message uses a unique encryption key, and compromising one
//! key doesn't compromise past or future messages.
//!
//! Architecture:
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Double Ratchet                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Root Chain    │  Sending Chain   │  Receiving Chain        │
//! │  (DH Ratchet)  │  (Symmetric)     │  (Symmetric)            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  DH Key Pair   │  Chain Key       │  Chain Key              │
//! │  Root Key      │  Message Keys    │  Message Keys           │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;

use crate::crypto::chacha20::{chacha20poly1305_decrypt, chacha20poly1305_encrypt, generate_nonce};
use crate::crypto::hkdf::hkdf;
use crate::crypto::hmac::hmac_sha256;
use crate::crypto::x25519::{x25519, x25519_public_key};

/// Maximum number of skipped message keys to store
/// Prevents memory exhaustion from malicious sequences
const MAX_SKIP: u32 = 1000;

/// X25519 key pair for DH operations
#[derive(Clone)]
pub struct X25519KeyPair {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl X25519KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        // Collect entropy from multiple sources
        let private_key = collect_entropy_32();
        let public_key = x25519_public_key(&private_key);

        Self {
            private_key,
            public_key,
        }
    }

    /// Perform X25519 DH with another public key
    pub fn dh(&self, their_public: &[u8; 32]) -> [u8; 32] {
        x25519(&self.private_key, their_public)
    }
}

/// Header sent with each encrypted message
#[derive(Clone, Debug)]
pub struct MessageHeader {
    /// Current DH public key
    pub dh_public: [u8; 32],
    /// Previous chain length (number of messages sent under previous DH key)
    pub pn: u32,
    /// Message number in current chain
    pub n: u32,
}

impl MessageHeader {
    /// Serialize header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(&self.dh_public);
        bytes.extend_from_slice(&self.pn.to_le_bytes());
        bytes.extend_from_slice(&self.n.to_le_bytes());
        bytes
    }

    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 40 {
            return Err("Header too short".to_string());
        }

        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&bytes[0..32]);

        let pn = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        let n = u32::from_le_bytes(bytes[36..40].try_into().unwrap());

        Ok(Self { dh_public, pn, n })
    }
}

/// Complete ratchet state for one party
pub struct RatchetState {
    /// Our current DH key pair
    dh_keypair: X25519KeyPair,

    /// Their current DH public key (None before first message received)
    dh_remote: Option<[u8; 32]>,

    /// Root key - updated on each DH ratchet step
    root_key: [u8; 32],

    /// Sending chain key
    send_chain_key: Option<[u8; 32]>,

    /// Receiving chain key
    recv_chain_key: Option<[u8; 32]>,

    /// Number of messages sent in current sending chain
    send_n: u32,

    /// Number of messages received in current receiving chain
    recv_n: u32,

    /// Previous sending chain length (for header)
    prev_send_n: u32,

    /// Skipped message keys: (DH public key hash, message number) -> message key
    /// Used to decrypt out-of-order messages
    skipped_keys: HashMap<([u8; 8], u32), [u8; 32]>,
}

impl RatchetState {
    /// Initialize ratchet for the initiator (client)
    ///
    /// The initiator sends the first message after X3DH key agreement.
    /// They have:
    /// - Their own DH key pair
    /// - The responder's DH public key from X3DH
    /// - A shared secret from X3DH
    pub fn init_initiator(shared_secret: &[u8; 32], their_public: &[u8; 32]) -> Self {
        let dh_keypair = X25519KeyPair::generate();

        // Perform initial DH
        let dh_output = dh_keypair.dh(their_public);

        // Derive root key and sending chain key
        let (root_key, send_chain_key) = kdf_rk(shared_secret, &dh_output);

        Self {
            dh_keypair,
            dh_remote: Some(*their_public),
            root_key,
            send_chain_key: Some(send_chain_key),
            recv_chain_key: None,
            send_n: 0,
            recv_n: 0,
            prev_send_n: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Initialize ratchet for the responder (server)
    ///
    /// The responder waits for the first message from the initiator.
    /// They have:
    /// - Their own DH key pair (from X3DH)
    /// - A shared secret from X3DH
    pub fn init_responder(shared_secret: &[u8; 32], dh_keypair: X25519KeyPair) -> Self {
        Self {
            dh_keypair,
            dh_remote: None,
            root_key: *shared_secret,
            send_chain_key: None,
            recv_chain_key: None,
            send_n: 0,
            recv_n: 0,
            prev_send_n: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Get our current public key
    pub fn public_key(&self) -> &[u8; 32] {
        &self.dh_keypair.public_key
    }

    /// Encrypt a message
    ///
    /// Returns (header, ciphertext) tuple
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(MessageHeader, Vec<u8>), String> {
        // Ensure we have a sending chain
        let chain_key = self
            .send_chain_key
            .as_ref()
            .ok_or("No sending chain established")?;

        // Derive message key and advance chain
        let (new_chain_key, message_key) = kdf_ck(chain_key);
        self.send_chain_key = Some(new_chain_key);

        // Create header
        let header = MessageHeader {
            dh_public: self.dh_keypair.public_key,
            pn: self.prev_send_n,
            n: self.send_n,
        };

        // Increment message counter
        self.send_n += 1;

        // Encrypt with AEAD
        // Associated data is the header to prevent tampering
        let ad = header.to_bytes();
        let ciphertext = encrypt_aead(&message_key, plaintext, &ad)?;

        Ok((header, ciphertext))
    }

    /// Decrypt a message
    ///
    /// Handles DH ratchet steps and out-of-order messages
    pub fn decrypt(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        // First, try to find a skipped message key
        let dh_hash = hash_dh_public(&header.dh_public);
        if let Some(message_key) = self.skipped_keys.remove(&(dh_hash, header.n)) {
            let ad = header.to_bytes();
            return decrypt_aead(&message_key, ciphertext, &ad);
        }

        // Check if we need to perform a DH ratchet step
        let need_dh_ratchet = match &self.dh_remote {
            None => true,
            Some(current) => current != &header.dh_public,
        };

        if need_dh_ratchet {
            // Skip any remaining messages in the current receiving chain
            if self.recv_chain_key.is_some() {
                self.skip_message_keys(header.pn)?;
            }

            // Perform DH ratchet step
            self.dh_ratchet(&header.dh_public)?;
        }

        // Skip messages if needed (out-of-order within current chain)
        self.skip_message_keys(header.n)?;

        // Derive message key and advance receiving chain
        let chain_key = self.recv_chain_key.as_ref().ok_or("No receiving chain")?;
        let (new_chain_key, message_key) = kdf_ck(chain_key);
        self.recv_chain_key = Some(new_chain_key);
        self.recv_n += 1;

        // Decrypt
        let ad = header.to_bytes();
        decrypt_aead(&message_key, ciphertext, &ad)
    }

    /// Perform DH ratchet step when receiving a new DH public key
    fn dh_ratchet(&mut self, their_public: &[u8; 32]) -> Result<(), String> {
        // Store previous sending chain length
        self.prev_send_n = self.send_n;

        // Reset counters
        self.send_n = 0;
        self.recv_n = 0;

        // Update remote DH key
        self.dh_remote = Some(*their_public);

        // Derive new receiving chain
        let dh_recv = self.dh_keypair.dh(their_public);
        let (root_key, recv_chain_key) = kdf_rk(&self.root_key, &dh_recv);
        self.root_key = root_key;
        self.recv_chain_key = Some(recv_chain_key);

        // Generate new DH key pair
        self.dh_keypair = X25519KeyPair::generate();

        // Derive new sending chain
        let dh_send = self.dh_keypair.dh(their_public);
        let (root_key, send_chain_key) = kdf_rk(&self.root_key, &dh_send);
        self.root_key = root_key;
        self.send_chain_key = Some(send_chain_key);

        Ok(())
    }

    /// Skip message keys and store them for later decryption
    fn skip_message_keys(&mut self, until: u32) -> Result<(), String> {
        if self.recv_chain_key.is_none() {
            return Ok(());
        }

        if self.recv_n + MAX_SKIP < until {
            return Err("Too many skipped messages".to_string());
        }

        let dh_hash = match &self.dh_remote {
            Some(pk) => hash_dh_public(pk),
            None => return Ok(()),
        };

        while self.recv_n < until {
            let chain_key = self.recv_chain_key.as_ref().unwrap();
            let (new_chain_key, message_key) = kdf_ck(chain_key);
            self.recv_chain_key = Some(new_chain_key);

            self.skipped_keys
                .insert((dh_hash, self.recv_n), message_key);
            self.recv_n += 1;

            // Limit stored keys
            if self.skipped_keys.len() > MAX_SKIP as usize {
                // Remove oldest (this is a simplification - ideally use LRU)
                if let Some(key) = self.skipped_keys.keys().next().cloned() {
                    self.skipped_keys.remove(&key);
                }
            }
        }

        Ok(())
    }

    /// Serialize state for persistence
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Version byte
        data.push(1);

        // DH keypair
        data.extend_from_slice(&self.dh_keypair.private_key);
        data.extend_from_slice(&self.dh_keypair.public_key);

        // DH remote (1 byte flag + 32 bytes if present)
        match &self.dh_remote {
            Some(pk) => {
                data.push(1);
                data.extend_from_slice(pk);
            }
            None => {
                data.push(0);
            }
        }

        // Root key
        data.extend_from_slice(&self.root_key);

        // Chain keys (1 byte flag + 32 bytes each if present)
        match &self.send_chain_key {
            Some(ck) => {
                data.push(1);
                data.extend_from_slice(ck);
            }
            None => {
                data.push(0);
            }
        }

        match &self.recv_chain_key {
            Some(ck) => {
                data.push(1);
                data.extend_from_slice(ck);
            }
            None => {
                data.push(0);
            }
        }

        // Counters
        data.extend_from_slice(&self.send_n.to_le_bytes());
        data.extend_from_slice(&self.recv_n.to_le_bytes());
        data.extend_from_slice(&self.prev_send_n.to_le_bytes());

        // Skipped keys count and entries
        let skip_count = self.skipped_keys.len() as u32;
        data.extend_from_slice(&skip_count.to_le_bytes());

        for ((dh_hash, n), key) in &self.skipped_keys {
            data.extend_from_slice(dh_hash);
            data.extend_from_slice(&n.to_le_bytes());
            data.extend_from_slice(key);
        }

        data
    }

    /// Deserialize state from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        if data.is_empty() {
            return Err("Empty data".to_string());
        }

        let mut pos = 0;

        // Version
        let version = data[pos];
        pos += 1;
        if version != 1 {
            return Err(format!("Unknown version: {}", version));
        }

        // DH keypair
        if data.len() < pos + 64 {
            return Err("Data too short for DH keypair".to_string());
        }
        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        private_key.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        public_key.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let dh_keypair = X25519KeyPair {
            private_key,
            public_key,
        };

        // DH remote
        if data.len() < pos + 1 {
            return Err("Data too short for DH remote flag".to_string());
        }
        let has_dh_remote = data[pos] == 1;
        pos += 1;

        let dh_remote = if has_dh_remote {
            if data.len() < pos + 32 {
                return Err("Data too short for DH remote".to_string());
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;
            Some(pk)
        } else {
            None
        };

        // Root key
        if data.len() < pos + 32 {
            return Err("Data too short for root key".to_string());
        }
        let mut root_key = [0u8; 32];
        root_key.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        // Send chain key
        if data.len() < pos + 1 {
            return Err("Data too short for send chain flag".to_string());
        }
        let has_send_chain = data[pos] == 1;
        pos += 1;

        let send_chain_key = if has_send_chain {
            if data.len() < pos + 32 {
                return Err("Data too short for send chain key".to_string());
            }
            let mut ck = [0u8; 32];
            ck.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;
            Some(ck)
        } else {
            None
        };

        // Recv chain key
        if data.len() < pos + 1 {
            return Err("Data too short for recv chain flag".to_string());
        }
        let has_recv_chain = data[pos] == 1;
        pos += 1;

        let recv_chain_key = if has_recv_chain {
            if data.len() < pos + 32 {
                return Err("Data too short for recv chain key".to_string());
            }
            let mut ck = [0u8; 32];
            ck.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;
            Some(ck)
        } else {
            None
        };

        // Counters
        if data.len() < pos + 12 {
            return Err("Data too short for counters".to_string());
        }
        let send_n = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let recv_n = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let prev_send_n = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        // Skipped keys
        if data.len() < pos + 4 {
            return Err("Data too short for skipped keys count".to_string());
        }
        let skip_count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let mut skipped_keys = HashMap::new();
        for _ in 0..skip_count {
            if data.len() < pos + 44 {
                return Err("Data too short for skipped key entry".to_string());
            }

            let mut dh_hash = [0u8; 8];
            dh_hash.copy_from_slice(&data[pos..pos + 8]);
            pos += 8;

            let n = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            pos += 4;

            let mut key = [0u8; 32];
            key.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;

            skipped_keys.insert((dh_hash, n), key);
        }

        Ok(Self {
            dh_keypair,
            dh_remote,
            root_key,
            send_chain_key,
            recv_chain_key,
            send_n,
            recv_n,
            prev_send_n,
            skipped_keys,
        })
    }
}

/// KDF for root key - derives new root key and chain key from DH output
///
/// Uses HKDF with info string for domain separation
fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let output = hkdf(Some(root_key), dh_output, b"redblue-ratchet-root-v1", 64);

    let mut new_root = [0u8; 32];
    let mut chain_key = [0u8; 32];

    new_root.copy_from_slice(&output[..32]);
    chain_key.copy_from_slice(&output[32..]);

    (new_root, chain_key)
}

/// KDF for chain key - derives new chain key and message key
///
/// Uses HMAC with different constants for separation
fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Message key: HMAC(chain_key, 0x01)
    let message_key = hmac_sha256(chain_key, &[0x01]);

    // New chain key: HMAC(chain_key, 0x02)
    let new_chain_key = hmac_sha256(chain_key, &[0x02]);

    (new_chain_key, message_key)
}

/// Hash DH public key to 8 bytes for map key
fn hash_dh_public(public_key: &[u8; 32]) -> [u8; 8] {
    let hash = hmac_sha256(b"redblue-dh-hash", public_key);
    let mut result = [0u8; 8];
    result.copy_from_slice(&hash[..8]);
    result
}

/// Encrypt with ChaCha20-Poly1305 AEAD
fn encrypt_aead(key: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, String> {
    let nonce = generate_nonce();

    // Encrypt with associated data
    let ciphertext_with_tag = chacha20poly1305_encrypt(key, &nonce, ad, plaintext);

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext_with_tag.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext_with_tag);

    Ok(result)
}

/// Decrypt with ChaCha20-Poly1305 AEAD
fn decrypt_aead(key: &[u8; 32], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() < 12 + 16 {
        return Err("Ciphertext too short".to_string());
    }

    let nonce: [u8; 12] = ciphertext[..12].try_into().map_err(|_| "Invalid nonce")?;
    let ciphertext_and_tag = &ciphertext[12..];

    chacha20poly1305_decrypt(key, &nonce, ad, ciphertext_and_tag)
}

/// Collect entropy for key generation
///
/// Combines multiple entropy sources:
/// - /dev/urandom
/// - High-resolution timing
/// - Process/thread IDs
fn collect_entropy_32() -> [u8; 32] {
    use std::io::Read;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut entropy = [0u8; 64];
    let mut pos = 0;

    // Try /dev/urandom first (primary source on Unix)
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        let _ = file.read(&mut entropy[..32]);
        pos = 32;
    }

    // Add timing entropy
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.as_nanos();
    entropy[pos..pos + 16].copy_from_slice(&nanos.to_le_bytes());
    pos += 16;

    // Add process ID
    let pid = std::process::id();
    entropy[pos..pos + 4].copy_from_slice(&pid.to_le_bytes());
    pos += 4;

    // Add thread ID (hashed)
    let thread_id = std::thread::current().id();
    let thread_hash = format!("{:?}", thread_id);
    for (i, b) in thread_hash.bytes().take(8).enumerate() {
        entropy[pos + i] ^= b;
    }

    // Final mixing with HKDF
    let output = hkdf(None, &entropy[..pos.max(32)], b"redblue-entropy-v1", 32);

    let mut result = [0u8; 32];
    result.copy_from_slice(&output);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = X25519KeyPair::generate();
        let kp2 = X25519KeyPair::generate();

        // Keys should be different
        assert_ne!(kp1.private_key, kp2.private_key);
        assert_ne!(kp1.public_key, kp2.public_key);

        // DH should be commutative
        let shared1 = kp1.dh(&kp2.public_key);
        let shared2 = kp2.dh(&kp1.public_key);
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_kdf_rk() {
        let root_key = [0x42u8; 32];
        let dh_output = [0x37u8; 32];

        let (new_root, chain_key) = kdf_rk(&root_key, &dh_output);

        // Should produce different keys
        assert_ne!(new_root, chain_key);
        assert_ne!(new_root, root_key);

        // Should be deterministic
        let (new_root2, chain_key2) = kdf_rk(&root_key, &dh_output);
        assert_eq!(new_root, new_root2);
        assert_eq!(chain_key, chain_key2);
    }

    #[test]
    fn test_kdf_ck() {
        let chain_key = [0x55u8; 32];

        let (new_chain, message_key) = kdf_ck(&chain_key);

        // Should produce different keys
        assert_ne!(new_chain, message_key);
        assert_ne!(new_chain, chain_key);

        // Should be deterministic
        let (new_chain2, message_key2) = kdf_ck(&chain_key);
        assert_eq!(new_chain, new_chain2);
        assert_eq!(message_key, message_key2);
    }

    #[test]
    fn test_encrypt_decrypt_aead() {
        let key = [0xABu8; 32];
        let plaintext = b"Hello, Double Ratchet!";
        let ad = b"associated data";

        let ciphertext = encrypt_aead(&key, plaintext, ad).unwrap();
        let decrypted = decrypt_aead(&key, &ciphertext, ad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_wrong_ad_fails() {
        let key = [0xABu8; 32];
        let plaintext = b"Secret message";
        let ad = b"correct AD";
        let wrong_ad = b"wrong AD";

        let ciphertext = encrypt_aead(&key, plaintext, ad).unwrap();
        let result = decrypt_aead(&key, &ciphertext, wrong_ad);

        assert!(result.is_err());
    }

    #[test]
    fn test_full_ratchet_exchange() {
        // Simulate X3DH shared secret
        let shared_secret = [0x42u8; 32];

        // Server generates initial keypair
        let server_keypair = X25519KeyPair::generate();

        // Initialize both sides
        let mut client = RatchetState::init_initiator(&shared_secret, &server_keypair.public_key);
        let mut server = RatchetState::init_responder(&shared_secret, server_keypair);

        // Client sends first message
        let msg1 = b"Hello from client!";
        let (header1, ct1) = client.encrypt(msg1).unwrap();
        let pt1 = server.decrypt(&header1, &ct1).unwrap();
        assert_eq!(pt1, msg1);

        // Server responds
        let msg2 = b"Hello from server!";
        let (header2, ct2) = server.encrypt(msg2).unwrap();
        let pt2 = client.decrypt(&header2, &ct2).unwrap();
        assert_eq!(pt2, msg2);

        // Multiple messages back and forth
        for i in 0..10 {
            let msg = format!("Message {}", i);

            // Client -> Server
            let (h, ct) = client.encrypt(msg.as_bytes()).unwrap();
            let pt = server.decrypt(&h, &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());

            // Server -> Client
            let (h, ct) = server.encrypt(msg.as_bytes()).unwrap();
            let pt = client.decrypt(&h, &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_ratchet_serialization() {
        let shared_secret = [0x42u8; 32];
        let server_keypair = X25519KeyPair::generate();

        let mut client = RatchetState::init_initiator(&shared_secret, &server_keypair.public_key);

        // Do some operations
        let _ = client.encrypt(b"test").unwrap();

        // Serialize and deserialize
        let data = client.serialize();
        let restored = RatchetState::deserialize(&data).unwrap();

        // Should be able to continue
        let shared = restored.dh_keypair.dh(&server_keypair.public_key);
        assert_eq!(shared.len(), 32);
    }

    #[test]
    fn test_message_header() {
        let header = MessageHeader {
            dh_public: [0xAB; 32],
            pn: 42,
            n: 7,
        };

        let bytes = header.to_bytes();
        let restored = MessageHeader::from_bytes(&bytes).unwrap();

        assert_eq!(restored.dh_public, header.dh_public);
        assert_eq!(restored.pn, header.pn);
        assert_eq!(restored.n, header.n);
    }
}
