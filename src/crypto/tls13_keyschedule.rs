/// TLS 1.3 Key Schedule Implementation
/// RFC 8446 Section 7 - Cryptographic Computations
///
/// TLS 1.3 uses a single key schedule that derives all keys from two input secrets
/// using HKDF-Extract and Derive-Secret.
///
/// The key schedule produces:
/// - Early Secret (for 0-RTT)
/// - Handshake Secret (for handshake encryption)
/// - Master Secret (for application data)
/// - Traffic Secrets (client/server write keys)
///
/// ✅ ZERO DEPENDENCIES - Pure Rust implementation
/// Replaces: rustls key schedule, ring
use super::tls13_hash::Tls13HashAlgorithm;

/// TLS 1.3 Key Schedule State
///
/// Tracks the progression through the 7-stage key derivation:
/// 1. Early Secret
/// 2. Handshake Secret
/// 3. Master Secret
/// 4. Client Handshake Traffic Secret
/// 5. Server Handshake Traffic Secret
/// 6. Client Application Traffic Secret
/// 7. Server Application Traffic Secret
pub struct Tls13KeySchedule {
    /// Active hash algorithm (derived from negotiated cipher suite)
    hash_alg: Tls13HashAlgorithm,

    /// Current secret (progresses: early → handshake → master)
    current_secret: Vec<u8>,

    /// Client handshake traffic secret
    pub client_handshake_traffic_secret: Option<Vec<u8>>,

    /// Server handshake traffic secret
    pub server_handshake_traffic_secret: Option<Vec<u8>>,

    /// Client application traffic secret
    pub client_application_traffic_secret: Option<Vec<u8>>,

    /// Server application traffic secret
    pub server_application_traffic_secret: Option<Vec<u8>>,

    /// Handshake messages hash (transcript)
    handshake_hash: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub enum ApplicationTrafficDirection {
    Client,
    Server,
}

impl Tls13KeySchedule {
    /// Create a new TLS 1.3 key schedule with the specified hash algorithm
    ///
    /// Initializes with Early Secret = HKDF-Extract(0, PSK)
    /// For non-PSK mode, PSK = zeros(Hash.length) per RFC 8446 §7.1
    pub fn new(hash_alg: Tls13HashAlgorithm) -> Self {
        // RFC 8446 §7.1: PSK defaults to a string of Hash.length zeros
        let zero_psk = vec![0u8; hash_alg.hash_len()];
        let early_secret = hash_alg.hkdf_extract(None, &zero_psk);
        eprintln!("DEBUG: Early Secret: {:02x?}", early_secret);

        Self {
            hash_alg,
            current_secret: early_secret,
            client_handshake_traffic_secret: None,
            server_handshake_traffic_secret: None,
            client_application_traffic_secret: None,
            server_application_traffic_secret: None,
            handshake_hash: Vec::new(),
        }
    }

    /// Add handshake message to transcript
    pub fn add_to_transcript(&mut self, message: &[u8]) {
        self.handshake_hash.extend_from_slice(message);
    }

    /// Replace the transcript with the provided bytes
    pub fn set_transcript(&mut self, transcript: &[u8]) {
        self.handshake_hash.clear();
        self.handshake_hash.extend_from_slice(transcript);
    }

    /// Get current transcript hash
    fn get_transcript_hash(&self) -> Vec<u8> {
        self.hash_alg.hash(&self.handshake_hash)
    }

    /// Expose the current transcript hash (ClientHello..latest message)
    pub fn get_handshake_hash_value(&self) -> Vec<u8> {
        self.hash_alg.hash(&self.handshake_hash)
    }

    /// Expose the current secret for debugging / tracing purposes
    pub fn current_secret(&self) -> &[u8] {
        &self.current_secret
    }

    /// Derive handshake secret from shared secret (e.g., X25519 output)
    ///
    /// RFC 8446 Section 7.1:
    /// ```text
    ///             0
    ///             |
    ///             v
    ///   PSK ->  HKDF-Extract = Early Secret
    ///             |
    ///             +-----> Derive-Secret(., "ext binder" | "res binder", "")
    ///             |                     = binder_key
    ///             |
    ///             +-----> Derive-Secret(., "c e traffic", ClientHello)
    ///             |                     = client_early_traffic_secret
    ///             |
    ///             +-----> Derive-Secret(., "e exp master", ClientHello)
    ///             |                     = early_exporter_master_secret
    ///             v
    ///       Derive-Secret(., "derived", "")
    ///             |
    ///             v
    ///   (EC)DHE -> HKDF-Extract = Handshake Secret
    /// ```
    pub fn derive_handshake_secret(&mut self, shared_secret: &[u8; 32]) {
        let empty_hash = self.hash_alg.hash(&[]);
        let derived = self
            .hash_alg
            .derive_secret(&self.current_secret, b"derived", &empty_hash)
            .expect("Failed to derive handshake secret base");

        eprintln!("DEBUG: Derived Secret (for Handshake): {:02x?}", derived);

        let handshake_secret = self.hash_alg.hkdf_extract(Some(&derived), shared_secret);
        eprintln!("DEBUG: Handshake Secret: {:02x?}", handshake_secret);

        self.current_secret = handshake_secret;
    }

    /// Derive handshake traffic secrets
    ///
    /// RFC 8446 Section 7.1:
    /// ```text
    ///   Handshake Secret
    ///             |
    ///             +-----> Derive-Secret(., "c hs traffic",
    ///             |                     ClientHello...ServerHello)
    ///             |                     = client_handshake_traffic_secret
    ///             |
    ///             +-----> Derive-Secret(., "s hs traffic",
    ///             |                     ClientHello...ServerHello)
    ///             |                     = server_handshake_traffic_secret
    /// ```
    pub fn derive_handshake_traffic_secrets(&mut self) {
        let transcript_hash = self.get_transcript_hash();
        eprintln!("Handshake Transcript Hash: {:02x?}", transcript_hash);
        eprintln!("Full Transcript: {:02x?}", self.handshake_hash);

        // Debugging SHA256 consistency
        eprintln!(
            "DEBUG CHECK: SHA256(Transcript) calculated via self.hash_alg.hash: {:02x?}",
            transcript_hash
        );

        let direct_sha256 = crate::crypto::sha256::sha256(&self.handshake_hash);
        eprintln!(
            "DEBUG CHECK: SHA256(Transcript) calculated directly via crypto::sha256: {:02x?}",
            direct_sha256
        );

        let hello_hash = crate::crypto::sha256::sha256(b"Hello");
        eprintln!("DEBUG CHECK: SHA256(b\"Hello\"): {:02x?}", hello_hash);

        // Client handshake traffic secret
        let client_secret = self
            .hash_alg
            .derive_secret(&self.current_secret, b"c hs traffic", &transcript_hash)
            .expect("Failed to derive client handshake traffic secret");
        eprintln!("Derived Client Handshake Secret: {:02x?}", client_secret);

        // Server handshake traffic secret
        let server_secret = self
            .hash_alg
            .derive_secret(&self.current_secret, b"s hs traffic", &transcript_hash)
            .expect("Failed to derive server handshake traffic secret");
        eprintln!("Derived Server Handshake Secret: {:02x?}", server_secret);

        self.client_handshake_traffic_secret = Some(client_secret);
        self.server_handshake_traffic_secret = Some(server_secret);
    }

    /// Derive master secret
    ///
    /// RFC 8446 Section 7.1:
    /// ```text
    ///             v
    ///       Derive-Secret(., "derived", "")
    ///             |
    ///             v
    ///      0 -> HKDF-Extract = Master Secret
    /// ```
    pub fn derive_master_secret(&mut self) {
        // Derive-Secret for "derived"
        let empty_hash = self.hash_alg.hash(&[]);
        let derived = self
            .hash_alg
            .derive_secret(&self.current_secret, b"derived", &empty_hash)
            .expect("Failed to derive master secret base");

        // HKDF-Extract with zero
        let zero_block = vec![0u8; self.hash_alg.hash_len()];
        let master_secret = self.hash_alg.hkdf_extract(Some(&derived), &zero_block);

        self.current_secret = master_secret;
    }

    /// Derive application traffic secrets
    ///
    /// RFC 8446 Section 7.1:
    /// ```text
    ///   Master Secret
    ///             |
    ///             +-----> Derive-Secret(., "c ap traffic",
    ///             |                     ClientHello...server Finished)
    ///             |                     = client_application_traffic_secret_0
    ///             |
    ///             +-----> Derive-Secret(., "s ap traffic",
    ///             |                     ClientHello...server Finished)
    ///             |                     = server_application_traffic_secret_0
    ///             |
    ///             +-----> Derive-Secret(., "exp master",
    ///             |                     ClientHello...server Finished)
    ///             |                     = exporter_master_secret
    ///             |
    ///             +-----> Derive-Secret(., "res master",
    ///                                   ClientHello...client Finished)
    ///                                   = resumption_master_secret
    /// ```
    pub fn derive_application_traffic_secrets(&mut self) {
        let transcript_hash = self.get_transcript_hash();
        eprintln!("Application Transcript Hash: {:02x?}", transcript_hash);
        eprintln!(
            "Application Transcript Length: {}",
            self.handshake_hash.len()
        );
        eprintln!("Master Secret (current): {:02x?}", self.current_secret);

        // Client application traffic secret
        let client_secret = self
            .hash_alg
            .derive_secret(&self.current_secret, b"c ap traffic", &transcript_hash)
            .expect("Failed to derive client application traffic secret");

        // Server application traffic secret
        let server_secret = self
            .hash_alg
            .derive_secret(&self.current_secret, b"s ap traffic", &transcript_hash)
            .expect("Failed to derive server application traffic secret");

        eprintln!("Client Application Traffic Secret: {:02x?}", client_secret);
        eprintln!("Server Application Traffic Secret: {:02x?}", server_secret);

        self.client_application_traffic_secret = Some(client_secret.clone());
        self.server_application_traffic_secret = Some(server_secret.clone());
    }

    pub fn update_application_traffic_secret(
        &mut self,
        direction: ApplicationTrafficDirection,
    ) -> Result<Vec<u8>, String> {
        let target = match direction {
            ApplicationTrafficDirection::Client => self
                .client_application_traffic_secret
                .as_mut()
                .ok_or_else(|| "client application traffic secret missing".to_string())?,
            ApplicationTrafficDirection::Server => self
                .server_application_traffic_secret
                .as_mut()
                .ok_or_else(|| "server application traffic secret missing".to_string())?,
        };

        let new_secret = self
            .hash_alg
            .hkdf_expand_label(target, b"traffic upd", b"", self.hash_alg.hash_len())
            .map_err(|e| format!("failed to derive updated traffic secret: {}", e))?;

        *target = new_secret.clone();
        Ok(new_secret)
    }

    /// Peek at the next traffic secret without updating the current one.
    ///
    /// This is used for pre-deriving keys to handle remote KEY_UPDATE (RFC 9001 §6.2).
    /// Returns what the next traffic secret would be after an update.
    pub fn peek_next_traffic_secret(
        &self,
        direction: ApplicationTrafficDirection,
    ) -> Result<Vec<u8>, String> {
        let current = match direction {
            ApplicationTrafficDirection::Client => self
                .client_application_traffic_secret
                .as_ref()
                .ok_or_else(|| "client application traffic secret missing".to_string())?,
            ApplicationTrafficDirection::Server => self
                .server_application_traffic_secret
                .as_ref()
                .ok_or_else(|| "server application traffic secret missing".to_string())?,
        };

        self.hash_alg
            .hkdf_expand_label(current, b"traffic upd", b"", self.hash_alg.hash_len())
            .map_err(|e| format!("failed to peek next traffic secret: {}", e))
    }

    /// Derive traffic keys from a traffic secret
    ///
    /// Derives:
    /// - write_key (for encryption)
    /// - write_iv (for nonce construction)
    ///
    /// # Arguments
    /// * `traffic_secret` - Traffic secret (handshake or application)
    /// * `key_length` - Length of encryption key (16 for AES-128, 32 for AES-256/ChaCha20)
    /// * `iv_length` - Length of IV (12 for GCM/ChaCha20-Poly1305)
    pub fn derive_traffic_keys(
        &self,
        traffic_secret: &[u8],
        key_length: u16,
        iv_length: u16,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let write_key = self
            .hash_alg
            .hkdf_expand_label(traffic_secret, b"key", b"", key_length as usize)
            .map_err(|e| format!("Failed to derive traffic key: {}", e))?;
        let write_iv = self
            .hash_alg
            .hkdf_expand_label(traffic_secret, b"iv", b"", iv_length as usize)
            .map_err(|e| format!("Failed to derive traffic IV: {}", e))?;

        Ok((write_key, write_iv))
    }

    /// Compute Finished verify_data
    ///
    /// RFC 8446 Section 4.4.4:
    /// ```text
    /// finished_key =
    ///     HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    ///
    /// verify_data =
    ///     HMAC(finished_key, Transcript-Hash(Handshake Context))
    /// ```
    pub fn compute_finished_verify_data(
        &self,
        base_key: &[u8],
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, String> {
        let hash_len = self.hash_alg.hash_len();
        if base_key.len() != hash_len {
            return Err("Base key has unexpected length".to_string());
        }
        if transcript_hash.len() != hash_len {
            return Err("Transcript hash has unexpected length".to_string());
        }

        let finished_key = self
            .hash_alg
            .hkdf_expand_label(base_key, b"finished", b"", hash_len)
            .map_err(|e| format!("Failed to derive Finished key: {}", e))?;

        Ok(self.hash_alg.hmac(&finished_key, transcript_hash))
    }

    /// Get client handshake finished verify_data
    pub fn client_finished_verify_data(&self) -> Result<Vec<u8>, String> {
        let transcript_hash = self.get_transcript_hash();
        let base_key = self
            .client_handshake_traffic_secret
            .as_ref()
            .ok_or_else(|| "Client handshake traffic secret not derived".to_string())?;

        self.compute_finished_verify_data(base_key, &transcript_hash)
    }

    /// Get server handshake finished verify_data
    pub fn server_finished_verify_data(&self) -> Result<Vec<u8>, String> {
        let transcript_hash = self.get_transcript_hash();
        let base_key = self
            .server_handshake_traffic_secret
            .as_ref()
            .ok_or_else(|| "Server handshake traffic secret not derived".to_string())?;

        self.compute_finished_verify_data(base_key, &transcript_hash)
    }
}

impl Default for Tls13KeySchedule {
    fn default() -> Self {
        Self::new(Tls13HashAlgorithm::Sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_schedule_initialization() {
        let ks = Tls13KeySchedule::new(Tls13HashAlgorithm::Sha256);

        // Should start with early secret (non-zero)
        assert_ne!(ks.current_secret, vec![0u8; 32]);

        // No traffic secrets yet
        assert!(ks.client_handshake_traffic_secret.is_none());
        assert!(ks.server_handshake_traffic_secret.is_none());
    }

    #[test]
    fn test_handshake_secret_derivation() {
        let mut ks = Tls13KeySchedule::new(Tls13HashAlgorithm::Sha256);
        let early_secret = ks.current_secret.clone();

        // Derive handshake secret from shared secret
        let shared_secret = [0x42u8; 32];
        ks.derive_handshake_secret(&shared_secret);

        // Secret should have changed
        assert_ne!(ks.current_secret, early_secret);
        assert_ne!(ks.current_secret, vec![0u8; 32]);
    }

    #[test]
    fn test_handshake_traffic_secrets() {
        let mut ks = Tls13KeySchedule::new(Tls13HashAlgorithm::Sha256);

        // Add some handshake messages
        ks.add_to_transcript(b"ClientHello");
        ks.add_to_transcript(b"ServerHello");

        // Derive handshake secret
        let shared_secret = [0x42u8; 32];
        ks.derive_handshake_secret(&shared_secret);

        // Derive traffic secrets
        ks.derive_handshake_traffic_secrets();

        // Both secrets should be derived
        assert!(ks.client_handshake_traffic_secret.is_some());
        assert!(ks.server_handshake_traffic_secret.is_some());

        // Should be different
        let client = ks.client_handshake_traffic_secret.clone().unwrap();
        let server = ks.server_handshake_traffic_secret.clone().unwrap();
        assert_ne!(client, server);
    }

    #[test]
    fn test_master_secret_derivation() {
        let mut ks = Tls13KeySchedule::new(Tls13HashAlgorithm::Sha256);
        let shared_secret = [0x42u8; 32];

        ks.derive_handshake_secret(&shared_secret);
        let handshake_secret = ks.current_secret.clone();

        ks.derive_master_secret();

        // Master secret should be different from handshake secret
        assert_ne!(ks.current_secret, handshake_secret);
        assert_ne!(ks.current_secret, vec![0u8; 32]);
    }

    #[test]
    fn test_application_traffic_secrets() {
        let mut ks = Tls13KeySchedule::new(Tls13HashAlgorithm::Sha256);

        // Full handshake simulation
        ks.add_to_transcript(b"ClientHello");
        ks.add_to_transcript(b"ServerHello");

        let shared_secret = [0x42u8; 32];
        ks.derive_handshake_secret(&shared_secret);
        ks.derive_handshake_traffic_secrets();

        ks.add_to_transcript(b"ServerFinished");

        ks.derive_master_secret();
        ks.derive_application_traffic_secrets();

        // Both application secrets should be derived
        assert!(ks.client_application_traffic_secret.is_some());
        assert!(ks.server_application_traffic_secret.is_some());

        // Should be different
        let client = ks.client_application_traffic_secret.clone().unwrap();
        let server = ks.server_application_traffic_secret.clone().unwrap();
        assert_ne!(client, server);
    }

    #[test]
    fn test_traffic_keys_derivation() {
        let traffic_secret = [0x42u8; 32];
        let ks = Tls13KeySchedule::new(Tls13HashAlgorithm::Sha256);

        // Derive keys for AES-256-GCM
        let (write_key, write_iv) = ks
            .derive_traffic_keys(&traffic_secret, 32, 12)
            .expect("traffic key derivation failed");

        assert_eq!(write_key.len(), 32);
        assert_eq!(write_iv.len(), 12);

        // Should be non-zero
        assert_ne!(write_key, vec![0u8; 32]);
        assert_ne!(write_iv, vec![0u8; 12]);
    }

    #[test]
    fn test_finished_verify_data() {
        let mut ks = Tls13KeySchedule::new(Tls13HashAlgorithm::Sha256);

        ks.add_to_transcript(b"ClientHello");
        ks.add_to_transcript(b"ServerHello");

        let shared_secret = [0x42u8; 32];
        ks.derive_handshake_secret(&shared_secret);
        ks.derive_handshake_traffic_secrets();

        // Compute finished verify data
        let client_verify = ks
            .client_finished_verify_data()
            .expect("client finished computation failed");
        let server_verify = ks
            .server_finished_verify_data()
            .expect("server finished computation failed");

        // Should be 32 bytes (SHA-256)
        assert_eq!(client_verify.len(), 32);
        assert_eq!(server_verify.len(), 32);

        // Should be different
        assert_ne!(client_verify, server_verify);

        // Should be deterministic
        let client_verify2 = ks
            .client_finished_verify_data()
            .expect("client finished computation failed");
        assert_eq!(client_verify, client_verify2);
    }

    #[test]
    fn test_transcript_hash() {
        let mut ks = Tls13KeySchedule::new(Tls13HashAlgorithm::Sha256);

        ks.add_to_transcript(b"Message1");
        let hash1 = ks.get_transcript_hash();

        ks.add_to_transcript(b"Message2");
        let hash2 = ks.get_transcript_hash();

        // Hashes should be different
        assert_ne!(hash1, hash2);

        // Should be deterministic
        let hash2_again = ks.get_transcript_hash();
        assert_eq!(hash2, hash2_again);
    }
}
