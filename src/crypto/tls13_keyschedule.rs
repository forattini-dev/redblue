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

use super::hkdf::{derive_secret, hkdf_expand_label, hkdf_extract};
use super::sha256::sha256;

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
    /// Current secret (progresses: early → handshake → master)
    current_secret: [u8; 32],

    /// Client handshake traffic secret
    pub client_handshake_traffic_secret: Option<[u8; 32]>,

    /// Server handshake traffic secret
    pub server_handshake_traffic_secret: Option<[u8; 32]>,

    /// Client application traffic secret
    pub client_application_traffic_secret: Option<[u8; 32]>,

    /// Server application traffic secret
    pub server_application_traffic_secret: Option<[u8; 32]>,

    /// Handshake messages hash (transcript)
    handshake_hash: Vec<u8>,
}

impl Tls13KeySchedule {
    /// Create a new TLS 1.3 key schedule
    ///
    /// Initializes with Early Secret = HKDF-Extract(0, 0)
    pub fn new() -> Self {
        // RFC 8446 Section 7.1:
        // Early Secret = HKDF-Extract(salt=0, IKM=0)
        let zero_key = [0u8; 32];
        let early_secret = hkdf_extract(None, &zero_key);

        Self {
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

    /// Get current transcript hash
    fn get_transcript_hash(&self) -> [u8; 32] {
        sha256(&self.handshake_hash)
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
        // Derive-Secret for "derived"
        let empty_hash = sha256(&[]);
        let derived = derive_secret(&self.current_secret, b"derived", &empty_hash);

        // HKDF-Extract with shared secret
        let handshake_secret = hkdf_extract(Some(&derived), shared_secret);

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

        // Client handshake traffic secret
        let client_secret = derive_secret(
            &self.current_secret,
            b"c hs traffic",
            &transcript_hash,
        );

        // Server handshake traffic secret
        let server_secret = derive_secret(
            &self.current_secret,
            b"s hs traffic",
            &transcript_hash,
        );

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
        let empty_hash = sha256(&[]);
        let derived = derive_secret(&self.current_secret, b"derived", &empty_hash);

        // HKDF-Extract with zero
        let zero_key = [0u8; 32];
        let master_secret = hkdf_extract(Some(&derived), &zero_key);

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

        // Client application traffic secret
        let client_secret = derive_secret(
            &self.current_secret,
            b"c ap traffic",
            &transcript_hash,
        );

        // Server application traffic secret
        let server_secret = derive_secret(
            &self.current_secret,
            b"s ap traffic",
            &transcript_hash,
        );

        self.client_application_traffic_secret = Some(client_secret);
        self.server_application_traffic_secret = Some(server_secret);
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
        traffic_secret: &[u8; 32],
        key_length: u16,
        iv_length: u16,
    ) -> (Vec<u8>, Vec<u8>) {
        // RFC 8446 Section 7.3:
        // [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
        // [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)

        let write_key = hkdf_expand_label(traffic_secret, b"key", b"", key_length);
        let write_iv = hkdf_expand_label(traffic_secret, b"iv", b"", iv_length);

        (write_key, write_iv)
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
        base_key: &[u8; 32],
        transcript_hash: &[u8; 32],
    ) -> [u8; 32] {
        use super::hmac::hmac_sha256;

        // Derive finished key
        let finished_key_vec = hkdf_expand_label(base_key, b"finished", b"", 32);
        let mut finished_key = [0u8; 32];
        finished_key.copy_from_slice(&finished_key_vec);

        // Compute HMAC over transcript hash
        hmac_sha256(&finished_key, transcript_hash)
    }

    /// Get client handshake finished verify_data
    pub fn client_finished_verify_data(&self) -> [u8; 32] {
        let transcript_hash = self.get_transcript_hash();
        let base_key = self.client_handshake_traffic_secret
            .expect("Client handshake traffic secret not derived");

        Self::compute_finished_verify_data(&base_key, &transcript_hash)
    }

    /// Get server handshake finished verify_data
    pub fn server_finished_verify_data(&self) -> [u8; 32] {
        let transcript_hash = self.get_transcript_hash();
        let base_key = self.server_handshake_traffic_secret
            .expect("Server handshake traffic secret not derived");

        Self::compute_finished_verify_data(&base_key, &transcript_hash)
    }
}

impl Default for Tls13KeySchedule {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_schedule_initialization() {
        let ks = Tls13KeySchedule::new();

        // Should start with early secret (non-zero)
        assert_ne!(ks.current_secret, [0u8; 32]);

        // No traffic secrets yet
        assert!(ks.client_handshake_traffic_secret.is_none());
        assert!(ks.server_handshake_traffic_secret.is_none());
    }

    #[test]
    fn test_handshake_secret_derivation() {
        let mut ks = Tls13KeySchedule::new();
        let early_secret = ks.current_secret;

        // Derive handshake secret from shared secret
        let shared_secret = [0x42u8; 32];
        ks.derive_handshake_secret(&shared_secret);

        // Secret should have changed
        assert_ne!(ks.current_secret, early_secret);
        assert_ne!(ks.current_secret, [0u8; 32]);
    }

    #[test]
    fn test_handshake_traffic_secrets() {
        let mut ks = Tls13KeySchedule::new();

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
        assert_ne!(
            ks.client_handshake_traffic_secret.unwrap(),
            ks.server_handshake_traffic_secret.unwrap()
        );
    }

    #[test]
    fn test_master_secret_derivation() {
        let mut ks = Tls13KeySchedule::new();
        let shared_secret = [0x42u8; 32];

        ks.derive_handshake_secret(&shared_secret);
        let handshake_secret = ks.current_secret;

        ks.derive_master_secret();

        // Master secret should be different from handshake secret
        assert_ne!(ks.current_secret, handshake_secret);
        assert_ne!(ks.current_secret, [0u8; 32]);
    }

    #[test]
    fn test_application_traffic_secrets() {
        let mut ks = Tls13KeySchedule::new();

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
        assert_ne!(
            ks.client_application_traffic_secret.unwrap(),
            ks.server_application_traffic_secret.unwrap()
        );
    }

    #[test]
    fn test_traffic_keys_derivation() {
        let traffic_secret = [0x42u8; 32];

        // Derive keys for AES-256-GCM
        let (write_key, write_iv) = Tls13KeySchedule::derive_traffic_keys(
            &traffic_secret,
            32, // AES-256 key length
            12, // GCM IV length
        );

        assert_eq!(write_key.len(), 32);
        assert_eq!(write_iv.len(), 12);

        // Should be non-zero
        assert_ne!(write_key, vec![0u8; 32]);
        assert_ne!(write_iv, vec![0u8; 12]);
    }

    #[test]
    fn test_finished_verify_data() {
        let mut ks = Tls13KeySchedule::new();

        ks.add_to_transcript(b"ClientHello");
        ks.add_to_transcript(b"ServerHello");

        let shared_secret = [0x42u8; 32];
        ks.derive_handshake_secret(&shared_secret);
        ks.derive_handshake_traffic_secrets();

        // Compute finished verify data
        let client_verify = ks.client_finished_verify_data();
        let server_verify = ks.server_finished_verify_data();

        // Should be 32 bytes (SHA-256)
        assert_eq!(client_verify.len(), 32);
        assert_eq!(server_verify.len(), 32);

        // Should be different
        assert_ne!(client_verify, server_verify);

        // Should be deterministic
        let client_verify2 = ks.client_finished_verify_data();
        assert_eq!(client_verify, client_verify2);
    }

    #[test]
    fn test_transcript_hash() {
        let mut ks = Tls13KeySchedule::new();

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
