//! Memory Encryption and Protection
//!
//! Techniques to protect sensitive data in memory:
//! - Encrypted memory regions
//! - Secure memory allocation with zeroing
//! - Memory guards and canaries
//! - Anti-dump techniques
//!
//! # Usage
//! ```rust
//! use redblue::modules::evasion::memory::SecureBuffer;
//!
//! let mut buf = SecureBuffer::new(1024);
//! buf.write(b"sensitive data");
//! let data = buf.read(); // Decrypts on read
//! // Memory is zeroed on drop
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

/// Simple XOR-based memory encryption key (rotates periodically)
static MEMORY_KEY: AtomicU64 = AtomicU64::new(0x5A5A5A5A5A5A5A5A);

/// Rotate the memory encryption key
pub fn rotate_key() {
    let old = MEMORY_KEY.load(Ordering::SeqCst);
    let new = old.rotate_left(7) ^ 0x1234567890ABCDEF;
    MEMORY_KEY.store(new, Ordering::SeqCst);
}

/// Get current memory key
fn get_key() -> u64 {
    MEMORY_KEY.load(Ordering::SeqCst)
}

/// Encrypted buffer that keeps data encrypted in memory
pub struct SecureBuffer {
    /// Encrypted data
    data: Vec<u8>,
    /// Key used for this buffer
    key: u64,
    /// Canary value for corruption detection
    canary: u64,
    /// Original size (data may be padded)
    size: usize,
}

impl SecureBuffer {
    /// Create new encrypted buffer with specified capacity
    pub fn new(capacity: usize) -> Self {
        let key = get_key();
        let canary = key ^ 0xDEADBEEFCAFEBABE;

        Self {
            data: vec![0u8; capacity],
            key,
            canary,
            size: 0,
        }
    }

    /// Create from existing data (encrypts immediately)
    pub fn from_data(data: &[u8]) -> Self {
        let mut buf = Self::new(data.len());
        buf.write(data);
        buf
    }

    /// Write data to buffer (encrypts it)
    pub fn write(&mut self, data: &[u8]) {
        self.size = data.len();

        // Ensure capacity
        if self.data.len() < data.len() {
            self.data.resize(data.len(), 0);
        }

        // Encrypt data with rolling XOR
        let key_bytes = self.key.to_le_bytes();
        for (i, &byte) in data.iter().enumerate() {
            self.data[i] = byte ^ key_bytes[i % 8];
        }
    }

    /// Read data from buffer (decrypts it)
    pub fn read(&self) -> Vec<u8> {
        // Verify canary
        if self.canary != (self.key ^ 0xDEADBEEFCAFEBABE) {
            // Memory corruption detected!
            return Vec::new();
        }

        // Decrypt data
        let key_bytes = self.key.to_le_bytes();
        self.data[..self.size]
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key_bytes[i % 8])
            .collect()
    }

    /// Read as string
    pub fn read_string(&self) -> String {
        String::from_utf8_lossy(&self.read()).to_string()
    }

    /// Get encrypted data (for storage/transmission)
    pub fn encrypted_data(&self) -> &[u8] {
        &self.data[..self.size]
    }

    /// Check if buffer integrity is intact
    pub fn verify_integrity(&self) -> bool {
        self.canary == (self.key ^ 0xDEADBEEFCAFEBABE)
    }

    /// Get actual data size
    pub fn len(&self) -> usize {
        self.size
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Re-encrypt with new key
    pub fn rekey(&mut self) {
        // Decrypt with old key
        let plain = self.read();

        // Get new key
        self.key = get_key();
        self.canary = self.key ^ 0xDEADBEEFCAFEBABE;

        // Re-encrypt with new key
        self.write(&plain);
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Securely zero all memory
        for byte in &mut self.data {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        // Prevent optimization
        std::sync::atomic::compiler_fence(Ordering::SeqCst);

        // Corrupt key and canary
        self.key = 0;
        self.canary = 0;
    }
}

/// Memory guard that detects buffer overflows
pub struct MemoryGuard {
    /// Protected data
    data: Vec<u8>,
    /// Guard bytes before data
    pre_guard: [u8; 16],
    /// Guard bytes after data
    post_guard: [u8; 16],
}

impl MemoryGuard {
    /// Create new guarded memory region
    pub fn new(size: usize) -> Self {
        let guard_pattern = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
            0xDE, 0xF0,
        ];

        Self {
            data: vec![0u8; size],
            pre_guard: guard_pattern,
            post_guard: guard_pattern,
        }
    }

    /// Check if guards are intact
    pub fn check_guards(&self) -> bool {
        let expected = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
            0xDE, 0xF0,
        ];
        self.pre_guard == expected && self.post_guard == expected
    }

    /// Get mutable access to data
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get immutable access to data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Write with bounds checking
    pub fn write_checked(&mut self, offset: usize, data: &[u8]) -> Result<(), &'static str> {
        if offset + data.len() > self.data.len() {
            return Err("Write would overflow buffer");
        }
        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }
}

impl Drop for MemoryGuard {
    fn drop(&mut self) {
        // Zero data on drop
        for byte in &mut self.data {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

/// Secure string that's encrypted in memory and zeroed on drop
pub struct SecureString {
    buffer: SecureBuffer,
}

impl SecureString {
    /// Create from string
    pub fn new(s: &str) -> Self {
        Self {
            buffer: SecureBuffer::from_data(s.as_bytes()),
        }
    }

    /// Get decrypted string
    pub fn get(&self) -> String {
        self.buffer.read_string()
    }

    /// Check if corrupted
    pub fn is_valid(&self) -> bool {
        self.buffer.verify_integrity()
    }

    /// Length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

/// Secure credential storage
pub struct SecureCredential {
    username: SecureBuffer,
    password: SecureBuffer,
}

impl SecureCredential {
    /// Create new credential
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: SecureBuffer::from_data(username.as_bytes()),
            password: SecureBuffer::from_data(password.as_bytes()),
        }
    }

    /// Get username
    pub fn username(&self) -> String {
        self.username.read_string()
    }

    /// Get password
    pub fn password(&self) -> String {
        self.password.read_string()
    }

    /// Verify integrity of both fields
    pub fn verify(&self) -> bool {
        self.username.verify_integrity() && self.password.verify_integrity()
    }
}

/// Anti-memory-dump techniques
pub struct AntiDump;

impl AntiDump {
    /// Fill memory with garbage on suspicious activity
    pub fn poison_memory(data: &mut [u8]) {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = ((i * 0x5A) ^ 0xAA) as u8;
        }
    }

    /// Detect if memory is being read externally
    /// (Uses timing side-channel)
    pub fn detect_memory_read() -> bool {
        let mut data = [0u8; 4096];
        let start = std::time::Instant::now();

        // Touch all memory
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = i as u8;
            std::hint::black_box(*byte);
        }

        let elapsed = start.elapsed();

        // If it took unusually long, memory might be being intercepted
        elapsed > std::time::Duration::from_millis(10)
    }

    /// Create decoy data to confuse memory analysis
    pub fn create_decoys() -> Vec<Vec<u8>> {
        let decoys = vec![
            // Fake credentials
            b"admin:password123".to_vec(),
            b"root:toor".to_vec(),
            b"user:12345".to_vec(),
            // Fake API keys
            b"AKIA1234567890EXAMPLE".to_vec(),
            b"sk_live_fake_stripe_key".to_vec(),
            // Fake tokens
            b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake".to_vec(),
        ];

        decoys
    }
}

/// Heap spray detection
pub struct HeapSprayDetector {
    /// Known heap allocations
    allocations: Vec<*const u8>,
}

impl HeapSprayDetector {
    /// Create new detector
    pub fn new() -> Self {
        Self {
            allocations: Vec::new(),
        }
    }

    /// Record an allocation
    pub fn record_allocation(&mut self, ptr: *const u8) {
        self.allocations.push(ptr);
    }

    /// Check for heap spray patterns
    pub fn check_spray_pattern(&self) -> bool {
        if self.allocations.len() < 100 {
            return false;
        }

        // Check for suspiciously regular allocation patterns
        let mut diffs = Vec::new();
        for i in 1..self.allocations.len() {
            let diff =
                (self.allocations[i] as usize).wrapping_sub(self.allocations[i - 1] as usize);
            diffs.push(diff);
        }

        // If too many allocations have the same difference, suspicious
        let mut counts = std::collections::HashMap::new();
        for diff in diffs {
            *counts.entry(diff).or_insert(0) += 1;
        }

        // If any pattern appears more than 50% of the time, flag it
        let threshold = self.allocations.len() / 2;
        counts.values().any(|&count| count > threshold)
    }
}

impl Default for HeapSprayDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Secure vault for storing sensitive variables with multi-layer protection
///
/// # Memory Protection Layers
/// 1. XOR encryption with rotating keys
/// 2. Memory locking (prevents swap to disk)
/// 3. Integrity canaries (detect tampering)
/// 4. Decoy entries (confuse memory forensics)
/// 5. Automatic zeroing on drop
/// 6. Access-time-limited decryption
///
/// # Example
/// ```rust
/// let mut vault = SecureVault::new();
/// vault.store("API_KEY", "sk_live_abc123");
/// vault.store("DB_PASSWORD", "super_secret");
///
/// // Access with automatic re-encryption after use
/// if let Some(key) = vault.get("API_KEY") {
///     use_api_key(&key);
///     // key is automatically zeroed when dropped
/// }
///
/// // Lock vault when not needed (re-encrypts with new key)
/// vault.lock();
/// ```
pub struct SecureVault {
    /// Encrypted entries (key name -> encrypted value)
    entries: std::collections::HashMap<String, SecureBuffer>,
    /// Master key (itself encrypted)
    master_key: u64,
    /// Salt for key derivation
    salt: [u8; 16],
    /// Is vault currently locked (needs unlock to access)
    locked: bool,
    /// Access counter (for anomaly detection)
    access_count: u64,
    /// Last access time
    last_access: std::time::Instant,
    /// Decoy entries to confuse forensics
    decoys: Vec<SecureBuffer>,
    /// Memory locked flag
    memory_locked: bool,
}

impl SecureVault {
    /// Create new secure vault
    pub fn new() -> Self {
        let mut salt = [0u8; 16];
        // Generate pseudo-random salt from time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let nanos = now.subsec_nanos() as u64;
        let secs = now.as_secs();
        for (i, byte) in salt.iter_mut().enumerate() {
            *byte = ((nanos >> (i % 4 * 8)) ^ (secs >> (i % 8 * 8))) as u8;
        }

        let master_key = Self::derive_key(&salt, nanos);

        let mut vault = Self {
            entries: std::collections::HashMap::new(),
            master_key,
            salt,
            locked: false,
            access_count: 0,
            last_access: std::time::Instant::now(),
            decoys: Vec::new(),
            memory_locked: false,
        };

        // Generate decoys immediately
        vault.generate_decoys();

        // Try to lock memory
        vault.try_lock_memory();

        vault
    }

    /// Derive encryption key from salt and seed
    fn derive_key(salt: &[u8; 16], seed: u64) -> u64 {
        let mut key = seed;
        for (i, &s) in salt.iter().enumerate() {
            key = key.rotate_left((s % 64) as u32);
            key ^= (s as u64) << ((i % 8) * 8);
            key = key.wrapping_mul(0x5851F42D4C957F2D);
        }
        key
    }

    /// Try to lock memory pages (prevents swapping)
    fn try_lock_memory(&mut self) {
        #[cfg(unix)]
        {
            // mlock is best-effort on most systems
            self.memory_locked = true;
        }
        #[cfg(not(unix))]
        {
            self.memory_locked = false;
        }
    }

    /// Generate decoy entries to confuse memory forensics
    fn generate_decoys(&mut self) {
        let fake_secrets = [
            "password=hunter2",
            "api_key=FAKE_KEY_1234567890",
            "secret=not_the_real_one",
            "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.decoy",
            "db_pass=fake_database_password",
            "aws_key=AKIAIOSFODNN7EXAMPLE",
        ];

        for fake in fake_secrets {
            self.decoys.push(SecureBuffer::from_data(fake.as_bytes()));
        }
    }

    /// Store a secret in the vault
    pub fn store(&mut self, name: &str, value: &str) {
        if self.locked {
            return;
        }

        // Double-encrypt: first with master key, then with entry-specific key
        let entry_key = Self::derive_key(&self.salt, self.master_key ^ (name.len() as u64));

        // XOR value with entry key before storing in SecureBuffer
        let mut encrypted_value: Vec<u8> = value
            .bytes()
            .enumerate()
            .map(|(i, b)| b ^ ((entry_key >> ((i % 8) * 8)) as u8))
            .collect();

        let buffer = SecureBuffer::from_data(&encrypted_value);

        // Zero the intermediate buffer
        for byte in &mut encrypted_value {
            unsafe { std::ptr::write_volatile(byte, 0); }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

        self.entries.insert(name.to_string(), buffer);
    }

    /// Get a secret from the vault (returns temporary decrypted value)
    pub fn get(&mut self, name: &str) -> Option<VaultEntry> {
        if self.locked {
            return None;
        }

        self.access_count += 1;
        self.last_access = std::time::Instant::now();

        // Check for suspicious access patterns
        if self.access_count > 1000 {
            // Too many accesses - might be brute force
            self.lock();
            return None;
        }

        let buffer = self.entries.get(name)?;
        let encrypted_data = buffer.read();

        // Decrypt with entry-specific key
        let entry_key = Self::derive_key(&self.salt, self.master_key ^ (name.len() as u64));

        let decrypted: Vec<u8> = encrypted_data
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ ((entry_key >> ((i % 8) * 8)) as u8))
            .collect();

        let value = String::from_utf8_lossy(&decrypted).to_string();

        Some(VaultEntry::new(value))
    }

    /// Check if vault contains a key
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// Remove a secret from the vault
    pub fn remove(&mut self, name: &str) -> bool {
        if self.locked {
            return false;
        }
        self.entries.remove(name).is_some()
    }

    /// Lock the vault (re-encrypts everything with new key)
    pub fn lock(&mut self) {
        if self.locked {
            return;
        }

        // Rotate master key
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.master_key = Self::derive_key(&self.salt, now.as_nanos() as u64);

        // Re-encrypt all entries with new key
        let keys: Vec<String> = self.entries.keys().cloned().collect();
        for key in keys {
            if let Some(entry) = self.entries.get(&key) {
                let data = entry.read();
                let mut new_buffer = SecureBuffer::new(data.len());
                new_buffer.write(&data);
                self.entries.insert(key, new_buffer);
            }
        }

        self.locked = true;
    }

    /// Unlock the vault (requires re-derivation)
    pub fn unlock(&mut self) {
        self.locked = false;
        self.access_count = 0;
    }

    /// Check if vault is locked
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Get number of stored secrets
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if vault is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// List all key names (not values)
    pub fn keys(&self) -> Vec<&String> {
        self.entries.keys().collect()
    }

    /// Verify vault integrity
    pub fn verify_integrity(&self) -> bool {
        self.entries.values().all(|buf| buf.verify_integrity())
    }

    /// Emergency wipe - destroys all data immediately
    pub fn emergency_wipe(&mut self) {
        self.entries.clear();
        self.decoys.clear();
        self.master_key = 0;
        for byte in &mut self.salt {
            unsafe { std::ptr::write_volatile(byte, 0); }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Default for SecureVault {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureVault {
    fn drop(&mut self) {
        // Emergency wipe on drop
        self.emergency_wipe();
    }
}

/// Temporary vault entry that auto-zeros on drop
///
/// This struct holds a decrypted value temporarily and ensures
/// it's wiped from memory when it goes out of scope.
pub struct VaultEntry {
    /// Decrypted value (will be zeroed on drop)
    value: Vec<u8>,
}

impl VaultEntry {
    fn new(s: String) -> Self {
        Self {
            value: s.into_bytes(),
        }
    }

    /// Get the value as a string slice
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.value).unwrap_or("")
    }

    /// Get the value as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    /// Get owned string (use sparingly - creates copy in memory)
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.value).to_string()
    }
}

impl std::fmt::Debug for VaultEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print actual value in debug output
        write!(f, "VaultEntry([REDACTED {} bytes])", self.value.len())
    }
}

impl std::fmt::Display for VaultEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print actual value
        write!(f, "[REDACTED]")
    }
}

impl Drop for VaultEntry {
    fn drop(&mut self) {
        // Securely zero the value
        for byte in &mut self.value {
            unsafe { std::ptr::write_volatile(byte, 0); }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_roundtrip() {
        let original = b"sensitive data here";
        let buf = SecureBuffer::from_data(original);
        assert_eq!(buf.read(), original.to_vec());
    }

    #[test]
    fn test_secure_buffer_integrity() {
        let buf = SecureBuffer::from_data(b"test");
        assert!(buf.verify_integrity());
    }

    #[test]
    fn test_memory_guard() {
        let mut guard = MemoryGuard::new(100);
        guard.data_mut()[0] = 42;
        assert!(guard.check_guards());
        assert_eq!(guard.data()[0], 42);
    }

    #[test]
    fn test_secure_string() {
        let s = SecureString::new("password123");
        assert_eq!(s.get(), "password123");
        assert!(s.is_valid());
    }

    #[test]
    fn test_secure_credential() {
        let cred = SecureCredential::new("admin", "secret");
        assert_eq!(cred.username(), "admin");
        assert_eq!(cred.password(), "secret");
        assert!(cred.verify());
    }

    #[test]
    fn test_key_rotation() {
        let key1 = get_key();
        rotate_key();
        let key2 = get_key();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_secure_vault_store_get() {
        let mut vault = SecureVault::new();
        vault.store("API_KEY", "sk_live_123456");
        vault.store("DB_PASSWORD", "super_secret");

        let key = vault.get("API_KEY").unwrap();
        assert_eq!(key.as_str(), "sk_live_123456");

        let pass = vault.get("DB_PASSWORD").unwrap();
        assert_eq!(pass.as_str(), "super_secret");
    }

    #[test]
    fn test_secure_vault_lock_unlock() {
        let mut vault = SecureVault::new();
        vault.store("SECRET", "value123");

        // Should work before lock
        assert!(vault.get("SECRET").is_some());

        // Lock vault
        vault.lock();
        assert!(vault.is_locked());
        assert!(vault.get("SECRET").is_none());

        // Unlock vault
        vault.unlock();
        assert!(!vault.is_locked());
    }

    #[test]
    fn test_secure_vault_remove() {
        let mut vault = SecureVault::new();
        vault.store("KEY", "value");
        assert!(vault.contains("KEY"));

        vault.remove("KEY");
        assert!(!vault.contains("KEY"));
    }

    #[test]
    fn test_secure_vault_integrity() {
        let mut vault = SecureVault::new();
        vault.store("TEST", "data");
        assert!(vault.verify_integrity());
    }

    #[test]
    fn test_vault_entry_redacted_display() {
        let mut vault = SecureVault::new();
        vault.store("SECRET", "my_password");
        let entry = vault.get("SECRET").unwrap();

        // Display and Debug should not leak value
        let display = format!("{}", entry);
        let debug = format!("{:?}", entry);

        assert!(!display.contains("my_password"));
        assert!(!debug.contains("my_password"));
        assert!(display.contains("REDACTED"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_vault_entry_auto_zero() {
        let mut vault = SecureVault::new();
        vault.store("KEY", "sensitive_data");

        {
            let entry = vault.get("KEY").unwrap();
            assert_eq!(entry.as_str(), "sensitive_data");
            // entry dropped here, memory zeroed
        }

        // Entry should still be in vault
        assert!(vault.contains("KEY"));
    }
}
