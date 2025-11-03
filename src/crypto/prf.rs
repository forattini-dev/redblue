/// TLS 1.2 PRF (Pseudo-Random Function)
/// RFC 5246 Section 5 - HMAC and the Pseudorandom Function
///
/// PRF(secret, label, seed) = P_SHA256(secret, label + seed)
use super::hmac::hmac_sha256;

/// TLS 1.2 PRF using HMAC-SHA256
/// Generates arbitrary-length output from a secret, label, and seed
pub fn prf_tls12(secret: &[u8], label: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    // Concatenate label + seed
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    // P_hash expansion
    p_sha256(secret, &label_seed, output_len)
}

/// P_SHA256 - Expansion function
/// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
///                        HMAC_hash(secret, A(2) + seed) +
///                        HMAC_hash(secret, A(3) + seed) + ...
///
/// Where:
///   A(0) = seed
///   A(i) = HMAC_hash(secret, A(i-1))
fn p_sha256(secret: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(output_len);
    let mut a = seed.to_vec(); // A(0) = seed

    while output.len() < output_len {
        // A(i) = HMAC(secret, A(i-1))
        a = hmac_sha256(secret, &a).to_vec();

        // Concatenate A(i) + seed
        let mut a_seed = Vec::with_capacity(a.len() + seed.len());
        a_seed.extend_from_slice(&a);
        a_seed.extend_from_slice(seed);

        // HMAC(secret, A(i) + seed)
        let chunk = hmac_sha256(secret, &a_seed);
        output.extend_from_slice(&chunk);
    }

    // Truncate to requested length
    output.truncate(output_len);
    output
}

/// Generate master secret from pre-master secret
/// master_secret = PRF(pre_master_secret, "master secret",
///                     ClientHello.random + ServerHello.random)[0..47]
pub fn derive_master_secret(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);

    let master_secret = prf_tls12(pre_master_secret, b"master secret", &seed, 48);

    let mut result = [0u8; 48];
    result.copy_from_slice(&master_secret);
    result
}

/// Generate key material from master secret
/// key_block = PRF(master_secret, "key expansion",
///                 ServerHello.random + ClientHello.random)
pub fn derive_keys(
    master_secret: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    key_material_len: usize,
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    prf_tls12(master_secret, b"key expansion", &seed, key_material_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_basic() {
        let secret = b"secret";
        let label = b"label";
        let seed = b"seed";
        let output = prf_tls12(secret, label, seed, 100);
        assert_eq!(output.len(), 100);
    }

    #[test]
    fn test_master_secret_derivation() {
        let pre_master = [0x03, 0x03]; // Simplified 2-byte pre-master for testing
        let client_random = [0x01; 32];
        let server_random = [0x02; 32];

        let master = derive_master_secret(&pre_master, &client_random, &server_random);
        assert_eq!(master.len(), 48);
        // Master secret should be deterministic
        let master2 = derive_master_secret(&pre_master, &client_random, &server_random);
        assert_eq!(master, master2);
    }

    #[test]
    fn test_key_derivation() {
        let master_secret = [0x42; 48];
        let server_random = [0x01; 32];
        let client_random = [0x02; 32];

        let keys = derive_keys(&master_secret, &server_random, &client_random, 104);
        assert_eq!(keys.len(), 104);
        // Keys should be deterministic
        let keys2 = derive_keys(&master_secret, &server_random, &client_random, 104);
        assert_eq!(keys, keys2);
    }
}
