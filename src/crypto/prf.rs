/// TLS PRF implementations
/// - TLS 1.0/1.1: MD5/SHA1 combined PRF (RFC 2246 / RFC 4346)
/// - TLS 1.2: HMAC-SHA256 / HMAC-SHA384 PRF (RFC 5246)
use super::hmac::{hmac_md5, hmac_sha1, hmac_sha256, hmac_sha384};

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

/// TLS 1.2 PRF with configurable hash (SHA-256 or SHA-384)
pub fn prf_tls12_with_hash(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    output_len: usize,
    hash: Tls12PrfAlgorithm,
) -> Vec<u8> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    match hash {
        Tls12PrfAlgorithm::Sha256 => p_sha256(secret, &label_seed, output_len),
        Tls12PrfAlgorithm::Sha384 => p_sha384(secret, &label_seed, output_len),
    }
}

/// TLS 1.0/1.1 PRF using MD5/SHA1 combination
pub fn prf_tls10(secret: &[u8], label: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    let half_len = secret.len().div_ceil(2);
    let s1 = &secret[..half_len];
    let s2 = &secret[secret.len() - half_len..];

    let md5_bytes = p_md5(s1, &label_seed, output_len);
    let sha1_bytes = p_sha1(s2, &label_seed, output_len);

    md5_bytes
        .iter()
        .zip(sha1_bytes.iter())
        .map(|(a, b)| a ^ b)
        .collect()
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

fn p_sha384(secret: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(output_len);
    let mut a = seed.to_vec(); // A(0) = seed

    while output.len() < output_len {
        a = hmac_sha384(secret, &a).to_vec();

        let mut a_seed = Vec::with_capacity(a.len() + seed.len());
        a_seed.extend_from_slice(&a);
        a_seed.extend_from_slice(seed);

        let chunk = hmac_sha384(secret, &a_seed);
        output.extend_from_slice(&chunk);
    }

    output.truncate(output_len);
    output
}

fn p_md5(secret: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(output_len);
    let mut a = seed.to_vec();

    while output.len() < output_len {
        a = hmac_md5(secret, &a).to_vec();

        let mut a_seed = Vec::with_capacity(a.len() + seed.len());
        a_seed.extend_from_slice(&a);
        a_seed.extend_from_slice(seed);

        let chunk = hmac_md5(secret, &a_seed);
        output.extend_from_slice(&chunk);
    }

    output.truncate(output_len);
    output
}

fn p_sha1(secret: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(output_len);
    let mut a = seed.to_vec();

    while output.len() < output_len {
        a = hmac_sha1(secret, &a).to_vec();

        let mut a_seed = Vec::with_capacity(a.len() + seed.len());
        a_seed.extend_from_slice(&a);
        a_seed.extend_from_slice(seed);

        let chunk = hmac_sha1(secret, &a_seed);
        output.extend_from_slice(&chunk);
    }

    output.truncate(output_len);
    output
}

/// Generate master secret from pre-master secret
/// master_secret = PRF(pre_master_secret, "master secret",
///                     ClientHello.random + ServerHello.random)[0..47]
pub fn derive_master_secret_tls12(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    derive_master_secret_tls12_with_hash(
        pre_master_secret,
        client_random,
        server_random,
        Tls12PrfAlgorithm::Sha256,
    )
}

/// Compatibility wrapper for legacy callers expecting TLS 1.2 semantics.
pub fn derive_master_secret(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    derive_master_secret_tls12(pre_master_secret, client_random, server_random)
}

pub fn derive_master_secret_tls12_with_hash(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    hash: Tls12PrfAlgorithm,
) -> [u8; 48] {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);

    let master_secret = prf_tls12_with_hash(pre_master_secret, b"master secret", &seed, 48, hash);

    let mut result = [0u8; 48];
    result.copy_from_slice(&master_secret);
    result
}

pub fn derive_master_secret_tls10(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);

    let master_secret = prf_tls10(pre_master_secret, b"master secret", &seed, 48);
    let mut result = [0u8; 48];
    result.copy_from_slice(&master_secret);
    result
}

/// Generate key material from master secret
/// key_block = PRF(master_secret, "key expansion",
///                 ServerHello.random + ClientHello.random)
pub fn derive_keys_tls12(
    master_secret: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    key_material_len: usize,
) -> Vec<u8> {
    derive_keys_tls12_with_hash(
        master_secret,
        server_random,
        client_random,
        key_material_len,
        Tls12PrfAlgorithm::Sha256,
    )
}

pub fn derive_keys_tls12_with_hash(
    master_secret: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    key_material_len: usize,
    hash: Tls12PrfAlgorithm,
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    prf_tls12_with_hash(
        master_secret,
        b"key expansion",
        &seed,
        key_material_len,
        hash,
    )
}

/// Compatibility wrapper for legacy callers expecting TLS 1.2 semantics.
pub fn derive_keys(
    master_secret: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    key_material_len: usize,
) -> Vec<u8> {
    derive_keys_tls12(
        master_secret,
        server_random,
        client_random,
        key_material_len,
    )
}

pub fn derive_keys_tls10(
    master_secret: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    key_material_len: usize,
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    prf_tls10(master_secret, b"key expansion", &seed, key_material_len)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tls12PrfAlgorithm {
    Sha256,
    Sha384,
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

        let master = derive_master_secret_tls12(&pre_master, &client_random, &server_random);
        assert_eq!(master.len(), 48);
        // Master secret should be deterministic
        let master2 = derive_master_secret_tls12(&pre_master, &client_random, &server_random);
        assert_eq!(master, master2);
    }

    #[test]
    fn test_key_derivation() {
        let master_secret = [0x42; 48];
        let server_random = [0x01; 32];
        let client_random = [0x02; 32];

        let keys = derive_keys_tls12(&master_secret, &server_random, &client_random, 104);
        assert_eq!(keys.len(), 104);
        // Keys should be deterministic
        let keys2 = derive_keys_tls12(&master_secret, &server_random, &client_random, 104);
        assert_eq!(keys, keys2);
    }

    #[test]
    fn test_prf_tls12_sha384() {
        let pre_master = [0x10u8; 48];
        let client_random = [0xAA; 32];
        let server_random = [0xBB; 32];

        let master_sha384 = derive_master_secret_tls12_with_hash(
            &pre_master,
            &client_random,
            &server_random,
            Tls12PrfAlgorithm::Sha384,
        );
        assert_eq!(master_sha384.len(), 48);

        let keys_sha384 = derive_keys_tls12_with_hash(
            &master_sha384,
            &server_random,
            &client_random,
            64,
            Tls12PrfAlgorithm::Sha384,
        );
        assert_eq!(keys_sha384.len(), 64);

        // Deterministic output
        let keys_sha384_repeat = derive_keys_tls12_with_hash(
            &master_sha384,
            &server_random,
            &client_random,
            64,
            Tls12PrfAlgorithm::Sha384,
        );
        assert_eq!(keys_sha384, keys_sha384_repeat);
    }

    #[test]
    fn test_prf_tls10_basic() {
        let secret = b"secret";
        let label = b"label";
        let seed = b"seed";
        let output = prf_tls10(secret, label, seed, 48);
        assert_eq!(output.len(), 48);
    }

    #[test]
    fn test_tls10_master_secret() {
        let pre_master = [0x03, 0x01];
        let client_random = [0x11; 32];
        let server_random = [0x22; 32];

        let master = derive_master_secret_tls10(&pre_master, &client_random, &server_random);
        assert_eq!(master.len(), 48);
        let again = derive_master_secret_tls10(&pre_master, &client_random, &server_random);
        assert_eq!(master, again);
    }
}
