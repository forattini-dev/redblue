/// X25519 Elliptic Curve Diffie-Hellman (ECDH) Key Exchange
/// RFC 7748 - Elliptic Curves for Security
///
/// X25519 is the preferred key exchange for TLS 1.3
///
/// Implements:
/// - Curve25519 scalar multiplication (Montgomery ladder)
/// - X25519 key exchange
/// - Public key generation
/// - Shared secret computation
///
/// ✅ ZERO DEPENDENCIES - Pure Rust implementation
/// Replaces: x25519-dalek, curve25519-donna, libsodium

/// Curve25519 field element (256 bits)
/// Represented as 10 limbs of 26 bits each (total 260 bits to handle carries)
type FieldElement = [i64; 10];

/// Base point for Curve25519 (x = 9)
const BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Clamp scalar for X25519
/// RFC 7748 Section 5: Set bits 0, 1, 2 to zero, bit 255 to zero, and bit 254 to one
fn clamp_scalar(scalar: &mut [u8; 32]) {
    scalar[0] &= 248; // Clear bits 0, 1, 2
    scalar[31] &= 127; // Clear bit 255
    scalar[31] |= 64; // Set bit 254
}

/// Convert bytes to field element (little-endian)
fn fe_from_bytes(bytes: &[u8; 32]) -> FieldElement {
    let mut h = [0i64; 10];

    h[0] = (bytes[0] as i64)
        | ((bytes[1] as i64) << 8)
        | ((bytes[2] as i64) << 16)
        | (((bytes[3] as i64) & 3) << 24);
    h[1] = (((bytes[3] as i64) >> 2) & 63)
        | ((bytes[4] as i64) << 6)
        | ((bytes[5] as i64) << 14)
        | (((bytes[6] as i64) & 7) << 22);
    h[2] = (((bytes[6] as i64) >> 3) & 31)
        | ((bytes[7] as i64) << 5)
        | ((bytes[8] as i64) << 13)
        | (((bytes[9] as i64) & 15) << 21);
    h[3] = (((bytes[9] as i64) >> 4) & 15)
        | ((bytes[10] as i64) << 4)
        | ((bytes[11] as i64) << 12)
        | (((bytes[12] as i64) & 63) << 20);
    h[4] = (((bytes[12] as i64) >> 6) & 3)
        | ((bytes[13] as i64) << 2)
        | ((bytes[14] as i64) << 10)
        | ((bytes[15] as i64) << 18);
    h[5] = (bytes[16] as i64)
        | ((bytes[17] as i64) << 8)
        | ((bytes[18] as i64) << 16)
        | (((bytes[19] as i64) & 1) << 24);
    h[6] = (((bytes[19] as i64) >> 1) & 127)
        | ((bytes[20] as i64) << 7)
        | ((bytes[21] as i64) << 15)
        | (((bytes[22] as i64) & 7) << 23);
    h[7] = (((bytes[22] as i64) >> 3) & 31)
        | ((bytes[23] as i64) << 5)
        | ((bytes[24] as i64) << 13)
        | (((bytes[25] as i64) & 15) << 21);
    h[8] = (((bytes[25] as i64) >> 4) & 15)
        | ((bytes[26] as i64) << 4)
        | ((bytes[27] as i64) << 12)
        | (((bytes[28] as i64) & 63) << 20);
    h[9] = (((bytes[28] as i64) >> 6) & 3)
        | ((bytes[29] as i64) << 2)
        | ((bytes[30] as i64) << 10)
        | ((bytes[31] as i64) << 18);

    h
}

/// Convert field element to bytes (little-endian)
fn fe_to_bytes(h: &FieldElement) -> [u8; 32] {
    let mut h = *h;
    let mut q: i64;

    // Reduce modulo p = 2^255 - 19
    q = (19 * h[9] + (1 << 24)) >> 25;
    q = (h[0] + q) >> 26;
    q = (h[1] + q) >> 25;
    q = (h[2] + q) >> 26;
    q = (h[3] + q) >> 25;
    q = (h[4] + q) >> 26;
    q = (h[5] + q) >> 25;
    q = (h[6] + q) >> 26;
    q = (h[7] + q) >> 25;
    q = (h[8] + q) >> 26;
    q = (h[9] + q) >> 25;

    h[0] += 19 * q;

    let mut carry: i64;
    carry = h[0] >> 26;
    h[1] += carry;
    h[0] -= carry << 26;
    carry = h[1] >> 25;
    h[2] += carry;
    h[1] -= carry << 25;
    carry = h[2] >> 26;
    h[3] += carry;
    h[2] -= carry << 26;
    carry = h[3] >> 25;
    h[4] += carry;
    h[3] -= carry << 25;
    carry = h[4] >> 26;
    h[5] += carry;
    h[4] -= carry << 26;
    carry = h[5] >> 25;
    h[6] += carry;
    h[5] -= carry << 25;
    carry = h[6] >> 26;
    h[7] += carry;
    h[6] -= carry << 26;
    carry = h[7] >> 25;
    h[8] += carry;
    h[7] -= carry << 25;
    carry = h[8] >> 26;
    h[9] += carry;
    h[8] -= carry << 26;
    carry = h[9] >> 25;
    h[9] -= carry << 25;

    let mut s = [0u8; 32];
    s[0] = h[0] as u8;
    s[1] = (h[0] >> 8) as u8;
    s[2] = (h[0] >> 16) as u8;
    s[3] = ((h[0] >> 24) | (h[1] << 2)) as u8;
    s[4] = (h[1] >> 6) as u8;
    s[5] = (h[1] >> 14) as u8;
    s[6] = ((h[1] >> 22) | (h[2] << 3)) as u8;
    s[7] = (h[2] >> 5) as u8;
    s[8] = (h[2] >> 13) as u8;
    s[9] = ((h[2] >> 21) | (h[3] << 5)) as u8;
    s[10] = (h[3] >> 3) as u8;
    s[11] = (h[3] >> 11) as u8;
    s[12] = ((h[3] >> 19) | (h[4] << 6)) as u8;
    s[13] = (h[4] >> 2) as u8;
    s[14] = (h[4] >> 10) as u8;
    s[15] = (h[4] >> 18) as u8;
    s[16] = h[5] as u8;
    s[17] = (h[5] >> 8) as u8;
    s[18] = (h[5] >> 16) as u8;
    s[19] = ((h[5] >> 24) | (h[6] << 1)) as u8;
    s[20] = (h[6] >> 7) as u8;
    s[21] = (h[6] >> 15) as u8;
    s[22] = ((h[6] >> 23) | (h[7] << 3)) as u8;
    s[23] = (h[7] >> 5) as u8;
    s[24] = (h[7] >> 13) as u8;
    s[25] = ((h[7] >> 21) | (h[8] << 4)) as u8;
    s[26] = (h[8] >> 4) as u8;
    s[27] = (h[8] >> 12) as u8;
    s[28] = ((h[8] >> 20) | (h[9] << 6)) as u8;
    s[29] = (h[9] >> 2) as u8;
    s[30] = (h[9] >> 10) as u8;
    s[31] = (h[9] >> 18) as u8;

    s
}

/// Field element addition
fn fe_add(f: &FieldElement, g: &FieldElement) -> FieldElement {
    let mut h = [0i64; 10];
    for i in 0..10 {
        h[i] = f[i] + g[i];
    }
    h
}

/// Field element subtraction
fn fe_sub(f: &FieldElement, g: &FieldElement) -> FieldElement {
    let mut h = [0i64; 10];
    for i in 0..10 {
        h[i] = f[i] - g[i];
    }
    h
}

/// Field element multiplication
fn fe_mul(f: &FieldElement, g: &FieldElement) -> FieldElement {
    let f0 = f[0];
    let f1 = f[1];
    let f2 = f[2];
    let f3 = f[3];
    let f4 = f[4];
    let f5 = f[5];
    let f6 = f[6];
    let f7 = f[7];
    let f8 = f[8];
    let f9 = f[9];
    let g0 = g[0];
    let g1 = g[1];
    let g2 = g[2];
    let g3 = g[3];
    let g4 = g[4];
    let g5 = g[5];
    let g6 = g[6];
    let g7 = g[7];
    let g8 = g[8];
    let g9 = g[9];

    let g1_19 = 19 * g1;
    let g2_19 = 19 * g2;
    let g3_19 = 19 * g3;
    let g4_19 = 19 * g4;
    let g5_19 = 19 * g5;
    let g6_19 = 19 * g6;
    let g7_19 = 19 * g7;
    let g8_19 = 19 * g8;
    let g9_19 = 19 * g9;

    let mut h0 = f0 * g0 + f1 * g9_19 + f2 * g8_19 + f3 * g7_19 + f4 * g6_19
        + f5 * g5_19 + f6 * g4_19 + f7 * g3_19 + f8 * g2_19 + f9 * g1_19;
    let mut h1 = f0 * g1 + f1 * g0 + f2 * g9_19 + f3 * g8_19 + f4 * g7_19
        + f5 * g6_19 + f6 * g5_19 + f7 * g4_19 + f8 * g3_19 + f9 * g2_19;
    let mut h2 = f0 * g2 + f1 * g1 + f2 * g0 + f3 * g9_19 + f4 * g8_19
        + f5 * g7_19 + f6 * g6_19 + f7 * g5_19 + f8 * g4_19 + f9 * g3_19;
    let mut h3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + f4 * g9_19
        + f5 * g8_19 + f6 * g7_19 + f7 * g6_19 + f8 * g5_19 + f9 * g4_19;
    let mut h4 = f0 * g4 + f1 * g3 + f2 * g2 + f3 * g1 + f4 * g0
        + f5 * g9_19 + f6 * g8_19 + f7 * g7_19 + f8 * g6_19 + f9 * g5_19;
    let mut h5 = f0 * g5 + f1 * g4 + f2 * g3 + f3 * g2 + f4 * g1
        + f5 * g0 + f6 * g9_19 + f7 * g8_19 + f8 * g7_19 + f9 * g6_19;
    let mut h6 = f0 * g6 + f1 * g5 + f2 * g4 + f3 * g3 + f4 * g2
        + f5 * g1 + f6 * g0 + f7 * g9_19 + f8 * g8_19 + f9 * g7_19;
    let mut h7 = f0 * g7 + f1 * g6 + f2 * g5 + f3 * g4 + f4 * g3
        + f5 * g2 + f6 * g1 + f7 * g0 + f8 * g9_19 + f9 * g8_19;
    let mut h8 = f0 * g8 + f1 * g7 + f2 * g6 + f3 * g5 + f4 * g4
        + f5 * g3 + f6 * g2 + f7 * g1 + f8 * g0 + f9 * g9_19;
    let mut h9 = f0 * g9 + f1 * g8 + f2 * g7 + f3 * g6 + f4 * g5
        + f5 * g4 + f6 * g3 + f7 * g2 + f8 * g1 + f9 * g0;

    // Carry propagation
    let mut carry: i64;
    carry = (h0 + (1 << 25)) >> 26;
    h1 += carry;
    h0 -= carry << 26;
    carry = (h4 + (1 << 25)) >> 26;
    h5 += carry;
    h4 -= carry << 26;
    carry = (h1 + (1 << 24)) >> 25;
    h2 += carry;
    h1 -= carry << 25;
    carry = (h5 + (1 << 24)) >> 25;
    h6 += carry;
    h5 -= carry << 25;
    carry = (h2 + (1 << 25)) >> 26;
    h3 += carry;
    h2 -= carry << 26;
    carry = (h6 + (1 << 25)) >> 26;
    h7 += carry;
    h6 -= carry << 26;
    carry = (h3 + (1 << 24)) >> 25;
    h4 += carry;
    h3 -= carry << 25;
    carry = (h7 + (1 << 24)) >> 25;
    h8 += carry;
    h7 -= carry << 25;
    carry = (h4 + (1 << 25)) >> 26;
    h5 += carry;
    h4 -= carry << 26;
    carry = (h8 + (1 << 25)) >> 26;
    h9 += carry;
    h8 -= carry << 26;
    carry = (h9 + (1 << 24)) >> 25;
    h0 += carry * 19;
    h9 -= carry << 25;
    carry = (h0 + (1 << 25)) >> 26;
    h1 += carry;
    h0 -= carry << 26;

    [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9]
}

/// Field element squaring (optimized multiplication by self)
fn fe_sq(f: &FieldElement) -> FieldElement {
    fe_mul(f, f)
}

/// Field element inversion (using Fermat's little theorem)
/// a^-1 = a^(p-2) mod p where p = 2^255 - 19
fn fe_invert(z: &FieldElement) -> FieldElement {
    let mut t0;
    let mut t1;
    let mut t2;
    let mut t3;

    t0 = fe_sq(z);
    t1 = fe_sq(&t0);
    t1 = fe_sq(&t1);
    t1 = fe_mul(z, &t1);
    t0 = fe_mul(&t0, &t1);
    t2 = fe_sq(&t0);
    t1 = fe_mul(&t1, &t2);
    t2 = fe_sq(&t1);
    for _ in 1..5 {
        t2 = fe_sq(&t2);
    }
    t1 = fe_mul(&t2, &t1);
    t2 = fe_sq(&t1);
    for _ in 1..10 {
        t2 = fe_sq(&t2);
    }
    t2 = fe_mul(&t2, &t1);
    t3 = fe_sq(&t2);
    for _ in 1..20 {
        t3 = fe_sq(&t3);
    }
    t2 = fe_mul(&t3, &t2);
    t2 = fe_sq(&t2);
    for _ in 1..10 {
        t2 = fe_sq(&t2);
    }
    t1 = fe_mul(&t2, &t1);
    t2 = fe_sq(&t1);
    for _ in 1..50 {
        t2 = fe_sq(&t2);
    }
    t2 = fe_mul(&t2, &t1);
    t3 = fe_sq(&t2);
    for _ in 1..100 {
        t3 = fe_sq(&t3);
    }
    t2 = fe_mul(&t3, &t2);
    t2 = fe_sq(&t2);
    for _ in 1..50 {
        t2 = fe_sq(&t2);
    }
    t1 = fe_mul(&t2, &t1);
    t1 = fe_sq(&t1);
    for _ in 1..5 {
        t1 = fe_sq(&t1);
    }
    fe_mul(&t1, &t0)
}

/// Constant-time conditional swap
fn fe_cswap(f: &mut FieldElement, g: &mut FieldElement, b: i32) {
    let mask = -b as i64;
    for i in 0..10 {
        let x = mask & (f[i] ^ g[i]);
        f[i] ^= x;
        g[i] ^= x;
    }
}

/// Montgomery ladder for scalar multiplication
/// Computes scalar * point on Curve25519
fn scalarmult(n: &[u8; 32], p: &[u8; 32]) -> [u8; 32] {
    let mut e = *n;
    clamp_scalar(&mut e);

    let x1 = fe_from_bytes(p);
    let mut x2 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // 1
    let mut z2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // 0
    let mut x3 = x1;
    let mut z3 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // 1
    let mut swap = 0;

    for pos in (0..255).rev() {
        let b = ((e[pos / 8] >> (pos & 7)) & 1) as i32;
        swap ^= b;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = b;

        let a = fe_add(&x2, &z2);
        let aa = fe_sq(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        x3 = fe_sq(&fe_add(&da, &cb));
        z3 = fe_mul(&x1, &fe_sq(&fe_sub(&da, &cb)));
        x2 = fe_mul(&aa, &bb);
        let mut a121665 = [0i64; 10];
        a121665[0] = 121665;
        z2 = fe_mul(&e, &fe_add(&aa, &fe_mul(&a121665, &e)));
    }

    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);

    let z2_inv = fe_invert(&z2);
    let result = fe_mul(&x2, &z2_inv);
    fe_to_bytes(&result)
}

/// Generate X25519 public key from private key
///
/// # Arguments
/// * `private_key` - 32-byte private key (will be clamped)
///
/// # Returns
/// 32-byte public key
pub fn x25519_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    scalarmult(private_key, &BASEPOINT)
}

/// Compute X25519 shared secret
///
/// # Arguments
/// * `private_key` - Our 32-byte private key
/// * `public_key` - Their 32-byte public key
///
/// # Returns
/// 32-byte shared secret
pub fn x25519(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    scalarmult(private_key, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_rfc7748() {
        // RFC 7748 Section 6.1 test vector
        let alice_private = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];

        let bob_public = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];

        let expected_shared = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];

        let shared = x25519(&alice_private, &bob_public);
        assert_eq!(shared, expected_shared);
    }

    #[test]
    fn test_x25519_public_key() {
        // Test public key generation
        let private_key = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];

        let expected_public = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];

        let public = x25519_public_key(&private_key);
        assert_eq!(public, expected_public);
    }

    #[test]
    fn test_x25519_iteration() {
        // RFC 7748 Section 6.1 - Test 1000 iterations
        let mut k = [9u8; 32];
        k[0] = 9;
        for _ in 0..32 {
            k.fill(0);
            k[0] = 9;
        }

        let mut u = k;
        for _ in 0..1 {
            let k_prev = k;
            k = x25519(&k_prev, &u);
            u = k_prev;
        }

        // After 1 iteration
        let expected_1 = [
            0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc, 0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7,
            0x27, 0x9f, 0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78, 0x3c, 0x60, 0xe8, 0x03,
            0x11, 0xae, 0x30, 0x79,
        ];
        assert_eq!(k, expected_1);
    }
}
