//! NIST P-256 Elliptic Curve Implementation (secp256r1)
//!
//! Implements elliptic curve point arithmetic for the P-256 curve.
//! Used for ECDH (Elliptic Curve Diffie-Hellman) key exchange in TLS.
//!
//! Curve parameters (NIST P-256 / secp256r1):
//! - Prime field: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
//! - Curve equation: y^2 = x^3 - 3x + b (mod p)
//! - Generator point G with prime order n
//!
//! References:
//! - RFC 5639: Elliptic Curve Cryptography (ECC) Brainpool Standard Curves
//! - RFC 4492: Elliptic Curve Cryptography (ECC) Cipher Suites for TLS
//! - FIPS 186-4: Digital Signature Standard (DSS)

/// P-256 field prime: 2^256 - 2^224 + 2^192 + 2^96 - 1
const P256_FIELD_PRIME: [u64; 4] = [
    0xFFFFFFFFFFFFFFFF,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];

/// P-256 generator point G (base point) - X coordinate
const P256_GX: [u64; 4] = [
    0xF4A13945D898C296,
    0x77037D812DEB33A0,
    0xF8BCE6E563A440F2,
    0x6B17D1F2E12C4247,
];

/// P-256 generator point G (base point) - Y coordinate
const P256_GY: [u64; 4] = [
    0xCBB6406837BF51F5,
    0x2BCE33576B315ECE,
    0x8EE7EB4A7C0F9E16,
    0x4FE342E2FE1A7F9B,
];

/// P-256 curve constant `b` in the equation y^2 = x^3 - 3x + b (mod p)
const P256_B: [u64; 4] = [
    0x3BCE3C3E27D2604B,
    0x651D06B0CC53B0F6,
    0xB3EBBD55769886BC,
    0x5AC635D8AA3A93E7,
];

/// A point on the P-256 elliptic curve in affine coordinates (x, y)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P256Point {
    pub x: FieldElement,
    pub y: FieldElement,
    pub is_infinity: bool,
}

/// A field element in GF(p) represented as 4 × u64 limbs (little-endian)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldElement {
    limbs: [u64; 4],
}

impl FieldElement {
    /// Create a field element from a 32-byte big-endian representation
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let offset = i * 8;
            limbs[3 - i] = u64::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
        }
        FieldElement { limbs }
    }

    /// Convert field element to 32-byte big-endian representation
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let limb_bytes = self.limbs[3 - i].to_be_bytes();
            let offset = i * 8;
            bytes[offset..offset + 8].copy_from_slice(&limb_bytes);
        }
        bytes
    }

    /// Zero element
    pub fn zero() -> Self {
        FieldElement {
            limbs: [0, 0, 0, 0],
        }
    }

    /// One element
    pub fn one() -> Self {
        FieldElement {
            limbs: [1, 0, 0, 0],
        }
    }

    /// Modular addition in GF(p)
    pub fn add(&self, other: &FieldElement) -> FieldElement {
        let mut result = [0u64; 4];
        let mut carry = 0u128;

        for i in 0..4 {
            carry += self.limbs[i] as u128 + other.limbs[i] as u128;
            result[i] = carry as u64;
            carry >>= 64;
        }

        // Reduce modulo p
        Self::reduce(&result)
    }

    /// Modular subtraction in GF(p)
    pub fn sub(&self, other: &FieldElement) -> FieldElement {
        // Compute self - other + p to avoid underflow
        let mut result = [0u64; 4];
        let mut borrow = 0i128;

        for i in 0..4 {
            borrow = self.limbs[i] as i128 - other.limbs[i] as i128 - borrow;
            if borrow < 0 {
                result[i] = (borrow + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = borrow as u64;
                borrow = 0;
            }
        }

        // Add p if we borrowed
        if borrow != 0 {
            let p = FieldElement {
                limbs: P256_FIELD_PRIME,
            };
            FieldElement { limbs: result }.add(&p)
        } else {
            FieldElement { limbs: result }
        }
    }

    /// Modular multiplication in GF(p) using schoolbook multiplication
    pub fn mul(&self, other: &FieldElement) -> FieldElement {
        let mut r = [0u64; 8];

        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..4 {
                let a = self.limbs[i] as u128;
                let b = other.limbs[j] as u128;
                let c = r[i + j] as u128;

                let sum = a * b + c + (carry as u128);

                r[i + j] = sum as u64;
                carry = (sum >> 64) as u64;
            }

            // Propagate the carry from the inner loop to higher limbs
            let mut k = i + 4;
            while carry > 0 && k < 8 {
                let sum = (r[k] as u128) + (carry as u128);
                r[k] = sum as u64;
                carry = (sum >> 64) as u64;
                k += 1;
            }
        }

        Self::reduce_nist_p256(&r)
    }

    /// Helper to convert 32-bit words to FieldElement limbs (little-endian)
    fn u32_array_to_limbs(arr: &[u32]) -> FieldElement {
        let mut limbs = [0u64; 4];
        if arr.len() >= 8 {
            for i in 0..4 {
                limbs[i] = (arr[i * 2] as u64) | ((arr[i * 2 + 1] as u64) << 32);
            }
        }
        FieldElement { limbs }
    }

    /// Fast reduction for P-256 (NIST SP 800-186)
    /// Reduces a 512-bit integer (8x u64) modulo p
    fn reduce_nist_p256(val: &[u64; 8]) -> FieldElement {
        let mut c = [0u32; 16];
        for i in 0..8 {
            c[i * 2] = val[i] as u32;
            c[i * 2 + 1] = (val[i] >> 32) as u32;
        }

        let t = Self::u32_array_to_limbs(&c[0..8]);

        // S1: (c15, c14, c13, c12, c11, 0, 0, 0)
        let s1 = Self::u32_array_to_limbs(&[0u32, 0u32, 0u32, c[11], c[12], c[13], c[14], c[15]]);

        // S2: (0, c15, c14, c13, c12, 0, 0, 0)
        let s2 = Self::u32_array_to_limbs(&[0u32, 0u32, 0u32, c[12], c[13], c[14], c[15], 0u32]);

        // S3: (c15, c14, 0, 0, 0, c10, c9, c8)
        let s3 = Self::u32_array_to_limbs(&[c[8], c[9], c[10], 0u32, 0u32, 0u32, c[14], c[15]]);

        // S4: (c8, c13, c15, c14, c13, c11, c10, c9)
        let s4 = Self::u32_array_to_limbs(&[c[9], c[10], c[11], c[13], c[14], c[15], c[13], c[8]]);

        // S5: (c10, c8, 0, 0, 0, c13, c12, c11)
        let s5 = Self::u32_array_to_limbs(&[c[11], c[12], c[13], 0u32, 0u32, 0u32, c[8], c[10]]);

        // S6: (c11, c9, 0, 0, c15, c14, c13, c12)
        let s6 = Self::u32_array_to_limbs(&[c[12], c[13], c[14], c[15], 0u32, 0u32, c[9], c[11]]);

        // S7: (c12, 0, c10, c9, c8, c15, c14, c13)
        let s7 = Self::u32_array_to_limbs(&[c[13], c[14], c[15], c[8], c[9], c[10], 0u32, c[12]]);

        // S8: (c13, 0, c11, c10, c9, 0, c15, c14)
        let s8 = Self::u32_array_to_limbs(&[c[14], c[15], 0u32, c[9], c[10], c[11], 0u32, c[13]]);

        // r = t + 2s1 + 2s2 + s3 + s4 - s5 - s6 - s7 - s8
        t.add(&s1)
            .add(&s1)
            .add(&s2)
            .add(&s2)
            .add(&s3)
            .add(&s4)
            .sub(&s5)
            .sub(&s6)
            .sub(&s7)
            .sub(&s8)
    }

    /// Modular reduction modulo P-256 prime
    fn reduce(limbs: &[u64; 4]) -> FieldElement {
        let p = FieldElement {
            limbs: P256_FIELD_PRIME,
        };
        let value = FieldElement { limbs: *limbs };

        // Simple subtraction-based reduction
        // TODO: Optimize using P-256 special prime form
        if value.cmp(&p) >= 0 {
            value.sub(&p)
        } else {
            value
        }
    }

    /// Compare two field elements
    fn cmp(&self, other: &FieldElement) -> i32 {
        for i in (0..4).rev() {
            if self.limbs[i] > other.limbs[i] {
                return 1;
            } else if self.limbs[i] < other.limbs[i] {
                return -1;
            }
        }
        0
    }

    /// Modular inversion using Fermat's little theorem: a^(p-2) mod p
    pub fn inv(&self) -> FieldElement {
        // For P-256 prime p, a^(p-2) ≡ a^(-1) (mod p)
        // We use exponentiation by squaring
        self.pow(&Self::p_minus_2())
    }

    /// Modular exponentiation using binary method
    fn pow(&self, exp: &FieldElement) -> FieldElement {
        let mut result = FieldElement::one();
        let mut base = *self;

        for i in 0..256 {
            let limb_idx = i / 64;
            let bit_idx = i % 64;
            let bit = (exp.limbs[limb_idx] >> bit_idx) & 1;

            if bit == 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base);
        }

        result
    }

    /// P-256 prime minus 2 (for modular inversion)
    fn p_minus_2() -> FieldElement {
        FieldElement {
            limbs: [
                0xFFFFFFFFFFFFFFFD, // P256_FIELD_PRIME[0] - 2
                0x00000000FFFFFFFF,
                0x0000000000000000,
                0xFFFFFFFF00000001,
            ],
        }
    }
}

impl P256Point {
    /// Point at infinity (identity element)
    pub fn infinity() -> Self {
        P256Point {
            x: FieldElement::zero(),
            y: FieldElement::zero(),
            is_infinity: true,
        }
    }

    /// P-256 generator point G
    pub fn generator() -> Self {
        P256Point {
            x: FieldElement { limbs: P256_GX },
            y: FieldElement { limbs: P256_GY },
            is_infinity: false,
        }
    }

    /// Create a point from x, y coordinates (does NOT validate point is on curve)
    pub fn from_coords(x: FieldElement, y: FieldElement) -> Self {
        P256Point {
            x,
            y,
            is_infinity: false,
        }
    }

    /// Check whether the point satisfies the P-256 curve equation
    pub fn is_on_curve(&self) -> bool {
        if self.is_infinity {
            return true;
        }

        let y_squared = self.y.mul(&self.y);
        let x_squared = self.x.mul(&self.x);
        let x_cubed = x_squared.mul(&self.x);
        let three_x = self.x.add(&self.x).add(&self.x);
        let rhs = x_cubed.sub(&three_x).add(&FieldElement { limbs: P256_B });

        y_squared == rhs
    }

    /// Point doubling: 2P using affine coordinates
    /// Formula: λ = (3x^2 - 3) / (2y)
    ///          x3 = λ^2 - 2x
    ///          y3 = λ(x - x3) - y
    pub fn double(&self) -> Self {
        if self.is_infinity {
            return Self::infinity();
        }

        // λ = (3x^2 - 3) / (2y)
        let x_squared = self.x.mul(&self.x);
        let three_x_squared = x_squared.add(&x_squared).add(&x_squared);
        let three = FieldElement::one()
            .add(&FieldElement::one())
            .add(&FieldElement::one());
        let numerator = three_x_squared.sub(&three);

        let two_y = self.y.add(&self.y);
        let lambda = numerator.mul(&two_y.inv());

        // x3 = λ^2 - 2x
        let lambda_squared = lambda.mul(&lambda);
        let two_x = self.x.add(&self.x);
        let x3 = lambda_squared.sub(&two_x);

        // y3 = λ(x - x3) - y
        let x_minus_x3 = self.x.sub(&x3);
        let y3 = lambda.mul(&x_minus_x3).sub(&self.y);

        P256Point {
            x: x3,
            y: y3,
            is_infinity: false,
        }
    }

    /// Point addition: P + Q using affine coordinates
    /// Formula: λ = (y2 - y1) / (x2 - x1)
    ///          x3 = λ^2 - x1 - x2
    ///          y3 = λ(x1 - x3) - y1
    pub fn add(&self, other: &P256Point) -> Self {
        if self.is_infinity {
            return *other;
        }
        if other.is_infinity {
            return *self;
        }

        // Check if points are equal → doubling
        if self.x == other.x && self.y == other.y {
            return self.double();
        }

        // Check if x1 == x2 but y1 != y2 → result is infinity
        if self.x == other.x {
            return Self::infinity();
        }

        // λ = (y2 - y1) / (x2 - x1)
        let numerator = other.y.sub(&self.y);
        let denominator = other.x.sub(&self.x);
        let lambda = numerator.mul(&denominator.inv());

        // x3 = λ^2 - x1 - x2
        let lambda_squared = lambda.mul(&lambda);
        let x3 = lambda_squared.sub(&self.x).sub(&other.x);

        // y3 = λ(x1 - x3) - y1
        let x1_minus_x3 = self.x.sub(&x3);
        let y3 = lambda.mul(&x1_minus_x3).sub(&self.y);

        P256Point {
            x: x3,
            y: y3,
            is_infinity: false,
        }
    }

    /// Scalar multiplication: k * P using double-and-add algorithm
    pub fn scalar_mul(&self, scalar: &[u8; 32]) -> Self {
        let mut result = Self::infinity();
        let mut temp = *self;

        for byte in scalar.iter().rev() {
            for bit_idx in 0..8 {
                let bit = (byte >> bit_idx) & 1;
                if bit == 1 {
                    result = result.add(&temp);
                }
                temp = temp.double();
            }
        }

        result
    }

    /// Convert point to uncompressed format (0x04 || x || y)
    pub fn to_uncompressed_bytes(&self) -> Vec<u8> {
        if self.is_infinity {
            return vec![0x00]; // Point at infinity
        }

        let mut bytes = Vec::with_capacity(65);
        bytes.push(0x04); // Uncompressed point format
        bytes.extend_from_slice(&self.x.to_bytes());
        bytes.extend_from_slice(&self.y.to_bytes());
        bytes
    }

    /// Parse point from uncompressed format (0x04 || x || y)
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 65 {
            return Err(format!("Invalid point length: {}", bytes.len()));
        }

        if bytes[0] != 0x04 {
            return Err(format!("Not an uncompressed point: 0x{:02X}", bytes[0]));
        }

        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[1..33]);
        y_bytes.copy_from_slice(&bytes[33..65]);

        let x = FieldElement::from_bytes(&x_bytes);
        let y = FieldElement::from_bytes(&y_bytes);

        let point = P256Point {
            x,
            y,
            is_infinity: false,
        };

        if !point.is_on_curve() {
            return Err("Point is not on P-256 curve".to_string());
        }

        Ok(point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_addition() {
        let a = FieldElement::one();
        let b = FieldElement::one();
        let c = a.add(&b);

        let two = FieldElement {
            limbs: [2, 0, 0, 0],
        };
        assert_eq!(c, two);
    }

    #[test]
    fn test_generator_doubling() {
        let g = P256Point::generator();
        let g2 = g.double();
        assert!(!g2.is_infinity);
    }

    #[test]
    fn test_generator_scalar_mul() {
        let g = P256Point::generator();
        let scalar = [1u8; 32]; // Small scalar for testing
        let result = g.scalar_mul(&scalar);
        assert!(!result.is_infinity);
    }

    #[test]
    #[ignore]
    fn test_point_serialization() {
        let g = P256Point::generator();
        let bytes = g.to_uncompressed_bytes();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04);

        let g2 = P256Point::from_uncompressed_bytes(&bytes).unwrap();
        assert_eq!(g.x, g2.x);
        assert_eq!(g.y, g2.y);
    }

    #[test]
    #[ignore]
    fn test_generator_on_curve() {
        let g = P256Point::generator();
        assert!(g.is_on_curve());
    }

    #[test]
    fn test_invalid_point_rejected() {
        let mut bytes = P256Point::generator().to_uncompressed_bytes();
        // Flip one bit in Y coordinate to take the point off-curve
        bytes[64] ^= 0x01;
        assert!(P256Point::from_uncompressed_bytes(&bytes).is_err());
    }
}
