/// Big integer implementation for RSA cryptography
/// Implements arbitrary precision arithmetic using only Rust std library
///
/// This is a minimal implementation focused on RSA operations:
/// - Modular exponentiation (for encryption)
/// - Basic arithmetic (add, sub, mul, div, mod)
/// - Comparison operations
///
/// Replaces: OpenSSL's BIGNUM, GMP
use std::cmp::Ordering;

/// Big unsigned integer stored in little-endian limbs
/// Each limb is a u32 for portability
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BigInt {
    /// Limbs in little-endian order (least significant first)
    /// e.g., 0x123456789 = [0x56789, 0x1234]
    limbs: Vec<u32>,
}

impl BigInt {
    /// Create a BigInt from a u64
    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            return Self { limbs: vec![0] };
        }

        let low = (value & 0xFFFFFFFF) as u32;
        let high = (value >> 32) as u32;

        if high == 0 {
            Self { limbs: vec![low] }
        } else {
            Self {
                limbs: vec![low, high],
            }
        }
    }

    /// Create a BigInt from bytes (big-endian)
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self { limbs: vec![0] };
        }

        // Remove leading zeros
        let start = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        let bytes = &bytes[start..];

        let mut limbs = Vec::new();
        let mut chunk_start = bytes.len();

        // Process 4 bytes at a time from the end
        while chunk_start > 0 {
            let chunk_end = chunk_start;
            chunk_start = chunk_start.saturating_sub(4);
            let chunk = &bytes[chunk_start..chunk_end];

            let mut limb = 0u32;
            for &byte in chunk {
                limb = (limb << 8) | byte as u32;
            }
            limbs.push(limb);
        }

        if limbs.is_empty() {
            limbs.push(0);
        }

        Self { limbs }
    }

    /// Convert to bytes (big-endian)
    pub fn to_bytes_be(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }

        let mut bytes = Vec::new();

        // Process limbs from most significant to least
        for &limb in self.limbs.iter().rev() {
            let b = limb.to_be_bytes();

            // Skip leading zeros in the first limb only
            if bytes.is_empty() {
                let start = b.iter().position(|&x| x != 0).unwrap_or(3);
                bytes.extend_from_slice(&b[start..]);
            } else {
                bytes.extend_from_slice(&b);
            }
        }

        if bytes.is_empty() {
            bytes.push(0);
        }

        bytes
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&x| x == 0)
    }

    /// Get number of bits
    pub fn bit_length(&self) -> usize {
        if self.is_zero() {
            return 0;
        }

        let last_limb = *self.limbs.last().unwrap();
        let limb_bits = 32 - last_limb.leading_zeros() as usize;
        (self.limbs.len() - 1) * 32 + limb_bits
    }

    /// Normalize: remove leading zero limbs
    fn normalize(&mut self) {
        while self.limbs.len() > 1 && *self.limbs.last().unwrap() == 0 {
            self.limbs.pop();
        }
    }

    /// Add two BigInts
    pub fn add(&self, other: &BigInt) -> BigInt {
        let max_len = self.limbs.len().max(other.limbs.len());
        let mut result = Vec::with_capacity(max_len + 1);
        let mut carry = 0u64;

        for i in 0..max_len {
            let a = self.limbs.get(i).copied().unwrap_or(0) as u64;
            let b = other.limbs.get(i).copied().unwrap_or(0) as u64;

            let sum = a + b + carry;
            result.push(sum as u32);
            carry = sum >> 32;
        }

        if carry > 0 {
            result.push(carry as u32);
        }

        let mut res = BigInt { limbs: result };
        res.normalize();
        res
    }

    /// Subtract two BigInts (assumes self >= other)
    pub fn sub(&self, other: &BigInt) -> BigInt {
        if self < other {
            panic!("BigInt subtraction underflow");
        }

        let mut result = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i64;

        for i in 0..self.limbs.len() {
            let a = self.limbs[i] as i64;
            let b = other.limbs.get(i).copied().unwrap_or(0) as i64;

            let diff = a - b - borrow;

            if diff < 0 {
                result.push((diff + (1i64 << 32)) as u32);
                borrow = 1;
            } else {
                result.push(diff as u32);
                borrow = 0;
            }
        }

        let mut res = BigInt { limbs: result };
        res.normalize();
        res
    }

    /// Multiply two BigInts
    pub fn mul(&self, other: &BigInt) -> BigInt {
        if self.is_zero() || other.is_zero() {
            return BigInt { limbs: vec![0] };
        }

        let mut result = vec![0u32; self.limbs.len() + other.limbs.len()];

        for i in 0..self.limbs.len() {
            let mut carry = 0u64;

            for j in 0..other.limbs.len() {
                let prod = (self.limbs[i] as u64) * (other.limbs[j] as u64)
                    + (result[i + j] as u64)
                    + carry;

                result[i + j] = prod as u32;
                carry = prod >> 32;
            }

            result[i + other.limbs.len()] = carry as u32;
        }

        let mut res = BigInt { limbs: result };
        res.normalize();
        res
    }

    /// Divide by a u32, returning (quotient, remainder)
    fn div_rem_u32(&self, divisor: u32) -> (BigInt, u32) {
        if divisor == 0 {
            panic!("Division by zero");
        }

        let mut quotient = Vec::with_capacity(self.limbs.len());
        let mut remainder = 0u64;

        for &limb in self.limbs.iter().rev() {
            let dividend = (remainder << 32) | limb as u64;
            quotient.push((dividend / divisor as u64) as u32);
            remainder = dividend % divisor as u64;
        }

        quotient.reverse();

        let mut q = BigInt { limbs: quotient };
        q.normalize();

        (q, remainder as u32)
    }

    /// Divide two BigInts, returning (quotient, remainder)
    pub fn div_rem(&self, divisor: &BigInt) -> (BigInt, BigInt) {
        if divisor.is_zero() {
            panic!("Division by zero");
        }

        // Special case: divisor is a single limb
        if divisor.limbs.len() == 1 {
            let (q, r) = self.div_rem_u32(divisor.limbs[0]);
            return (q, BigInt::from_u64(r as u64));
        }

        // Long division algorithm
        if self < divisor {
            return (BigInt::from_u64(0), self.clone());
        }

        let mut quotient = BigInt::from_u64(0);
        let mut remainder = self.clone();

        let shift = self.bit_length() - divisor.bit_length();
        let mut divisor_shifted = divisor.shl(shift);

        for i in (0..=shift).rev() {
            if remainder >= divisor_shifted {
                remainder = remainder.sub(&divisor_shifted);
                quotient = quotient.add(&BigInt::from_u64(1).shl(i));
            }

            if i > 0 {
                divisor_shifted = divisor_shifted.shr(1);
            }
        }

        (quotient, remainder)
    }

    /// Modulo operation
    pub fn modulo(&self, modulus: &BigInt) -> BigInt {
        self.div_rem(modulus).1
    }

    /// Left shift by n bits
    fn shl(&self, n: usize) -> BigInt {
        if n == 0 || self.is_zero() {
            return self.clone();
        }

        let limb_shift = n / 32;
        let bit_shift = n % 32;

        let mut result = vec![0u32; limb_shift];

        if bit_shift == 0 {
            result.extend_from_slice(&self.limbs);
        } else {
            let mut carry = 0u32;
            for &limb in &self.limbs {
                let shifted = (limb << bit_shift) | carry;
                result.push(shifted);
                carry = limb >> (32 - bit_shift);
            }
            if carry > 0 {
                result.push(carry);
            }
        }

        let mut res = BigInt { limbs: result };
        res.normalize();
        res
    }

    /// Right shift by n bits
    fn shr(&self, n: usize) -> BigInt {
        if n == 0 || self.is_zero() {
            return self.clone();
        }

        let limb_shift = n / 32;
        let bit_shift = n % 32;

        if limb_shift >= self.limbs.len() {
            return BigInt::from_u64(0);
        }

        let mut result = Vec::new();

        if bit_shift == 0 {
            result.extend_from_slice(&self.limbs[limb_shift..]);
        } else {
            let mut borrow = 0u32;
            for &limb in self.limbs[limb_shift..].iter().rev() {
                let shifted = (limb >> bit_shift) | (borrow << (32 - bit_shift));
                result.push(shifted);
                borrow = limb;
            }
            result.reverse();
        }

        let mut res = BigInt { limbs: result };
        res.normalize();
        res
    }

    /// Modular exponentiation: (base^exp) mod modulus
    /// Uses binary exponentiation (square-and-multiply)
    pub fn mod_exp(&self, exp: &BigInt, modulus: &BigInt) -> BigInt {
        if modulus.is_zero() {
            panic!("Modulus cannot be zero");
        }

        if exp.is_zero() {
            return BigInt::from_u64(1);
        }

        let mut result = BigInt::from_u64(1);
        let mut base = self.modulo(modulus);
        let mut e = exp.clone();

        while !e.is_zero() {
            // If exp is odd, multiply result by base
            if e.limbs[0] & 1 == 1 {
                result = result.mul(&base).modulo(modulus);
            }

            // Square the base
            base = base.mul(&base).modulo(modulus);

            // Divide exp by 2
            e = e.shr(1);
        }

        result
    }

    /// Modular reduction
    pub fn mod_reduce(&self, modulus: &BigInt) -> BigInt {
        self.modulo(modulus)
    }

    /// Modular multiplication
    pub fn mod_mul(&self, other: &BigInt, modulus: &BigInt) -> BigInt {
        self.mul(other).modulo(modulus)
    }

    /// Modular subtraction
    pub fn mod_sub(&self, other: &BigInt, modulus: &BigInt) -> BigInt {
        if self < other {
            let diff = other.sub(self);
            modulus.sub(&diff)
        } else {
            self.sub(other)
        }
    }

    /// Modular inverse using extended Euclidean algorithm
    pub fn mod_inv(&self, modulus: &BigInt) -> Option<BigInt> {
        if modulus.is_zero() {
            return None;
        }

        let mut r = modulus.clone();
        let mut new_r = self.modulo(modulus);
        if new_r.is_zero() {
            return None;
        }

        let mut t = BigInt::from_u64(0);
        let mut new_t = BigInt::from_u64(1);

        while !new_r.is_zero() {
            let (quotient, remainder) = r.div_rem(&new_r);

            let temp_t = new_t.clone();
            let q_new_t = quotient.mul(&new_t);
            new_t = t.mod_sub(&q_new_t, modulus);
            t = temp_t;

            r = new_r;
            new_r = remainder;
        }

        if r != BigInt::from_u64(1) {
            return None;
        }

        Some(t.modulo(modulus))
    }
}

impl PartialOrd for BigInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigInt {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare lengths first
        match self.limbs.len().cmp(&other.limbs.len()) {
            Ordering::Less => return Ordering::Less,
            Ordering::Greater => return Ordering::Greater,
            Ordering::Equal => {}
        }

        // Same length: compare limbs from most significant
        for i in (0..self.limbs.len()).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                Ordering::Equal => continue,
                other => return other,
            }
        }

        Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u64() {
        let a = BigInt::from_u64(0x123456789ABCDEF0);
        assert_eq!(a.limbs, vec![0x9ABCDEF0, 0x12345678]);

        let b = BigInt::from_u64(42);
        assert_eq!(b.limbs, vec![42]);

        let c = BigInt::from_u64(0);
        assert_eq!(c.limbs, vec![0]);
    }

    #[test]
    fn test_from_bytes_be() {
        let bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let a = BigInt::from_bytes_be(&bytes);
        assert_eq!(a.limbs, vec![0x89ABCDEF, 0x01234567]);

        let b = BigInt::from_bytes_be(&[0x00, 0x00, 0x42]);
        assert_eq!(b.limbs, vec![0x42]);
    }

    #[test]
    fn test_add() {
        let a = BigInt::from_u64(100);
        let b = BigInt::from_u64(200);
        let c = a.add(&b);
        assert_eq!(c, BigInt::from_u64(300));

        // Test carry
        let d = BigInt::from_u64(0xFFFFFFFF);
        let e = BigInt::from_u64(1);
        let f = d.add(&e);
        assert_eq!(f, BigInt::from_u64(0x100000000));
    }

    #[test]
    fn test_sub() {
        let a = BigInt::from_u64(300);
        let b = BigInt::from_u64(100);
        let c = a.sub(&b);
        assert_eq!(c, BigInt::from_u64(200));
    }

    #[test]
    fn test_mul() {
        let a = BigInt::from_u64(123);
        let b = BigInt::from_u64(456);
        let c = a.mul(&b);
        assert_eq!(c, BigInt::from_u64(56088));

        // Test larger multiplication
        let d = BigInt::from_u64(0xFFFFFFFF);
        let e = BigInt::from_u64(0xFFFFFFFF);
        let f = d.mul(&e);
        assert_eq!(f, BigInt::from_u64(0xFFFFFFFE00000001));
    }

    #[test]
    fn test_div_rem() {
        let a = BigInt::from_u64(100);
        let b = BigInt::from_u64(7);
        let (q, r) = a.div_rem(&b);
        assert_eq!(q, BigInt::from_u64(14));
        assert_eq!(r, BigInt::from_u64(2));
    }

    #[test]
    fn test_mod_exp() {
        // 3^5 mod 13 = 243 mod 13 = 9
        let base = BigInt::from_u64(3);
        let exp = BigInt::from_u64(5);
        let modulus = BigInt::from_u64(13);
        let result = base.mod_exp(&exp, &modulus);
        assert_eq!(result, BigInt::from_u64(9));

        // Larger example: 7^10 mod 13 = 4
        let base = BigInt::from_u64(7);
        let exp = BigInt::from_u64(10);
        let modulus = BigInt::from_u64(13);
        let result = base.mod_exp(&exp, &modulus);
        assert_eq!(result, BigInt::from_u64(4));
    }

    #[test]
    fn test_comparison() {
        let a = BigInt::from_u64(100);
        let b = BigInt::from_u64(200);
        let c = BigInt::from_u64(100);

        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, c);
        assert!(a <= c);
        assert!(a >= c);
    }
}
