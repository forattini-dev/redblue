//! RSA PKCS#1 v1.5 Encryption Implementation from Scratch
//!
//! This implements RSA public key encryption WITHOUT external dependencies.
//! Only uses Rust std library.
//!
//! References:
//! - RFC 8017 (PKCS#1): https://www.rfc-editor.org/rfc/rfc8017
//! - RFC 3447 (PKCS#1 v2.1): https://www.rfc-editor.org/rfc/rfc3447
//!
//! Status: Basic implementation for TLS 1.2 ClientKeyExchange

#![allow(clippy::needless_range_loop)]
use super::crypto::SecureRandom;
use std::cmp::Ordering;

/// Big integer implementation for RSA operations
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BigInt {
    /// Digits in base 2^32 (little-endian: digits[0] is least significant)
    digits: Vec<u32>,
}

impl BigInt {
    /// Create from byte slice (big-endian)
    pub(crate) fn from_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self { digits: vec![0] };
        }

        let mut digits = Vec::new();
        let mut i = bytes.len();

        while i > 0 {
            let start = i.saturating_sub(4);
            let chunk = &bytes[start..i];

            let mut digit = 0u32;
            for &byte in chunk {
                digit = (digit << 8) | (byte as u32);
            }

            digits.push(digit);
            i = start;
        }

        // Remove leading zeros
        while digits.len() > 1 && digits[digits.len() - 1] == 0 {
            digits.pop();
        }

        Self { digits }
    }

    /// Convert to byte slice (big-endian)
    pub(crate) fn to_bytes_be(&self) -> Vec<u8> {
        if self.digits.is_empty() || (self.digits.len() == 1 && self.digits[0] == 0) {
            return vec![0];
        }

        let mut bytes = Vec::new();

        for &digit in self.digits.iter().rev() {
            bytes.extend_from_slice(&digit.to_be_bytes());
        }

        // Remove leading zeros
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }

        bytes
    }

    /// Create from u32
    pub(crate) fn from_u32(value: u32) -> Self {
        Self {
            digits: vec![value],
        }
    }

    /// Compare two BigInts
    pub(crate) fn cmp(&self, other: &Self) -> Ordering {
        if self.digits.len() != other.digits.len() {
            return self.digits.len().cmp(&other.digits.len());
        }

        for i in (0..self.digits.len()).rev() {
            match self.digits[i].cmp(&other.digits[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }

        Ordering::Equal
    }

    /// Subtract (assumes self >= other)
    pub(crate) fn sub(&self, other: &Self) -> Self {
        let mut result = self.digits.clone();
        let mut borrow = 0u64;

        for i in 0..result.len() {
            let other_digit = if i < other.digits.len() {
                other.digits[i] as u64
            } else {
                0
            };
            let diff = (result[i] as u64)
                .wrapping_sub(other_digit)
                .wrapping_sub(borrow);

            result[i] = diff as u32;
            borrow = if diff > 0xFFFFFFFF { 1 } else { 0 };
        }

        // Remove leading zeros
        while result.len() > 1 && result[result.len() - 1] == 0 {
            result.pop();
        }

        Self { digits: result }
    }

    /// Modular exponentiation: base^exp mod modulus
    /// Using binary exponentiation (right-to-left)
    pub(crate) fn mod_exp(base: &Self, exp: &Self, modulus: &Self) -> Self {
        let mut result = Self::from_u32(1);
        let mut base = base.mod_reduce(modulus);
        let mut exp = exp.clone();

        while !exp.is_zero() {
            if exp.is_odd() {
                result = result.mul(&base).mod_reduce(modulus);
            }
            base = base.mul(&base).mod_reduce(modulus);
            exp = exp.shr_one();
        }

        result
    }

    /// Multiply two BigInts
    pub(crate) fn mul(&self, other: &Self) -> Self {
        let mut result = vec![0u32; self.digits.len() + other.digits.len()];

        for i in 0..self.digits.len() {
            let mut carry = 0u64;
            for j in 0..other.digits.len() {
                let prod = (self.digits[i] as u64) * (other.digits[j] as u64)
                    + (result[i + j] as u64)
                    + carry;
                result[i + j] = prod as u32;
                carry = prod >> 32;
            }
            result[i + other.digits.len()] = carry as u32;
        }

        // Remove leading zeros
        while result.len() > 1 && result[result.len() - 1] == 0 {
            result.pop();
        }

        Self { digits: result }
    }

    /// Modular reduction using division (efficient for large numbers)
    pub(crate) fn mod_reduce(&self, modulus: &Self) -> Self {
        // If self < modulus, no reduction needed
        if self.cmp(modulus) == Ordering::Less {
            return self.clone();
        }

        // Use long division algorithm: divide self by modulus, return remainder
        self.div_rem(modulus).1
    }

    /// Integer division: returns (quotient, remainder)
    /// Implements long division algorithm for BigInt
    pub(crate) fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        // Handle edge cases
        if divisor.is_zero() {
            panic!("Division by zero");
        }

        match self.cmp(divisor) {
            Ordering::Less => {
                // self < divisor: quotient = 0, remainder = self
                return (Self::from_u32(0), self.clone());
            }
            Ordering::Equal => {
                // self == divisor: quotient = 1, remainder = 0
                return (Self::from_u32(1), Self::from_u32(0));
            }
            Ordering::Greater => {
                // Continue with division
            }
        }

        // Long division algorithm
        let mut quotient = Self::from_u32(0);
        let mut remainder = Self::from_u32(0);

        // Process bits from most significant to least significant
        let self_bits = self.bit_length();

        for i in (0..self_bits).rev() {
            // Shift remainder left by 1
            remainder = remainder.shl_one();

            // Set the lowest bit of remainder to bit i of self
            if self.get_bit(i) {
                remainder = remainder.add_u32(1);
            }

            // If remainder >= divisor, subtract and set quotient bit
            if remainder.cmp(divisor) != Ordering::Less {
                remainder = remainder.sub(divisor);
                quotient = quotient.set_bit(i);
            }
        }

        (quotient, remainder)
    }

    /// Get the bit at position i (0 = least significant)
    fn get_bit(&self, i: usize) -> bool {
        let digit_idx = i / 32;
        let bit_idx = i % 32;

        if digit_idx >= self.digits.len() {
            return false;
        }

        ((self.digits[digit_idx] >> bit_idx) & 1) == 1
    }

    /// Set the bit at position i to 1
    fn set_bit(&self, i: usize) -> Self {
        let digit_idx = i / 32;
        let bit_idx = i % 32;

        let mut result = self.clone();

        // Extend digits if necessary
        while result.digits.len() <= digit_idx {
            result.digits.push(0);
        }

        result.digits[digit_idx] |= 1 << bit_idx;
        result
    }

    /// Count the number of bits in this number
    pub(crate) fn bit_length(&self) -> usize {
        if self.is_zero() {
            return 0;
        }

        let last_digit = self.digits[self.digits.len() - 1];
        let last_digit_bits = 32 - last_digit.leading_zeros() as usize;

        (self.digits.len() - 1) * 32 + last_digit_bits
    }

    /// Left shift by 1 bit (multiply by 2)
    fn shl_one(&self) -> Self {
        let mut result = vec![0u32; self.digits.len() + 1];
        let mut carry = 0u32;

        for i in 0..self.digits.len() {
            let digit = self.digits[i];
            result[i] = (digit << 1) | carry;
            carry = digit >> 31;
        }

        result[self.digits.len()] = carry;

        // Remove leading zeros
        while result.len() > 1 && result[result.len() - 1] == 0 {
            result.pop();
        }

        Self { digits: result }
    }

    /// Add a small u32 value
    fn add_u32(&self, value: u32) -> Self {
        let mut result = self.digits.clone();
        let mut carry = value as u64;

        for i in 0..result.len() {
            let sum = result[i] as u64 + carry;
            result[i] = sum as u32;
            carry = sum >> 32;

            if carry == 0 {
                break;
            }
        }

        if carry > 0 {
            result.push(carry as u32);
        }

        Self { digits: result }
    }

    /// Check if zero
    pub(crate) fn is_zero(&self) -> bool {
        self.digits.len() == 1 && self.digits[0] == 0
    }

    /// Check if odd
    pub(crate) fn is_odd(&self) -> bool {
        (self.digits[0] & 1) == 1
    }

    /// Right shift by 1 bit (divide by 2)
    fn shr_one(&self) -> Self {
        let mut result = vec![0u32; self.digits.len()];
        let mut carry = 0u32;

        for i in (0..self.digits.len()).rev() {
            let digit = self.digits[i];
            result[i] = (digit >> 1) | (carry << 31);
            carry = digit & 1;
        }

        // Remove leading zeros
        while result.len() > 1 && result[result.len() - 1] == 0 {
            result.pop();
        }

        Self { digits: result }
    }

    pub(crate) fn mod_sub(&self, other: &Self, modulus: &Self) -> Self {
        if self.cmp(other) == Ordering::Less {
            let diff = other.sub(self);
            modulus.sub(&diff)
        } else {
            self.sub(other)
        }
    }

    pub(crate) fn mod_mul(&self, other: &Self, modulus: &Self) -> Self {
        self.mul(other).mod_reduce(modulus)
    }

    pub(crate) fn mod_inv(&self, modulus: &Self) -> Option<Self> {
        if modulus.is_zero() {
            return None;
        }

        let mut r = modulus.clone();
        let mut new_r = self.mod_reduce(modulus);
        if new_r.is_zero() {
            return None;
        }

        let mut t = BigInt::from_u32(0);
        let mut new_t = BigInt::from_u32(1);

        while !new_r.is_zero() {
            let (quotient, remainder) = r.div_rem(&new_r);

            let temp_t = new_t.clone();
            let q_new_t = quotient.mul(&new_t);
            new_t = t.mod_sub(&q_new_t, modulus);
            t = temp_t;

            r = new_r;
            new_r = remainder;
        }

        if r.cmp(&BigInt::from_u32(1)) != Ordering::Equal {
            return None;
        }

        Some(t.mod_reduce(modulus))
    }
}

/// RSA public key
#[derive(Clone, Debug)]
pub struct RsaPublicKey {
    /// Modulus (n)
    n: BigInt,
    /// Public exponent (e)
    e: BigInt,
    /// Key size in bytes
    k: usize,
}

impl RsaPublicKey {
    /// Create from modulus and exponent bytes (big-endian)
    pub fn from_components(n_bytes: &[u8], e_bytes: &[u8]) -> Self {
        let n = BigInt::from_bytes_be(n_bytes);
        let e = BigInt::from_bytes_be(e_bytes);
        let k = n_bytes.len();

        Self { n, e, k }
    }

    /// Encrypt data using PKCS#1 v1.5 padding
    pub fn encrypt_pkcs1v15(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        // Check length constraint
        if data.len() > self.k - 11 {
            return Err(format!(
                "Data too long for key size: {} bytes, max {} bytes",
                data.len(),
                self.k - 11
            ));
        }

        // PKCS#1 v1.5 padding: 0x00 || 0x02 || PS || 0x00 || M
        // where PS is at least 8 random non-zero bytes

        let ps_len = self.k - data.len() - 3;
        if ps_len < 8 {
            return Err("Insufficient padding space".to_string());
        }

        let mut padded = vec![0u8; self.k];
        padded[0] = 0x00;
        padded[1] = 0x02;

        let mut rng = SecureRandom::new()
            .map_err(|e| format!("SecureRandom initialization failed: {}", e))?;
        let mut ps_index = 0usize;
        while ps_index < ps_len {
            let mut byte = [0u8; 1];
            rng.fill_bytes(&mut byte)
                .map_err(|e| format!("SecureRandom failure: {}", e))?;
            if byte[0] == 0 {
                continue; // padding must be non-zero
            }
            padded[2 + ps_index] = byte[0];
            ps_index += 1;
        }

        padded[2 + ps_len] = 0x00;
        padded[3 + ps_len..].copy_from_slice(data);

        // RSA encryption: ciphertext = plaintext^e mod n
        let m = BigInt::from_bytes_be(&padded);
        let c = BigInt::mod_exp(&m, &self.e, &self.n);

        let mut encrypted = c.to_bytes_be();

        // Ensure output is exactly k bytes (prepend zeros if needed)
        while encrypted.len() < self.k {
            encrypted.insert(0, 0);
        }

        Ok(encrypted)
    }

    pub fn verify_pkcs1_v15(
        &self,
        expected_digest_info: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        if signature.len() != self.k && signature.len() > self.k {
            return Err("Signature length larger than modulus size".to_string());
        }

        let sig_int = BigInt::from_bytes_be(signature);
        let decrypted = BigInt::mod_exp(&sig_int, &self.e, &self.n);
        let mut em = decrypted.to_bytes_be();
        if em.len() < self.k {
            let mut padded = vec![0u8; self.k - em.len()];
            padded.extend_from_slice(&em);
            em = padded;
        }

        if em.len() < expected_digest_info.len() + 11 {
            return Err("Decrypted signature too short".to_string());
        }

        if em[0] != 0x00 || em[1] != 0x01 {
            return Err("Invalid PKCS#1 padding header".to_string());
        }

        let mut index = 2;
        while index < em.len() && em[index] == 0xFF {
            index += 1;
        }

        if index >= em.len() || em[index] != 0x00 {
            return Err("Invalid PKCS#1 separator".to_string());
        }
        index += 1;

        let digest_region = &em[index..];
        if digest_region != expected_digest_info {
            return Err("DigestInfo mismatch".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bigint_from_bytes() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let big = BigInt::from_bytes_be(&bytes);
        assert_eq!(big.to_bytes_be(), bytes);
    }

    #[test]
    fn test_bigint_mul() {
        let a = BigInt::from_u32(123);
        let b = BigInt::from_u32(456);
        let result = a.mul(&b);
        assert_eq!(result, BigInt::from_u32(123 * 456));
    }

    #[test]
    fn test_bigint_mod_exp_small() {
        // 3^4 mod 5 = 81 mod 5 = 1
        let base = BigInt::from_u32(3);
        let exp = BigInt::from_u32(4);
        let modulus = BigInt::from_u32(5);
        let result = BigInt::mod_exp(&base, &exp, &modulus);
        assert_eq!(result, BigInt::from_u32(1));
    }

    #[test]
    fn test_rsa_key_creation() {
        // Small test key (not cryptographically secure, just for testing)
        let n = vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        let e = vec![0x01, 0x00, 0x01]; // 65537

        let key = RsaPublicKey::from_components(&n, &e);
        assert_eq!(key.k, 5);
    }
}
