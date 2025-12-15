#![allow(clippy::all)]

pub type FieldElement = [i64; 16];

const FE_ZERO: FieldElement = [0; 16];
const FE_ONE: FieldElement = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const FE_121665: FieldElement = [121665, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const BASEPOINT: [u8; 32] = {
    let mut bp = [0u8; 32];
    bp[0] = 9;
    bp
};

fn car25519(o: &mut FieldElement) {
    for i in 0..16 {
        o[i] += 1i64 << 16;
        let c = o[i] >> 16;
        if i < 15 {
            o[i + 1] += c - 1;
        } else {
            o[0] += (c - 1) * 38;
        }
        o[i] -= c << 16;
    }
}

fn sel25519(p: &mut FieldElement, q: &mut FieldElement, b: i64) {
    let c = !(b - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn pack25519(out: &mut [u8; 32], n: &FieldElement) {
    let mut t = *n;
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);

    let mut m = [0i64; 16];
    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let carry = (m[15] >> 16) & 1;
        m[15] &= 0xffff;
        sel25519(&mut t, &mut m, 1 - carry);
    }

    for i in 0..16 {
        out[2 * i] = (t[i] & 0xff) as u8;
        out[2 * i + 1] = ((t[i] >> 8) & 0xff) as u8;
    }
}

fn unpack25519(out: &mut FieldElement, input: &[u8; 32]) {
    for i in 0..16 {
        out[i] = input[2 * i] as i64 + ((input[2 * i + 1] as i64) << 8);
    }
    out[15] &= 0x7fff;
}

fn add25519(out: &mut FieldElement, a: &FieldElement, b: &FieldElement) {
    for i in 0..16 {
        out[i] = a[i] + b[i];
    }
}

fn sub25519(out: &mut FieldElement, a: &FieldElement, b: &FieldElement) {
    for i in 0..16 {
        out[i] = a[i] - b[i];
    }
}

fn mul25519(out: &mut FieldElement, a: &FieldElement, b: &FieldElement) {
    let mut t = [0i128; 31];
    for v in &mut t {
        *v = 0;
    }
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += (a[i] as i128) * (b[j] as i128);
        }
    }

    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut tmp = [0i64; 16];
    for i in 0..16 {
        debug_assert!(t[i] <= i64::MAX as i128 && t[i] >= i64::MIN as i128);
        tmp[i] = t[i] as i64;
    }
    car25519(&mut tmp);
    car25519(&mut tmp);
    out.copy_from_slice(&tmp);
}

fn square25519(out: &mut FieldElement, a: &FieldElement) {
    mul25519(out, a, a);
}

fn mult121665(out: &mut FieldElement, a: &FieldElement) {
    mul25519(out, a, &FE_121665);
}

fn inv25519(out: &mut FieldElement, input: &FieldElement) {
    let mut c = *input;
    for a in (0..=253).rev() {
        let tmp = c;
        square25519(&mut c, &tmp);
        if a != 2 && a != 4 {
            let tmp = c;
            mul25519(&mut c, &tmp, input);
        }
    }
    out.copy_from_slice(&c);
}

fn scalarmult(out: &mut [u8; 32], scalar: &[u8; 32], point: &[u8; 32]) {
    let mut z = *scalar;
    z[0] &= 248;
    z[31] &= 127;
    z[31] |= 64;

    let mut x1 = [0i64; 16];
    unpack25519(&mut x1, point);

    let mut x2 = FE_ONE;
    let mut z2 = FE_ZERO;
    let mut x3 = x1;
    let mut z3 = FE_ONE;

    let mut a = [0i64; 16];
    let mut b = [0i64; 16];
    let mut c = [0i64; 16];
    let mut d = [0i64; 16];
    let mut da = [0i64; 16];
    let mut cb = [0i64; 16];
    let mut tmp = [0i64; 16];
    let mut aa = [0i64; 16];
    let mut bb = [0i64; 16];
    let mut e = [0i64; 16];
    let mut tmp2 = [0i64; 16];

    let mut swap = 0i64;
    for pos in (0..=254).rev() {
        let bit = ((z[pos >> 3] >> (pos & 7)) & 1) as i64;
        swap ^= bit;
        sel25519(&mut x2, &mut x3, swap);
        sel25519(&mut z2, &mut z3, swap);
        swap = bit;

        add25519(&mut a, &x2, &z2); // A = X2 + Z2
        sub25519(&mut b, &x2, &z2); // B = X2 - Z2
        add25519(&mut c, &x3, &z3); // C = X3 + Z3
        sub25519(&mut d, &x3, &z3); // D = X3 - Z3

        mul25519(&mut da, &d, &a); // DA = D * A
        mul25519(&mut cb, &c, &b); // CB = C * B

        add25519(&mut tmp, &da, &cb); // DA + CB
        let tmp_copy = tmp;
        square25519(&mut x3, &tmp_copy);

        sub25519(&mut tmp, &da, &cb); // DA - CB
        let tmp_copy = tmp;
        square25519(&mut tmp, &tmp_copy);
        mul25519(&mut z3, &tmp, &x1); // Z3 = X1 * (DA - CB)^2

        square25519(&mut aa, &a); // AA = A^2
        square25519(&mut bb, &b); // BB = B^2
        mul25519(&mut x2, &aa, &bb); // X2 = AA * BB

        sub25519(&mut e, &aa, &bb); // E = AA - BB
        mult121665(&mut tmp, &e); // tmp = 121665 * E
        add25519(&mut tmp2, &tmp, &aa); // tmp2 = AA + 121665 * E
        mul25519(&mut z2, &e, &tmp2); // Z2 = E * tmp2
    }

    sel25519(&mut x2, &mut x3, swap);
    sel25519(&mut z2, &mut z3, swap);

    let mut z2_inv = [0i64; 16];
    inv25519(&mut z2_inv, &z2);
    let x2_copy = x2;
    mul25519(&mut x2, &x2_copy, &z2_inv);

    pack25519(out, &x2);
}

fn scalarmult_base(out: &mut [u8; 32], scalar: &[u8; 32]) {
    scalarmult(out, scalar, &BASEPOINT);
}

/// Compute X25519 shared secret using pure Rust implementation
pub fn x25519(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    let mut shared_secret = [0u8; 32];
    scalarmult(&mut shared_secret, private_key, public_key);
    shared_secret
}

/// Compute X25519 public key from private key using pure Rust implementation
pub fn x25519_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let mut public_key = [0u8; 32];
    scalarmult_base(&mut public_key, private_key);
    public_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_roundtrip() {
        let mut basepoint = [0u8; 32];
        basepoint[0] = 9;
        let mut fe = [0i64; 16];
        unpack25519(&mut fe, &basepoint);
        let mut encoded = [0u8; 32];
        pack25519(&mut encoded, &fe);
        assert_eq!(encoded, basepoint);
    }

    #[test]
    fn test_sel_no_swap() {
        let mut p = [1i64; 16];
        let mut q = [2i64; 16];
        sel25519(&mut p, &mut q, 0);
        assert_eq!(p, [1i64; 16]);
        assert_eq!(q, [2i64; 16]);
        sel25519(&mut p, &mut q, 1);
        assert_eq!(p, [2i64; 16]);
        assert_eq!(q, [1i64; 16]);
    }
}
