# HKDF Bug Analysis - Initial Key Derivation Mismatch

## Problem Identified

Server rejects our Initial packet with "authentication failed". Root cause: our HKDF derivation produces **different keys** than RFC 9001 Appendix A.

## Test Results (RFC 9001 Appendix A.1)

**Input DCID:** `8394c8f03e515708` (8 bytes)

### Our Implementation Output:
```
Initial Secret:        7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44
Client Initial Secret: e3b09cca423d9bcb50de2e453552aff0b684108c398581b28c3e5502a638c8af
Client Key:            c47f9b1d4244f7b2d4e94339b83141fc
Client IV:             43034542cd984298c19761f1
Client HP:             a4ef1c087665acadb9c74195ec2478dc
```

### RFC 9001 Expected Values:
```
Initial Secret:        ??? (not in Appendix A, need to check)
Client Initial Secret: c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea
Client Key:            1f369613dd76d5467730efcbe3b1a22d
Client IV:             fa044b2f42a3fd3b46fb255c
Client HP:             9f50449e04a0e810283a1e9933adedd2
```

### Comparison:
| Value | Ours | Expected | Match? |
|-------|------|----------|--------|
| Initial Secret | `7db5df...` | `???` | ❌ Different |
| Client Secret | `e3b09c...` | `c00cf1...` | ❌ Different |
| Client Key | `c47f9b...` | `1f3696...` | ❌ Different |
| Client IV | `430345...` | `fa044b...` | ❌ Different |
| Client HP | `a4ef1c...` | `9f5044...` | ❌ Different |

## Root Cause Analysis

The **Initial Secret** (from HKDF-Extract) is already wrong, which means:
- Either the **INITIAL_SALT_V1** is incorrect
- Or our **HKDF-Extract** implementation has a bug
- Or we're passing the wrong DCID

### HKDF-Extract Formula (RFC 5869):
```
PRK = HMAC-Hash(salt, IKM)
```

For QUIC Initial keys (RFC 9001 §5.2):
```
initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
```

### Our Constants:
```rust
pub const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
```

This matches RFC 9001! ✅

### Our HKDF-Extract (src/crypto/hkdf.rs):
```rust
pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 32] {
    match salt {
        Some(s) => hmac_sha256(s, ikm),
        None => {
            let zero_salt = [0u8; 32];
            hmac_sha256(&zero_salt, ikm)
        }
    }
}
```

Wait... our HKDF tests pass! So basic HKDF is correct.

## Next Steps

1. ✅ Verify INITIAL_SALT_V1 matches RFC 9001 (already confirmed)
2. ✅ Test HKDF with RFC 5869 test vectors (already passing)
3. 🔍 **Check RFC 9001 Appendix A** for Initial Secret expected value
4. 🔍 Debug HKDF-Expand-Label - maybe "quic " prefix issue?
5. 🔍 Compare byte-by-byte with Quinn's implementation

## Hypothesis

Given that:
- RFC 5869 HKDF tests pass ✅
- INITIAL_SALT_V1 is correct ✅
- But Initial Secret is wrong ❌

The bug is likely in `quic_hkdf_expand_label()` - the QUIC-specific wrapper that adds "quic " prefix.

**Action:** Need to check RFC 9001 Appendix A to see if there's an expected Initial Secret value to verify HKDF-Extract first.
