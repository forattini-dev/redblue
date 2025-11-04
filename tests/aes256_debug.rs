/// Debug AES-256 step by step to find where we diverge from FIPS-197
/// This will show the state after each transformation

fn hex_decode(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .flat_map(|s| {
            (0..s.len())
                .step_by(2)
                .map(move |i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        })
        .collect()
}

fn print_state(label: &str, state: &[u8; 16]) {
    println!(
        "{}: {}",
        label,
        state
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    // Also print as 4x4 matrix (column-major format)
    println!("  Matrix (column-major):");
    for row in 0..4 {
        print!("  ");
        for col in 0..4 {
            print!("{:02x} ", state[col * 4 + row]);
        }
        println!();
    }
}

// Copy the SBOX and other constants we need
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn gmul(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut a = a;
    let mut b = b;

    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi_bit_set = a & 0x80 != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1b; // AES irreducible polynomial
        }
        b >>= 1;
    }
    p
}

fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    // Row 1: shift left by 1
    let temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 2: shift left by 2
    let temp1 = state[2];
    let temp2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = temp1;
    state[14] = temp2;

    // Row 3: shift left by 3
    let temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

fn mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let s0 = state[i * 4];
        let s1 = state[i * 4 + 1];
        let s2 = state[i * 4 + 2];
        let s3 = state[i * 4 + 3];

        state[i * 4] = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3;
        state[i * 4 + 1] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3;
        state[i * 4 + 2] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3);
        state[i * 4 + 3] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2);
    }
}

fn aes256_key_expansion_debug(key: &[u8; 32]) -> Vec<u8> {
    let mut expanded = vec![0u8; 240];
    expanded[..32].copy_from_slice(key);

    println!("\n=== KEY EXPANSION DEBUG ===");
    println!(
        "Original key (32 bytes): {}",
        key.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    );

    let mut rcon = 1u8;

    for i in 8..60 {
        let word_offset = i * 4;
        let prev_word_offset = (i - 1) * 4;

        if i % 8 == 0 {
            let mut temp = [
                expanded[prev_word_offset + 1],
                expanded[prev_word_offset + 2],
                expanded[prev_word_offset + 3],
                expanded[prev_word_offset + 0],
            ];

            for byte in &mut temp {
                *byte = SBOX[*byte as usize];
            }

            for j in 0..4 {
                expanded[word_offset + j] = expanded[word_offset - 32 + j] ^ temp[j];
                if j == 0 {
                    expanded[word_offset + j] ^= rcon;
                }
            }

            if i == 8 {
                println!(
                    "Word {}: {:02x}{:02x}{:02x}{:02x} (RotWord+SubWord+Rcon={:02x})",
                    i,
                    expanded[word_offset],
                    expanded[word_offset + 1],
                    expanded[word_offset + 2],
                    expanded[word_offset + 3],
                    rcon
                );
            }

            rcon = gmul(rcon, 0x02);
        } else if i % 8 == 4 {
            let mut temp = [
                expanded[prev_word_offset + 0],
                expanded[prev_word_offset + 1],
                expanded[prev_word_offset + 2],
                expanded[prev_word_offset + 3],
            ];

            for byte in &mut temp {
                *byte = SBOX[*byte as usize];
            }

            for j in 0..4 {
                expanded[word_offset + j] = expanded[word_offset - 32 + j] ^ temp[j];
            }

            if i == 12 {
                println!(
                    "Word {}: {:02x}{:02x}{:02x}{:02x} (SubWord only)",
                    i,
                    expanded[word_offset],
                    expanded[word_offset + 1],
                    expanded[word_offset + 2],
                    expanded[word_offset + 3]
                );
            }
        } else {
            for j in 0..4 {
                expanded[word_offset + j] =
                    expanded[word_offset - 4 + j] ^ expanded[word_offset - 32 + j];
            }
        }
    }

    println!(
        "Round 0 key: {}",
        expanded[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!(
        "Round 1 key: {}",
        expanded[16..32]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    expanded
}

#[test]
fn test_aes256_debug_encryption() {
    println!("\n🔍 AES-256 DEBUG ENCRYPTION");
    println!("   FIPS-197 Appendix C.3 Test Vector\n");

    // FIPS-197 test vector
    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let plaintext_hex = "00112233445566778899aabbccddeeff";
    let expected_hex = "8ea2b7ca516745bfeafc49904b496089";

    let key_vec = hex_decode(key_hex);
    let plaintext_vec = hex_decode(plaintext_hex);
    let expected = hex_decode(expected_hex);

    let mut key = [0u8; 32];
    let mut state = [0u8; 16];
    key.copy_from_slice(&key_vec);
    state.copy_from_slice(&plaintext_vec);

    println!("Key:       {}", key_hex);
    println!("Plaintext: {}", plaintext_hex);
    println!("Expected:  {}", expected_hex);

    let expanded_key = aes256_key_expansion_debug(&key);

    println!("\n=== ENCRYPTION ROUNDS ===");
    print_state("Initial state", &state);

    // Initial AddRoundKey
    for i in 0..16 {
        state[i] ^= expanded_key[i];
    }
    print_state("After initial AddRoundKey", &state);

    // Main rounds (1-13)
    for round in 1..14 {
        println!("\n--- Round {} ---", round);

        sub_bytes(&mut state);
        print_state("After SubBytes", &state);

        shift_rows(&mut state);
        print_state("After ShiftRows", &state);

        mix_columns(&mut state);
        print_state("After MixColumns", &state);

        let round_key_offset = round * 16;
        for i in 0..16 {
            state[i] ^= expanded_key[round_key_offset + i];
        }
        print_state("After AddRoundKey", &state);

        // Only print first and last rounds in detail
        if round > 1 && round < 13 {
            println!("(rounds 2-12 details omitted for brevity)");
            if round == 2 {
                continue;
            }
            if round < 13 {
                // Fast-forward: apply remaining transformations without printing
                for r in (round + 1)..13 {
                    sub_bytes(&mut state);
                    shift_rows(&mut state);
                    mix_columns(&mut state);
                    let rk_offset = r * 16;
                    for i in 0..16 {
                        state[i] ^= expanded_key[rk_offset + i];
                    }
                }
                break;
            }
        }
    }

    // Final round (no MixColumns)
    println!("\n--- Final Round (14) ---");
    sub_bytes(&mut state);
    print_state("After SubBytes", &state);

    shift_rows(&mut state);
    print_state("After ShiftRows", &state);

    for i in 0..16 {
        state[i] ^= expanded_key[224 + i];
    }
    print_state("After AddRoundKey (final)", &state);

    println!("\n=== RESULT ===");
    let computed_hex: String = state.iter().map(|b| format!("{:02x}", b)).collect();
    println!("Expected:  {}", expected_hex);
    println!("Computed:  {}", computed_hex);

    if state.as_slice() == &expected[..] {
        println!("\n✅ SUCCESS!");
    } else {
        println!("\n❌ FAILED - Byte-by-byte comparison:");
        for (i, (exp, got)) in expected.iter().zip(state.iter()).enumerate() {
            let marker = if exp == got { "✓" } else { "❌" };
            println!(
                "  Byte {}: expected {:02x}, got {:02x} {}",
                i, exp, got, marker
            );
        }
        panic!("AES-256 test failed!");
    }
}
