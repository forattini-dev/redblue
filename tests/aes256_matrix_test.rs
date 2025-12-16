/// Test to verify AES matrix interpretation (row-major vs column-major)
/// AES specification uses COLUMN-MAJOR order for state matrix

#[test]
fn test_aes_state_matrix_interpretation() {
    println!("\n📐 AES State Matrix Interpretation Test\n");

    // FIPS-197 plaintext: 00112233445566778899aabbccddeeff
    let plaintext = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    println!("Plaintext bytes (linear): {:02x?}", plaintext);

    // AES state matrix is in COLUMN-MAJOR order!
    // This means: state[col*4 + row]
    println!("\nFIPS-197 says the state matrix should be:");
    println!("  00 44 88 cc");
    println!("  11 55 99 dd");
    println!("  22 66 aa ee");
    println!("  33 77 bb ff");

    println!("\nOur interpretation (column-major, state[col*4 + row]):");
    for row in 0..4 {
        print!("  ");
        for col in 0..4 {
            print!("{:02x} ", plaintext[col * 4 + row]);
        }
        println!();
    }

    println!("\nROW-MAJOR interpretation (state[row*4 + col]) - WRONG for AES:");
    for row in 0..4 {
        print!("  ");
        for col in 0..4 {
            print!("{:02x} ", plaintext[row * 4 + col]);
        }
        println!();
    }

    // Verify our column-major interpretation matches FIPS-197
    assert_eq!(plaintext[0], 0x00); // Column 0, Row 0
    assert_eq!(plaintext[1], 0x11); // Column 0, Row 1
    assert_eq!(plaintext[2], 0x22); // Column 0, Row 2
    assert_eq!(plaintext[3], 0x33); // Column 0, Row 3

    assert_eq!(plaintext[1 * 4 + 0], 0x44); // Column 1, Row 0
    assert_eq!(plaintext[1 * 4 + 1], 0x55); // Column 1, Row 1

    assert_eq!(plaintext[3 * 4 + 3], 0xff); // Column 3, Row 3

    println!("\n✅ Column-major interpretation is CORRECT!");
}

#[test]
fn test_shiftrows_interpretation() {
    println!("\n🔄 ShiftRows Transformation Test\n");

    // After initial AddRoundKey: 00 10 20 30 40 50 60 70 80 90 a0 b0 c0 d0 e0 f0
    let mut state = [
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
        0xf0,
    ];

    println!("Before ShiftRows:");
    println!("  Linear: {:02x?}", state);
    println!("  Matrix (column-major):");
    for row in 0..4 {
        print!("  ");
        for col in 0..4 {
            print!("{:02x} ", state[col * 4 + row]);
        }
        println!();
    }

    // ShiftRows operates on ROWS:
    // Row 0: no shift
    // Row 1: shift left by 1
    // Row 2: shift left by 2
    // Row 3: shift left by 3

    // Current implementation
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

    println!("\nAfter ShiftRows:");
    println!("  Linear: {:02x?}", state);
    println!("  Matrix (column-major):");
    for row in 0..4 {
        print!("  ");
        for col in 0..4 {
            print!("{:02x} ", state[col * 4 + row]);
        }
        println!();
    }

    println!("\nExpected after ShiftRows:");
    println!("  00 40 80 c0  (Row 0 unchanged)");
    println!("  50 90 d0 10  (Row 1 shifted left by 1)");
    println!("  a0 e0 20 60  (Row 2 shifted left by 2)");
    println!("  f0 30 70 b0  (Row 3 shifted left by 3)");

    // Verify
    // Row 0: 00 40 80 c0
    assert_eq!(state[0 * 4 + 0], 0x00);
    assert_eq!(state[1 * 4 + 0], 0x40);
    assert_eq!(state[2 * 4 + 0], 0x80);
    assert_eq!(state[3 * 4 + 0], 0xc0);

    // Row 1: 50 90 d0 10
    assert_eq!(state[0 * 4 + 1], 0x50, "Row 1, Col 0 should be 0x50");
    assert_eq!(state[1 * 4 + 1], 0x90, "Row 1, Col 1 should be 0x90");
    assert_eq!(state[2 * 4 + 1], 0xd0, "Row 1, Col 2 should be 0xd0");
    assert_eq!(state[3 * 4 + 1], 0x10, "Row 1, Col 3 should be 0x10");

    println!("\n✅ ShiftRows is CORRECT!");
}

#[test]
fn test_mixcolumns_single_column() {
    println!("\n🔀 MixColumns Single Column Test\n");

    // Test MixColumns on a single column
    // Example from FIPS-197: column [db, 13, 53, 45] -> [8e, 4d, a1, bc]

    let mut state = [
        0xdb, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x53, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00,
        0x00,
    ];

    println!("Input column 0: db 13 53 45");
    println!("Expected output: 8e 4d a1 bc");

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
                a ^= 0x1b;
            }
            b >>= 1;
        }
        p
    }

    // Apply MixColumns to column 0
    let s0 = state[0];
    let s1 = state[1];
    let s2 = state[2];
    let s3 = state[3];

    state[0] = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3;
    state[1] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3;
    state[2] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3);
    state[3] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2);

    println!(
        "Computed output: {:02x} {:02x} {:02x} {:02x}",
        state[0], state[1], state[2], state[3]
    );

    assert_eq!(state[0], 0x8e, "MixColumns[0] should be 0x8e");
    assert_eq!(state[1], 0x4d, "MixColumns[1] should be 0x4d");
    assert_eq!(state[2], 0xa1, "MixColumns[2] should be 0xa1");
    assert_eq!(state[3], 0xbc, "MixColumns[3] should be 0xbc");

    println!("\n✅ MixColumns computation is CORRECT!");
}
