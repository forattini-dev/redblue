/// Test Galois Field multiplication (gmul) used in AES MixColumns

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

#[test]
fn test_gmul_basic() {
    println!("\n🧮 Galois Field Multiplication Test\n");

    // Known test vectors from AES specification
    println!("Basic multiplication tests:");

    // gmul(2, x) is just x << 1 with reduction
    assert_eq!(gmul(0x57, 0x02), 0xae, "gmul(0x57, 2) should be 0xae");
    assert_eq!(gmul(0xae, 0x02), 0x47, "gmul(0xae, 2) should be 0x47");

    // gmul(3, x) = gmul(2, x) XOR x
    assert_eq!(gmul(0x57, 0x03), 0xf9, "gmul(0x57, 3) should be 0xf9");

    println!("  gmul(0x57, 2) = 0x{:02x} ✓", gmul(0x57, 0x02));
    println!("  gmul(0xae, 2) = 0x{:02x} ✓", gmul(0xae, 0x02));
    println!("  gmul(0x57, 3) = 0x{:02x} ✓", gmul(0x57, 0x03));

    println!("\n✅ Basic gmul tests passed!");
}

#[test]
fn test_mixcolumns_computation() {
    println!("\n🔀 MixColumns Detailed Computation\n");

    // FIPS-197 example: [db, 13, 53, 45] -> [8e, 4d, a1, bc]
    let s0 = 0xdb;
    let s1 = 0x13;
    let s2 = 0x53;
    let s3 = 0x45;

    println!("Input column: {:02x} {:02x} {:02x} {:02x}", s0, s1, s2, s3);
    println!("Expected output: 8e 4d a1 bc\n");

    // First output byte: 2*s0 + 3*s1 + s2 + s3
    println!("Computing output[0] = gmul(s0,2) ^ gmul(s1,3) ^ s2 ^ s3:");
    let term1 = gmul(s0, 2);
    let term2 = gmul(s1, 3);
    println!("  gmul(0x{:02x}, 2) = 0x{:02x}", s0, term1);
    println!("  gmul(0x{:02x}, 3) = 0x{:02x}", s1, term2);
    println!("  s2 = 0x{:02x}", s2);
    println!("  s3 = 0x{:02x}", s3);
    let out0 = term1 ^ term2 ^ s2 ^ s3;
    println!(
        "  Result: 0x{:02x} ^ 0x{:02x} ^ 0x{:02x} ^ 0x{:02x} = 0x{:02x}",
        term1, term2, s2, s3, out0
    );
    println!(
        "  Expected: 0x8e, Got: 0x{:02x} {}",
        out0,
        if out0 == 0x8e { "✓" } else { "❌" }
    );

    // Second output byte: s0 + 2*s1 + 3*s2 + s3
    println!("\nComputing output[1] = s0 ^ gmul(s1,2) ^ gmul(s2,3) ^ s3:");
    let term1 = gmul(s1, 2);
    let term2 = gmul(s2, 3);
    println!("  s0 = 0x{:02x}", s0);
    println!("  gmul(0x{:02x}, 2) = 0x{:02x}", s1, term1);
    println!("  gmul(0x{:02x}, 3) = 0x{:02x}", s2, term2);
    println!("  s3 = 0x{:02x}", s3);
    let out1 = s0 ^ term1 ^ term2 ^ s3;
    println!(
        "  Result: 0x{:02x} ^ 0x{:02x} ^ 0x{:02x} ^ 0x{:02x} = 0x{:02x}",
        s0, term1, term2, s3, out1
    );
    println!(
        "  Expected: 0x4d, Got: 0x{:02x} {}",
        out1,
        if out1 == 0x4d { "✓" } else { "❌" }
    );

    // Third output byte: s0 + s1 + 2*s2 + 3*s3
    println!("\nComputing output[2] = s0 ^ s1 ^ gmul(s2,2) ^ gmul(s3,3):");
    let term1 = gmul(s2, 2);
    let term2 = gmul(s3, 3);
    println!("  s0 = 0x{:02x}", s0);
    println!("  s1 = 0x{:02x}", s1);
    println!("  gmul(0x{:02x}, 2) = 0x{:02x}", s2, term1);
    println!("  gmul(0x{:02x}, 3) = 0x{:02x}", s3, term2);
    let out2 = s0 ^ s1 ^ term1 ^ term2;
    println!(
        "  Result: 0x{:02x} ^ 0x{:02x} ^ 0x{:02x} ^ 0x{:02x} = 0x{:02x}",
        s0, s1, term1, term2, out2
    );
    println!(
        "  Expected: 0xa1, Got: 0x{:02x} {}",
        out2,
        if out2 == 0xa1 { "✓" } else { "❌" }
    );

    // Fourth output byte: 3*s0 + s1 + s2 + 2*s3
    println!("\nComputing output[3] = gmul(s0,3) ^ s1 ^ s2 ^ gmul(s3,2):");
    let term1 = gmul(s0, 3);
    let term2 = gmul(s3, 2);
    println!("  gmul(0x{:02x}, 3) = 0x{:02x}", s0, term1);
    println!("  s1 = 0x{:02x}", s1);
    println!("  s2 = 0x{:02x}", s2);
    println!("  gmul(0x{:02x}, 2) = 0x{:02x}", s3, term2);
    let out3 = term1 ^ s1 ^ s2 ^ term2;
    println!(
        "  Result: 0x{:02x} ^ 0x{:02x} ^ 0x{:02x} ^ 0x{:02x} = 0x{:02x}",
        term1, s1, s2, term2, out3
    );
    println!(
        "  Expected: 0xbc, Got: 0x{:02x} {}",
        out3,
        if out3 == 0xbc { "✓" } else { "❌" }
    );

    println!(
        "\nFinal result: {:02x} {:02x} {:02x} {:02x}",
        out0, out1, out2, out3
    );
    println!("Expected:     8e 4d a1 bc");

    assert_eq!(out0, 0x8e);
    assert_eq!(out1, 0x4d);
    assert_eq!(out2, 0xa1);
    assert_eq!(out3, 0xbc);

    println!("\n✅ MixColumns computation is CORRECT!");
}

#[test]
fn test_gmul_by_2() {
    println!("\n✖️  Testing gmul(x, 2) for all values\n");

    // Test a few specific cases
    let test_cases = vec![
        (0xdb, 0xb6), // From FIPS-197
        (0x13, 0x26),
        (0x53, 0xa6),
        (0x45, 0x8a),
    ];

    for (input, expected) in test_cases {
        let result = gmul(input, 2);
        println!(
            "  gmul(0x{:02x}, 2) = 0x{:02x} (expected 0x{:02x}) {}",
            input,
            result,
            expected,
            if result == expected { "✓" } else { "❌" }
        );
        assert_eq!(result, expected, "gmul(0x{:02x}, 2) failed", input);
    }

    println!("\n✅ gmul(x, 2) is correct!");
}

#[test]
fn test_gmul_by_3() {
    println!("\n✖️  Testing gmul(x, 3) for specific values\n");

    // gmul(x, 3) = gmul(x, 2) XOR x
    let test_cases = vec![
        (0xdb, 0x6d), // gmul(0xdb, 2) ^ 0xdb = 0xb6 ^ 0xdb = 0x6d
        (0x13, 0x35), // gmul(0x13, 2) ^ 0x13 = 0x26 ^ 0x13 = 0x35
        (0x53, 0xf5), // gmul(0x53, 2) ^ 0x53 = 0xa6 ^ 0x53 = 0xf5
        (0x45, 0xcf), // gmul(0x45, 2) ^ 0x45 = 0x8a ^ 0x45 = 0xcf
    ];

    for (input, expected) in test_cases {
        let result = gmul(input, 3);
        let check = gmul(input, 2) ^ input;
        println!(
            "  gmul(0x{:02x}, 3) = 0x{:02x} (expected 0x{:02x}) {}",
            input,
            result,
            expected,
            if result == expected { "✓" } else { "❌" }
        );
        println!(
            "    Verification: gmul(0x{:02x}, 2) ^ 0x{:02x} = 0x{:02x} ^ 0x{:02x} = 0x{:02x}",
            input,
            input,
            gmul(input, 2),
            input,
            check
        );
        assert_eq!(result, expected, "gmul(0x{:02x}, 3) failed", input);
        assert_eq!(result, check, "gmul(x,3) should equal gmul(x,2) XOR x");
    }

    println!("\n✅ gmul(x, 3) is correct!");
}
