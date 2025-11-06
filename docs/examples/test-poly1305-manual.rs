/// Manual Poly1305 test to find the bug
/// We'll implement a minimal version step by step

fn main() {
    // RFC 8439 Section 2.5.2 test
    let key_hex = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b";
    let msg = b"Cryptographic Forum Research Group";

    println!("Testing Poly1305 with RFC 8439 Section 2.5.2 test vector");
    println!("Message: {:?}", std::str::from_utf8(msg).unwrap());

    let key = hex_decode(key_hex);

    // Step 1: Extract and clamp r
    let mut r_bytes = [0u8; 16];
    r_bytes.copy_from_slice(&key[0..16]);

    println!("\nBefore clamping:");
    println!("r_bytes: {:02x?}", r_bytes);

    // Clamp per RFC 8439
    r_bytes[3] &= 15;
    r_bytes[7] &= 15;
    r_bytes[11] &= 15;
    r_bytes[15] &= 15;
    r_bytes[4] &= 252;
    r_bytes[8] &= 252;
    r_bytes[12] &= 252;

    println!("\nAfter clamping:");
    println!("r_bytes: {:02x?}", r_bytes);

    // Convert to u32
    let r0 = u32::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3]]);
    let r1 = u32::from_le_bytes([r_bytes[4], r_bytes[5], r_bytes[6], r_bytes[7]]);
    let r2 = u32::from_le_bytes([r_bytes[8], r_bytes[9], r_bytes[10], r_bytes[11]]);
    let r3 = u32::from_le_bytes([r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15]]);

    println!("\nr as u32 words:");
    println!("r[0] = 0x{:08x}", r0);
    println!("r[1] = 0x{:08x}", r1);
    println!("r[2] = 0x{:08x}", r2);
    println!("r[3] = 0x{:08x}", r3);

    // Step 2: Extract s
    let s0 = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
    let s1 = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
    let s2 = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
    let s3 = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);

    println!("\ns as u32 words:");
    println!("s[0] = 0x{:08x}", s0);
    println!("s[1] = 0x{:08x}", s1);
    println!("s[2] = 0x{:08x}", s2);
    println!("s[3] = 0x{:08x}", s3);

    println!("\nExpected tag: a8061dc1305136c6c22b8baf0c0127a9");
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
