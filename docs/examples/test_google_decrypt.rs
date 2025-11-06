fn hex_decode(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .flat_map(|s| {
            (0..s.len())
                .step_by(2)
                .map(move |i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        })
        .collect()
}

fn main() {
    println!("🔍 Testing Google's TLS 1.3 Encrypted Handshake\n");

    // From debug output
    let key_hex = "19 d7 0a 72 de f7 cf 11 fa a3 80 14 a8 e0 ba 1d \
                   25 62 f7 6c 41 a5 0d 54 ce b9 c9 41 fc 11 87 b0";
    let iv_hex = "5f 01 d4 6a 23 3e cc 9d 5a a6 84 a9";
    let aad_hex = "17 03 03 19 72";

    // First 80 bytes of ciphertext (includes some ciphertext + will add tag separately)
    let ciphertext_start_hex = "0b 1e 0b 91 e9 f0 f7 05 45 8f ad e5 f4 23 76 14 \
                                 ed 3d 01 7f 1e 6b 21 bb e8 4f 07 e5 b7 4c 9d 73 \
                                 54 21 0b 13 73 7c c6 0e d9 c3 9f aa ca e0 23 ba \
                                 b5 4b 4f b7 30 ab 2d 69 c4 91 0b 7a 3b ba 68 87";

    // Last 32 bytes (includes tag at the end)
    let ciphertext_end_hex = "bb 96 7b ee a6 94 3c 53 1f 88 3f 75 0b 41 58 d3 \
                               bf 49 ec 9e 5a 11 76 ad 14 04 da 84 f6 84 f1 93";

    let key = hex_decode(key_hex);
    let iv = hex_decode(iv_hex);
    let aad = hex_decode(aad_hex);

    println!("Key: {} bytes", key.len());
    println!("IV: {} bytes", iv.len());
    println!("AAD: {:02x?}", aad);
    println!();

    // Construct nonce (sequence 0)
    let seq = 0u64;
    let mut nonce = iv.clone();
    for i in 0..8 {
        nonce[12 - 8 + i] ^= ((seq >> (56 - i * 8)) & 0xff) as u8;
    }
    println!("Nonce (seq=0): {:02x?}", nonce);
    println!();

    // We need the FULL ciphertext. For now, let's just test with what we know
    // The actual ciphertext is 6514 bytes, but let's test with the first + last bytes
    println!("⚠️  Cannot test without full ciphertext");
    println!("    Need all 6514 bytes from Google's response");
    println!();

    println!("Expected behavior:");
    println!("  - Ciphertext length: 6514 bytes (6498 plaintext + 16 tag)");
    println!("  - AAD: [17, 03, 03, 19, 72]");
    println!("  - Nonce: IV XOR (seq_num padded to 12 bytes)");
    println!("  - For seq=0: nonce = IV");
}
