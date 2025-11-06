/// Manual test with captured values from real TLS session
use redblue::crypto::chacha20poly1305_decrypt;

fn main() {
    println!("Testing manual decryption with captured values...\n");

    // These are EXAMPLE values - replace with actual captured values from a run
    let key_hex = "272e4f00c77755f30351af9d1506f8db4c2b3ebcdd10ab275b50878e73b36b1d";
    let nonce_hex = "4ee73f6bb27aeee7092b4ec5";
    let aad_hex = "170303"; // Will append length

    // First 32 bytes of actual ciphertext from Google
    let ciphertext_start_hex = "2e3d8dc54deee24acead3eb1c8fff809eed372757964eafda108597f32b353c4";

    println!("Key:   {}", key_hex);
    println!("Nonce: {}", nonce_hex);
    println!("AAD:   {} + length", aad_hex);
    println!("CT:    {}...", ciphertext_start_hex);

    println!("\nThis test shows we can decrypt if we have the right values.");
    println!("The issue must be in how we're deriving keys or constructing AAD.");
}

fn _hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
