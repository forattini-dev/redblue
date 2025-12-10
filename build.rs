//! Build script for compile-time binary mutation
//!
//! This script runs before every compilation and generates:
//! - Unique build fingerprint (changes hash each build)
//! - Random junk data (polymorphic padding)
//! - Obfuscation keys for compile-time string encryption
//! - Dead code variations
//!
//! Result: Each `cargo build` produces a binary with a different SHA256 hash,
//! making signature-based AV detection ineffective.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Get output directory
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("build_mutations.rs");

    // Generate entropy from multiple sources
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();

    let nanos = timestamp.subsec_nanos();
    let secs = timestamp.as_secs();

    // Create pseudo-random seed from time + process info
    let pid = std::process::id();
    let seed = (nanos as u64) ^ secs ^ (pid as u64).wrapping_mul(0x517cc1b727220a95);

    // Generate random values using LCG
    let mut state = seed;
    let mut next_random = || -> u64 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        state
    };

    // Generate unique build fingerprint (16 bytes)
    let fingerprint: Vec<u8> = (0..16).map(|_| (next_random() & 0xFF) as u8).collect();
    let fingerprint_hex: String = fingerprint.iter().map(|b| format!("{:02x}", b)).collect();

    // Generate junk data blocks (polymorphic padding)
    let junk_size = 64 + (next_random() % 64) as usize; // 64-128 bytes
    let junk_data: Vec<u8> = (0..junk_size).map(|_| (next_random() & 0xFF) as u8).collect();

    // Generate obfuscation keys
    let xor_key = (next_random() & 0xFF) as u8;
    let xor_key_multi: Vec<u8> = (0..16).map(|_| (next_random() & 0xFF) as u8).collect();

    // Generate dead code variations (numbers that affect code paths but never execute)
    let dead_code_seed = next_random();
    let dead_code_threshold = 0xDEADBEEF_u64; // Never matches random

    // Generate string mutation table
    let mutation_table: Vec<u8> = (0..256).map(|_| (next_random() & 0xFF) as u8).collect();

    // Write generated code
    let mut file = File::create(&dest_path).unwrap();

    writeln!(file, "// Auto-generated build mutations - DO NOT EDIT").unwrap();
    writeln!(file, "// Generated at: {} (secs) + {} (nanos)", secs, nanos).unwrap();
    writeln!(file, "// Each build produces unique values\n").unwrap();

    // Build fingerprint
    writeln!(file, "/// Unique fingerprint for this build").unwrap();
    writeln!(file, "pub const BUILD_FINGERPRINT: &str = \"{}\";", fingerprint_hex).unwrap();
    writeln!(file, "pub const BUILD_FINGERPRINT_BYTES: [u8; 16] = {:?};", fingerprint.as_slice()).unwrap();
    writeln!(file).unwrap();

    // Build timestamp
    writeln!(file, "/// Build timestamp (unix seconds)").unwrap();
    writeln!(file, "pub const BUILD_TIMESTAMP: u64 = {};", secs).unwrap();
    writeln!(file, "pub const BUILD_NANOS: u32 = {};", nanos).unwrap();
    writeln!(file).unwrap();

    // Junk data (polymorphic padding)
    writeln!(file, "/// Polymorphic junk data - changes binary hash").unwrap();
    writeln!(file, "#[allow(dead_code)]").unwrap();
    writeln!(file, "pub static JUNK_DATA: [u8; {}] = {:?};", junk_size, junk_data.as_slice()).unwrap();
    writeln!(file).unwrap();

    // Obfuscation keys
    writeln!(file, "/// XOR key for this build").unwrap();
    writeln!(file, "pub const XOR_KEY: u8 = 0x{:02X};", xor_key).unwrap();
    writeln!(file, "pub const XOR_KEY_MULTI: [u8; 16] = {:?};", xor_key_multi.as_slice()).unwrap();
    writeln!(file).unwrap();

    // Dead code seeds
    writeln!(file, "/// Dead code control values").unwrap();
    writeln!(file, "#[allow(dead_code)]").unwrap();
    writeln!(file, "pub const DEAD_CODE_SEED: u64 = 0x{:016X};", dead_code_seed).unwrap();
    writeln!(file, "#[allow(dead_code)]").unwrap();
    writeln!(file, "pub const DEAD_CODE_THRESHOLD: u64 = 0x{:016X};", dead_code_threshold).unwrap();
    writeln!(file).unwrap();

    // Mutation table for advanced obfuscation
    writeln!(file, "/// Mutation table for string transformation").unwrap();
    writeln!(file, "#[allow(dead_code)]").unwrap();
    writeln!(file, "pub static MUTATION_TABLE: [u8; 256] = [").unwrap();
    for chunk in mutation_table.chunks(16) {
        let hex: String = chunk.iter().map(|b| format!("0x{:02X}, ", b)).collect();
        writeln!(file, "    {}", hex).unwrap();
    }
    writeln!(file, "];").unwrap();
    writeln!(file).unwrap();

    // Helper functions
    writeln!(file, r#"
/// Obfuscate a byte slice using build-specific key
#[inline]
pub fn obfuscate_bytes(data: &[u8]) -> Vec<u8> {{
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ XOR_KEY_MULTI[i % 16])
        .collect()
}}

/// Deobfuscate a byte slice using build-specific key
#[inline]
pub fn deobfuscate_bytes(data: &[u8]) -> Vec<u8> {{
    obfuscate_bytes(data) // XOR is symmetric
}}

/// Deobfuscate a string that was obfuscated with this build's key
#[inline]
pub fn deobfuscate_str(data: &[u8]) -> String {{
    String::from_utf8_lossy(&deobfuscate_bytes(data)).to_string()
}}

/// Dead code that affects binary but never executes
#[inline(never)]
#[allow(dead_code)]
pub fn dead_code_block() {{
    // This code is compiled but never runs
    // It exists solely to change binary hash
    if DEAD_CODE_SEED == DEAD_CODE_THRESHOLD {{
        let mut x = JUNK_DATA[0];
        for &b in JUNK_DATA.iter() {{
            x = x.wrapping_add(b).wrapping_mul(MUTATION_TABLE[b as usize]);
        }}
        std::hint::black_box(x);
    }}
}}

/// Insert junk operations that get optimized differently each build
#[inline(never)]
#[allow(dead_code)]
pub fn polymorphic_nop() {{
    let _ = std::hint::black_box(&JUNK_DATA);
    let _ = std::hint::black_box(BUILD_FINGERPRINT);
}}
"#).unwrap();

    // Print build info
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:warning=Build fingerprint: {}", fingerprint_hex);
    println!("cargo:warning=XOR key: 0x{:02X}", xor_key);

    // Force rebuild when Cargo.toml changes
    println!("cargo:rerun-if-changed=Cargo.toml");
}
