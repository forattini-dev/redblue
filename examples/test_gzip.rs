/// Minimal gzip test binary
/// Run with: cargo run --example test_gzip

fn main() {
    println!("Testing native gzip decompression...\n");

    // Test CRC32
    let crc = redblue::compression::crc32(b"123456789");
    println!("CRC32('123456789') = 0x{:08X}", crc);
    assert_eq!(crc, 0xCBF43926, "CRC32 test failed!");
    println!("✓ CRC32 works!\n");

    // Test gzip decompression
    // "Hello, World!\n" compressed with Python: gzip.compress(b'Hello, World!\n')
    // Note: shell echo escapes '!' incorrectly, so we use Python-generated test data
    let compressed: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0xae, 0xc7, 0x36, 0x69, 0x02, 0xff, 0xf3, 0x48, 0xcd, 0xc9, 0xc9,
        0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0xe4, 0x02, 0x00, 0x84, 0x9e, 0xe8, 0xb4,
        0x0e, 0x00, 0x00, 0x00,
    ];

    println!("Compressed size: {} bytes", compressed.len());

    match redblue::compression::gzip_decompress(compressed) {
        Ok(decompressed) => {
            println!("Decompressed size: {} bytes", decompressed.len());
            println!("Content: {:?}", String::from_utf8_lossy(&decompressed));
            assert_eq!(decompressed, b"Hello, World!\n");
            println!("✓ Gzip decompression works!");
        }
        Err(e) => {
            println!("✗ Decompression failed: {}", e);
            std::process::exit(1);
        }
    }
}
