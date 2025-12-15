use std::fs;

fn main() {
    let compressed = fs::read("/tmp/large_test.gz").expect("Failed to read file");
    println!("Compressed size: {} bytes", compressed.len());

    match redblue::compression::gzip_decompress(&compressed) {
        Ok(decompressed) => {
            println!("Decompressed size: {} bytes", decompressed.len());
            // Verify by comparing with original
            let original = fs::read("/tmp/large_test.txt").expect("Failed to read original");
            if decompressed == original {
                println!("✓ Content matches original!");
            } else {
                println!("✗ Content mismatch!");
                std::process::exit(1);
            }
        }
        Err(e) => {
            println!("✗ Error: {}", e);
            std::process::exit(1);
        }
    }
}
