use std::fs;

fn main() {
    let compressed = fs::read("/tmp/rockyou75.txt.gz").expect("Failed to read file");
    println!("Compressed size: {} bytes", compressed.len());

    match redblue::compression::gzip_decompress(&compressed) {
        Ok(decompressed) => {
            println!("Decompressed size: {} bytes", decompressed.len());

            // Verify content matches original
            let original = fs::read("/tmp/rockyou75.txt").expect("Failed to read original");
            if decompressed == original {
                let lines = String::from_utf8_lossy(&decompressed).lines().count();
                println!("✓ SUCCESS! Content matches original ({} lines)", lines);
            } else {
                println!("✗ Content mismatch!");
                println!("  Original: {} bytes", original.len());
                println!("  Decompressed: {} bytes", decompressed.len());
                std::process::exit(1);
            }
        }
        Err(e) => {
            println!("✗ Error: {}", e);
            std::process::exit(1);
        }
    }
}
