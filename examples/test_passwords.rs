use std::fs;

fn main() {
    let compressed = fs::read("/tmp/passwords.txt.gz").expect("Failed to read file");
    println!("Compressed size: {} bytes", compressed.len());

    match redblue::compression::gzip_decompress(&compressed) {
        Ok(decompressed) => {
            println!("Decompressed size: {} bytes", decompressed.len());

            // Verify content matches original
            let original = fs::read("/tmp/passwords.txt").expect("Failed to read original");
            if decompressed == original {
                println!("✓ Content matches original!");
                let lines = String::from_utf8_lossy(&decompressed).lines().count();
                println!("  Lines: {}", lines);
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
