use std::fs;

fn main() {
    let compressed = fs::read("/tmp/darkweb.txt.gz").expect("Failed to read file");
    println!("Compressed size: {} bytes", compressed.len());
    
    match redblue::compression::gzip_decompress(&compressed) {
        Ok(decompressed) => {
            println!("Decompressed size: {} bytes", decompressed.len());
            println!("First 5 lines:");
            let content = String::from_utf8_lossy(&decompressed);
            for line in content.lines().take(5) {
                println!("  {}", line);
            }
            println!("✓ Real downloaded gzip decompression works!");
        }
        Err(e) => {
            println!("✗ Error: {}", e);
            std::process::exit(1);
        }
    }
}
