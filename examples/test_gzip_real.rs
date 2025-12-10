use std::fs;

fn main() {
    let compressed = fs::read("/tmp/test.gz").expect("Failed to read file");
    println!("Compressed size: {} bytes", compressed.len());
    
    match redblue::compression::gzip_decompress(&compressed) {
        Ok(decompressed) => {
            println!("Decompressed size: {} bytes", decompressed.len());
            println!("Content: {}", String::from_utf8_lossy(&decompressed));
            println!("✓ Real gzip file decompression works!");
        }
        Err(e) => {
            println!("✗ Error: {}", e);
            std::process::exit(1);
        }
    }
}
