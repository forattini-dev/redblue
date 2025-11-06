/// Debug TLS 1.3 ClientHello encoding

fn main() {
    // Simulate building a ClientHello to see the hex

    let server_name = "google.com";
    let name_bytes = server_name.as_bytes();

    println!("Building ClientHello for: {}", server_name);
    println!("Name length: {}\n", name_bytes.len());

    // Build SNI extension
    let mut server_name_list = Vec::new();
    server_name_list.push(0x00); // Name type: host_name
    server_name_list.push((name_bytes.len() >> 8) as u8);
    server_name_list.push(name_bytes.len() as u8);
    server_name_list.extend_from_slice(name_bytes);

    println!("server_name_list length: {}", server_name_list.len());
    println!("server_name_list hex: {:02x?}", server_name_list);

    let mut extensions = Vec::new();
    extensions.push(0x00);
    extensions.push(0x00); // Extension type: server_name
    let ext_len = 2 + server_name_list.len(); // 2 bytes for list length + list
    extensions.push((ext_len >> 8) as u8);
    extensions.push(ext_len as u8);
    extensions.push((server_name_list.len() >> 8) as u8);
    extensions.push(server_name_list.len() as u8);
    extensions.extend_from_slice(&server_name_list);

    println!("\nSNI extension total length: {}", extensions.len());
    println!("SNI extension hex:");
    for (i, chunk) in extensions.chunks(16).enumerate() {
        print!("{:04x}: ", i * 16);
        for byte in chunk {
            print!("{:02x} ", byte);
        }
        println!();
    }

    // Now check what a correct ClientHello should look like
    println!("\n=== Expected Format ===");
    println!("Extension Type: 00 00 (server_name)");
    println!("Extension Length: 00 0f (15 bytes)");
    println!("  Server Name List Length: 00 0d (13 bytes)");
    println!("    Name Type: 00 (host_name)");
    println!("    Name Length: 00 0a (10 bytes)");
    println!("    Name: {} (67 6f 6f 67 6c 65 2e 63 6f 6d)", server_name);

    println!("\n=== Our Format ===");
    println!(
        "Extension Type: {:02x} {:02x}",
        extensions[0], extensions[1]
    );
    println!(
        "Extension Length: {:02x} {:02x} ({} bytes)",
        extensions[2], extensions[3], ext_len
    );
    println!(
        "  Server Name List Length: {:02x} {:02x} ({} bytes)",
        extensions[4],
        extensions[5],
        server_name_list.len()
    );
    println!("    Name Type: {:02x}", extensions[6]);
    println!(
        "    Name Length: {:02x} {:02x} ({} bytes)",
        extensions[7],
        extensions[8],
        name_bytes.len()
    );
    print!("    Name: ");
    for b in &extensions[9..9 + name_bytes.len()] {
        print!("{:02x} ", b);
    }
    println!();
}
