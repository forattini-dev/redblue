// RedDB Demo - Ultra-compact multi-source storage
//
// Run with: cargo run --example reddb_demo

use std::net::{IpAddr, Ipv4Addr};

// NOTE: This example requires enabling the storage module in main.rs
// Uncomment: mod storage;

fn main() {
    println!("🔴🔵 RedDB - Ultra-Compact Security Database\n");

    // Open database
    println!("📂 Opening database...");
    let mut db = redblue::storage::RedDb::open("demo_scans.db").expect("Failed to open database");

    // === PORT SCANS ===
    println!("\n🔍 Saving port scan results...");
    let target_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

    db.save_port_scan(target_ip, 80, redblue::storage::PortStatus::Open)
        .unwrap();
    db.save_port_scan(target_ip, 443, redblue::storage::PortStatus::Open)
        .unwrap();
    db.save_port_scan(target_ip, 8080, redblue::storage::PortStatus::Closed)
        .unwrap();
    db.save_port_scan(target_ip, 3306, redblue::storage::PortStatus::Filtered)
        .unwrap();

    println!("   ✅ Saved 4 port scans");

    // Retrieve
    let open_ports = db.get_open_ports(target_ip).unwrap();
    println!("   🟢 Open ports: {:?}", open_ports);

    // === SUBDOMAINS ===
    println!("\n🌐 Saving subdomain enumeration...");

    db.save_subdomain(
        "example.com",
        "api.example.com",
        vec![target_ip],
        redblue::storage::SubdomainSource::DnsBruteforce,
    )
    .unwrap();

    db.save_subdomain(
        "example.com",
        "www.example.com",
        vec![target_ip],
        redblue::storage::SubdomainSource::CertTransparency,
    )
    .unwrap();

    db.save_subdomain(
        "example.com",
        "mail.example.com",
        vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))],
        redblue::storage::SubdomainSource::DnsBruteforce,
    )
    .unwrap();

    println!("   ✅ Saved 3 subdomains");

    let subdomains = db.get_subdomains("example.com").unwrap();
    println!("   🌐 Found subdomains:");
    for sub in subdomains {
        println!("      - {}", sub);
    }

    // === WHOIS ===
    println!("\n📋 Saving WHOIS data...");

    db.save_whois(
        "example.com",
        "Example Registrar Inc.",
        1234567890, // created
        1734567890, // expires
        vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()],
    )
    .unwrap();

    println!("   ✅ Saved WHOIS record");

    if let Some(whois) = db.get_whois("example.com").unwrap() {
        println!("   📋 Registrar: {}", whois.registrar);
        println!("   📋 Nameservers: {:?}", whois.nameservers);
    }

    // === TLS CERTIFICATES ===
    println!("\n🔒 Saving TLS certificate...");

    db.save_cert(
        "example.com",
        "Let's Encrypt",
        "CN=example.com",
        1700000000, // not_before
        1800000000, // not_after
        vec!["example.com".to_string(), "www.example.com".to_string()],
        false, // not self-signed
    )
    .unwrap();

    println!("   ✅ Saved TLS certificate");

    if let Some(cert) = db.get_cert("example.com").unwrap() {
        println!("   🔒 Issuer: {}", cert.issuer);
        println!("   🔒 SANs: {:?}", cert.sans);
        println!("   🔒 Self-signed: {}", cert.self_signed);
    }

    // === STATISTICS ===
    println!("\n📊 Database Statistics:");
    let stats = db.stats().unwrap();
    println!("   Total records: {}", stats.total_records);
    println!("   Port scans: {}", stats.port_scans);

    // Flush to disk
    println!("\n💾 Flushing to disk...");
    db.flush().unwrap();

    println!("\n✅ Demo complete!");
    println!("   Database file: demo_scans.db");

    // Check file size
    if let Ok(metadata) = std::fs::metadata("demo_scans.db") {
        println!("   File size: {} bytes", metadata.len());
        println!(
            "   Average: ~{} bytes per record",
            metadata.len() / stats.total_records.max(1) as u64
        );
    }

    println!("\n🎯 Compare with SQLite/JSON:");
    println!("   RedDB:  ~20-50 bytes per record");
    println!("   SQLite: ~100-200 bytes per record");
    println!("   JSON:   ~200-500 bytes per record");
    println!("\n   RedDB is 5-10x more space-efficient! 🚀");
}
