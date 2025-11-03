/// Example: Deep Connection Intelligence Extraction
///
/// This example demonstrates how to extract maximum intelligence from a single connection.
/// Compare to traditional tools that only report "port open".
use std::net::{IpAddr, TcpStream};
use std::time::Instant;

// In real code: use crate::intelligence::connection_intel::*;
// For example purposes, we'll simulate the usage

fn main() {
    println!("🧠 Connection Intelligence Extraction Example\n");
    println!("{}", "=".repeat(60));

    // Example 1: Basic connection to HTTPS service
    example_https_intelligence();

    println!("\n{}\n", "=".repeat(60));

    // Example 2: HTTP service with security analysis
    example_http_security();

    println!("\n{}\n", "=".repeat(60));

    // Example 3: Infrastructure detection
    example_infrastructure_detection();
}

fn example_https_intelligence() {
    println!("📡 Example 1: HTTPS Connection to cloudflare.com:443\n");

    let target = "1.1.1.1";
    let port = 443;

    println!("Traditional tool output:");
    println!("  443/tcp open\n");

    println!("redblue intelligence output:");
    println!("  PORT     STATE    SERVICE    INTELLIGENCE");
    println!("  443/tcp  open     https      TLS 1.3, ECDHE-RSA-AES128-GCM-SHA256");
    println!("                                ↳ Certificate: Cloudflare Inc");
    println!("                                ↳ Valid: 89 days remaining");
    println!("                                ↳ Wildcard: *.cloudflare.com");
    println!("                                ↳ SANs: 14 domains");
    println!("                                ↳ Key: RSA 2048-bit");
    println!();
    println!("  Network:");
    println!("    • Latency: 12ms (nearby)");
    println!("    • TTL: 56 hops (CDN edge server)");
    println!("    • TCP Window: 65535 (tuned)");
    println!();
    println!("  Infrastructure:");
    println!("    • CDN: Cloudflare (detected)");
    println!("    • WAF: Cloudflare (detected)");
    println!("    • Load Balancer: Yes (sticky sessions)");
    println!("    • Cloud: Multi-cloud (anycast IP)");
    println!();
    println!("  Security:");
    println!("    ✓ HSTS: max-age=31536000");
    println!("    ✓ CSP: strict policy");
    println!("    ✓ X-Frame-Options: DENY");
    println!("    ⚠️  Missing: X-Content-Type-Options");
    println!();
    println!("  Server: cloudflare");
    println!("  HTTP/2: Supported");
    println!("  Compression: br, gzip");

    println!("\n📊 Intelligence value: 🚀 15+ data points vs 1");
}

fn example_http_security() {
    println!("🔒 Example 2: Security Analysis of example.com:80\n");

    println!("Intelligence extracted:");
    println!();
    println!("  Server: Apache/2.4.41 (Ubuntu)");
    println!("    → OS: Ubuntu Linux");
    println!("    → Web server: Apache 2.4.41");
    println!("    → Age: ~4 years old (potential CVEs)");
    println!();
    println!("  Security Headers:");
    println!("    ❌ HSTS: NOT PRESENT (no HTTPS enforcement)");
    println!("    ❌ CSP: NOT PRESENT (XSS vulnerable)");
    println!("    ❌ X-Frame-Options: NOT PRESENT (clickjacking risk)");
    println!("    ❌ X-Content-Type-Options: NOT PRESENT");
    println!("    ❌ X-XSS-Protection: NOT PRESENT");
    println!();
    println!("  Risk Assessment:");
    println!("    ⚠️  HIGH: Missing all security headers");
    println!("    ⚠️  MEDIUM: Outdated Apache version");
    println!("    ⚠️  LOW: Server version disclosure");
    println!();
    println!("  Recommendations:");
    println!("    1. Enable HTTPS with HSTS");
    println!("    2. Add Content-Security-Policy");
    println!("    3. Update Apache to latest version");
    println!("    4. Hide server version (ServerTokens Prod)");
}

fn example_infrastructure_detection() {
    println!("🏗️  Example 3: Infrastructure Detection\n");

    println!("Target: api.company.com:443");
    println!();
    println!("Certificate Analysis:");
    println!("  Subject: *.company.com");
    println!("  Issuer: Amazon (AWS Certificate Manager)");
    println!("  SANs: api.company.com, www.company.com, cdn.company.com");
    println!();
    println!("HTTP Headers:");
    println!("  Server: CloudFront");
    println!("  X-Amz-Cf-Id: abc123... (CloudFront trace ID)");
    println!("  Via: 1.1 abc123.cloudfront.net");
    println!();
    println!("Timing Analysis:");
    println!("  Connect: 45ms");
    println!("  First byte: 48ms (+3ms processing)");
    println!("  Variation: ±12ms (multiple backends)");
    println!();
    println!("🎯 Infrastructure Intelligence:");
    println!("  ✓ Cloud Provider: AWS");
    println!("  ✓ CDN: Amazon CloudFront");
    println!("  ✓ Load Balancer: Application Load Balancer (ALB)");
    println!("    → Evidence: Sticky session cookies, timing variation");
    println!("  ✓ Region: us-east-1 (Virginia)");
    println!("    → Evidence: Low latency, CloudFront edge location");
    println!("  ✓ Auto-scaling: Likely enabled");
    println!("    → Evidence: Multiple backend IPs over time");
    println!();
    println!("📍 Attack Surface Insights:");
    println!("  • Direct origin IP: Hidden (good security)");
    println!("  • WAF: CloudFront + AWS WAF (likely)");
    println!("  • Rate limiting: Aggressive (429 after 100 req/min)");
    println!("  • Origin protection: Yes (CloudFront signed URLs)");
    println!();
    println!("💡 Pentesting Strategy:");
    println!("  1. Test CloudFront origin bypass (misconfigurations)");
    println!("  2. Check S3 bucket permissions (public access)");
    println!("  3. API fuzzing within rate limits");
    println!("  4. Check for exposed AWS metadata endpoints");
}

/// Real usage code (commented out - requires full crate context)
#[allow(dead_code)]
fn real_usage_example() {
    /*
    use crate::intelligence::connection_intel::ConnectionAnalyzer;
    use std::net::TcpStream;

    // Target
    let target_ip: IpAddr = "1.1.1.1".parse().unwrap();
    let port = 443;

    // Create analyzer
    let mut analyzer = ConnectionAnalyzer::new(target_ip, port);

    // Connect and analyze TCP
    let connect_start = Instant::now();
    let stream = TcpStream::connect((target_ip, port)).unwrap();
    analyzer.analyze_tcp(&stream);
    analyzer.analyze_timing(connect_start, Some(Instant::now()));

    // If TLS connection:
    // 1. Perform TLS handshake
    // 2. Extract server_hello and certificates
    // 3. Analyze with:
    // analyzer.analyze_tls_handshake(&server_hello, &certificates);

    // If HTTP connection:
    // 1. Send HTTP request
    // 2. Parse response headers
    // 3. Analyze with:
    // analyzer.analyze_http_headers(&headers);

    // Get full intelligence report
    let intel = analyzer.finalize();
    println!("{}", intel.summary());

    // Access specific fields
    if let Some(cdn) = intel.likely_cdn {
        println!("CDN detected: {}", cdn);
    }

    if intel.cert_is_self_signed {
        println!("⚠️  Self-signed certificate!");
    }

    if !intel.http_missing_security_headers.is_empty() {
        println!("Missing security headers: {:?}",
            intel.http_missing_security_headers);
    }
    */
}

/// Compare extraction capabilities
fn comparison_table() {
    println!("\n📊 Intelligence Extraction Comparison\n");
    println!(
        "{:<30} {:<15} {:<15}",
        "Information", "Traditional", "redblue"
    );
    println!("{}", "-".repeat(60));
    println!("{:<30} {:<15} {:<15}", "Port open/closed", "✓", "✓");
    println!("{:<30} {:<15} {:<15}", "Service name", "✓", "✓");
    println!("{:<30} {:<15} {:<15}", "TLS version", "❌", "✓");
    println!("{:<30} {:<15} {:<15}", "Cipher suite", "❌", "✓");
    println!("{:<30} {:<15} {:<15}", "Certificate details", "❌", "✓");
    println!("{:<30} {:<15} {:<15}", "Certificate chain", "❌", "✓");
    println!("{:<30} {:<15} {:<15}", "HTTP security headers", "❌", "✓");
    println!("{:<30} {:<15} {:<15}", "CDN detection", "❌", "✓");
    println!("{:<30} {:<15} {:<15}", "WAF detection", "❌", "✓");
    println!("{:<30} {:<15} {:<15}", "Cloud provider", "❌", "✓");
    println!("{:<30} {:<15} {:<15}", "Load balancer", "❌", "✓");
    println!("{:<30} {:<15} {:<15}", "Timing analysis", "❌", "✓");
    println!("{:<30} {:<15} {:<15}", "TCP fingerprinting", "❌", "✓");
    println!(
        "{:<30} {:<15} {:<15}",
        "Missing security headers", "❌", "✓"
    );
    println!(
        "{:<30} {:<15} {:<15}",
        "Infrastructure inference", "❌", "✓"
    );
}
