//! TLS timing breakdown visualization
//!
//! Shows how the UI library can visualize TLS connection timing breakdown:
//! - DNS resolution time
//! - TCP connection time
//! - TLS handshake time
//! - Data transfer time
//!
//! This demonstrates how timing data from `rb tls intel scan` could be visualized.
//!
//! Run with:
//! ```
//! cargo run --example ui-tls-timing
//! ```

use redblue::ui::colors::colors::{BLUE, GREEN, ORANGE, RED, YELLOW};
use redblue::ui::{Chart, ColorPlot, Shape};

struct TlsTiming {
    host: &'static str,
    dns_ms: f32,
    tcp_ms: f32,
    tls_ms: f32,
    transfer_ms: f32,
}

fn main() {
    println!("\n=== TLS Connection Timing Breakdown ===\n");

    // Sample timing data from various hosts
    let timings = vec![
        TlsTiming {
            host: "google.com",
            dns_ms: 15.2,
            tcp_ms: 8.5,
            tls_ms: 42.1,
            transfer_ms: 12.3,
        },
        TlsTiming {
            host: "github.com",
            dns_ms: 18.7,
            tcp_ms: 12.4,
            tls_ms: 65.8,
            transfer_ms: 18.9,
        },
        TlsTiming {
            host: "amazon.com",
            dns_ms: 22.1,
            tcp_ms: 15.2,
            tls_ms: 78.3,
            transfer_ms: 25.6,
        },
        TlsTiming {
            host: "cloudflare.com",
            dns_ms: 12.3,
            tcp_ms: 6.8,
            tls_ms: 35.4,
            transfer_ms: 9.2,
        },
        TlsTiming {
            host: "microsoft.com",
            dns_ms: 19.8,
            tcp_ms: 11.7,
            tls_ms: 58.9,
            transfer_ms: 16.4,
        },
    ];

    // Calculate total times for each host
    let host_indices: Vec<f32> = (0..timings.len()).map(|i| i as f32).collect();
    let dns_data: Vec<(f32, f32)> = timings
        .iter()
        .enumerate()
        .map(|(i, t)| (i as f32, t.dns_ms))
        .collect();
    let tcp_data: Vec<(f32, f32)> = timings
        .iter()
        .enumerate()
        .map(|(i, t)| (i as f32, t.tcp_ms))
        .collect();
    let tls_data: Vec<(f32, f32)> = timings
        .iter()
        .enumerate()
        .map(|(i, t)| (i as f32, t.tls_ms))
        .collect();
    let transfer_data: Vec<(f32, f32)> = timings
        .iter()
        .enumerate()
        .map(|(i, t)| (i as f32, t.transfer_ms))
        .collect();
    let total_data: Vec<(f32, f32)> = timings
        .iter()
        .enumerate()
        .map(|(i, t)| {
            (
                i as f32,
                t.dns_ms + t.tcp_ms + t.tls_ms + t.transfer_ms,
            )
        })
        .collect();

    // Chart 1: Individual timing components as bars
    println!("1. Timing Components (Separate)\n");

    println!("   🔵 DNS Resolution\n");
    Chart::new_with_y_range(120, 15, -0.5, timings.len() as f32 - 0.5, 0.0, 100.0)
        .linecolorplot(&Shape::Bars(&dns_data), BLUE)
        .display();

    println!("\n   🟢 TCP Connection\n");
    Chart::new_with_y_range(120, 15, -0.5, timings.len() as f32 - 0.5, 0.0, 100.0)
        .linecolorplot(&Shape::Bars(&tcp_data), GREEN)
        .display();

    println!("\n   🟡 TLS Handshake\n");
    Chart::new_with_y_range(120, 15, -0.5, timings.len() as f32 - 0.5, 0.0, 100.0)
        .linecolorplot(&Shape::Bars(&tls_data), YELLOW)
        .display();

    println!("\n   🔴 Data Transfer\n");
    Chart::new_with_y_range(120, 15, -0.5, timings.len() as f32 - 0.5, 0.0, 100.0)
        .linecolorplot(&Shape::Bars(&transfer_data), RED)
        .display();

    // Chart 2: Total connection time comparison
    println!("\n2. Total Connection Time (All Phases)\n");
    Chart::new_with_y_range(120, 30, -0.5, timings.len() as f32 - 0.5, 0.0, 150.0)
        .linecolorplot(&Shape::Bars(&total_data), ORANGE)
        .display();

    // Print detailed breakdown table
    println!("\n3. Detailed Timing Breakdown\n");
    println!("┌──────────────────┬────────┬────────┬────────┬──────────┬────────┐");
    println!("│ Host             │ DNS    │ TCP    │ TLS    │ Transfer │ Total  │");
    println!("├──────────────────┼────────┼────────┼────────┼──────────┼────────┤");

    for timing in &timings {
        let total = timing.dns_ms + timing.tcp_ms + timing.tls_ms + timing.transfer_ms;
        println!(
            "│ {:<16} │ {:>5.1}ms│ {:>5.1}ms│ {:>5.1}ms│ {:>7.1}ms│ {:>5.1}ms│",
            timing.host, timing.dns_ms, timing.tcp_ms, timing.tls_ms, timing.transfer_ms, total
        );
    }

    println!("└──────────────────┴────────┴────────┴────────┴──────────┴────────┘");

    // Chart 3: Phase comparison across hosts (stacked visualization concept)
    println!("\n4. Performance Insights\n");

    // Calculate percentages
    for timing in &timings {
        let total = timing.dns_ms + timing.tcp_ms + timing.tls_ms + timing.transfer_ms;
        let dns_pct = (timing.dns_ms / total) * 100.0;
        let tcp_pct = (timing.tcp_ms / total) * 100.0;
        let tls_pct = (timing.tls_ms / total) * 100.0;
        let transfer_pct = (timing.transfer_ms / total) * 100.0;

        println!("   {} ({:.1}ms total):", timing.host, total);
        println!("      DNS:      {:>5.1}% ({:>5.1}ms)", dns_pct, timing.dns_ms);
        println!("      TCP:      {:>5.1}% ({:>5.1}ms)", tcp_pct, timing.tcp_ms);
        println!("      TLS:      {:>5.1}% ({:>5.1}ms)", tls_pct, timing.tls_ms);
        println!("      Transfer: {:>5.1}% ({:>5.1}ms)\n", transfer_pct, timing.transfer_ms);
    }

    println!("=== Analysis Complete ===\n");
    println!("💡 Insights:");
    println!("   • TLS handshake is the slowest phase (40-55% of total time)");
    println!("   • DNS resolution adds 15-25ms overhead");
    println!("   • Cloudflare.com has the fastest total connection time\n");
    println!("✓ Zero external dependencies");
    println!("✓ Braille patterns for high-resolution graphs\n");
}
