//! Real-time load testing dashboard simulation
//!
//! Simulates a load testing dashboard with multiple real-time charts:
//! - Concurrent users over time
//! - Requests per second (RPS)
//! - Response latency (ms)
//!
//! This demonstrates how the UI library could be used in `rb bench load test`.
//!
//! Run with:
//! ```
//! cargo run --example ui-load-dashboard
//! ```

use redblue::ui::colors::colors::{BLUE, GREEN, RED, YELLOW};
use redblue::ui::{Chart, ColorPlot, Shape};
use std::io::{self, Write};
use std::thread;
use std::time::Duration;

const WINDOW_SIZE: usize = 100;
const UPDATE_INTERVAL_MS: u64 = 100;
const DURATION_SEC: u64 = 10;

fn main() {
    println!("\n=== Load Testing Dashboard (Simulated) ===\n");
    println!("Simulating 10 seconds of load testing...\n");
    println!("Press Ctrl+C to stop\n");

    thread::sleep(Duration::from_secs(1));

    // Hide cursor
    print!("\x1b[?25l");
    io::stdout().flush().unwrap();

    // Data buffers for sliding window
    let mut time_points: Vec<f32> = Vec::with_capacity(WINDOW_SIZE);
    let mut users_data: Vec<(f32, f32)> = Vec::with_capacity(WINDOW_SIZE);
    let mut rps_data: Vec<(f32, f32)> = Vec::with_capacity(WINDOW_SIZE);
    let mut latency_data: Vec<(f32, f32)> = Vec::with_capacity(WINDOW_SIZE);

    let start_time = std::time::Instant::now();
    let mut frame_count = 0;

    loop {
        let elapsed = start_time.elapsed().as_secs_f32();
        if elapsed > DURATION_SEC as f32 {
            break;
        }

        // Simulate load testing metrics
        let t = elapsed;
        let users = simulate_users(t);
        let rps = simulate_rps(t);
        let latency = simulate_latency(t);

        // Add to sliding window
        time_points.push(t);
        users_data.push((t, users));
        rps_data.push((t, rps));
        latency_data.push((t, latency));

        // Keep only last WINDOW_SIZE points
        if time_points.len() > WINDOW_SIZE {
            time_points.remove(0);
            users_data.remove(0);
            rps_data.remove(0);
            latency_data.remove(0);
        }

        // Get time range for X-axis
        let xmin = time_points.first().copied().unwrap_or(0.0);
        let xmax = time_points.last().copied().unwrap_or(10.0);

        // Move cursor to top-left (redraw in place)
        print!("\x1b[H");

        // Chart 1: Concurrent Users
        println!("\n📊 Concurrent Users\n");
        Chart::new_with_y_range(160, 20, xmin, xmax, 0.0, 60.0)
            .linecolorplot(&Shape::Lines(&users_data), GREEN)
            .display();

        // Chart 2: Requests Per Second
        println!("\n⚡ Requests/Second (RPS)\n");
        Chart::new_with_y_range(160, 20, xmin, xmax, 0.0, 2000.0)
            .linecolorplot(&Shape::Lines(&rps_data), BLUE)
            .display();

        // Chart 3: Response Latency
        println!("\n⏱️  Response Latency (ms)\n");
        Chart::new_with_y_range(160, 20, xmin, xmax, 0.0, 200.0)
            .linecolorplot(&Shape::Lines(&latency_data), YELLOW)
            .display();

        // Stats summary
        println!("\n📈 Current Metrics:");
        println!("   Users: {:.0}  |  RPS: {:.0}  |  Latency: {:.1}ms  |  Time: {:.1}s",
                 users, rps, latency, elapsed);
        println!("\n   Frame: {}  |  Data points: {}", frame_count, time_points.len());

        io::stdout().flush().unwrap();

        frame_count += 1;
        thread::sleep(Duration::from_millis(UPDATE_INTERVAL_MS));
    }

    // Show cursor again
    print!("\x1b[?25h");
    io::stdout().flush().unwrap();

    println!("\n\n=== Load Testing Complete ===\n");
    println!("✓ {} frames rendered", frame_count);
    println!("✓ {} data points collected", time_points.len());
    println!("✓ Zero external dependencies\n");
}

// Simulate gradually increasing concurrent users
fn simulate_users(t: f32) -> f32 {
    // Ramp up from 0 to 50 users over 10 seconds
    let base = (t / 10.0) * 50.0;
    let noise = ((t * 3.0).sin() * 2.0);
    (base + noise).max(0.0)
}

// Simulate RPS that increases with users but has spikes
fn simulate_rps(t: f32) -> f32 {
    let users = simulate_users(t);
    let base_rps = users * 30.0; // Each user generates ~30 req/s
    let spike = (t * 5.0).sin() * 200.0; // Random spikes
    (base_rps + spike).max(0.0)
}

// Simulate latency that increases under load
fn simulate_latency(t: f32) -> f32 {
    let users = simulate_users(t);
    // Latency increases with load
    let base_latency = 50.0 + (users / 50.0) * 100.0;
    // Add some jitter
    let jitter = (t * 10.0).sin() * 20.0;
    (base_latency + jitter).max(10.0)
}
