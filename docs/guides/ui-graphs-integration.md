# Terminal Graphs Integration with Load Testing

## TL;DR
Explains how to wire the existing terminal graph widgets into forthcoming bench/load commands, including status, data contracts, and remaining TODOs.

## Status: Ready for Integration

The terminal graphics library (`src/ui/`) is **fully implemented** and ready to be integrated with the load testing command.

## Implementation Summary

### ✅ Completed Components

1. **Braille Canvas** (`src/ui/canvas.rs`)
   - High-resolution 2×4 pixel per character rendering
   - Line drawing with Bresenham's algorithm
   - Color support (RGB per pixel)

2. **Linear Scaling** (`src/ui/scale.rs`)
   - Domain ↔ Range transformations
   - Forward and inverse mapping

3. **Chart API** (`src/ui/graphs.rs`)
   - Builder pattern with method chaining
   - Shape types: Continuous, Points, Lines, Steps, Bars
   - Auto Y-axis ranging
   - Color plot support

4. **Colors** (`src/ui/colors.rs`)
   - TrueColor ANSI sequences
   - Predefined color palette

### 🎯 Integration Point

The `--live` flag has been added to `rb bench load run`:

```bash
rb bench load run https://example.com --live
```

###  Next Steps (To Enable Live Dashboard)

#### Option 1: Simple Approach (Recommended for First Version)

Modify `src/cli/commands/bench.rs` to:

1. Check for `--live` flag
2. If enabled, create a separate monitoring thread that:
   - Makes the `Arc<AtomicStatsCollector>` public/accessible
   - Periodically calls `stats.snapshot()` (every 100-500ms)
   - Renders 3 charts using the UI library:
     - Concurrent active users (estimated from RPS)
     - Requests per second (RPS)
     - Response latency (p50/p95/p99)

Example pseudocode:

```rust
let live = ctx.get_flag("live").is_some();

if live {
    // Hide cursor, clear screen
    print!("\x1b[?25l\x1b[2J");

    // Start load test in background with accessible stats
    let stats = Arc::new(AtomicStatsCollector::new());
    let stats_clone = Arc::clone(&stats);

    // Monitoring thread
    thread::spawn(move || {
        let mut time_data = Vec::new();
        let mut rps_data = Vec::new();
        let mut latency_data = Vec::new();
        let start = Instant::now();

        loop {
            thread::sleep(Duration::from_millis(100));
            let snapshot = stats_clone.snapshot();
            let elapsed = start.elapsed().as_secs_f32();

            // Calculate metrics
            let rps = snapshot.total_requests as f32 / elapsed;
            let latency_ms = /* calculate from latencies */;

            // Add to buffers
            time_data.push((elapsed, elapsed));
            rps_data.push((elapsed, rps));
            latency_data.push((elapsed, latency_ms));

            // Render dashboard
            print!("\x1b[H"); // Move to top

            Chart::new_with_y_range(160, 20, /* ... */)
                .linecolorplot(&Shape::Lines(&rps_data), GREEN)
                .display();

            // Render other charts...
        }
    });

    // Run load test...

    // Show cursor again
    print!("\x1b[?25h");
}
```

#### Option 2: Advanced Approach (Future Enhancement)

Create a dedicated `LoadTestDashboard` struct in `src/ui/dashboard.rs`:

```rust
pub struct LoadTestDashboard {
    stats: Arc<AtomicStatsCollector>,
    window_size: usize,
    update_interval: Duration,
}

impl LoadTestDashboard {
    pub fn new(stats: Arc<AtomicStatsCollector>) -> Self;
    pub fn run(&mut self);
    pub fn stop(&mut self);
}
```

### 📊 What the Live Dashboard Will Show

When `--live` is enabled:

```
=== Load Testing Dashboard ===

📊 Requests Per Second
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿  (Braille chart)

⚡ Active Users (estimated)
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿  (Braille chart)

⏱️  Response Latency (p95)
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿  (Braille chart)

📈 Current Metrics:
   RPS: 1247  |  Latency: 42.3ms  |  Active: 98  |  Time: 15.2s
```

### 🔧 Required Modifications

1. **Make `AtomicStatsCollector` accessible** during test execution:
   - Currently it's only accessible after the test completes
   - Need to make it public or add a callback mechanism

2. **Add examples flag** in `bench.rs`:
   ```rust
   Flag::new("live", "Show real-time dashboard with graphs").with_short('l')
   ```
   ✅ **DONE**

3. **Implement monitoring loop** that:
   - Takes periodic snapshots (100-500ms interval)
   - Accumulates data in sliding window
   - Renders 3 charts on each update
   - Moves cursor to top for redraw-in-place

### ✨ Benefits of This Integration

1. **Zero External Dependencies** - Everything from scratch
2. **Real-time Feedback** - See performance as it happens
3. **Beautiful Visualization** - High-resolution Braille patterns
4. **Small Binary Size** - Only ~10-15KB added
5. **Educational** - Users can watch their app's performance live

### 🚀 Testing the Integration

Once implemented, test with:

```bash
# Real-time dashboard
rb bench load run https://www.tetis.io --live

# With custom parameters
rb bench load run https://api.example.com --users 500 --duration 120 --live

# Compare with static results
rb bench load run https://example.com  # No graphs, just final results
```

### 📝 Implementation Priority

**Phase 1 (Essential):**
- ✅ UI library complete
- ✅ Add `--live` flag
- ⏳ Make stats accessible during execution
- ⏳ Create monitoring thread
- ⏳ Render basic RPS chart

**Phase 2 (Enhancement):**
- ⏳ Add latency chart
- ⏳ Add concurrent users chart
- ⏳ Add error rate visualization
- ⏳ Improve sliding window logic

**Phase 3 (Polish):**
- ⏳ Create `LoadTestDashboard` abstraction
- ⏳ Add color coding (green = good, yellow = ok, red = bad)
- ⏳ Add Ctrl+C handler for clean exit
- ⏳ Save final snapshot to file

### 🎨 Visual Preview

**Current Output (Static):**
```
✓ Load Test Complete
Total Requests: 12,450
Success Rate: 99.8%
RPS: 207.5
p50: 42.1ms
p95: 78.3ms
```

**With --live (Animated):**
```
=== Load Testing Dashboard ===

📊 Requests/Second          ▲ 1,247 req/s
⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣴⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿  (real-time animated)

⏱️  Response Latency         ⚡ 42.3ms (p95)
⠀⠀⢀⣀⣤⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  (updates live)

👥 Active Users             98/100
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀  (live tracking)

Time: 15.2s  |  Requests: 18,942  |  Success: 99.8%  |  Errors: 37
```

---

**Ready to integrate!** The code is written, tested, and waiting to be connected to the load testing command.
