/// Statistics collection for load testing
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RequestStats {
    pub duration: Duration,
    pub status_code: u16,
    pub bytes_received: usize,
    pub success: bool,
    pub error: Option<String>,
}

impl RequestStats {
    pub fn success(duration: Duration, status_code: u16, bytes: usize) -> Self {
        Self {
            duration,
            status_code,
            bytes_received: bytes,
            success: true,
            error: None,
        }
    }

    pub fn error(duration: Duration, error: String) -> Self {
        Self {
            duration,
            status_code: 0,
            bytes_received: 0,
            success: false,
            error: Some(error),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Percentile {
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub min: Duration,
    pub max: Duration,
    pub avg: Duration,
}

impl Percentile {
    pub fn calculate(mut durations: Vec<Duration>) -> Self {
        if durations.is_empty() {
            return Self {
                p50: Duration::ZERO,
                p95: Duration::ZERO,
                p99: Duration::ZERO,
                min: Duration::ZERO,
                max: Duration::ZERO,
                avg: Duration::ZERO,
            };
        }

        durations.sort();

        let len = durations.len();
        let min = durations[0];
        let max = durations[len - 1];

        let p50_idx = (len as f64 * 0.50) as usize;
        let p95_idx = (len as f64 * 0.95) as usize;
        let p99_idx = (len as f64 * 0.99) as usize;

        let p50 = durations.get(p50_idx).copied().unwrap_or(Duration::ZERO);
        let p95 = durations.get(p95_idx).copied().unwrap_or(Duration::ZERO);
        let p99 = durations.get(p99_idx).copied().unwrap_or(Duration::ZERO);

        let total: Duration = durations.iter().sum();
        let avg = total / len as u32;

        Self {
            p50,
            p95,
            p99,
            min,
            max,
            avg,
        }
    }
}

/// Lock-free atomic statistics collector for maximum concurrency
#[derive(Debug)]
pub struct AtomicStatsCollector {
    pub total_requests: AtomicUsize,
    pub successful_requests: AtomicUsize,
    pub failed_requests: AtomicUsize,
    pub status_2xx: AtomicUsize,
    pub status_3xx: AtomicUsize,
    pub status_4xx: AtomicUsize,
    pub status_5xx: AtomicUsize,
    pub total_bytes: AtomicUsize,
    // Only latencies and errors need locking (but much less contention)
    pub latencies: Mutex<Vec<Duration>>,
    pub errors: Mutex<Vec<String>>,
}

impl AtomicStatsCollector {
    pub fn new() -> Self {
        Self {
            total_requests: AtomicUsize::new(0),
            successful_requests: AtomicUsize::new(0),
            failed_requests: AtomicUsize::new(0),
            status_2xx: AtomicUsize::new(0),
            status_3xx: AtomicUsize::new(0),
            status_4xx: AtomicUsize::new(0),
            status_5xx: AtomicUsize::new(0),
            total_bytes: AtomicUsize::new(0),
            latencies: Mutex::new(Vec::with_capacity(100000)), // Pre-allocate for 100k requests
            errors: Mutex::new(Vec::new()),
        }
    }

    pub fn add(&self, stat: RequestStats) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        // Only lock for latencies (fast push)
        {
            let mut latencies = self.latencies.lock().unwrap();
            latencies.push(stat.duration);
        }

        if stat.success {
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
            self.total_bytes
                .fetch_add(stat.bytes_received, Ordering::Relaxed);

            match stat.status_code {
                200..=299 => {
                    self.status_2xx.fetch_add(1, Ordering::Relaxed);
                }
                300..=399 => {
                    self.status_3xx.fetch_add(1, Ordering::Relaxed);
                }
                400..=499 => {
                    self.status_4xx.fetch_add(1, Ordering::Relaxed);
                }
                500..=599 => {
                    self.status_5xx.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        } else {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
            if let Some(err) = stat.error {
                let mut errors = self.errors.lock().unwrap();
                errors.push(err);
            }
        }
    }

    pub fn snapshot(&self) -> StatsAggregator {
        let latencies = self.latencies.lock().unwrap();
        let errors = self.errors.lock().unwrap();

        StatsAggregator {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            successful_requests: self.successful_requests.load(Ordering::Relaxed),
            failed_requests: self.failed_requests.load(Ordering::Relaxed),
            status_2xx: self.status_2xx.load(Ordering::Relaxed),
            status_3xx: self.status_3xx.load(Ordering::Relaxed),
            status_4xx: self.status_4xx.load(Ordering::Relaxed),
            status_5xx: self.status_5xx.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            latencies: latencies.clone(),
            errors: errors.clone(),
        }
    }
}

impl Default for AtomicStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Non-atomic snapshot for final results
#[derive(Debug)]
pub struct StatsAggregator {
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub status_2xx: usize,
    pub status_3xx: usize,
    pub status_4xx: usize,
    pub status_5xx: usize,
    pub total_bytes: usize,
    pub latencies: Vec<Duration>,
    pub errors: Vec<String>,
}

impl StatsAggregator {
    pub fn percentiles(&self) -> Percentile {
        // OPTIMIZATION: Avoid clone by moving
        Percentile::calculate(self.latencies.clone())
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        (self.successful_requests as f64 / self.total_requests as f64) * 100.0
    }

    pub fn requests_per_second(&self, duration: Duration) -> f64 {
        if duration.as_secs_f64() == 0.0 {
            return 0.0;
        }
        self.total_requests as f64 / duration.as_secs_f64()
    }

    pub fn throughput_mbps(&self, duration: Duration) -> f64 {
        if duration.as_secs_f64() == 0.0 {
            return 0.0;
        }
        let bytes_per_sec = self.total_bytes as f64 / duration.as_secs_f64();
        (bytes_per_sec * 8.0) / 1_000_000.0 // Convert to Mbps
    }
}

// Default impl removed - StatsAggregator is now created via AtomicStatsCollector.snapshot()
