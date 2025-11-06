/// Multi-threaded load generator using std::thread
use super::pool::{ConnectionPool, PooledHttpClient};
use super::stats::{AtomicStatsCollector, Percentile, RequestStats, StatsAggregator};
use super::thread_pool::ThreadPool;
use crate::protocols::http::HttpClient;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct LoadConfig {
    pub url: String,
    pub concurrent_users: usize,
    pub requests_per_user: Option<usize>,
    pub duration: Option<Duration>,
    pub think_time: Duration,
    pub timeout: Duration,
    pub use_connection_pool: bool,
    pub max_idle_per_host: usize,
    pub use_thread_pool: bool, // NEW: Reuse worker threads
}

impl LoadConfig {
    pub fn new(url: String) -> Self {
        Self {
            url,
            concurrent_users: 100,
            requests_per_user: None,
            duration: Some(Duration::from_secs(60)),
            think_time: Duration::from_millis(100),
            timeout: Duration::from_secs(30),
            use_connection_pool: true, // Enable by default for better performance
            max_idle_per_host: 50,
            use_thread_pool: true, // Enable thread pool by default
        }
    }

    pub fn with_users(mut self, users: usize) -> Self {
        self.concurrent_users = users;
        self
    }

    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self.requests_per_user = None;
        self
    }

    pub fn with_requests(mut self, requests: usize) -> Self {
        self.requests_per_user = Some(requests);
        self.duration = None;
        self
    }

    pub fn with_think_time(mut self, think_time: Duration) -> Self {
        self.think_time = think_time;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_connection_pool(mut self, enabled: bool) -> Self {
        self.use_connection_pool = enabled;
        self
    }

    pub fn with_max_idle_per_host(mut self, max: usize) -> Self {
        self.max_idle_per_host = max;
        self
    }

    pub fn with_thread_pool(mut self, enabled: bool) -> Self {
        self.use_thread_pool = enabled;
        self
    }
}

#[derive(Debug)]
pub struct LoadTestResults {
    pub config: LoadConfig,
    pub test_duration: Duration,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub requests_per_second: f64,
    pub latency: Percentile,
    pub status_2xx: usize,
    pub status_3xx: usize,
    pub status_4xx: usize,
    pub status_5xx: usize,
    pub total_bytes: usize,
    pub throughput_mbps: f64,
    pub success_rate: f64,
    pub errors: Vec<String>,
}

pub struct LoadGenerator {
    config: LoadConfig,
}

#[derive(Clone)]
struct LiveObserver {
    callback: Arc<dyn Fn(LiveSnapshot) + Send + Sync>,
    interval: Duration,
}

#[derive(Debug, Clone)]
pub struct LiveSnapshot {
    pub elapsed: Duration,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub status_2xx: usize,
    pub status_3xx: usize,
    pub status_4xx: usize,
    pub status_5xx: usize,
    pub requests_per_second: f64,
    pub throughput_mbps: f64,
    pub success_rate: f64,
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
}

impl LoadGenerator {
    pub fn new(config: LoadConfig) -> Self {
        Self { config }
    }

    /// Run load test with multi-threading
    pub fn run(&self) -> Result<LoadTestResults, String> {
        self.run_internal(None)
    }

    /// Run load test with periodic observer callbacks.
    pub fn run_with_observer(
        &self,
        interval: Duration,
        observer: Arc<dyn Fn(LiveSnapshot) + Send + Sync>,
    ) -> Result<LoadTestResults, String> {
        let live = LiveObserver {
            callback: observer,
            interval,
        };
        self.run_internal(Some(live))
    }

    fn run_internal(&self, live: Option<LiveObserver>) -> Result<LoadTestResults, String> {
        if self.config.use_thread_pool {
            self.run_with_thread_pool(live)
        } else {
            self.run_with_spawn(live)
        }
    }

    /// Run using thread pool (FASTEST - reuses threads)
    fn run_with_thread_pool(&self, live: Option<LiveObserver>) -> Result<LoadTestResults, String> {
        let start_time = Instant::now();
        let stats = Arc::new(AtomicStatsCollector::new());
        let should_stop = Arc::new(Mutex::new(false));

        // Create connection pool if enabled
        let pool = if self.config.use_connection_pool {
            Some(Arc::new(
                ConnectionPool::new().with_max_idle(self.config.max_idle_per_host),
            ))
        } else {
            None
        };

        // Create thread pool (reuses threads!)
        let thread_pool = ThreadPool::new(self.config.concurrent_users);
        let active_workers = Arc::new(AtomicUsize::new(self.config.concurrent_users));

        let live_handle = live.as_ref().map(|observer| {
            spawn_live_reporter(
                Arc::clone(&stats),
                Arc::clone(&should_stop),
                observer.clone(),
                start_time,
            )
        });

        for _user_id in 0..self.config.concurrent_users {
            let url = self.config.url.clone();
            let requests_per_user = self.config.requests_per_user;
            let duration = self.config.duration;
            let think_time = self.config.think_time;
            let timeout = self.config.timeout;
            let stats = Arc::clone(&stats);
            let should_stop = Arc::clone(&should_stop);
            let pool = pool.clone();
            let active_workers = Arc::clone(&active_workers);

            thread_pool.execute(move || {
                let user_start = Instant::now();
                let max_requests = requests_per_user.unwrap_or(usize::MAX);
                let max_duration = duration.unwrap_or(Duration::from_secs(86400));
                let mut request_count = 0;

                loop {
                    {
                        let stop = should_stop.lock().unwrap();
                        if *stop {
                            break;
                        }
                    }

                    if request_count >= max_requests || user_start.elapsed() >= max_duration {
                        if user_start.elapsed() >= max_duration {
                            let mut stop = should_stop.lock().unwrap();
                            *stop = true;
                        }
                        break;
                    }

                    let req_start = Instant::now();
                    let stat = if let Some(ref pool) = pool {
                        let pooled_client =
                            PooledHttpClient::new(Arc::clone(pool)).with_timeout(timeout);
                        match pooled_client.get(&url) {
                            Ok((status_code, body)) => {
                                RequestStats::success(req_start.elapsed(), status_code, body.len())
                            }
                            Err(e) => RequestStats::error(req_start.elapsed(), e),
                        }
                    } else {
                        let client = HttpClient::new().with_timeout(timeout);
                        match client.get(&url) {
                            Ok(response) => RequestStats::success(
                                req_start.elapsed(),
                                response.status_code,
                                response.body.len(),
                            ),
                            Err(e) => RequestStats::error(req_start.elapsed(), e),
                        }
                    };

                    stats.add(stat);
                    request_count += 1;

                    if think_time > Duration::ZERO {
                        thread::sleep(think_time);
                    }
                }

                // Decrement active workers counter
                active_workers.fetch_sub(1, Ordering::Relaxed);
            });
        }

        // Wait for all workers to complete
        while active_workers.load(Ordering::Relaxed) > 0 {
            thread::sleep(Duration::from_millis(10));
        }

        {
            let mut stop = should_stop.lock().unwrap();
            *stop = true;
        }

        if let Some(handle) = live_handle {
            let _ = handle.join();
        }

        let test_duration = start_time.elapsed();

        // Take snapshot of atomic stats
        let stats = match Arc::try_unwrap(stats) {
            Ok(atomic_stats) => atomic_stats.snapshot(),
            Err(arc) => arc.snapshot(),
        };

        build_results(&self.config, stats, test_duration)
    }

    /// Run using thread::spawn (legacy method)
    fn run_with_spawn(&self, live: Option<LiveObserver>) -> Result<LoadTestResults, String> {
        let start_time = Instant::now();
        let stats = Arc::new(AtomicStatsCollector::new());
        let should_stop = Arc::new(Mutex::new(false));

        // Create connection pool if enabled
        let pool = if self.config.use_connection_pool {
            Some(Arc::new(
                ConnectionPool::new().with_max_idle(self.config.max_idle_per_host),
            ))
        } else {
            None
        };

        // Spawn worker threads with smaller stack size
        let mut handles = Vec::new();

        let live_handle = live.as_ref().map(|observer| {
            spawn_live_reporter(
                Arc::clone(&stats),
                Arc::clone(&should_stop),
                observer.clone(),
                start_time,
            )
        });

        for _user_id in 0..self.config.concurrent_users {
            let url = self.config.url.clone();
            let requests_per_user = self.config.requests_per_user;
            let duration = self.config.duration;
            let think_time = self.config.think_time;
            let timeout = self.config.timeout;
            let stats = Arc::clone(&stats);
            let should_stop = Arc::clone(&should_stop);
            let pool = pool.clone();

            // Use Builder to set smaller stack (256KB instead of default 2MB)
            // This allows 8x more concurrent users with same memory!
            let handle = thread::Builder::new()
                .stack_size(256 * 1024) // 256KB stack
                .spawn(move || {
                    let user_start = Instant::now();

                    // Determine when to stop
                    let max_requests = requests_per_user.unwrap_or(usize::MAX);
                    let max_duration = duration.unwrap_or(Duration::from_secs(86400)); // 24h default

                    let mut request_count = 0;

                    loop {
                        // Check stop conditions
                        {
                            let stop = should_stop.lock().unwrap();
                            if *stop {
                                break;
                            }
                        }

                        if request_count >= max_requests {
                            break;
                        }

                        if user_start.elapsed() >= max_duration {
                            // Signal all threads to stop
                            let mut stop = should_stop.lock().unwrap();
                            *stop = true;
                            break;
                        }

                        // Make HTTP request (with or without connection pooling)
                        let req_start = Instant::now();
                        let stat = if let Some(ref pool) = pool {
                            // Use pooled client for better performance
                            let pooled_client =
                                PooledHttpClient::new(Arc::clone(pool)).with_timeout(timeout);
                            match pooled_client.get(&url) {
                                Ok((status_code, body)) => RequestStats::success(
                                    req_start.elapsed(),
                                    status_code,
                                    body.len(),
                                ),
                                Err(e) => RequestStats::error(req_start.elapsed(), e),
                            }
                        } else {
                            // Use regular client
                            let client = HttpClient::new().with_timeout(timeout);
                            match client.get(&url) {
                                Ok(response) => RequestStats::success(
                                    req_start.elapsed(),
                                    response.status_code,
                                    response.body.len(),
                                ),
                                Err(e) => RequestStats::error(req_start.elapsed(), e),
                            }
                        };

                        // Record stats (lock-free atomic operations!)
                        stats.add(stat);

                        request_count += 1;

                        // Think time (simulate real user)
                        if think_time > Duration::ZERO {
                            thread::sleep(think_time);
                        }
                    }
                })
                .expect("Failed to spawn thread");

            handles.push(handle);
        }

        // Wait for all workers
        for handle in handles {
            let _ = handle.join();
        }

        {
            let mut stop = should_stop.lock().unwrap();
            *stop = true;
        }

        if let Some(handle) = live_handle {
            let _ = handle.join();
        }

        let test_duration = start_time.elapsed();

        // Take snapshot of atomic stats
        let stats = match Arc::try_unwrap(stats) {
            Ok(atomic_stats) => atomic_stats.snapshot(),
            Err(arc) => arc.snapshot(),
        };

        build_results(&self.config, stats, test_duration)
    }
}

fn build_results(
    config: &LoadConfig,
    stats: StatsAggregator,
    test_duration: Duration,
) -> Result<LoadTestResults, String> {
    let latency = stats.percentiles();
    let success_rate = stats.success_rate();
    let rps = stats.requests_per_second(test_duration);
    let throughput = stats.throughput_mbps(test_duration);

    // Take only first 100 errors to avoid huge output
    let mut errors = stats.errors.clone();
    errors.truncate(100);

    Ok(LoadTestResults {
        config: config.clone(),
        test_duration,
        total_requests: stats.total_requests,
        successful_requests: stats.successful_requests,
        failed_requests: stats.failed_requests,
        requests_per_second: rps,
        latency,
        status_2xx: stats.status_2xx,
        status_3xx: stats.status_3xx,
        status_4xx: stats.status_4xx,
        status_5xx: stats.status_5xx,
        total_bytes: stats.total_bytes,
        throughput_mbps: throughput,
        success_rate,
        errors,
    })
}

// Clone impl no longer needed - using AtomicStatsCollector.snapshot() instead

fn spawn_live_reporter(
    stats: Arc<AtomicStatsCollector>,
    should_stop: Arc<Mutex<bool>>,
    observer: LiveObserver,
    start_time: Instant,
) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        {
            if *should_stop.lock().unwrap() {
                break;
            }
        }

        let snapshot = stats.snapshot();
        let elapsed = start_time.elapsed();
        let percentiles = snapshot.percentiles();
        let live_snapshot = LiveSnapshot {
            elapsed,
            total_requests: snapshot.total_requests,
            successful_requests: snapshot.successful_requests,
            failed_requests: snapshot.failed_requests,
            status_2xx: snapshot.status_2xx,
            status_3xx: snapshot.status_3xx,
            status_4xx: snapshot.status_4xx,
            status_5xx: snapshot.status_5xx,
            requests_per_second: snapshot.requests_per_second(elapsed),
            throughput_mbps: snapshot.throughput_mbps(elapsed),
            success_rate: snapshot.success_rate(),
            p50: percentiles.p50,
            p95: percentiles.p95,
            p99: percentiles.p99,
        };

        (observer.callback)(live_snapshot);

        thread::sleep(observer.interval);
    })
}
