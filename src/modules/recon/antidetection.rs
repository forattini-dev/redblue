use std::time::{Duration, Instant};
use std::thread;

pub struct AntiDetection {
    base_delay: Duration,
    max_delay: Duration,
    backoff_factor: f64,
    last_request_time: Instant,
    current_delay: Duration,
    user_agents: Vec<String>,
    current_ua_idx: usize,
}

impl AntiDetection {
    pub fn new() -> Self {
        Self {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            backoff_factor: 2.0,
            last_request_time: Instant::now() - Duration::from_secs(3600), // Initialize far in past
            current_delay: Duration::from_millis(0),
            user_agents: Self::default_user_agents(),
            current_ua_idx: 0,
        }
    }

    pub fn with_base_delay(mut self, millis: u64) -> Self {
        self.base_delay = Duration::from_millis(millis);
        self.current_delay = self.base_delay;
        self
    }

    pub fn with_max_delay(mut self, secs: u64) -> Self {
        self.max_delay = Duration::from_secs(secs);
        self
    }

    /// Call this before making a request to apply rate limiting.
    pub fn wait_for_next_request(&mut self) {
        let elapsed = self.last_request_time.elapsed();
        if elapsed < self.current_delay {
            let sleep_time = self.current_delay - elapsed;
            thread::sleep(sleep_time);
        }
        self.last_request_time = Instant::now();
    }

    /// Call this after a request, reporting success or failure.
    pub fn report_request_outcome(&mut self, success: bool, is_rate_limited: bool) {
        if is_rate_limited || !success {
            // Exponential backoff
            let new_delay_secs = (self.current_delay.as_secs_f64() * self.backoff_factor)
                .min(self.max_delay.as_secs_f64())
                .max(self.base_delay.as_secs_f64());
            self.current_delay = Duration::from_secs_f64(new_delay_secs);
        } else {
            // Reset delay gradually on success
            let new_delay_secs = (self.current_delay.as_secs_f64() / self.backoff_factor)
                .max(self.base_delay.as_secs_f64());
            self.current_delay = Duration::from_secs_f64(new_delay_secs);
        }
    }

    /// Get the next User-Agent in rotation.
    pub fn get_next_user_agent(&mut self) -> &str {
        let ua = &self.user_agents[self.current_ua_idx];
        self.current_ua_idx = (self.current_ua_idx + 1) % self.user_agents.len();
        ua
    }

    fn default_user_agents() -> Vec<String> {
        vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/109.0".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0".to_string(),
        ]
    }
}
