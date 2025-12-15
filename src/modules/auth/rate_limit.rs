use std::thread;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    last_attempt: Instant,
    delay: Duration,
    consecutive_failures: u32,
    lockout_detected: bool,
}

impl RateLimiter {
    pub fn new(delay_ms: u64) -> Self {
        Self {
            last_attempt: Instant::now(),
            delay: Duration::from_millis(delay_ms),
            consecutive_failures: 0,
            lockout_detected: false,
        }
    }

    pub fn wait(&mut self) {
        let elapsed = self.last_attempt.elapsed();
        if elapsed < self.delay {
            thread::sleep(self.delay - elapsed);
        }
        self.last_attempt = Instant::now();
    }

    pub fn report_result(&mut self, status_code: u16) {
        if status_code == 429 || status_code == 403 {
            // Lockout or rate limit detected
            self.lockout_detected = true;
            // Increase delay
            self.delay = self.delay * 2;
        } else {
            // Reset logic if needed, or if we see success/normal fail
            if self.lockout_detected && status_code != 429 && status_code != 403 {
                // Maybe slowly decrease? Or keep it safe?
            }
        }
    }
}
