//! Network Evasion Techniques
//!
//! Techniques to evade network-based detection:
//! - Beacon jitter (randomize timing to avoid pattern detection)
//! - Request delays (avoid burst traffic)
//! - Traffic shaping (mimic normal user behavior)
//!
//! # Usage
//! ```rust
//! use redblue::modules::evasion::network;
//!
//! // Sleep with 30% jitter around 60 seconds
//! network::jittered_sleep(60_000, 30);
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Sleep with jitter to avoid pattern detection
///
/// # Arguments
/// * `base_ms` - Base sleep duration in milliseconds
/// * `jitter_percent` - Jitter percentage (0-100)
pub fn jittered_sleep(base_ms: u64, jitter_percent: u8) {
    let duration = jittered_duration(base_ms, jitter_percent);
    std::thread::sleep(duration);
}

/// Calculate a jittered duration
///
/// # Arguments
/// * `base_ms` - Base duration in milliseconds
/// * `jitter_percent` - Jitter percentage (0-100)
///
/// # Returns
/// Duration with random jitter applied
pub fn jittered_duration(base_ms: u64, jitter_percent: u8) -> Duration {
    if jitter_percent == 0 || base_ms == 0 {
        return Duration::from_millis(base_ms);
    }

    let jitter_percent = jitter_percent.min(100) as u64;
    let jitter_range = (base_ms * jitter_percent) / 100;

    // Generate pseudo-random value
    let random = pseudo_random();

    // Calculate actual jitter (-jitter_range to +jitter_range)
    let jitter = (random % (jitter_range * 2 + 1)) as i64 - jitter_range as i64;
    let actual_ms = (base_ms as i64 + jitter).max(1) as u64;

    Duration::from_millis(actual_ms)
}

/// Simple pseudo-random number generator (no external crates)
fn pseudo_random() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    // Mix time components for pseudo-randomness
    let nanos = now.subsec_nanos() as u64;
    let secs = now.as_secs();

    // Simple LCG-style mixing
    let mut state = nanos ^ secs;
    state = state.wrapping_mul(6364136223846793005);
    state = state.wrapping_add(1442695040888963407);
    state
}

/// Generate a random delay within a range
///
/// # Arguments
/// * `min_ms` - Minimum delay in milliseconds
/// * `max_ms` - Maximum delay in milliseconds
///
/// # Returns
/// Random duration between min and max
pub fn random_delay(min_ms: u64, max_ms: u64) -> Duration {
    if min_ms >= max_ms {
        return Duration::from_millis(min_ms);
    }

    let range = max_ms - min_ms;
    let random = pseudo_random() % (range + 1);
    Duration::from_millis(min_ms + random)
}

/// Sleep for a random duration within a range
pub fn random_sleep(min_ms: u64, max_ms: u64) {
    std::thread::sleep(random_delay(min_ms, max_ms));
}

/// Beacon timing calculator
pub struct BeaconTimer {
    base_interval_ms: u64,
    jitter_percent: u8,
    last_beacon: Option<SystemTime>,
    beacon_count: u64,
}

impl BeaconTimer {
    /// Create a new beacon timer
    pub fn new(base_interval_ms: u64, jitter_percent: u8) -> Self {
        Self {
            base_interval_ms,
            jitter_percent,
            last_beacon: None,
            beacon_count: 0,
        }
    }

    /// Get the next beacon delay
    pub fn next_delay(&mut self) -> Duration {
        self.beacon_count += 1;
        self.last_beacon = Some(SystemTime::now());
        jittered_duration(self.base_interval_ms, self.jitter_percent)
    }

    /// Wait until next beacon
    pub fn wait(&mut self) {
        let delay = self.next_delay();
        std::thread::sleep(delay);
    }

    /// Get beacon count
    pub fn count(&self) -> u64 {
        self.beacon_count
    }

    /// Check if we should beacon (time elapsed since last)
    pub fn should_beacon(&self) -> bool {
        match self.last_beacon {
            None => true,
            Some(last) => {
                if let Ok(elapsed) = last.elapsed() {
                    elapsed.as_millis() as u64 >= self.base_interval_ms
                } else {
                    true
                }
            }
        }
    }
}

/// Traffic shaper for mimicking normal behavior
pub struct TrafficShaper {
    /// Minimum delay between requests
    min_delay_ms: u64,
    /// Maximum delay between requests
    max_delay_ms: u64,
    /// Chance of longer pause (0-100)
    pause_chance: u8,
    /// Duration of longer pause
    pause_duration_ms: u64,
}

impl Default for TrafficShaper {
    fn default() -> Self {
        Self {
            min_delay_ms: 500,
            max_delay_ms: 3000,
            pause_chance: 10,
            pause_duration_ms: 15000,
        }
    }
}

impl TrafficShaper {
    /// Create a new traffic shaper
    pub fn new(min_ms: u64, max_ms: u64) -> Self {
        Self {
            min_delay_ms: min_ms,
            max_delay_ms: max_ms,
            pause_chance: 10,
            pause_duration_ms: 15000,
        }
    }

    /// Set pause behavior
    pub fn with_pauses(mut self, chance: u8, duration_ms: u64) -> Self {
        self.pause_chance = chance;
        self.pause_duration_ms = duration_ms;
        self
    }

    /// Delay before next request (mimics human behavior)
    pub fn delay(&self) {
        // Check if we should take a longer pause
        if (pseudo_random() % 100) < self.pause_chance as u64 {
            std::thread::sleep(Duration::from_millis(self.pause_duration_ms));
            return;
        }

        random_sleep(self.min_delay_ms, self.max_delay_ms);
    }

    /// Get next delay without sleeping
    pub fn next_delay(&self) -> Duration {
        if (pseudo_random() % 100) < self.pause_chance as u64 {
            return Duration::from_millis(self.pause_duration_ms);
        }

        random_delay(self.min_delay_ms, self.max_delay_ms)
    }
}

/// Request rate limiter
pub struct RateLimiter {
    /// Maximum requests per window
    max_requests: u32,
    /// Window size in milliseconds
    window_ms: u64,
    /// Request timestamps in current window
    requests: Vec<SystemTime>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_requests: u32, window_ms: u64) -> Self {
        Self {
            max_requests,
            window_ms,
            requests: Vec::with_capacity(max_requests as usize),
        }
    }

    /// Check if we can make a request
    pub fn can_request(&mut self) -> bool {
        self.cleanup_old_requests();
        (self.requests.len() as u32) < self.max_requests
    }

    /// Record a request
    pub fn record_request(&mut self) {
        self.requests.push(SystemTime::now());
    }

    /// Wait until we can make a request
    pub fn wait_for_slot(&mut self) {
        while !self.can_request() {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Cleanup requests outside the window
    fn cleanup_old_requests(&mut self) {
        let now = SystemTime::now();
        let window = Duration::from_millis(self.window_ms);

        self.requests.retain(|&time| {
            now.duration_since(time)
                .map(|elapsed| elapsed < window)
                .unwrap_or(false)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jittered_duration() {
        let base = 1000;
        let jitter = 30;

        let mut durations = Vec::new();
        for _ in 0..10 {
            let d = jittered_duration(base, jitter);
            durations.push(d.as_millis());
            std::thread::sleep(Duration::from_millis(1)); // Ensure different random values
        }

        // All durations should be within jitter range
        for d in &durations {
            assert!(*d >= 700 && *d <= 1300, "Duration {} out of range", d);
        }
    }

    #[test]
    fn test_jittered_duration_zero() {
        let d = jittered_duration(0, 50);
        assert_eq!(d.as_millis(), 0);

        let d = jittered_duration(1000, 0);
        assert_eq!(d.as_millis(), 1000);
    }

    #[test]
    fn test_random_delay() {
        let delay = random_delay(100, 200);
        let ms = delay.as_millis();
        assert!(ms >= 100 && ms <= 200);
    }

    #[test]
    fn test_beacon_timer() {
        let mut timer = BeaconTimer::new(100, 20);
        assert!(timer.should_beacon());
        assert_eq!(timer.count(), 0);

        let delay = timer.next_delay();
        assert!(delay.as_millis() >= 80 && delay.as_millis() <= 120);
        assert_eq!(timer.count(), 1);
    }

    #[test]
    fn test_traffic_shaper() {
        let shaper = TrafficShaper::new(50, 100);
        let delay = shaper.next_delay();
        // Should be within range (or pause duration)
        assert!(
            (delay.as_millis() >= 50 && delay.as_millis() <= 100) || delay.as_millis() == 15000
        );
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(2, 1000);
        assert!(limiter.can_request());

        limiter.record_request();
        assert!(limiter.can_request());

        limiter.record_request();
        assert!(!limiter.can_request());

        // After window expires, should be able to request again
        std::thread::sleep(Duration::from_millis(1100));
        assert!(limiter.can_request());
    }
}
