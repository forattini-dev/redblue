//! Transport abstraction for C2 communication
//!
//! This module provides a unified interface for different transport mechanisms
//! used by the C2 agent. Supported transports:
//! - HTTP: Standard HTTP/HTTPS with endpoint rotation
//! - DNS: DNS tunneling using TXT records
//! - WebSocket: Full-duplex WebSocket communication

pub mod dns;
pub mod http;
pub mod websocket;

use std::time::Duration;

/// Transport result type
pub type TransportResult<T> = Result<T, TransportError>;

/// Transport errors
#[derive(Debug, Clone)]
pub enum TransportError {
    /// Connection failed
    ConnectionFailed(String),
    /// Timeout waiting for response
    Timeout,
    /// Transport is disconnected
    Disconnected,
    /// Invalid data received
    InvalidData(String),
    /// DNS resolution failed
    DnsResolutionFailed(String),
    /// TLS handshake failed
    TlsError(String),
    /// Rate limited
    RateLimited,
    /// Generic transport error
    Other(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            Self::Timeout => write!(f, "Transport timeout"),
            Self::Disconnected => write!(f, "Transport disconnected"),
            Self::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            Self::DnsResolutionFailed(msg) => write!(f, "DNS resolution failed: {}", msg),
            Self::TlsError(msg) => write!(f, "TLS error: {}", msg),
            Self::RateLimited => write!(f, "Rate limited"),
            Self::Other(msg) => write!(f, "Transport error: {}", msg),
        }
    }
}

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Read/write timeout
    pub io_timeout: Duration,
    /// Number of retry attempts
    pub retry_count: u32,
    /// Delay between retries
    pub retry_delay: Duration,
    /// Enable TLS
    pub use_tls: bool,
    /// TLS certificate pinning (SHA256 fingerprints)
    pub cert_pins: Vec<[u8; 32]>,
    /// Custom headers for HTTP
    pub custom_headers: Vec<(String, String)>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
            retry_count: 3,
            retry_delay: Duration::from_secs(1),
            use_tls: false,
            cert_pins: Vec::new(),
            custom_headers: Vec::new(),
        }
    }
}

/// Transport trait - abstraction for different communication channels
pub trait Transport: Send + Sync {
    /// Send data and receive response
    fn send(&mut self, data: &[u8]) -> TransportResult<Vec<u8>>;

    /// Check if transport is currently connected
    fn is_connected(&self) -> bool;

    /// Attempt to reconnect if disconnected
    fn reconnect(&mut self) -> TransportResult<()>;

    /// Get transport name for logging
    fn name(&self) -> &str;

    /// Get current endpoint being used
    fn current_endpoint(&self) -> String;

    /// Rotate to next endpoint (if supported)
    fn rotate_endpoint(&mut self) -> bool {
        false // Default: no rotation support
    }

    /// Close the transport connection
    fn close(&mut self);
}

/// Transport health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportHealth {
    /// Transport is healthy and operational
    Healthy,
    /// Transport is degraded (slow, high latency)
    Degraded,
    /// Transport is unhealthy (errors, disconnects)
    Unhealthy,
    /// Transport status unknown
    Unknown,
}

/// Transport statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Number of successful requests
    pub requests_success: u64,
    /// Number of failed requests
    pub requests_failed: u64,
    /// Average latency in milliseconds
    pub avg_latency_ms: u64,
    /// Last error message
    pub last_error: Option<String>,
    /// Consecutive failures count
    pub consecutive_failures: u32,
}

impl TransportStats {
    /// Update stats after successful request
    pub fn record_success(&mut self, bytes_sent: usize, bytes_received: usize, latency_ms: u64) {
        self.bytes_sent += bytes_sent as u64;
        self.bytes_received += bytes_received as u64;
        self.requests_success += 1;
        self.consecutive_failures = 0;

        // Update rolling average latency
        let total = self.requests_success;
        self.avg_latency_ms = (self.avg_latency_ms * (total - 1) + latency_ms) / total;
    }

    /// Update stats after failed request
    pub fn record_failure(&mut self, error: &str) {
        self.requests_failed += 1;
        self.consecutive_failures += 1;
        self.last_error = Some(error.to_string());
    }

    /// Get current health based on stats
    pub fn health(&self) -> TransportHealth {
        if self.consecutive_failures >= 5 {
            TransportHealth::Unhealthy
        } else if self.consecutive_failures >= 2 || self.avg_latency_ms > 5000 {
            TransportHealth::Degraded
        } else if self.requests_success > 0 {
            TransportHealth::Healthy
        } else {
            TransportHealth::Unknown
        }
    }
}

/// Transport selector with fallback support
pub struct TransportChain {
    /// List of transports in priority order
    transports: Vec<Box<dyn Transport>>,
    /// Index of currently active transport
    active_index: usize,
    /// Stats for each transport
    stats: Vec<TransportStats>,
    /// Auto-fallback on failure
    auto_fallback: bool,
    /// Consecutive failures before fallback
    fallback_threshold: u32,
}

impl TransportChain {
    /// Create new transport chain
    pub fn new() -> Self {
        Self {
            transports: Vec::new(),
            active_index: 0,
            stats: Vec::new(),
            auto_fallback: true,
            fallback_threshold: 3,
        }
    }

    /// Add a transport to the chain
    pub fn add_transport(&mut self, transport: Box<dyn Transport>) {
        self.transports.push(transport);
        self.stats.push(TransportStats::default());
    }

    /// Set auto-fallback behavior
    pub fn with_auto_fallback(mut self, enabled: bool) -> Self {
        self.auto_fallback = enabled;
        self
    }

    /// Set fallback threshold
    pub fn with_fallback_threshold(mut self, threshold: u32) -> Self {
        self.fallback_threshold = threshold;
        self
    }

    /// Get currently active transport
    pub fn active_transport(&self) -> Option<&dyn Transport> {
        self.transports.get(self.active_index).map(|t| t.as_ref())
    }

    /// Get mutable reference to active transport
    pub fn active_transport_mut(&mut self) -> Option<&mut Box<dyn Transport>> {
        self.transports.get_mut(self.active_index)
    }

    /// Send data through active transport with fallback
    pub fn send(&mut self, data: &[u8]) -> TransportResult<Vec<u8>> {
        if self.transports.is_empty() {
            return Err(TransportError::Other("No transports configured".into()));
        }

        let start = std::time::Instant::now();
        let sent_bytes = data.len();

        match self.transports[self.active_index].send(data) {
            Ok(response) => {
                let latency = start.elapsed().as_millis() as u64;
                self.stats[self.active_index].record_success(sent_bytes, response.len(), latency);
                Ok(response)
            }
            Err(e) => {
                self.stats[self.active_index].record_failure(&e.to_string());

                // Try fallback if enabled
                if self.auto_fallback
                    && self.stats[self.active_index].consecutive_failures >= self.fallback_threshold
                {
                    if self.fallback_to_next() {
                        // Retry with new transport
                        return self.send(data);
                    }
                }

                Err(e)
            }
        }
    }

    /// Fallback to next available transport
    pub fn fallback_to_next(&mut self) -> bool {
        let original = self.active_index;
        let count = self.transports.len();

        for i in 1..count {
            let next = (original + i) % count;
            if self.transports[next].is_connected() || self.transports[next].reconnect().is_ok() {
                self.active_index = next;
                return true;
            }
        }

        false
    }

    /// Get health of all transports
    pub fn health_report(&self) -> Vec<(String, TransportHealth)> {
        self.transports
            .iter()
            .zip(self.stats.iter())
            .map(|(t, s)| (t.name().to_string(), s.health()))
            .collect()
    }

    /// Reset to primary transport
    pub fn reset_to_primary(&mut self) {
        self.active_index = 0;
    }
}

impl Default for TransportChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTransport {
        name: String,
        connected: bool,
        response: Vec<u8>,
        fail_count: u32,
        current_fails: u32,
    }

    impl MockTransport {
        fn new(name: &str, fail_count: u32) -> Self {
            Self {
                name: name.to_string(),
                connected: true,
                response: b"OK".to_vec(),
                fail_count,
                current_fails: 0,
            }
        }
    }

    impl Transport for MockTransport {
        fn send(&mut self, _data: &[u8]) -> TransportResult<Vec<u8>> {
            if self.current_fails < self.fail_count {
                self.current_fails += 1;
                Err(TransportError::ConnectionFailed("mock failure".into()))
            } else {
                Ok(self.response.clone())
            }
        }

        fn is_connected(&self) -> bool {
            self.connected
        }

        fn reconnect(&mut self) -> TransportResult<()> {
            self.connected = true;
            self.current_fails = 0;
            Ok(())
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn current_endpoint(&self) -> String {
            "mock://localhost".into()
        }

        fn close(&mut self) {
            self.connected = false;
        }
    }

    #[test]
    fn test_transport_chain_fallback() {
        let mut chain = TransportChain::new()
            .with_auto_fallback(true)
            .with_fallback_threshold(2);

        // First transport always fails
        chain.add_transport(Box::new(MockTransport::new("http", 100)));
        // Second transport works
        chain.add_transport(Box::new(MockTransport::new("dns", 0)));

        // First call: http fails, consecutive_failures = 1, returns error
        let result1 = chain.send(b"test");
        assert!(result1.is_err());
        assert_eq!(chain.active_index, 0); // Still on http

        // Second call: http fails again, consecutive_failures = 2, triggers fallback
        // Then retries with dns which succeeds
        let result2 = chain.send(b"test");
        assert!(result2.is_ok());
        assert_eq!(chain.active_index, 1); // Now on dns
    }

    #[test]
    fn test_transport_stats() {
        let mut stats = TransportStats::default();

        stats.record_success(100, 200, 50);
        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.bytes_received, 200);
        assert_eq!(stats.requests_success, 1);
        assert_eq!(stats.health(), TransportHealth::Healthy);

        // Multiple failures
        for _ in 0..5 {
            stats.record_failure("error");
        }
        assert_eq!(stats.health(), TransportHealth::Unhealthy);
    }

    #[test]
    fn test_transport_error_display() {
        let err = TransportError::Timeout;
        assert_eq!(format!("{}", err), "Transport timeout");

        let err = TransportError::TlsError("cert invalid".into());
        assert_eq!(format!("{}", err), "TLS error: cert invalid");
    }
}
