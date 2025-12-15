//! Shared HTTP/2 Connection Pool
//!
//! Allows multiple workers to share HTTP/2 connections for efficient load testing.
//! HTTP/2 supports multiplexing (100+ concurrent streams), but since our Http2Client
//! requires &mut self, we serialize access with a Mutex per connection.
//!
//! Benefits:
//! - Reduces TLS handshakes (expensive: ~100ms each)
//! - Reduces connection establishment overhead
//! - Better utilizes HTTP/2's persistent connection model

use super::connection::Http2Client;
use super::hpack::Header;
use super::{Http2Response, Http2ResponseHandler, Http2ResponseHead};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Entry in the shared pool with connection and metadata
struct PoolEntry {
    client: Http2Client,
    created_at: Instant,
    request_count: usize,
}

impl PoolEntry {
    fn new(client: Http2Client) -> Self {
        Self {
            client,
            created_at: Instant::now(),
            request_count: 0,
        }
    }

    fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

/// Configuration for the shared HTTP/2 pool
#[derive(Debug, Clone)]
pub struct SharedHttp2PoolConfig {
    /// Maximum connections per origin (host:port)
    pub max_connections_per_origin: usize,
    /// Maximum age before connection is recycled
    pub max_connection_age: Duration,
    /// Maximum requests per connection before recycling
    pub max_requests_per_connection: usize,
}

impl Default for SharedHttp2PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_origin: 6,
            max_connection_age: Duration::from_secs(300),
            max_requests_per_connection: 10000,
        }
    }
}

/// Shared HTTP/2 connection pool for multi-threaded load testing
///
/// Uses RwLock for the outer HashMap (fast reads) and Mutex per connection
/// to serialize access. This reduces TLS handshake overhead while maintaining
/// thread safety.
pub struct SharedHttp2Pool {
    /// Pool of connections keyed by origin (host:port)
    /// Each origin can have multiple connections, each wrapped in a Mutex
    connections: RwLock<HashMap<String, Vec<Arc<Mutex<PoolEntry>>>>>,
    config: SharedHttp2PoolConfig,
}

impl SharedHttp2Pool {
    /// Create a new shared HTTP/2 pool with default configuration
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            config: SharedHttp2PoolConfig::default(),
        }
    }

    /// Create a new shared HTTP/2 pool with custom configuration
    pub fn with_config(config: SharedHttp2PoolConfig) -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Get an origin key from host and port
    fn origin_key(host: &str, port: u16) -> String {
        format!("{}:{}", host, port)
    }

    /// Execute a request using a pooled connection
    ///
    /// This method handles connection acquisition, request execution, and
    /// connection return automatically. It will create new connections if
    /// none are available or all existing ones are busy.
    pub fn execute_request(
        &self,
        host: &str,
        port: u16,
        method: &str,
        path: &str,
        authority: &str,
        headers: Vec<Header>,
        body: Option<Vec<u8>>,
        start_time: Instant,
    ) -> Result<(Http2Response, Duration), String> {
        let key = Self::origin_key(host, port);

        // Try to find an available connection
        if let Some(entry) = self.try_acquire_connection(&key) {
            let mut guard = entry.lock().map_err(|_| "Connection lock poisoned")?;

            // Check if connection is still healthy
            if guard.age() < self.config.max_connection_age
                && guard.request_count < self.config.max_requests_per_connection
            {
                guard.request_count += 1;
                return guard
                    .client
                    .send_request_with_timing(method, path, authority, headers, body, start_time);
            }

            // Connection is stale, remove it and create new one
            self.remove_connection(&key, &entry);
        }

        // Create new connection
        let mut client = Http2Client::connect(host, port)?;
        let result = client.send_request_with_timing(
            method,
            path,
            authority,
            headers.clone(),
            body,
            start_time,
        );

        // Store the connection for reuse if successful
        if result.is_ok() {
            let mut entry = PoolEntry::new(client);
            entry.request_count = 1;
            self.store_connection(&key, entry);
        }

        result
    }

    /// Execute a request with streaming response handler
    pub fn execute_request_with_handler(
        &self,
        host: &str,
        port: u16,
        method: &str,
        path: &str,
        authority: &str,
        headers: Vec<Header>,
        body: Option<Vec<u8>>,
        handler: &mut dyn Http2ResponseHandler,
    ) -> Result<(Http2ResponseHead, Duration), String> {
        let key = Self::origin_key(host, port);

        // Try to find an available connection
        if let Some(entry) = self.try_acquire_connection(&key) {
            let mut guard = entry.lock().map_err(|_| "Connection lock poisoned")?;

            // Check if connection is still healthy
            if guard.age() < self.config.max_connection_age
                && guard.request_count < self.config.max_requests_per_connection
            {
                guard.request_count += 1;
                return guard
                    .client
                    .send_request_with_handler(method, path, authority, headers, body, handler);
            }
        }

        // Create new connection
        let mut client = Http2Client::connect(host, port)?;
        let result = client.send_request_with_handler(
            method,
            path,
            authority,
            headers.clone(),
            body,
            handler,
        );

        // Store the connection for reuse if successful
        if result.is_ok() {
            let mut entry = PoolEntry::new(client);
            entry.request_count = 1;
            self.store_connection(&key, entry);
        }

        result
    }

    /// Try to acquire an available connection from the pool
    fn try_acquire_connection(&self, key: &str) -> Option<Arc<Mutex<PoolEntry>>> {
        let connections = self.connections.read().ok()?;
        let pool = connections.get(key)?;

        // Try each connection in the pool
        for entry in pool.iter() {
            // Try to acquire lock without blocking
            if entry.try_lock().is_ok() {
                return Some(Arc::clone(entry));
            }
        }

        // All connections are busy, but we might be able to create a new one
        if pool.len() < self.config.max_connections_per_origin {
            return None; // Signal that we should create a new connection
        }

        // Pool is full, wait for any available connection
        for entry in pool.iter() {
            return Some(Arc::clone(entry));
        }

        None
    }

    /// Store a connection in the pool
    fn store_connection(&self, key: &str, entry: PoolEntry) {
        let mut connections = match self.connections.write() {
            Ok(guard) => guard,
            Err(_) => return,
        };

        let pool = connections.entry(key.to_string()).or_insert_with(Vec::new);

        // Only add if we haven't reached the limit
        if pool.len() < self.config.max_connections_per_origin {
            pool.push(Arc::new(Mutex::new(entry)));
        }
    }

    /// Remove a specific connection from the pool
    fn remove_connection(&self, key: &str, to_remove: &Arc<Mutex<PoolEntry>>) {
        let mut connections = match self.connections.write() {
            Ok(guard) => guard,
            Err(_) => return,
        };

        if let Some(pool) = connections.get_mut(key) {
            pool.retain(|entry| !Arc::ptr_eq(entry, to_remove));
        }
    }

    /// Clear all connections from the pool
    pub fn clear(&self) {
        if let Ok(mut connections) = self.connections.write() {
            connections.clear();
        }
    }

    /// Get statistics about the pool
    pub fn stats(&self) -> SharedHttp2PoolStats {
        let connections = match self.connections.read() {
            Ok(guard) => guard,
            Err(_) => {
                return SharedHttp2PoolStats {
                    origins: 0,
                    total_connections: 0,
                    total_requests: 0,
                }
            }
        };

        let mut total_connections = 0;
        let mut total_requests = 0;

        for pool in connections.values() {
            total_connections += pool.len();
            for entry in pool {
                if let Ok(guard) = entry.lock() {
                    total_requests += guard.request_count;
                }
            }
        }

        SharedHttp2PoolStats {
            origins: connections.len(),
            total_connections,
            total_requests,
        }
    }
}

impl Default for SharedHttp2Pool {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the shared HTTP/2 pool
#[derive(Debug, Clone)]
pub struct SharedHttp2PoolStats {
    /// Number of distinct origins (host:port combinations)
    pub origins: usize,
    /// Total number of connections across all origins
    pub total_connections: usize,
    /// Total requests served through the pool
    pub total_requests: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_default() {
        let config = SharedHttp2PoolConfig::default();
        assert_eq!(config.max_connections_per_origin, 6);
        assert_eq!(config.max_connection_age, Duration::from_secs(300));
        assert_eq!(config.max_requests_per_connection, 10000);
    }

    #[test]
    fn test_origin_key() {
        assert_eq!(
            SharedHttp2Pool::origin_key("example.com", 443),
            "example.com:443"
        );
        assert_eq!(
            SharedHttp2Pool::origin_key("api.test.io", 8443),
            "api.test.io:8443"
        );
    }

    #[test]
    fn test_pool_stats_empty() {
        let pool = SharedHttp2Pool::new();
        let stats = pool.stats();
        assert_eq!(stats.origins, 0);
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.total_requests, 0);
    }
}
