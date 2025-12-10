//! Shell Interceptor - Bridge between MitmProxy and MitmShell TUI
//!
//! Sends events to the shell for display and receives decisions for intercepted requests.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::time::Instant;

use crate::modules::proxy::mitm::{HttpRequest, HttpResponse, InterceptAction, RequestInterceptor};

/// Event sent from interceptor to shell
#[derive(Debug)]
pub enum ShellEvent {
    /// New HTTP request received
    NewRequest {
        id: u64,
        source_ip: String,
        method: String,
        host: String,
        path: String,
        version: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    },
    /// Response received for a request
    ResponseReceived {
        id: u64,
        status_code: u16,
        status_text: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        duration_ms: u64,
    },
    /// Request was dropped
    RequestDropped {
        id: u64,
    },
}

/// Shell interceptor - sends events to the TUI
pub struct ShellInterceptor {
    /// Channel to send events to the shell
    event_tx: Sender<ShellEvent>,
    /// Request ID counter
    next_id: AtomicU64,
    /// Request start times for duration calculation
    request_times: std::sync::Mutex<HashMap<u64, Instant>>,
}

impl ShellInterceptor {
    /// Create new shell interceptor
    pub fn new(event_tx: Sender<ShellEvent>) -> Self {
        Self {
            event_tx,
            next_id: AtomicU64::new(1),
            request_times: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Get current request ID
    fn current_id(&self) -> u64 {
        self.next_id.load(Ordering::Relaxed)
    }

    /// Allocate new request ID
    fn next_request_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Record request start time
    fn record_start(&self, id: u64) {
        if let Ok(mut times) = self.request_times.lock() {
            times.insert(id, Instant::now());
        }
    }

    /// Get and remove request duration
    fn get_duration(&self, id: u64) -> u64 {
        if let Ok(mut times) = self.request_times.lock() {
            if let Some(start) = times.remove(&id) {
                return start.elapsed().as_millis() as u64;
            }
        }
        0
    }

    /// Extract request ID from headers (we inject it during on_request)
    fn extract_id_from_request(&self, req: &HttpRequest) -> u64 {
        req.headers
            .get("X-RB-Request-Id")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }
}

impl RequestInterceptor for ShellInterceptor {
    fn on_request(&self, req: &mut HttpRequest, client_addr: Option<&str>) -> InterceptAction {
        let id = self.next_request_id();
        self.record_start(id);

        // Inject our request ID header for tracking
        req.headers.insert("X-RB-Request-Id".to_string(), id.to_string());

        // Send event to shell
        let event = ShellEvent::NewRequest {
            id,
            source_ip: client_addr.unwrap_or("unknown").to_string(),
            method: req.method.clone(),
            host: req.host.clone(),
            path: req.path.clone(),
            version: req.version.clone(),
            headers: req.headers.clone(),
            body: req.body.clone(),
        };

        // Best effort send - don't block on slow UI
        let _ = self.event_tx.send(event);

        InterceptAction::Continue
    }

    fn on_response(&self, req: &HttpRequest, resp: &mut HttpResponse) -> InterceptAction {
        let id = self.extract_id_from_request(req);
        let duration_ms = self.get_duration(id);

        // Send response event
        let event = ShellEvent::ResponseReceived {
            id,
            status_code: resp.status_code,
            status_text: resp.status_text.clone(),
            headers: resp.headers.clone(),
            body: resp.body.clone(),
            duration_ms,
        };

        let _ = self.event_tx.send(event);

        InterceptAction::Continue
    }
}

/// Interactive shell interceptor - can pause and wait for user decisions
pub struct InteractiveShellInterceptor {
    /// Base interceptor for events
    base: ShellInterceptor,
    /// Whether intercept mode is enabled
    intercept_enabled: std::sync::atomic::AtomicBool,
    // TODO: Add channel for receiving decisions from the shell
    // decision_rx: Receiver<InterceptDecision>,
}

impl InteractiveShellInterceptor {
    /// Create new interactive interceptor
    pub fn new(event_tx: Sender<ShellEvent>) -> Self {
        Self {
            base: ShellInterceptor::new(event_tx),
            intercept_enabled: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Enable or disable intercept mode
    pub fn set_intercept(&self, enabled: bool) {
        self.intercept_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Check if intercept is enabled
    pub fn is_intercept_enabled(&self) -> bool {
        self.intercept_enabled.load(Ordering::Relaxed)
    }
}

impl RequestInterceptor for InteractiveShellInterceptor {
    fn on_request(&self, req: &mut HttpRequest, client_addr: Option<&str>) -> InterceptAction {
        // For now, delegate to base - full intercept logic will be added later
        self.base.on_request(req, client_addr)
    }

    fn on_response(&self, req: &HttpRequest, resp: &mut HttpResponse) -> InterceptAction {
        self.base.on_response(req, resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn test_shell_interceptor_basic() {
        let (tx, rx) = mpsc::channel();
        let interceptor = ShellInterceptor::new(tx);

        let mut req = HttpRequest {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
            host: "example.com".to_string(),
            client_addr: None,
        };

        // Call on_request with client address
        let action = interceptor.on_request(&mut req, Some("192.168.1.100:54321"));
        assert!(matches!(action, InterceptAction::Continue));

        // Check event was sent
        let event = rx.try_recv().unwrap();
        match event {
            ShellEvent::NewRequest { id, source_ip, method, host, path, .. } => {
                assert_eq!(id, 1);
                assert_eq!(source_ip, "192.168.1.100:54321");
                assert_eq!(method, "GET");
                assert_eq!(host, "example.com");
                assert_eq!(path, "/api/test");
            }
            _ => panic!("Expected NewRequest event"),
        }

        // Check ID was injected into headers
        assert!(req.headers.contains_key("X-RB-Request-Id"));
    }

    #[test]
    fn test_shell_interceptor_response() {
        let (tx, rx) = mpsc::channel();
        let interceptor = ShellInterceptor::new(tx);

        // Create request with injected ID
        let mut req = HttpRequest {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
            host: "example.com".to_string(),
            client_addr: None,
        };

        interceptor.on_request(&mut req, Some("10.0.0.1:12345"));

        // Drain the request event
        let _ = rx.try_recv();

        // Create response
        let mut resp = HttpResponse {
            version: "HTTP/1.1".to_string(),
            status_code: 200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            body: b"{\"status\":\"ok\"}".to_vec(),
        };

        // Call on_response
        let action = interceptor.on_response(&req, &mut resp);
        assert!(matches!(action, InterceptAction::Continue));

        // Check response event
        let event = rx.try_recv().unwrap();
        match event {
            ShellEvent::ResponseReceived { id, status_code, status_text, .. } => {
                assert_eq!(id, 1);
                assert_eq!(status_code, 200);
                assert_eq!(status_text, "OK");
            }
            _ => panic!("Expected ResponseReceived event"),
        }
    }
}
