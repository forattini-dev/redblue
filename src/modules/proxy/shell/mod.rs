//! MITM Interactive Shell - k9s-style TUI for HTTP proxy inspection
//!
//! Provides a full-featured interactive terminal interface for:
//! - Real-time request/response streaming
//! - Request interception and modification
//! - History browsing and replay
//! - Filtering and search
//!
//! # Usage
//!
//! ```bash
//! rb mitm intercept shell --port 8080
//! ```

pub mod app;
pub mod input;
pub mod interceptor;
pub mod state;
pub mod ui;

pub use app::MitmShell;
pub use interceptor::ShellInterceptor;
pub use state::{HttpExchange, RequestFilter, ShellState, ShellViewMode};
