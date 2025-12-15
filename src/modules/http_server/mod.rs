//! Built-in HTTP Server for Payload Hosting
//!
//! A simple, multi-threaded HTTP server for hosting payloads and files
//! without external dependencies.
//!
//! # Features
//!
//! - Static file serving
//! - Directory listing (optional)
//! - CORS support (enabled by default)
//! - MIME type auto-detection
//! - Embedded default files (hook.js)
//! - Multi-threaded request handling
//!
//! # Usage
//!
//! ```bash
//! # Serve current directory
//! rb http serve --port 8080
//!
//! # Serve specific directory
//! rb http serve --port 8080 --dir ./payloads
//!
//! # Disable directory listing
//! rb http serve --port 8080 --no-listing
//!
//! # Disable CORS
//! rb http serve --port 8080 --no-cors
//! ```

mod embedded;
mod mime;
mod server;

pub use embedded::EmbeddedFiles;
pub use mime::MimeType;
pub use server::{HttpRequest, HttpResponse, HttpServer, HttpServerConfig};
