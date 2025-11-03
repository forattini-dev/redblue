/// RedBlue error types for consistent error handling across modules
use std::fmt;

#[derive(Debug, Clone)]
pub enum RedBlueError {
    /// Network-related errors (connection, timeout, DNS)
    Network(String),

    /// Parsing errors (JSON, HTML, response format)
    Parse(String),

    /// Validation errors (invalid domain, IP, URL)
    Validation(String),

    /// Resource not found (404, missing file)
    NotFound(String),

    /// Authentication/authorization failures
    Unauthorized(String),

    /// Operation timeout
    Timeout(String),

    /// I/O errors (file read/write)
    Io(String),

    /// SSL/TLS errors
    Tls(String),

    /// Generic errors that don't fit other categories
    Other(String),
}

impl fmt::Display for RedBlueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedBlueError::Network(msg) => write!(f, "Network error: {}", msg),
            RedBlueError::Parse(msg) => write!(f, "Parse error: {}", msg),
            RedBlueError::Validation(msg) => write!(f, "Validation error: {}", msg),
            RedBlueError::NotFound(msg) => write!(f, "Not found: {}", msg),
            RedBlueError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            RedBlueError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            RedBlueError::Io(msg) => write!(f, "I/O error: {}", msg),
            RedBlueError::Tls(msg) => write!(f, "TLS error: {}", msg),
            RedBlueError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for RedBlueError {}

// Conversion from String for backward compatibility
impl From<String> for RedBlueError {
    fn from(s: String) -> Self {
        RedBlueError::Other(s)
    }
}

impl From<&str> for RedBlueError {
    fn from(s: &str) -> Self {
        RedBlueError::Other(s.to_string())
    }
}

impl From<std::io::Error> for RedBlueError {
    fn from(err: std::io::Error) -> Self {
        RedBlueError::Io(err.to_string())
    }
}

// Result type alias for convenience
pub type Result<T> = std::result::Result<T, RedBlueError>;
