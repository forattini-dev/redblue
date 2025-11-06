/// Centralized logging module for redblue
///
/// Controls debug output with --verbose flag

use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Enable verbose/debug logging
pub fn enable_verbose() {
    VERBOSE.store(true, Ordering::Relaxed);
}

/// Check if verbose logging is enabled
pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Log debug message (only if verbose mode is enabled)
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::utils::logger::is_verbose() {
            eprintln!("[DEBUG] {}", format!($($arg)*));
        }
    };
}

/// Log info message (always shown)
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        eprintln!("[INFO] {}", format!($($arg)*));
    };
}

/// Log warning message (always shown)
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        eprintln!("[WARN] {}", format!($($arg)*));
    };
}

/// Log error message (always shown)
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        eprintln!("[ERROR] {}", format!($($arg)*));
    };
}
