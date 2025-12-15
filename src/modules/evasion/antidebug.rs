//! Advanced Anti-Debugging Techniques
//!
//! Multiple layers of debugger detection:
//! - Timing-based detection (RDTSC, QueryPerformanceCounter)
//! - Process environment checks
//! - Hardware breakpoint detection
//! - Exception-based detection
//! - API hooking detection
//!
//! # Warning
//! These techniques are for authorized security testing only.

use std::time::{Duration, Instant};

/// Anti-debugging detection results
#[derive(Debug, Clone)]
pub struct AntiDebugResult {
    /// Overall detection status
    pub debugger_detected: bool,
    /// Individual check results
    pub checks: Vec<(String, bool)>,
    /// Detection score (0-100)
    pub score: u32,
    /// Recommended action
    pub action: AntiDebugAction,
}

/// Recommended action when debugger detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiDebugAction {
    /// Continue normally
    Continue,
    /// Add delay before continuing
    Delay,
    /// Exit immediately
    Exit,
    /// Crash/corrupt execution
    Crash,
}

/// Comprehensive anti-debugging checks
pub struct AntiDebug {
    /// Sensitivity level (0-100)
    sensitivity: u32,
    /// Whether to use aggressive techniques
    aggressive: bool,
}

impl Default for AntiDebug {
    fn default() -> Self {
        Self {
            sensitivity: 50,
            aggressive: false,
        }
    }
}

impl AntiDebug {
    /// Create with custom settings
    pub fn new(sensitivity: u32, aggressive: bool) -> Self {
        Self {
            sensitivity: sensitivity.min(100),
            aggressive,
        }
    }

    /// Create with maximum detection
    pub fn paranoid() -> Self {
        Self {
            sensitivity: 100,
            aggressive: true,
        }
    }

    /// Run all anti-debugging checks
    pub fn check_all(&self) -> AntiDebugResult {
        let mut checks = Vec::new();
        let mut score = 0u32;

        // Timing checks (most reliable)
        let timing = self.check_timing_anomaly();
        if timing {
            score += 30;
        }
        checks.push(("Timing anomaly".to_string(), timing));

        // RDTSC-based timing
        let rdtsc = self.check_rdtsc_timing();
        if rdtsc {
            score += 25;
        }
        checks.push(("RDTSC timing".to_string(), rdtsc));

        // Process checks
        let parent = self.check_parent_process();
        if parent {
            score += 15;
        }
        checks.push(("Suspicious parent".to_string(), parent));

        // Environment checks
        let env = self.check_environment();
        if env {
            score += 10;
        }
        checks.push(("Debug environment".to_string(), env));

        // Hardware breakpoint check
        let hwbp = self.check_hardware_breakpoints();
        if hwbp {
            score += 35;
        }
        checks.push(("Hardware breakpoints".to_string(), hwbp));

        // Debug flags check
        let flags = self.check_debug_flags();
        if flags {
            score += 25;
        }
        checks.push(("Debug flags".to_string(), flags));

        // Self-modification check
        let selfmod = self.check_self_modification();
        if selfmod {
            score += 20;
        }
        checks.push(("Code modification".to_string(), selfmod));

        // Determine action based on score and sensitivity
        let threshold = 100 - self.sensitivity;
        let action = if score >= 80 {
            if self.aggressive {
                AntiDebugAction::Crash
            } else {
                AntiDebugAction::Exit
            }
        } else if score >= 50 {
            AntiDebugAction::Delay
        } else if score > threshold {
            AntiDebugAction::Delay
        } else {
            AntiDebugAction::Continue
        };

        AntiDebugResult {
            debugger_detected: score >= threshold,
            checks,
            score,
            action,
        }
    }

    /// Check for timing anomalies (debuggers slow execution)
    pub fn check_timing_anomaly(&self) -> bool {
        let iterations = 1000;
        let expected_max = Duration::from_millis(10);

        let start = Instant::now();

        // Simple loop that should be very fast
        let mut sum = 0u64;
        for i in 0..iterations {
            sum = sum.wrapping_add(i as u64);
            std::hint::black_box(sum);
        }

        let elapsed = start.elapsed();

        // If it took longer than expected, might be debugged
        elapsed > expected_max
    }

    /// RDTSC-based timing check
    pub fn check_rdtsc_timing(&self) -> bool {
        // Use high-resolution timing
        let start = Instant::now();

        // Execute some instructions
        let mut x = 0u64;
        for _ in 0..100 {
            x = x.wrapping_add(1);
            std::hint::black_box(x);
        }

        let elapsed = start.elapsed();

        // Very short operations taking too long indicates debugging
        elapsed > Duration::from_micros(1000)
    }

    /// Check parent process for known debuggers
    pub fn check_parent_process(&self) -> bool {
        // Read /proc/self/status on Linux
        #[cfg(target_os = "linux")]
        {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                // Check TracerPid (non-zero means being traced)
                for line in status.lines() {
                    if line.starts_with("TracerPid:") {
                        let pid: i32 = line
                            .split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                        if pid != 0 {
                            return true;
                        }
                    }
                }
            }

            // Check /proc/self/exe for debugger-related paths
            if let Ok(exe) = std::fs::read_link("/proc/self/exe") {
                let exe_str = exe.to_string_lossy().to_lowercase();
                let debuggers = ["gdb", "lldb", "strace", "ltrace", "radare", "ida", "x64dbg"];
                for dbg in &debuggers {
                    if exe_str.contains(dbg) {
                        return true;
                    }
                }
            }
        }

        // Check environment for debug indicators
        let debug_vars = ["_", "LINES", "COLUMNS", "DEBUGGER", "DEBUG"];
        for var in &debug_vars {
            if let Ok(val) = std::env::var(var) {
                let val_lower = val.to_lowercase();
                if val_lower.contains("gdb")
                    || val_lower.contains("lldb")
                    || val_lower.contains("debug")
                {
                    return true;
                }
            }
        }

        false
    }

    /// Check for debug-related environment variables
    pub fn check_environment(&self) -> bool {
        let suspicious_vars = [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DEBUGGER",
            "_JAVA_OPTIONS",
        ];

        for var in &suspicious_vars {
            if std::env::var(var).is_ok() {
                return true;
            }
        }

        // Check for common debug flags
        if std::env::var("DEBUG").is_ok() || std::env::var("RUST_BACKTRACE").is_ok() {
            return true;
        }

        false
    }

    /// Check for hardware breakpoints (x86/x64)
    pub fn check_hardware_breakpoints(&self) -> bool {
        // On Linux, we can try to detect via timing
        // Hardware breakpoints cause slight timing differences

        let iterations = 5;
        let mut timings = Vec::new();

        for _ in 0..iterations {
            let start = Instant::now();

            // Execute some code that would trigger breakpoints
            let mut x = 0u64;
            for i in 0..1000 {
                x = x.wrapping_add(i);
                x = x.wrapping_mul(0x5DEECE66D);
                x = x.wrapping_add(0xB);
            }
            std::hint::black_box(x);

            timings.push(start.elapsed());
        }

        // Check for anomalous timing variance
        if timings.len() >= 2 {
            let avg: u128 =
                timings.iter().map(|t| t.as_nanos()).sum::<u128>() / timings.len() as u128;
            let variance: u128 = timings
                .iter()
                .map(|t| {
                    let diff = t.as_nanos() as i128 - avg as i128;
                    (diff * diff) as u128
                })
                .sum::<u128>()
                / timings.len() as u128;

            // High variance indicates potential breakpoints
            variance > 1_000_000_000 // 1ms variance threshold
        } else {
            false
        }
    }

    /// Check debug flags in process
    pub fn check_debug_flags(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            // Check /proc/self/status for various debug indicators
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    // Check if being ptraced
                    if line.starts_with("TracerPid:") {
                        let pid: i32 = line
                            .split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                        if pid != 0 {
                            return true;
                        }
                    }
                }
            }

            // Try to ptrace ourselves (fails if already being traced)
            // This is a classic anti-debug technique
            unsafe {
                let result = libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                );
                if result == -1 {
                    // Already being traced
                    return true;
                }
                // Detach if successful
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                );
            }
        }

        false
    }

    /// Check if code has been modified (breakpoint detection)
    pub fn check_self_modification(&self) -> bool {
        // Check if any functions start with INT3 (0xCC) or other breakpoint bytes
        let func_ptr = Self::check_self_modification as *const u8;

        unsafe {
            let first_byte = *func_ptr;
            // INT3 = 0xCC, INT1 = 0xF1
            if first_byte == 0xCC || first_byte == 0xF1 {
                return true;
            }

            // Check next few bytes for common breakpoint patterns
            for i in 0..16 {
                let byte = *func_ptr.add(i);
                // Look for unusual NOP sleds or breakpoint patterns
                if byte == 0xCC {
                    return true;
                }
            }
        }

        false
    }

    /// Execute action based on detection result
    pub fn take_action(&self, result: &AntiDebugResult) {
        match result.action {
            AntiDebugAction::Continue => {
                // Do nothing
            }
            AntiDebugAction::Delay => {
                // Random delay between 30-60 seconds
                let delay = 30 + (result.score % 31);
                std::thread::sleep(Duration::from_secs(delay as u64));
            }
            AntiDebugAction::Exit => {
                std::process::exit(0);
            }
            AntiDebugAction::Crash => {
                // Corrupt execution to make debugging harder
                if self.aggressive {
                    // Cause intentional crash
                    unsafe {
                        let ptr: *mut u8 = std::ptr::null_mut();
                        std::ptr::write_volatile(ptr, 0);
                    }
                } else {
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Quick anti-debug check (returns true if debugger likely present)
pub fn quick_check() -> bool {
    let ad = AntiDebug::default();
    let result = ad.check_all();
    result.debugger_detected
}

/// Check with custom sensitivity (0-100)
pub fn check_with_sensitivity(sensitivity: u32) -> AntiDebugResult {
    let ad = AntiDebug::new(sensitivity, false);
    ad.check_all()
}

/// Paranoid check with all techniques
pub fn paranoid_check() -> AntiDebugResult {
    let ad = AntiDebug::paranoid();
    ad.check_all()
}

/// Timing-based trap - will detect single-stepping
pub fn timing_trap<F, R>(func: F) -> Option<R>
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let result = func();
    let elapsed = start.elapsed();

    // If the function took way too long, we're being debugged
    if elapsed > Duration::from_secs(1) {
        None
    } else {
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_debug_creation() {
        let ad = AntiDebug::default();
        assert_eq!(ad.sensitivity, 50);
        assert!(!ad.aggressive);

        let paranoid = AntiDebug::paranoid();
        assert_eq!(paranoid.sensitivity, 100);
        assert!(paranoid.aggressive);
    }

    #[test]
    fn test_timing_check() {
        let ad = AntiDebug::default();
        // Should usually pass in non-debug environment
        let _result = ad.check_timing_anomaly();
    }

    #[test]
    fn test_environment_check() {
        let ad = AntiDebug::default();
        let _result = ad.check_environment();
    }

    #[test]
    fn test_full_check() {
        let ad = AntiDebug::default();
        let result = ad.check_all();
        assert!(result.score <= 100);
        assert!(!result.checks.is_empty());
    }

    #[test]
    fn test_timing_trap() {
        let result = timing_trap(|| {
            // Simple fast operation
            let mut x = 0;
            for i in 0..100 {
                x += i;
            }
            x
        });
        assert!(result.is_some());
    }
}
