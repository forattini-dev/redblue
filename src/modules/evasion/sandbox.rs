//! Sandbox and VM Detection
//!
//! Techniques to detect if code is running in a sandbox, VM, or analysis environment:
//! - File system artifacts (VM tools, sandbox markers)
//! - Timing checks (accelerated time in sandboxes)
//! - Resource checks (low memory, few processes)
//! - Hardware checks (CPUID, MAC addresses)
//!
//! # Usage
//! ```rust
//! use redblue::modules::evasion::sandbox;
//!
//! if sandbox::detect_sandbox() {
//!     // Delay or exit
//!     sandbox::delay_execution(300_000); // 5 minutes
//! }
//! ```

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

/// Comprehensive sandbox detection - returns true if likely in sandbox/VM
pub fn detect_sandbox() -> bool {
    let mut score = 0u32;

    // Check for VM artifacts
    if check_vm_files() {
        score += 30;
    }

    // Check for sandbox processes
    if check_sandbox_processes() {
        score += 25;
    }

    // Check timing (sandboxes often accelerate time)
    if check_timing_anomaly() {
        score += 40;
    }

    // Check for low resources
    if check_low_resources() {
        score += 15;
    }

    // Check for suspicious usernames
    if check_suspicious_username() {
        score += 20;
    }

    // Check for debugging
    if check_debugger() {
        score += 35;
    }

    // Threshold: 50+ points indicates sandbox
    score >= 50
}

/// Check for VM-related files
pub fn check_vm_files() -> bool {
    let vm_artifacts = [
        // VMware
        "/usr/bin/vmtoolsd",
        "/usr/bin/vmware-toolbox-cmd",
        "/etc/vmware-tools",
        // VirtualBox
        "/usr/bin/VBoxClient",
        "/usr/bin/VBoxService",
        "/dev/vboxguest",
        // QEMU/KVM
        "/dev/kvm",
        "/usr/bin/qemu-ga",
        // Hyper-V
        "/usr/bin/hv_kvp_daemon",
        // Generic
        "/sys/class/dmi/id/product_name",
    ];

    #[cfg(target_os = "windows")]
    let vm_artifacts_win = [
        "C:\\Windows\\System32\\vmGuestLib.dll",
        "C:\\Windows\\System32\\vboxdisp.dll",
        "C:\\Windows\\System32\\vboxhook.dll",
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
    ];

    for artifact in &vm_artifacts {
        if Path::new(artifact).exists() {
            return true;
        }
    }

    #[cfg(target_os = "windows")]
    {
        for artifact in &vm_artifacts_win {
            if Path::new(artifact).exists() {
                return true;
            }
        }
    }

    // Check DMI product name on Linux
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = fs::read_to_string("/sys/class/dmi/id/product_name") {
            let lower = content.to_lowercase();
            if lower.contains("vmware")
                || lower.contains("virtualbox")
                || lower.contains("kvm")
                || lower.contains("qemu")
                || lower.contains("hyper-v")
                || lower.contains("xen")
            {
                return true;
            }
        }
    }

    false
}

/// Check for sandbox-related processes
pub fn check_sandbox_processes() -> bool {
    let sandbox_processes = [
        "vmsrvc",
        "vboxservice",
        "vmtoolsd",
        "vmwaretray",
        "wireshark",
        "fiddler",
        "procmon",
        "regmon",
        "filemon",
        "ollydbg",
        "x64dbg",
        "idaq",
        "idaq64",
        "windbg",
        "ghidra",
        "sandboxie",
        "cuckoo",
        "malwarebytes",
    ];

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("ps").args(["aux"]).output() {
            let ps_output = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for proc in &sandbox_processes {
                if ps_output.contains(proc) {
                    return true;
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("tasklist").output() {
            let tasklist = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for proc in &sandbox_processes {
                if tasklist.contains(proc) {
                    return true;
                }
            }
        }
    }

    false
}

/// Check for timing anomalies (sandboxes often accelerate time)
pub fn check_timing_anomaly() -> bool {
    let expected_ms = 100;
    let tolerance_ms = 20; // Allow 20% deviation

    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(expected_ms));
    let elapsed = start.elapsed().as_millis() as i64;

    let deviation = (elapsed - expected_ms as i64).abs();

    // If time elapsed significantly less than expected, likely accelerated
    if elapsed < (expected_ms as i64 - tolerance_ms as i64) {
        return true;
    }

    // Large deviation in either direction is suspicious
    deviation > (expected_ms as i64 * 2)
}

/// Check for low resources (sandboxes often have minimal resources)
pub fn check_low_resources() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check RAM (less than 2GB is suspicious)
        if let Ok(content) = fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            if kb < 2_000_000 {
                                // Less than ~2GB
                                return true;
                            }
                        }
                    }
                }
            }
        }

        // Check CPU count (1 CPU is suspicious)
        if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
            let cpu_count = content.matches("processor").count();
            if cpu_count <= 1 {
                return true;
            }
        }

        // Check disk size (less than 60GB is suspicious)
        if let Ok(output) = std::process::Command::new("df").args(["-B1", "/"]).output() {
            let df_output = String::from_utf8_lossy(&output.stdout);
            for line in df_output.lines().skip(1) {
                if let Some(size_str) = line.split_whitespace().nth(1) {
                    if let Ok(bytes) = size_str.parse::<u64>() {
                        if bytes < 60_000_000_000 {
                            // Less than 60GB
                            return true;
                        }
                    }
                }
                break;
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // TODO: Windows resource checks using WMI or similar
    }

    false
}

/// Check for suspicious usernames often used in sandboxes
pub fn check_suspicious_username() -> bool {
    let suspicious_names = [
        "sandbox", "malware", "virus", "test", "sample", "user", "admin", "john", "cuckoo",
        "honey", "virtual", "vmware", "vbox",
    ];

    if let Ok(username) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
        let lower = username.to_lowercase();
        for name in &suspicious_names {
            if lower.contains(name) {
                return true;
            }
        }
    }

    false
}

/// Check for debugger presence
pub fn check_debugger() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check TracerPid in /proc/self/status
        if let Ok(content) = fs::read_to_string("/proc/self/status") {
            for line in content.lines() {
                if line.starts_with("TracerPid:") {
                    if let Some(pid_str) = line.split_whitespace().nth(1) {
                        if let Ok(pid) = pid_str.parse::<i32>() {
                            if pid != 0 {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows: Check IsDebuggerPresent via kernel32
        // This would require unsafe FFI, so we skip for now
    }

    false
}

/// Delay execution for specified milliseconds
pub fn delay_execution(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

/// Exit process if sandbox detected
pub fn exit_if_sandbox() {
    if detect_sandbox() {
        std::process::exit(0);
    }
}

/// Get sandbox detection score (0-100)
pub fn sandbox_score() -> u32 {
    let mut score = 0u32;

    if check_vm_files() {
        score += 20;
    }
    if check_sandbox_processes() {
        score += 20;
    }
    if check_timing_anomaly() {
        score += 25;
    }
    if check_low_resources() {
        score += 15;
    }
    if check_suspicious_username() {
        score += 10;
    }
    if check_debugger() {
        score += 10;
    }

    score.min(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_score() {
        let score = sandbox_score();
        assert!(score <= 100);
    }

    #[test]
    fn test_timing_check() {
        // This should pass on a normal system
        let result = check_timing_anomaly();
        // We can't assert the result since it depends on the environment
        let _ = result;
    }

    #[test]
    fn test_username_check() {
        // Just ensure it doesn't panic
        let result = check_suspicious_username();
        let _ = result;
    }

    #[test]
    fn test_delay_execution() {
        let start = Instant::now();
        delay_execution(50);
        let elapsed = start.elapsed().as_millis();
        assert!(elapsed >= 45); // Allow some variance
    }
}
