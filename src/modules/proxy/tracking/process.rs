//! Process Information Tracking
//!
//! Provides process information for connections (Linux only).
//! Useful for per-process filtering and logging.

use std::fs;
use std::net::SocketAddr;
use std::path::Path;

/// Process information for a connection
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name (from /proc/[pid]/comm)
    pub name: String,
    /// Command line (from /proc/[pid]/cmdline)
    pub cmdline: Option<String>,
    /// User ID
    pub uid: Option<u32>,
}

impl ProcessInfo {
    /// Get process info for a PID
    #[cfg(target_os = "linux")]
    pub fn from_pid(pid: u32) -> Option<Self> {
        let proc_path = format!("/proc/{}", pid);
        if !Path::new(&proc_path).exists() {
            return None;
        }

        // Read process name
        let name = fs::read_to_string(format!("{}/comm", proc_path))
            .ok()?
            .trim()
            .to_string();

        // Read command line
        let cmdline = fs::read_to_string(format!("{}/cmdline", proc_path))
            .ok()
            .map(|s| s.replace('\0', " ").trim().to_string())
            .filter(|s| !s.is_empty());

        // Read UID from status
        let uid = fs::read_to_string(format!("{}/status", proc_path))
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("Uid:"))
                    .and_then(|line| {
                        line.split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse().ok())
                    })
            });

        Some(Self {
            pid,
            name,
            cmdline,
            uid,
        })
    }

    /// Get process info for a PID (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn from_pid(_pid: u32) -> Option<Self> {
        None // Process tracking only available on Linux
    }

    /// Find process owning a socket
    #[cfg(target_os = "linux")]
    pub fn from_socket(local_addr: SocketAddr, remote_addr: SocketAddr) -> Option<Self> {
        // Parse /proc/net/tcp or /proc/net/tcp6
        let (tcp_file, is_v6) = if local_addr.is_ipv4() {
            ("/proc/net/tcp", false)
        } else {
            ("/proc/net/tcp6", true)
        };

        let content = fs::read_to_string(tcp_file).ok()?;

        // Format: local_addr:port remote_addr:port ... inode
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            let local = parse_socket_addr(parts[1], is_v6)?;
            let remote = parse_socket_addr(parts[2], is_v6)?;

            if local == local_addr && remote == remote_addr {
                let inode: u64 = parts[9].parse().ok()?;
                return Self::from_inode(inode);
            }
        }

        None
    }

    /// Find process owning a socket (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn from_socket(_local_addr: SocketAddr, _remote_addr: SocketAddr) -> Option<Self> {
        None
    }

    /// Find process from socket inode
    #[cfg(target_os = "linux")]
    fn from_inode(inode: u64) -> Option<Self> {
        let socket_link = format!("socket:[{}]", inode);

        // Scan all processes for this inode
        for entry in fs::read_dir("/proc").ok()? {
            let entry = entry.ok()?;
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;

            let fd_path = format!("/proc/{}/fd", pid);
            if let Ok(fds) = fs::read_dir(&fd_path) {
                for fd in fds.flatten() {
                    if let Ok(link) = fs::read_link(fd.path()) {
                        if link.to_string_lossy() == socket_link {
                            return Self::from_pid(pid);
                        }
                    }
                }
            }
        }

        None
    }
}

/// Parse socket address from /proc/net/tcp format
#[cfg(target_os = "linux")]
fn parse_socket_addr(s: &str, is_v6: bool) -> Option<SocketAddr> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let port = u16::from_str_radix(parts[1], 16).ok()?;

    if is_v6 {
        // IPv6: 32 hex chars
        let hex = parts[0];
        if hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        // Network byte order is reversed in /proc
        bytes.reverse();
        let ip = std::net::Ipv6Addr::from(bytes);
        Some(SocketAddr::new(ip.into(), port))
    } else {
        // IPv4: 8 hex chars
        let hex = parts[0];
        if hex.len() != 8 {
            return None;
        }
        let ip_num = u32::from_str_radix(hex, 16).ok()?;
        let ip = std::net::Ipv4Addr::from(ip_num.to_be()); // Network byte order
        Some(SocketAddr::new(ip.into(), port))
    }
}

/// Get list of all processes
#[cfg(target_os = "linux")]
pub fn list_processes() -> Vec<ProcessInfo> {
    let mut processes = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<u32>() {
                    if let Some(info) = ProcessInfo::from_pid(pid) {
                        processes.push(info);
                    }
                }
            }
        }
    }

    processes
}

/// Get list of all processes (non-Linux stub)
#[cfg(not(target_os = "linux"))]
pub fn list_processes() -> Vec<ProcessInfo> {
    Vec::new()
}

/// Find processes by name pattern
pub fn find_by_name(pattern: &str) -> Vec<ProcessInfo> {
    list_processes()
        .into_iter()
        .filter(|p| p.name.contains(pattern))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_process_info_current() {
        let pid = std::process::id();
        let info = ProcessInfo::from_pid(pid);
        assert!(info.is_some());

        let info = info.unwrap();
        assert_eq!(info.pid, pid);
        assert!(!info.name.is_empty());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_list_processes() {
        let processes = list_processes();
        assert!(!processes.is_empty());

        // Should find init (PID 1)
        assert!(processes.iter().any(|p| p.pid == 1));
    }

    #[test]
    fn test_find_by_name_empty() {
        let found = find_by_name("nonexistent_process_12345");
        assert!(found.is_empty());
    }
}
