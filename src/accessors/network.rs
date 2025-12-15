use super::{Accessor, AccessorInfo, AccessorResult};
use std::collections::HashMap;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::io::BufRead;

pub struct NetworkAccessor;

impl NetworkAccessor {
    pub fn new() -> Self {
        Self
    }

    #[cfg(target_os = "linux")]
    fn get_connections(&self) -> AccessorResult {
        let mut connections = Vec::new();
        
        // Parse /proc/net/tcp and udp
        self.parse_proc_net("tcp", &mut connections);
        self.parse_proc_net("udp", &mut connections);
        self.parse_proc_net("tcp6", &mut connections);
        self.parse_proc_net("udp6", &mut connections);

        AccessorResult::success(json!(connections))
    }

    #[cfg(not(target_os = "linux"))]
    fn get_connections(&self) -> AccessorResult {
        AccessorResult::error("Network connections listing only implemented for Linux currently")
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_net(&self, proto: &str, connections: &mut Vec<Value>) {
        let path = format!("/proc/net/{}", proto);
        if let Ok(file) = fs::File::open(&path) {
            let reader = std::io::BufReader::new(file);
            for (i, line) in reader.lines().enumerate() {
                if i == 0 { continue; } // Skip header
                if let Ok(l) = line {
                    // Format: sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
                    let parts: Vec<&str> = l.split_whitespace().collect();
                    if parts.len() < 10 { continue; }

                    let local = self.parse_hex_ip_port(parts[1]);
                    let remote = self.parse_hex_ip_port(parts[2]);
                    let state = self.parse_tcp_state(parts[3]);
                    let uid = parts[7].parse::<u32>().unwrap_or(0);
                    let inode = parts[9].parse::<u64>().unwrap_or(0);

                    // Attempt to find PID for inode (expensive, maybe optimize later)
                    let pid = self.find_pid_by_inode(inode).unwrap_or(0);

                    connections.push(json!({
                        "protocol": proto,
                        "local_address": local,
                        "remote_address": remote,
                        "state": state,
                        "uid": uid,
                        "inode": inode,
                        "pid": pid
                    }));
                }
            }
        }
    }

    fn parse_hex_ip_port(&self, s: &str) -> String {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 { return s.to_string(); }

        let ip_hex = parts[0];
        let port_hex = parts[1];

        let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
        
        if ip_hex.len() == 8 {
            // IPv4
            if let Ok(ip_int) = u32::from_str_radix(ip_hex, 16) {
                // Little endian
                let ip = std::net::Ipv4Addr::from(u32::from_be(ip_int)); // Actually Linux /proc is native endian, but often printed as such. Wait, it's usually machine endian. 
                // Let's assume standard behavior: bytes 3,2,1,0
                let b = ip_int.to_ne_bytes();
                return format!("{}:{}", std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]), port);
            }
        } else if ip_hex.len() == 32 {
            // IPv6
             // TODO: parsing IPv6 from proc is more complex structure
             return format!("[ipv6]:{}", port);
        }

        format!("{}:{}", ip_hex, port)
    }

    fn parse_tcp_state(&self, s: &str) -> String {
        match s {
            "01" => "ESTABLISHED",
            "02" => "SYN_SENT",
            "03" => "SYN_RECV",
            "04" => "FIN_WAIT1",
            "05" => "FIN_WAIT2",
            "06" => "TIME_WAIT",
            "07" => "CLOSE",
            "08" => "CLOSE_WAIT",
            "09" => "LAST_ACK",
            "0A" => "LISTEN",
            "0B" => "CLOSING",
            _ => "UNKNOWN"
        }.to_string()
    }

    #[cfg(target_os = "linux")]
    fn find_pid_by_inode(&self, target_inode: u64) -> Option<u32> {
        if target_inode == 0 { return None; }
        // Iterate /proc/[pid]/fd/*
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() { continue; }
                
                if let Some(fname) = path.file_name() {
                    if let Ok(pid) = fname.to_string_lossy().parse::<u32>() {
                        let fd_path = path.join("fd");
                        if let Ok(fds) = fs::read_dir(fd_path) {
                            for fd in fds.flatten() {
                                if let Ok(target) = fs::read_link(fd.path()) {
                                    let target_str = target.to_string_lossy();
                                    if target_str.starts_with("socket:[") {
                                        let inode_str = target_str
                                            .trim_start_matches("socket:[")
                                            .trim_end_matches(']');
                                        if let Ok(inode) = inode_str.parse::<u64>() {
                                            if inode == target_inode {
                                                return Some(pid);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn get_arp_cache(&self) -> AccessorResult {
        let mut arp_entries = Vec::new();
        if let Ok(file) = fs::File::open("/proc/net/arp") {
            let reader = std::io::BufReader::new(file);
            for (i, line) in reader.lines().enumerate() {
                if i == 0 { continue; }
                if let Ok(l) = line {
                    let parts: Vec<&str> = l.split_whitespace().collect();
                    if parts.len() >= 6 {
                        arp_entries.push(json!({
                            "ip": parts[0],
                            "hw_type": parts[1],
                            "flags": parts[2],
                            "mac": parts[3],
                            "mask": parts[4],
                            "interface": parts[5]
                        }));
                    }
                }
            }
        }
        AccessorResult::success(json!(arp_entries))
    }

    #[cfg(not(target_os = "linux"))]
    fn get_arp_cache(&self) -> AccessorResult {
        AccessorResult::error("ARP cache only implemented for Linux")
    }

    #[cfg(target_os = "linux")]
    fn get_interfaces(&self) -> AccessorResult {
        let mut interfaces = Vec::new();
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let path = entry.path();
                
                let mac = fs::read_to_string(path.join("address")).unwrap_or_default().trim().to_string();
                let mtu = fs::read_to_string(path.join("mtu")).unwrap_or_default().trim().to_string();
                let operstate = fs::read_to_string(path.join("operstate")).unwrap_or_default().trim().to_string();

                interfaces.push(json!({
                    "name": name,
                    "mac": mac,
                    "mtu": mtu,
                    "state": operstate
                }));
            }
        }
        AccessorResult::success(json!(interfaces))
    }

    #[cfg(not(target_os = "linux"))]
    fn get_interfaces(&self) -> AccessorResult {
        AccessorResult::error("Interface listing only implemented for Linux")
    }
}

impl Accessor for NetworkAccessor {
    fn name(&self) -> &str {
        "network"
    }

    fn info(&self) -> AccessorInfo {
        AccessorInfo {
            name: "Network Accessor".to_string(),
            description: "Interact with network stack".to_string(),
            methods: vec![
                "connections".to_string(),
                "arp".to_string(),
                "interfaces".to_string()
            ],
        }
    }

    fn execute(&self, method: &str, _args: &HashMap<String, String>) -> AccessorResult {
        match method {
            "connections" => self.get_connections(),
            "arp" => self.get_arp_cache(),
            "interfaces" => self.get_interfaces(),
            _ => AccessorResult::error(&format!("Unknown method: {}", method)),
        }
    }
}
