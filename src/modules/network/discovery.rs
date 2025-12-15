//! Network Discovery Module
//!
//! Local network enumeration capabilities:
//! - ARP scanning (MAC address collection, OUI vendor lookup)
//! - NetBIOS/SMB enumeration (name queries)
//! - mDNS/Bonjour discovery (multicast DNS service discovery)
//!
//! All implementations from scratch using raw sockets.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Result of network discovery
#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub ip: Ipv4Addr,
    pub mac: Option<MacAddress>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub netbios_name: Option<String>,
    pub services: Vec<DiscoveredService>,
    pub response_time_ms: u64,
}

impl DiscoveredHost {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            mac: None,
            vendor: None,
            hostname: None,
            netbios_name: None,
            services: Vec::new(),
            response_time_ms: 0,
        }
    }

    pub fn with_mac(mut self, mac: MacAddress) -> Self {
        self.mac = Some(mac);
        self
    }

    pub fn with_vendor(mut self, vendor: String) -> Self {
        self.vendor = Some(vendor);
        self
    }
}

/// MAC address representation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Parse MAC from string (various formats)
    pub fn parse(s: &str) -> Option<Self> {
        let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();

        if cleaned.len() != 12 {
            return None;
        }

        let mut bytes = [0u8; 6];
        for i in 0..6 {
            bytes[i] = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(MacAddress(bytes))
    }

    /// Get OUI prefix (first 3 bytes)
    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    /// Format as colon-separated string
    pub fn to_string(&self) -> String {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// Discovered service via mDNS or probing
#[derive(Debug, Clone)]
pub struct DiscoveredService {
    pub name: String,
    pub service_type: String,
    pub port: u16,
    pub txt_records: HashMap<String, String>,
}

/// OUI (Organizationally Unique Identifier) database for vendor lookup
pub struct OuiDatabase {
    /// Map of OUI prefix to vendor name
    entries: HashMap<[u8; 3], &'static str>,
}

impl OuiDatabase {
    /// Create database with common vendor prefixes
    pub fn new() -> Self {
        let mut entries = HashMap::new();

        // Top ~100 most common OUI prefixes (embedded in binary)
        let oui_data: &[([u8; 3], &'static str)] = &[
            // Apple
            ([0x00, 0x03, 0x93], "Apple"),
            ([0x00, 0x0A, 0x95], "Apple"),
            ([0x00, 0x0D, 0x93], "Apple"),
            ([0x00, 0x11, 0x24], "Apple"),
            ([0x00, 0x14, 0x51], "Apple"),
            ([0x00, 0x16, 0xCB], "Apple"),
            ([0x00, 0x17, 0xF2], "Apple"),
            ([0x00, 0x19, 0xE3], "Apple"),
            ([0x00, 0x1B, 0x63], "Apple"),
            ([0x00, 0x1C, 0xB3], "Apple"),
            ([0x00, 0x1D, 0x4F], "Apple"),
            ([0x00, 0x1E, 0x52], "Apple"),
            ([0x00, 0x1E, 0xC2], "Apple"),
            ([0x00, 0x1F, 0x5B], "Apple"),
            ([0x00, 0x1F, 0xF3], "Apple"),
            ([0x00, 0x21, 0xE9], "Apple"),
            ([0x00, 0x22, 0x41], "Apple"),
            ([0x00, 0x23, 0x12], "Apple"),
            ([0x00, 0x23, 0x32], "Apple"),
            ([0x00, 0x23, 0x6C], "Apple"),
            ([0x00, 0x23, 0xDF], "Apple"),
            ([0x00, 0x24, 0x36], "Apple"),
            ([0x00, 0x25, 0x00], "Apple"),
            ([0x00, 0x25, 0x4B], "Apple"),
            ([0x00, 0x25, 0xBC], "Apple"),
            ([0x00, 0x26, 0x08], "Apple"),
            ([0x00, 0x26, 0x4A], "Apple"),
            ([0x00, 0x26, 0xB0], "Apple"),
            ([0x00, 0x26, 0xBB], "Apple"),
            // Samsung
            ([0x00, 0x00, 0xF0], "Samsung"),
            ([0x00, 0x02, 0x78], "Samsung"),
            ([0x00, 0x07, 0xAB], "Samsung"),
            ([0x00, 0x09, 0x18], "Samsung"),
            ([0x00, 0x0D, 0xAE], "Samsung"),
            ([0x00, 0x12, 0x47], "Samsung"),
            ([0x00, 0x12, 0xFB], "Samsung"),
            ([0x00, 0x13, 0x77], "Samsung"),
            ([0x00, 0x15, 0x99], "Samsung"),
            ([0x00, 0x15, 0xB9], "Samsung"),
            ([0x00, 0x16, 0x32], "Samsung"),
            ([0x00, 0x16, 0x6B], "Samsung"),
            ([0x00, 0x16, 0x6C], "Samsung"),
            ([0x00, 0x16, 0xDB], "Samsung"),
            ([0x00, 0x17, 0xC9], "Samsung"),
            ([0x00, 0x17, 0xD5], "Samsung"),
            ([0x00, 0x18, 0xAF], "Samsung"),
            // Intel
            ([0x00, 0x02, 0xB3], "Intel"),
            ([0x00, 0x03, 0x47], "Intel"),
            ([0x00, 0x04, 0x23], "Intel"),
            ([0x00, 0x07, 0xE9], "Intel"),
            ([0x00, 0x0C, 0xF1], "Intel"),
            ([0x00, 0x0E, 0x0C], "Intel"),
            ([0x00, 0x0E, 0x35], "Intel"),
            ([0x00, 0x11, 0x11], "Intel"),
            ([0x00, 0x12, 0xF0], "Intel"),
            ([0x00, 0x13, 0x02], "Intel"),
            ([0x00, 0x13, 0x20], "Intel"),
            ([0x00, 0x13, 0xCE], "Intel"),
            ([0x00, 0x13, 0xE8], "Intel"),
            ([0x00, 0x15, 0x00], "Intel"),
            ([0x00, 0x15, 0x17], "Intel"),
            ([0x00, 0x16, 0x6F], "Intel"),
            ([0x00, 0x16, 0x76], "Intel"),
            ([0x00, 0x16, 0xEA], "Intel"),
            ([0x00, 0x16, 0xEB], "Intel"),
            ([0x00, 0x18, 0xDE], "Intel"),
            ([0x00, 0x19, 0xD1], "Intel"),
            ([0x00, 0x19, 0xD2], "Intel"),
            ([0x00, 0x1B, 0x21], "Intel"),
            ([0x00, 0x1B, 0x77], "Intel"),
            ([0x00, 0x1C, 0xBF], "Intel"),
            ([0x00, 0x1C, 0xC0], "Intel"),
            ([0x00, 0x1D, 0xE0], "Intel"),
            ([0x00, 0x1D, 0xE1], "Intel"),
            ([0x00, 0x1E, 0x64], "Intel"),
            ([0x00, 0x1E, 0x65], "Intel"),
            ([0x00, 0x1E, 0x67], "Intel"),
            ([0x00, 0x1F, 0x3B], "Intel"),
            ([0x00, 0x1F, 0x3C], "Intel"),
            ([0x00, 0x20, 0xE0], "Intel"),
            ([0x00, 0x21, 0x5C], "Intel"),
            ([0x00, 0x21, 0x5D], "Intel"),
            ([0x00, 0x21, 0x6A], "Intel"),
            ([0x00, 0x21, 0x6B], "Intel"),
            ([0x00, 0x22, 0xFA], "Intel"),
            ([0x00, 0x22, 0xFB], "Intel"),
            ([0x00, 0x24, 0xD6], "Intel"),
            ([0x00, 0x24, 0xD7], "Intel"),
            // Cisco
            ([0x00, 0x00, 0x0C], "Cisco"),
            ([0x00, 0x01, 0x42], "Cisco"),
            ([0x00, 0x01, 0x43], "Cisco"),
            ([0x00, 0x01, 0x63], "Cisco"),
            ([0x00, 0x01, 0x64], "Cisco"),
            ([0x00, 0x01, 0x96], "Cisco"),
            ([0x00, 0x01, 0x97], "Cisco"),
            ([0x00, 0x01, 0xC7], "Cisco"),
            ([0x00, 0x01, 0xC9], "Cisco"),
            ([0x00, 0x02, 0x16], "Cisco"),
            ([0x00, 0x02, 0x17], "Cisco"),
            ([0x00, 0x02, 0x3D], "Cisco"),
            ([0x00, 0x02, 0x4A], "Cisco"),
            ([0x00, 0x02, 0x4B], "Cisco"),
            ([0x00, 0x02, 0x7D], "Cisco"),
            ([0x00, 0x02, 0x7E], "Cisco"),
            ([0x00, 0x02, 0xB9], "Cisco"),
            ([0x00, 0x02, 0xBA], "Cisco"),
            ([0x00, 0x02, 0xFC], "Cisco"),
            ([0x00, 0x02, 0xFD], "Cisco"),
            // Dell
            ([0x00, 0x06, 0x5B], "Dell"),
            ([0x00, 0x08, 0x74], "Dell"),
            ([0x00, 0x0B, 0xDB], "Dell"),
            ([0x00, 0x0D, 0x56], "Dell"),
            ([0x00, 0x0F, 0x1F], "Dell"),
            ([0x00, 0x11, 0x43], "Dell"),
            ([0x00, 0x12, 0x3F], "Dell"),
            ([0x00, 0x13, 0x72], "Dell"),
            ([0x00, 0x14, 0x22], "Dell"),
            ([0x00, 0x15, 0xC5], "Dell"),
            ([0x00, 0x16, 0xF0], "Dell"),
            ([0x00, 0x18, 0x8B], "Dell"),
            ([0x00, 0x19, 0xB9], "Dell"),
            ([0x00, 0x1A, 0xA0], "Dell"),
            ([0x00, 0x1C, 0x23], "Dell"),
            ([0x00, 0x1D, 0x09], "Dell"),
            ([0x00, 0x1E, 0x4F], "Dell"),
            ([0x00, 0x1E, 0xC9], "Dell"),
            ([0x00, 0x21, 0x70], "Dell"),
            ([0x00, 0x21, 0x9B], "Dell"),
            ([0x00, 0x22, 0x19], "Dell"),
            ([0x00, 0x23, 0xAE], "Dell"),
            ([0x00, 0x24, 0xE8], "Dell"),
            ([0x00, 0x25, 0x64], "Dell"),
            ([0x00, 0x26, 0xB9], "Dell"),
            // HP
            ([0x00, 0x00, 0x63], "HP"),
            ([0x00, 0x01, 0xE6], "HP"),
            ([0x00, 0x01, 0xE7], "HP"),
            ([0x00, 0x02, 0xA5], "HP"),
            ([0x00, 0x04, 0xEA], "HP"),
            ([0x00, 0x08, 0x02], "HP"),
            ([0x00, 0x08, 0x83], "HP"),
            ([0x00, 0x0A, 0x57], "HP"),
            ([0x00, 0x0B, 0xCD], "HP"),
            ([0x00, 0x0D, 0x9D], "HP"),
            ([0x00, 0x0E, 0x7F], "HP"),
            ([0x00, 0x0F, 0x20], "HP"),
            ([0x00, 0x0F, 0x61], "HP"),
            ([0x00, 0x10, 0x83], "HP"),
            ([0x00, 0x10, 0xE3], "HP"),
            ([0x00, 0x11, 0x0A], "HP"),
            ([0x00, 0x11, 0x85], "HP"),
            ([0x00, 0x12, 0x79], "HP"),
            ([0x00, 0x13, 0x21], "HP"),
            ([0x00, 0x14, 0x38], "HP"),
            ([0x00, 0x14, 0xC2], "HP"),
            ([0x00, 0x15, 0x60], "HP"),
            ([0x00, 0x16, 0x35], "HP"),
            ([0x00, 0x17, 0x08], "HP"),
            ([0x00, 0x17, 0xA4], "HP"),
            ([0x00, 0x18, 0x71], "HP"),
            ([0x00, 0x18, 0xFE], "HP"),
            ([0x00, 0x19, 0xBB], "HP"),
            ([0x00, 0x1A, 0x4B], "HP"),
            ([0x00, 0x1B, 0x78], "HP"),
            ([0x00, 0x1C, 0x2E], "HP"),
            ([0x00, 0x1C, 0xC4], "HP"),
            ([0x00, 0x1D, 0xB3], "HP"),
            ([0x00, 0x1D, 0xB3], "HP"),
            ([0x00, 0x1E, 0x0B], "HP"),
            ([0x00, 0x1F, 0x29], "HP"),
            ([0x00, 0x1F, 0xFE], "HP"),
            ([0x00, 0x21, 0x5A], "HP"),
            ([0x00, 0x22, 0x64], "HP"),
            ([0x00, 0x23, 0x7D], "HP"),
            ([0x00, 0x24, 0x81], "HP"),
            ([0x00, 0x25, 0xB3], "HP"),
            ([0x00, 0x26, 0x55], "HP"),
            ([0x00, 0x26, 0xF1], "HP"),
            // TP-Link
            ([0x00, 0x1D, 0x0F], "TP-Link"),
            ([0x00, 0x23, 0xCD], "TP-Link"),
            ([0x00, 0x25, 0x86], "TP-Link"),
            ([0x00, 0x27, 0x19], "TP-Link"),
            ([0x14, 0xCF, 0x92], "TP-Link"),
            ([0x14, 0xE6, 0xE4], "TP-Link"),
            ([0x18, 0xA6, 0xF7], "TP-Link"),
            ([0x1C, 0xFA, 0x68], "TP-Link"),
            ([0x30, 0xB5, 0xC2], "TP-Link"),
            ([0x50, 0xC7, 0xBF], "TP-Link"),
            ([0x54, 0xC8, 0x0F], "TP-Link"),
            ([0x54, 0xE6, 0xFC], "TP-Link"),
            ([0x60, 0xE3, 0x27], "TP-Link"),
            ([0x64, 0x56, 0x01], "TP-Link"),
            ([0x64, 0x70, 0x02], "TP-Link"),
            ([0x6C, 0xE8, 0x73], "TP-Link"),
            ([0x74, 0xDA, 0x88], "TP-Link"),
            ([0x78, 0x44, 0x76], "TP-Link"),
            ([0x7C, 0x8B, 0xCA], "TP-Link"),
            ([0x84, 0x16, 0xF9], "TP-Link"),
            ([0x88, 0x1F, 0xA1], "TP-Link"),
            ([0x90, 0xF6, 0x52], "TP-Link"),
            ([0x94, 0x0C, 0x6D], "TP-Link"),
            ([0x98, 0xDA, 0xC4], "TP-Link"),
            ([0xA0, 0xF3, 0xC1], "TP-Link"),
            ([0xAC, 0x84, 0xC6], "TP-Link"),
            ([0xB0, 0x48, 0x7A], "TP-Link"),
            ([0xB0, 0x95, 0x8E], "TP-Link"),
            ([0xB8, 0xD5, 0x26], "TP-Link"),
            ([0xBC, 0x46, 0x99], "TP-Link"),
            ([0xC0, 0x25, 0xE9], "TP-Link"),
            ([0xC4, 0xE9, 0x84], "TP-Link"),
            ([0xD4, 0x6E, 0x0E], "TP-Link"),
            ([0xD8, 0x07, 0xB6], "TP-Link"),
            ([0xDC, 0xFE, 0x18], "TP-Link"),
            ([0xE4, 0xD3, 0x32], "TP-Link"),
            ([0xE8, 0x94, 0xF6], "TP-Link"),
            ([0xEC, 0x08, 0x6B], "TP-Link"),
            ([0xEC, 0x17, 0x2F], "TP-Link"),
            ([0xEC, 0x26, 0xCA], "TP-Link"),
            ([0xF4, 0xF2, 0x6D], "TP-Link"),
            ([0xF8, 0x1A, 0x67], "TP-Link"),
            // Netgear
            ([0x00, 0x09, 0x5B], "Netgear"),
            ([0x00, 0x0F, 0xB5], "Netgear"),
            ([0x00, 0x14, 0x6C], "Netgear"),
            ([0x00, 0x18, 0x4D], "Netgear"),
            ([0x00, 0x1B, 0x2F], "Netgear"),
            ([0x00, 0x1E, 0x2A], "Netgear"),
            ([0x00, 0x1F, 0x33], "Netgear"),
            ([0x00, 0x22, 0x3F], "Netgear"),
            ([0x00, 0x24, 0xB2], "Netgear"),
            ([0x00, 0x26, 0xF2], "Netgear"),
            ([0x20, 0x4E, 0x7F], "Netgear"),
            ([0x2C, 0xB0, 0x5D], "Netgear"),
            ([0x30, 0x46, 0x9A], "Netgear"),
            ([0x44, 0x94, 0xFC], "Netgear"),
            ([0x4C, 0x60, 0xDE], "Netgear"),
            ([0x6C, 0xB0, 0xCE], "Netgear"),
            ([0x84, 0x1B, 0x5E], "Netgear"),
            ([0x9C, 0x3D, 0xCF], "Netgear"),
            ([0xA0, 0x21, 0xB7], "Netgear"),
            ([0xA4, 0x2B, 0x8C], "Netgear"),
            ([0xB0, 0x7F, 0xB9], "Netgear"),
            ([0xC0, 0x3F, 0x0E], "Netgear"),
            ([0xC4, 0x04, 0x15], "Netgear"),
            ([0xC4, 0x3D, 0xC7], "Netgear"),
            ([0xDC, 0xEF, 0x09], "Netgear"),
            ([0xE0, 0x46, 0x9A], "Netgear"),
            ([0xE0, 0x91, 0xF5], "Netgear"),
            ([0xE8, 0xFC, 0xAF], "Netgear"),
            // Raspberry Pi
            ([0xB8, 0x27, 0xEB], "Raspberry Pi"),
            ([0xDC, 0xA6, 0x32], "Raspberry Pi"),
            ([0xE4, 0x5F, 0x01], "Raspberry Pi"),
            // VMware
            ([0x00, 0x0C, 0x29], "VMware"),
            ([0x00, 0x50, 0x56], "VMware"),
            ([0x00, 0x05, 0x69], "VMware"),
            // VirtualBox
            ([0x08, 0x00, 0x27], "VirtualBox"),
            // Microsoft (Hyper-V)
            ([0x00, 0x15, 0x5D], "Microsoft Hyper-V"),
            // QEMU/KVM
            ([0x52, 0x54, 0x00], "QEMU/KVM"),
            // Amazon (AWS)
            ([0x06, 0x00, 0x00], "Amazon AWS"),
            ([0x02, 0x00, 0x00], "Amazon AWS"),
            // Google
            ([0x42, 0x01, 0x0A], "Google Cloud"),
            // Espressif (ESP32/ESP8266)
            ([0x24, 0x0A, 0xC4], "Espressif"),
            ([0x24, 0x62, 0xAB], "Espressif"),
            ([0x24, 0xB2, 0xDE], "Espressif"),
            ([0x30, 0xAE, 0xA4], "Espressif"),
            ([0x3C, 0x61, 0x05], "Espressif"),
            ([0x3C, 0x71, 0xBF], "Espressif"),
            ([0x40, 0xF5, 0x20], "Espressif"),
            ([0x48, 0x3F, 0xDA], "Espressif"),
            ([0x5C, 0xCF, 0x7F], "Espressif"),
            ([0x60, 0x01, 0x94], "Espressif"),
            ([0x68, 0xC6, 0x3A], "Espressif"),
            ([0x80, 0x7D, 0x3A], "Espressif"),
            ([0x84, 0x0D, 0x8E], "Espressif"),
            ([0x84, 0xCC, 0xA8], "Espressif"),
            ([0x84, 0xF3, 0xEB], "Espressif"),
            ([0x8C, 0xAA, 0xB5], "Espressif"),
            ([0x98, 0xCD, 0xAC], "Espressif"),
            ([0xA0, 0x20, 0xA6], "Espressif"),
            ([0xA4, 0x7B, 0x9D], "Espressif"),
            ([0xA4, 0xCF, 0x12], "Espressif"),
            ([0xAC, 0x67, 0xB2], "Espressif"),
            ([0xAC, 0xD0, 0x74], "Espressif"),
            ([0xB4, 0xE6, 0x2D], "Espressif"),
            ([0xBC, 0xDD, 0xC2], "Espressif"),
            ([0xC4, 0x4F, 0x33], "Espressif"),
            ([0xCC, 0x50, 0xE3], "Espressif"),
            ([0xD8, 0xA0, 0x1D], "Espressif"),
            ([0xDC, 0x4F, 0x22], "Espressif"),
            ([0xE8, 0xDB, 0x84], "Espressif"),
            ([0xEC, 0xFA, 0xBC], "Espressif"),
            ([0xF0, 0x08, 0xD1], "Espressif"),
            ([0xF4, 0xCF, 0xA2], "Espressif"),
            // Ubiquiti
            ([0x00, 0x27, 0x22], "Ubiquiti"),
            ([0x04, 0x18, 0xD6], "Ubiquiti"),
            ([0x18, 0xE8, 0x29], "Ubiquiti"),
            ([0x24, 0xA4, 0x3C], "Ubiquiti"),
            ([0x44, 0xD9, 0xE7], "Ubiquiti"),
            ([0x68, 0x72, 0x51], "Ubiquiti"),
            ([0x74, 0x83, 0xC2], "Ubiquiti"),
            ([0x78, 0x8A, 0x20], "Ubiquiti"),
            ([0x80, 0x2A, 0xA8], "Ubiquiti"),
            ([0xB4, 0xFB, 0xE4], "Ubiquiti"),
            ([0xDC, 0x9F, 0xDB], "Ubiquiti"),
            ([0xE0, 0x63, 0xDA], "Ubiquiti"),
            ([0xE2, 0x63, 0xDA], "Ubiquiti"),
            ([0xF0, 0x9F, 0xC2], "Ubiquiti"),
            ([0xFC, 0xEC, 0xDA], "Ubiquiti"),
            // ASUS
            ([0x00, 0x0C, 0x6E], "ASUS"),
            ([0x00, 0x0E, 0xA6], "ASUS"),
            ([0x00, 0x11, 0x2F], "ASUS"),
            ([0x00, 0x11, 0xD8], "ASUS"),
            ([0x00, 0x13, 0xD4], "ASUS"),
            ([0x00, 0x15, 0xF2], "ASUS"),
            ([0x00, 0x17, 0x31], "ASUS"),
            ([0x00, 0x18, 0xF3], "ASUS"),
            ([0x00, 0x1A, 0x92], "ASUS"),
            ([0x00, 0x1B, 0xFC], "ASUS"),
            ([0x00, 0x1D, 0x60], "ASUS"),
            ([0x00, 0x1E, 0x8C], "ASUS"),
            ([0x00, 0x1F, 0xC6], "ASUS"),
            ([0x00, 0x22, 0x15], "ASUS"),
            ([0x00, 0x23, 0x54], "ASUS"),
            ([0x00, 0x24, 0x8C], "ASUS"),
            ([0x00, 0x25, 0x22], "ASUS"),
            ([0x00, 0x26, 0x18], "ASUS"),
            ([0x04, 0x92, 0x26], "ASUS"),
            ([0x08, 0x60, 0x6E], "ASUS"),
            ([0x08, 0x62, 0x66], "ASUS"),
            ([0x10, 0x7B, 0x44], "ASUS"),
            ([0x10, 0xBF, 0x48], "ASUS"),
            ([0x10, 0xC3, 0x7B], "ASUS"),
            ([0x14, 0xDA, 0xE9], "ASUS"),
            ([0x14, 0xDD, 0xA9], "ASUS"),
            ([0x18, 0x31, 0xBF], "ASUS"),
            ([0x1C, 0x87, 0x2C], "ASUS"),
            ([0x1C, 0xB7, 0x2C], "ASUS"),
            ([0x20, 0xCF, 0x30], "ASUS"),
            ([0x24, 0x4B, 0xFE], "ASUS"),
            ([0x2C, 0x4D, 0x54], "ASUS"),
            ([0x2C, 0x56, 0xDC], "ASUS"),
            ([0x30, 0x5A, 0x3A], "ASUS"),
            ([0x30, 0x85, 0xA9], "ASUS"),
            ([0x34, 0x97, 0xF6], "ASUS"),
            ([0x38, 0x2C, 0x4A], "ASUS"),
            ([0x38, 0xD5, 0x47], "ASUS"),
            ([0x3C, 0x97, 0x0E], "ASUS"),
            ([0x40, 0x16, 0x7E], "ASUS"),
            ([0x40, 0xB0, 0x76], "ASUS"),
            ([0x48, 0x5B, 0x39], "ASUS"),
            ([0x4C, 0xED, 0xFB], "ASUS"),
            ([0x50, 0x46, 0x5D], "ASUS"),
            ([0x50, 0x67, 0xF0], "ASUS"),
            ([0x54, 0x04, 0xA6], "ASUS"),
            ([0x60, 0x45, 0xCB], "ASUS"),
            ([0x60, 0xA4, 0x4C], "ASUS"),
            ([0x60, 0xCF, 0x84], "ASUS"),
            ([0x74, 0xD0, 0x2B], "ASUS"),
            ([0x78, 0x24, 0xAF], "ASUS"),
        ];

        for (oui, vendor) in oui_data {
            entries.insert(*oui, *vendor);
        }

        Self { entries }
    }

    /// Lookup vendor by MAC address
    pub fn lookup(&self, mac: &MacAddress) -> Option<&'static str> {
        self.entries.get(&mac.oui()).copied()
    }

    /// Lookup vendor by OUI bytes
    pub fn lookup_oui(&self, oui: &[u8; 3]) -> Option<&'static str> {
        self.entries.get(oui).copied()
    }
}

impl Default for OuiDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== NetBIOS Enumeration ====================

/// NetBIOS Name Service client (UDP port 137)
pub struct NetBiosScanner {
    timeout: Duration,
}

impl NetBiosScanner {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(2),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Query NetBIOS name for a single host
    pub fn query_name(&self, target: Ipv4Addr) -> Option<String> {
        let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.set_read_timeout(Some(self.timeout)).ok()?;

        // NetBIOS Name Query packet (RFC 1002)
        let transaction_id: u16 = 0x0001;
        let mut query = Vec::with_capacity(50);

        // Header
        query.extend_from_slice(&transaction_id.to_be_bytes()); // Transaction ID
        query.extend_from_slice(&[0x00, 0x10]); // Flags: query, recursion desired
        query.extend_from_slice(&[0x00, 0x01]); // Questions: 1
        query.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
        query.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
        query.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

        // Question: *<00><00> (wildcard query)
        // Encoded name: 32 bytes (16 chars * 2)
        query.push(32); // Name length

        // Encode "*" + 15 spaces as NetBIOS first-level encoding
        let name = b"*               "; // 16 bytes
        for &b in name {
            query.push(((b >> 4) & 0x0F) + b'A');
            query.push((b & 0x0F) + b'A');
        }

        query.push(0x00); // Null terminator for name
        query.extend_from_slice(&[0x00, 0x21]); // Type: NBSTAT (0x21)
        query.extend_from_slice(&[0x00, 0x01]); // Class: IN

        // Send query
        let dest = SocketAddr::new(IpAddr::V4(target), 137);
        socket.send_to(&query, dest).ok()?;

        // Receive response
        let mut response = [0u8; 512];
        let (len, _) = socket.recv_from(&mut response).ok()?;

        if len < 57 {
            return None;
        }

        // Parse response - skip header (12 bytes) and question (38 bytes)
        // Answer starts at offset 50
        let num_names = response[56] as usize;
        if num_names == 0 || len < 57 + num_names * 18 {
            return None;
        }

        // First name entry starts at offset 57
        // Each entry is 18 bytes: 15-byte name + 1-byte suffix + 2-byte flags
        let name_bytes = &response[57..57 + 15];
        let name = String::from_utf8_lossy(name_bytes).trim().to_string();

        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    /// Scan a subnet for NetBIOS names
    pub fn scan_subnet(&self, network: Ipv4Addr, mask_bits: u8) -> Vec<(Ipv4Addr, String)> {
        let hosts = subnet_hosts(network, mask_bits);
        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        let chunk_size = 50; // Concurrent queries limit
        for chunk in hosts.chunks(chunk_size) {
            let chunk_vec: Vec<Ipv4Addr> = chunk.to_vec();
            let results = Arc::clone(&results);
            let timeout = self.timeout;

            let handle = thread::spawn(move || {
                let scanner = NetBiosScanner::new().with_timeout(timeout);
                for ip in chunk_vec {
                    if let Some(name) = scanner.query_name(ip) {
                        let mut results = results.lock().unwrap();
                        results.push((ip, name));
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.join();
        }

        Arc::try_unwrap(results).unwrap().into_inner().unwrap()
    }
}

impl Default for NetBiosScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== mDNS Discovery ====================

/// mDNS service type constants
pub mod mdns_services {
    pub const HTTP: &str = "_http._tcp.local";
    pub const HTTPS: &str = "_https._tcp.local";
    pub const SSH: &str = "_ssh._tcp.local";
    pub const SFTP: &str = "_sftp-ssh._tcp.local";
    pub const SMB: &str = "_smb._tcp.local";
    pub const FTP: &str = "_ftp._tcp.local";
    pub const PRINTER: &str = "_ipp._tcp.local";
    pub const AIRPLAY: &str = "_airplay._tcp.local";
    pub const SPOTIFY: &str = "_spotify-connect._tcp.local";
    pub const GOOGLECAST: &str = "_googlecast._tcp.local";
    pub const HOMEKIT: &str = "_hap._tcp.local";
    pub const RAOP: &str = "_raop._tcp.local";
    pub const AFP: &str = "_afpovertcp._tcp.local";
    pub const NFS: &str = "_nfs._tcp.local";
    pub const DAAP: &str = "_daap._tcp.local";
    pub const WORKSTATION: &str = "_workstation._tcp.local";
}

/// mDNS scanner for service discovery
pub struct MdnsScanner {
    timeout: Duration,
}

impl MdnsScanner {
    const MDNS_ADDR: &'static str = "224.0.0.251";
    const MDNS_PORT: u16 = 5353;

    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(3),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Query for a specific service type
    pub fn query_service(&self, service_type: &str) -> Vec<DiscoveredService> {
        let mut results = Vec::new();

        // Create UDP socket
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => return results,
        };

        // Set multicast options
        let _ = socket.set_multicast_ttl_v4(255);
        let _ = socket.set_read_timeout(Some(self.timeout));

        // Build mDNS query
        let query = self.build_query(service_type);

        // Send query to multicast address
        let mdns_addr: SocketAddr = format!("{}:{}", Self::MDNS_ADDR, Self::MDNS_PORT)
            .parse()
            .unwrap();

        if socket.send_to(&query, mdns_addr).is_err() {
            return results;
        }

        // Collect responses until timeout
        let start = Instant::now();
        let mut buf = [0u8; 4096];

        while start.elapsed() < self.timeout {
            match socket.recv_from(&mut buf) {
                Ok((len, addr)) => {
                    if let Some(service) = self.parse_response(&buf[..len], addr) {
                        // Deduplicate
                        if !results
                            .iter()
                            .any(|s: &DiscoveredService| s.name == service.name)
                        {
                            results.push(service);
                        }
                    }
                }
                Err(_) => break,
            }
        }

        results
    }

    /// Discover all common services
    pub fn discover_all(&self) -> Vec<DiscoveredService> {
        let service_types = [
            mdns_services::HTTP,
            mdns_services::HTTPS,
            mdns_services::SSH,
            mdns_services::SMB,
            mdns_services::PRINTER,
            mdns_services::AIRPLAY,
            mdns_services::GOOGLECAST,
            mdns_services::WORKSTATION,
        ];

        let mut all_results = Vec::new();
        for service_type in service_types {
            let results = self.query_service(service_type);
            all_results.extend(results);
        }

        all_results
    }

    fn build_query(&self, service_type: &str) -> Vec<u8> {
        let mut query = Vec::with_capacity(256);

        // Transaction ID (random for mDNS)
        query.extend_from_slice(&[0x00, 0x00]);

        // Flags: standard query
        query.extend_from_slice(&[0x00, 0x00]);

        // Questions: 1
        query.extend_from_slice(&[0x00, 0x01]);

        // Answer/Authority/Additional RRs: 0
        query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Encode service type as DNS name
        for label in service_type.split('.') {
            let len = label.len() as u8;
            query.push(len);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0x00); // Null terminator

        // Type: PTR (12)
        query.extend_from_slice(&[0x00, 0x0C]);

        // Class: IN with cache flush bit
        query.extend_from_slice(&[0x00, 0x01]);

        query
    }

    fn parse_response(&self, data: &[u8], addr: SocketAddr) -> Option<DiscoveredService> {
        if data.len() < 12 {
            return None;
        }

        // Skip header (12 bytes)
        // This is a simplified parser that extracts service name from PTR records

        // Check answer count
        let answer_count = u16::from_be_bytes([data[6], data[7]]);
        if answer_count == 0 {
            return None;
        }

        // Find service name in response (simplified)
        // Look for readable ASCII strings that look like service names
        let mut name = String::new();
        let mut i = 12;

        // Skip question section
        while i < data.len() && data[i] != 0 {
            let label_len = data[i] as usize;
            if label_len > 63 || i + 1 + label_len > data.len() {
                break;
            }
            if !name.is_empty() {
                name.push('.');
            }
            if let Ok(label) = std::str::from_utf8(&data[i + 1..i + 1 + label_len]) {
                name.push_str(label);
            }
            i += 1 + label_len;
        }

        // Extract port from address
        let port = if name.contains("_http") {
            80
        } else if name.contains("_https") {
            443
        } else if name.contains("_ssh") {
            22
        } else if name.contains("_smb") {
            445
        } else if name.contains("_ipp") {
            631
        } else {
            0
        };

        // Build service name from IP address
        let service_name = if let IpAddr::V4(ip) = addr.ip() {
            format!("{}@{}", name.split('.').next().unwrap_or("unknown"), ip)
        } else {
            name.split('.').next().unwrap_or("unknown").to_string()
        };

        Some(DiscoveredService {
            name: service_name,
            service_type: name,
            port,
            txt_records: HashMap::new(),
        })
    }
}

impl Default for MdnsScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== Network Discovery Engine ====================

/// Combined network discovery engine
pub struct NetworkDiscovery {
    timeout: Duration,
    oui_db: OuiDatabase,
}

impl NetworkDiscovery {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            oui_db: OuiDatabase::new(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Discover hosts on local network using multiple methods
    pub fn discover_subnet(&self, network: Ipv4Addr, mask_bits: u8) -> Vec<DiscoveredHost> {
        let mut hosts: HashMap<Ipv4Addr, DiscoveredHost> = HashMap::new();

        // 1. NetBIOS scan
        let netbios = NetBiosScanner::new().with_timeout(self.timeout);
        for (ip, name) in netbios.scan_subnet(network, mask_bits) {
            let host = hosts.entry(ip).or_insert_with(|| DiscoveredHost::new(ip));
            host.netbios_name = Some(name.clone());
            host.hostname = Some(name);
        }

        // 2. ICMP ping sweep (TCP fallback)
        let ping_hosts = self.ping_sweep(network, mask_bits);
        for ip in ping_hosts {
            hosts.entry(ip).or_insert_with(|| DiscoveredHost::new(ip));
        }

        // 3. mDNS discovery (for local services)
        let mdns = MdnsScanner::new().with_timeout(self.timeout);
        let services = mdns.discover_all();
        for service in services {
            // Extract IP from service name if possible
            if let Some(ip_str) = service.name.split('@').nth(1) {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    let host = hosts.entry(ip).or_insert_with(|| DiscoveredHost::new(ip));
                    host.services.push(service);
                }
            }
        }

        // Sort by IP
        let mut result: Vec<_> = hosts.into_values().collect();
        result.sort_by_key(|h| h.ip);
        result
    }

    /// TCP-based ping sweep (works without raw sockets)
    fn ping_sweep(&self, network: Ipv4Addr, mask_bits: u8) -> Vec<Ipv4Addr> {
        let hosts = subnet_hosts(network, mask_bits);
        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        // Common ports to probe
        let probe_ports = [22, 80, 443, 445, 3389, 8080];

        let chunk_size = 50;
        for chunk in hosts.chunks(chunk_size) {
            let chunk_vec: Vec<Ipv4Addr> = chunk.to_vec();
            let results = Arc::clone(&results);
            let timeout = Duration::from_millis(500);

            let handle = thread::spawn(move || {
                for ip in chunk_vec {
                    for &port in &probe_ports {
                        let addr = SocketAddr::new(IpAddr::V4(ip), port);
                        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                            let mut results = results.lock().unwrap();
                            if !results.contains(&ip) {
                                results.push(ip);
                            }
                            break;
                        }
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.join();
        }

        Arc::try_unwrap(results).unwrap().into_inner().unwrap()
    }

    /// Lookup vendor from MAC address
    pub fn lookup_vendor(&self, mac: &MacAddress) -> Option<&'static str> {
        self.oui_db.lookup(mac)
    }
}

impl Default for NetworkDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== Helper Functions ====================

/// Generate all host IPs in a subnet
fn subnet_hosts(network: Ipv4Addr, mask_bits: u8) -> Vec<Ipv4Addr> {
    if mask_bits > 30 {
        return vec![network];
    }

    let network_u32 = u32::from(network);
    let host_bits = 32 - mask_bits;
    let num_hosts = (1u32 << host_bits) - 2; // Exclude network and broadcast

    (1..=num_hosts)
        .map(|i| Ipv4Addr::from(network_u32 + i))
        .collect()
}

/// Parse CIDR notation
pub fn parse_cidr(cidr: &str) -> Option<(Ipv4Addr, u8)> {
    let (network_str, mask_str) = cidr.split_once('/')?;
    let network: Ipv4Addr = network_str.parse().ok()?;
    let mask: u8 = mask_str.parse().ok()?;

    if mask > 32 {
        return None;
    }

    Some((network, mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_parse() {
        let mac = MacAddress::parse("00:11:22:33:44:55").unwrap();
        assert_eq!(mac.0, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let mac2 = MacAddress::parse("00-11-22-33-44-55").unwrap();
        assert_eq!(mac2.0, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let mac3 = MacAddress::parse("001122334455").unwrap();
        assert_eq!(mac3.0, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_mac_to_string() {
        let mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(mac.to_string(), "00:11:22:33:44:55");
    }

    #[test]
    fn test_oui_lookup() {
        let db = OuiDatabase::new();

        // Apple
        let mac = MacAddress([0x00, 0x03, 0x93, 0x12, 0x34, 0x56]);
        assert_eq!(db.lookup(&mac), Some("Apple"));

        // VMware
        let mac = MacAddress([0x00, 0x0C, 0x29, 0x12, 0x34, 0x56]);
        assert_eq!(db.lookup(&mac), Some("VMware"));

        // Raspberry Pi
        let mac = MacAddress([0xB8, 0x27, 0xEB, 0x12, 0x34, 0x56]);
        assert_eq!(db.lookup(&mac), Some("Raspberry Pi"));

        // Unknown
        let mac = MacAddress([0xFF, 0xFF, 0xFF, 0x12, 0x34, 0x56]);
        assert_eq!(db.lookup(&mac), None);
    }

    #[test]
    fn test_subnet_hosts() {
        let hosts = subnet_hosts(Ipv4Addr::new(192, 168, 1, 0), 30);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[1], Ipv4Addr::new(192, 168, 1, 2));

        let hosts = subnet_hosts(Ipv4Addr::new(192, 168, 1, 0), 24);
        assert_eq!(hosts.len(), 254);
    }

    #[test]
    fn test_parse_cidr() {
        let (network, mask) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(mask, 24);

        assert!(parse_cidr("192.168.1.0/33").is_none());
        assert!(parse_cidr("invalid").is_none());
    }
}
