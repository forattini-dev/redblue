/// DNS Protocol Implementation from Scratch
/// RFC 1035 - Domain Names - Implementation and Specification
use std::net::{ToSocketAddrs, UdpSocket};

/// DNS Header (12 bytes)
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,      // Transaction ID
    pub flags: u16,   // Flags
    pub qdcount: u16, // Number of questions
    pub ancount: u16, // Number of answers
    pub nscount: u16, // Number of authority records
    pub arcount: u16, // Number of additional records
}

impl DnsHeader {
    pub fn new(id: u16) -> Self {
        Self {
            id,
            flags: 0x0100, // Standard query with recursion desired
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.qdcount.to_be_bytes());
        bytes.extend_from_slice(&self.ancount.to_be_bytes());
        bytes.extend_from_slice(&self.nscount.to_be_bytes());
        bytes.extend_from_slice(&self.arcount.to_be_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 12 {
            return Err("DNS header too short");
        }

        Ok(Self {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            flags: u16::from_be_bytes([bytes[2], bytes[3]]),
            qdcount: u16::from_be_bytes([bytes[4], bytes[5]]),
            ancount: u16::from_be_bytes([bytes[6], bytes[7]]),
            nscount: u16::from_be_bytes([bytes[8], bytes[9]]),
            arcount: u16::from_be_bytes([bytes[10], bytes[11]]),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnsRecordType {
    A = 1,     // IPv4
    NS = 2,    // Name Server
    CNAME = 5, // Canonical Name
    SOA = 6,   // Start of Authority
    PTR = 12,  // Pointer
    MX = 15,   // Mail Exchange
    TXT = 16,  // Text
    AAAA = 28, // IPv6
    SRV = 33,  // Service
    ANY = 255, // Any record
}

impl DnsRecordType {
    pub fn to_u16(&self) -> u16 {
        *self as u16
    }
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn new(domain: &str, qtype: DnsRecordType) -> Self {
        Self {
            qname: domain.to_string(),
            qtype: qtype.to_u16(),
            qclass: 1, // IN (Internet)
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode domain name in DNS format
        for label in self.qname.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0); // Null terminator

        bytes.extend_from_slice(&self.qtype.to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());

        bytes
    }
}

#[derive(Debug, Clone)]
pub enum DnsRdata {
    A(String),
    AAAA(String),
    NS(String),
    CNAME(String),
    PTR(String),
    MX { preference: u16, exchange: String },
    TXT(Vec<String>),
    SOA {
        mname: String,   // Primary nameserver
        rname: String,   // Responsible email (@ replaced with .)
        serial: u32,     // Version number
        refresh: u32,    // Refresh interval (seconds)
        retry: u32,      // Retry interval (seconds)
        expire: u32,     // Expiration limit (seconds)
        minimum: u32,    // Minimum TTL
    },
    Raw(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: DnsRdata,
}

impl DnsAnswer {
    pub fn as_ip(&self) -> Option<String> {
        match &self.data {
            DnsRdata::A(ip) | DnsRdata::AAAA(ip) => Some(ip.clone()),
            _ => None,
        }
    }

    pub fn as_mx(&self) -> Option<(u16, String)> {
        match &self.data {
            DnsRdata::MX { preference, exchange } => Some((*preference, exchange.clone())),
            _ => None,
        }
    }

    pub fn as_cname(&self) -> Option<String> {
        match &self.data {
            DnsRdata::CNAME(cname) => Some(cname.clone()),
            _ => None,
        }
    }

    pub fn type_string(&self) -> String {
        match self.record_type {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            255 => "ANY",
            other => return format!("TYPE{}", other),
        }
        .to_string()
    }

    pub fn display_value(&self) -> String {
        match &self.data {
            DnsRdata::A(ip) | DnsRdata::AAAA(ip) => ip.clone(),
            DnsRdata::NS(name) | DnsRdata::CNAME(name) | DnsRdata::PTR(name) => name.clone(),
            DnsRdata::MX {
                preference,
                exchange,
            } => format!("{} {}", preference, exchange),
            DnsRdata::TXT(chunks) => chunks.join(" "),
            DnsRdata::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => format!(
                "{} {} {} {} {} {} {}",
                mname, rname, serial, refresh, retry, expire, minimum
            ),
            DnsRdata::Raw(bytes) => bytes.iter().fold(String::from("0x"), |mut acc, b| {
                acc.push_str(&format!("{:02X}", b));
                acc
            }),
        }
    }
}

pub struct DnsClient {
    server: String,
    timeout_ms: u64,
}

impl DnsClient {
    pub fn new(server: &str) -> Self {
        Self {
            server: server.to_string(),
            timeout_ms: 5000,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms.max(1);
        self
    }

    pub fn query(
        &self,
        domain: &str,
        record_type: DnsRecordType,
    ) -> Result<Vec<DnsAnswer>, String> {
        let server_target = if self.server.contains(':') {
            // Try to interpret as host:port first
            if self.server.contains(']') {
                self.server.clone()
            } else if self.server.parse::<std::net::SocketAddr>().is_ok() {
                self.server.clone()
            } else {
                format!("{}:53", self.server)
            }
        } else {
            format!("{}:53", self.server)
        };

        let mut addrs = server_target
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve DNS server '{}': {}", self.server, e))?;

        let server_addr = addrs
            .next()
            .ok_or_else(|| format!("No address resolved for DNS server '{}'", self.server))?;

        let bind_addr = if server_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };

        let socket = UdpSocket::bind(bind_addr)
            .map_err(|e| format!("Failed to bind socket '{}': {}", bind_addr, e))?;

        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(self.timeout_ms)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        // Build DNS query packet
        let header = DnsHeader::new(rand_u16());
        let question = DnsQuestion::new(domain, record_type);

        let mut packet = Vec::new();
        packet.extend_from_slice(&header.to_bytes());
        packet.extend_from_slice(&question.to_bytes());

        // Send query
        socket
            .send_to(&packet, server_addr)
            .map_err(|e| format!("Failed to send query: {}", e))?;

        // Receive response
        let mut buffer = [0u8; 512];
        let (size, _) = socket
            .recv_from(&mut buffer)
            .map_err(|e| format!("Failed to receive response: {}", e))?;

        self.parse_response(&buffer[..size])
    }

    fn parse_response(&self, data: &[u8]) -> Result<Vec<DnsAnswer>, String> {
        if data.len() < 12 {
            return Err("Response too short".to_string());
        }

        let header = DnsHeader::from_bytes(data).map_err(|e| e.to_string())?;

        let mut answers = Vec::new();
        let mut offset = 12;

        // Skip questions section
        for _ in 0..header.qdcount {
            offset = self.skip_name(data, offset)?;
            offset += 4; // Skip QTYPE and QCLASS
        }

        // Parse answers
        for _ in 0..header.ancount {
            let (answer, new_offset) = self.parse_answer(data, offset)?;
            answers.push(answer);
            offset = new_offset;
        }

        Ok(answers)
    }

    fn skip_name(&self, data: &[u8], offset: usize) -> Result<usize, String> {
        let (_, next) = self.read_name(data, offset)?;
        Ok(next)
    }

    fn read_name(&self, data: &[u8], offset: usize) -> Result<(String, usize), String> {
        let mut labels = Vec::new();
        let mut pos = offset;
        let mut jumped = false;
        let mut jump_return = 0usize;
        let mut guard = 0usize;

        loop {
            guard += 1;
            if guard > data.len() {
                return Err("DNS name pointer loop".to_string());
            }

            if pos >= data.len() {
                return Err("Invalid name offset".to_string());
            }

            let len = data[pos];
            if len == 0 {
                let next = if jumped { jump_return } else { pos + 1 };
                return Ok((labels.join("."), next));
            }

            if len & 0xC0 == 0xC0 {
                if pos + 1 >= data.len() {
                    return Err("Invalid compression pointer".to_string());
                }
                let pointer = (((len & 0x3F) as u16) << 8 | data[pos + 1] as u16) as usize;
                if !jumped {
                    jump_return = pos + 2;
                    jumped = true;
                }
                pos = pointer;
                continue;
            }

            let label_len = len as usize;
            if pos + 1 + label_len > data.len() {
                return Err("Invalid label length".to_string());
            }

            let label_bytes = &data[pos + 1..pos + 1 + label_len];
            labels.push(String::from_utf8_lossy(label_bytes).to_string());
            pos += 1 + label_len;
        }
    }

    fn parse_answer(&self, data: &[u8], offset: usize) -> Result<(DnsAnswer, usize), String> {
        let (name, mut pos) = self.read_name(data, offset)?;

        if pos + 10 > data.len() {
            return Err("Invalid answer section".to_string());
        }

        let record_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let class = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]);

        pos += 10;

        if pos + rdlength as usize > data.len() {
            return Err("Invalid rdata length".to_string());
        }

        let rdata_start = pos;
        let rdata_end = pos + rdlength as usize;
        let rdata_slice = &data[rdata_start..rdata_end];

        let parsed = match record_type {
            1 if rdlength == 4 => DnsRdata::A(format!(
                "{}.{}.{}.{}",
                rdata_slice[0], rdata_slice[1], rdata_slice[2], rdata_slice[3]
            )),
            28 if rdlength == 16 => {
                let hextets: Vec<String> = rdata_slice
                    .chunks(2)
                    .map(|chunk| format!("{:x}", u16::from_be_bytes([chunk[0], chunk[1]])))
                    .collect();
                DnsRdata::AAAA(hextets.join(":"))
            }
            2 | 5 | 12 => {
                let (target, _) = self.read_name(data, rdata_start)?;
                match record_type {
                    2 => DnsRdata::NS(target),
                    5 => DnsRdata::CNAME(target),
                    _ => DnsRdata::PTR(target),
                }
            }
            15 if rdlength >= 3 => {
                let preference = u16::from_be_bytes([rdata_slice[0], rdata_slice[1]]);
                let (exchange, _) = self.read_name(data, rdata_start + 2)?;
                DnsRdata::MX {
                    preference,
                    exchange,
                }
            }
            16 => {
                let mut pieces = Vec::new();
                let mut idx = 0usize;
                while idx < rdata_slice.len() {
                    let len = rdata_slice[idx] as usize;
                    idx += 1;
                    if idx + len > rdata_slice.len() {
                        break;
                    }
                    let text = &rdata_slice[idx..idx + len];
                    pieces.push(String::from_utf8_lossy(text).to_string());
                    idx += len;
                }
                DnsRdata::TXT(pieces)
            }
            6 => {
                // SOA record: MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM
                let (mname, mname_end) = self.read_name(data, rdata_start)?;
                let (rname, rname_end) = self.read_name(data, mname_end)?;

                // After the two names, we have 5 x 4-byte integers
                let nums_start = rname_end;
                if nums_start + 20 > data.len() {
                    DnsRdata::Raw(rdata_slice.to_vec())
                } else {
                    let serial = u32::from_be_bytes([
                        data[nums_start],
                        data[nums_start + 1],
                        data[nums_start + 2],
                        data[nums_start + 3],
                    ]);
                    let refresh = u32::from_be_bytes([
                        data[nums_start + 4],
                        data[nums_start + 5],
                        data[nums_start + 6],
                        data[nums_start + 7],
                    ]);
                    let retry = u32::from_be_bytes([
                        data[nums_start + 8],
                        data[nums_start + 9],
                        data[nums_start + 10],
                        data[nums_start + 11],
                    ]);
                    let expire = u32::from_be_bytes([
                        data[nums_start + 12],
                        data[nums_start + 13],
                        data[nums_start + 14],
                        data[nums_start + 15],
                    ]);
                    let minimum = u32::from_be_bytes([
                        data[nums_start + 16],
                        data[nums_start + 17],
                        data[nums_start + 18],
                        data[nums_start + 19],
                    ]);
                    DnsRdata::SOA {
                        mname,
                        rname,
                        serial,
                        refresh,
                        retry,
                        expire,
                        minimum,
                    }
                }
            }
            _ => DnsRdata::Raw(rdata_slice.to_vec()),
        };

        pos = rdata_end;

        Ok((
            DnsAnswer {
                name,
                record_type,
                class,
                ttl,
                data: parsed,
            },
            pos,
        ))
    }

    /// Lookup CNAME record for a domain
    pub fn lookup_cname(&self, domain: &str) -> Result<String, String> {
        let answers = self.query(domain, DnsRecordType::CNAME)?;

        for answer in &answers {
            if let DnsRdata::CNAME(cname) = &answer.data {
                return Ok(cname.clone());
            }
        }

        Err(format!("No CNAME record found for {}", domain))
    }
}

// Simple random number generator for transaction IDs
fn rand_u16() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    ((now.as_secs() ^ now.subsec_nanos() as u64) & 0xFFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_header() {
        let header = DnsHeader::new(1234);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 12);

        let parsed = DnsHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.id, 1234);
    }

    #[test]
    fn test_dns_question() {
        let question = DnsQuestion::new("example.com", DnsRecordType::A);
        let bytes = question.to_bytes();
        assert!(bytes.len() > 0);
    }
}
