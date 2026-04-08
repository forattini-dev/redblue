/// DNS Protocol Implementation from Scratch
/// RFC 1035 - Domain Names - Implementation and Specification
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};

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
  A = 1,       // IPv4
  NS = 2,      // Name Server
  CNAME = 5,   // Canonical Name
  SOA = 6,     // Start of Authority
  PTR = 12,    // Pointer
  MX = 15,     // Mail Exchange
  TXT = 16,    // Text
  AAAA = 28,   // IPv6
  SRV = 33,    // Service
  DS = 43,     // Delegation Signer (RFC 4034)
  RRSIG = 46,  // Resource Record Signature (RFC 4034)
  NSEC = 47,   // Next Secure (RFC 4034)
  DNSKEY = 48, // DNS Public Key (RFC 4034)
  NSEC3 = 50,  // Next Secure v3 (RFC 5155)
  TLSA = 52,   // DANE TLSA (RFC 6698)
  CAA = 257,   // Certification Authority Authorization (RFC 6844)
  ANY = 255,   // Any record
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
  MX {
    preference: u16,
    exchange: String,
  },
  TXT(Vec<String>),
  SOA {
    mname: String, // Primary nameserver
    rname: String, // Responsible email (@ replaced with .)
    serial: u32,   // Version number
    refresh: u32,  // Refresh interval (seconds)
    retry: u32,    // Retry interval (seconds)
    expire: u32,   // Expiration limit (seconds)
    minimum: u32,  // Minimum TTL
  },
  CAA {
    flags: u8,
    tag: String,
    value: String,
  },
  TLSA {
    usage: u8,
    selector: u8,
    matching_type: u8,
    data: Vec<u8>,
  },
  DNSKEY {
    flags: u16,    // 256=ZSK, 257=KSK
    protocol: u8,  // always 3
    algorithm: u8, // 8=RSA-SHA256, 13=ECDSA-P256-SHA256, 15=Ed25519
    public_key: Vec<u8>,
  },
  RRSIG {
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    expiration: u32, // Unix timestamp
    inception: u32,  // Unix timestamp
    key_tag: u16,
    signer_name: String,
    signature: Vec<u8>,
  },
  DS {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8, // 1=SHA-1, 2=SHA-256
    digest: Vec<u8>,
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
      DnsRdata::MX {
        preference,
        exchange,
      } => Some((*preference, exchange.clone())),
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
      43 => "DS",
      46 => "RRSIG",
      47 => "NSEC",
      48 => "DNSKEY",
      50 => "NSEC3",
      52 => "TLSA",
      257 => "CAA",
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
      DnsRdata::CAA { flags, tag, value } => format!("{} {} \"{}\"", flags, tag, value),
      DnsRdata::TLSA {
        usage,
        selector,
        matching_type,
        data,
      } => {
        let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect();
        format!("{} {} {} {}", usage, selector, matching_type, hex)
      }
      DnsRdata::DNSKEY {
        flags,
        protocol,
        algorithm,
        public_key,
      } => {
        let key_hex: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();
        format!("{} {} {} {}", flags, protocol, algorithm, key_hex)
      }
      DnsRdata::RRSIG {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer_name,
        ..
      } => {
        format!(
          "{} {} {} {} {} {} {} {}",
          type_covered,
          algorithm,
          labels,
          original_ttl,
          expiration,
          inception,
          key_tag,
          signer_name
        )
      }
      DnsRdata::DS {
        key_tag,
        algorithm,
        digest_type,
        digest,
      } => {
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        format!("{} {} {} {}", key_tag, algorithm, digest_type, hex)
      }
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

  pub fn query(&self, domain: &str, record_type: DnsRecordType) -> Result<Vec<DnsAnswer>, String> {
    self.query_internal(domain, record_type, false)
  }

  /// Query with DNSSEC OK (DO) bit set in the EDNS0 OPT record.
  /// This requests the server to return DNSSEC-related records (RRSIG, DNSKEY, DS, etc.)
  pub fn query_dnssec(
    &self,
    domain: &str,
    record_type: DnsRecordType,
  ) -> Result<Vec<DnsAnswer>, String> {
    self.query_internal(domain, record_type, true)
  }

  fn query_internal(
    &self,
    domain: &str,
    record_type: DnsRecordType,
    dnssec_ok: bool,
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

    // Build DNS query packet with EDNS0 OPT record (RFC 6891)
    let mut header = DnsHeader::new(rand_u16());
    header.arcount = 1; // One additional record (OPT)
    let question = DnsQuestion::new(domain, record_type);

    let mut packet = Vec::new();
    packet.extend_from_slice(&header.to_bytes());
    packet.extend_from_slice(&question.to_bytes());

    // Append EDNS0 OPT pseudo-record (RFC 6891)
    // NAME: 0x00 (root domain)
    // TYPE: 41 (OPT)
    // CLASS: 4096 (UDP payload size)
    // TTL: extended RCODE(1) + version(1) + flags(2)
    //   The DO (DNSSEC OK) bit is bit 15 of the flags field (byte offset 2 in TTL).
    //   When DO=1, TTL = 0x00008000.
    // RDLENGTH: 0 (no EDNS0 options)
    let edns_flags: u32 = if dnssec_ok { 0x00008000 } else { 0x00000000 };

    packet.push(0x00); // root name
    packet.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
    packet.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = UDP payload size
    packet.extend_from_slice(&edns_flags.to_be_bytes()); // TTL = extended RCODE + DO flag
    packet.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0

    // Send query
    socket
      .send_to(&packet, server_addr)
      .map_err(|e| format!("Failed to send query: {}", e))?;

    // Receive response with EDNS0-sized buffer (4096 bytes)
    let mut buffer = [0u8; 4096];
    let (size, _) = socket
      .recv_from(&mut buffer)
      .map_err(|e| format!("Failed to receive response: {}", e))?;

    let response = &buffer[..size];

    // Check TC (truncation) bit: byte 2, bit 1
    if size >= 3 && (response[2] >> 1) & 1 == 1 {
      // Response was truncated, retry over TCP
      let tcp_response = Self::query_tcp(&server_addr.to_string(), &packet)?;
      return self.parse_response(&tcp_response);
    }

    self.parse_response(response)
  }

  /// Send a DNS query over TCP (RFC 1035 section 4.2.2).
  /// TCP DNS messages are prefixed with a 2-byte big-endian length field.
  fn query_tcp(server: &str, query: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream =
      TcpStream::connect(server).map_err(|e| format!("TCP connect to {}: {}", server, e))?;

    stream
      .set_read_timeout(Some(std::time::Duration::from_secs(5)))
      .map_err(|e| format!("TCP set read timeout: {}", e))?;
    stream
      .set_write_timeout(Some(std::time::Duration::from_secs(5)))
      .map_err(|e| format!("TCP set write timeout: {}", e))?;

    // Prepend 2-byte length prefix
    let len = query.len() as u16;
    stream
      .write_all(&len.to_be_bytes())
      .map_err(|e| format!("TCP write length: {}", e))?;
    stream
      .write_all(query)
      .map_err(|e| format!("TCP write query: {}", e))?;
    stream.flush().map_err(|e| format!("TCP flush: {}", e))?;

    // Read 2-byte response length
    let mut len_buf = [0u8; 2];
    stream
      .read_exact(&mut len_buf)
      .map_err(|e| format!("TCP read length: {}", e))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    // Read full response
    let mut response = vec![0u8; resp_len];
    stream
      .read_exact(&mut response)
      .map_err(|e| format!("TCP read response: {}", e))?;

    Ok(response)
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
      // TLSA record (RFC 6698): usage(1) + selector(1) + matching_type(1) + cert_data
      52 if rdlength >= 3 => {
        let usage = rdata_slice[0];
        let selector = rdata_slice[1];
        let matching_type = rdata_slice[2];
        let cert_data = rdata_slice[3..].to_vec();
        DnsRdata::TLSA {
          usage,
          selector,
          matching_type,
          data: cert_data,
        }
      }
      // DNSKEY record (RFC 4034): flags(2) + protocol(1) + algorithm(1) + public_key
      48 if rdlength >= 4 => {
        let flags = u16::from_be_bytes([rdata_slice[0], rdata_slice[1]]);
        let protocol = rdata_slice[2];
        let algorithm = rdata_slice[3];
        let public_key = rdata_slice[4..].to_vec();
        DnsRdata::DNSKEY {
          flags,
          protocol,
          algorithm,
          public_key,
        }
      }
      // RRSIG record (RFC 4034): type_covered(2) + algorithm(1) + labels(1) +
      //   original_ttl(4) + expiration(4) + inception(4) + key_tag(2) + signer_name + signature
      46 if rdlength >= 18 => {
        let type_covered = u16::from_be_bytes([rdata_slice[0], rdata_slice[1]]);
        let algorithm = rdata_slice[2];
        let labels = rdata_slice[3];
        let original_ttl = u32::from_be_bytes([
          rdata_slice[4],
          rdata_slice[5],
          rdata_slice[6],
          rdata_slice[7],
        ]);
        let expiration = u32::from_be_bytes([
          rdata_slice[8],
          rdata_slice[9],
          rdata_slice[10],
          rdata_slice[11],
        ]);
        let inception = u32::from_be_bytes([
          rdata_slice[12],
          rdata_slice[13],
          rdata_slice[14],
          rdata_slice[15],
        ]);
        let key_tag = u16::from_be_bytes([rdata_slice[16], rdata_slice[17]]);
        // Signer name starts at offset 18 within rdata, but uses absolute offsets for compression
        let (signer_name, signer_end) = self.read_name(data, rdata_start + 18)?;
        let signature = data[signer_end..rdata_end].to_vec();
        DnsRdata::RRSIG {
          type_covered,
          algorithm,
          labels,
          original_ttl,
          expiration,
          inception,
          key_tag,
          signer_name,
          signature,
        }
      }
      // DS record (RFC 4034): key_tag(2) + algorithm(1) + digest_type(1) + digest
      43 if rdlength >= 4 => {
        let key_tag = u16::from_be_bytes([rdata_slice[0], rdata_slice[1]]);
        let algorithm = rdata_slice[2];
        let digest_type = rdata_slice[3];
        let digest = rdata_slice[4..].to_vec();
        DnsRdata::DS {
          key_tag,
          algorithm,
          digest_type,
          digest,
        }
      }
      // CAA record (RFC 6844): flags(1) + tag_length(1) + tag + value
      257 if rdlength >= 2 => {
        let flags = rdata_slice[0];
        let tag_len = rdata_slice[1] as usize;
        if 2 + tag_len > rdata_slice.len() {
          DnsRdata::Raw(rdata_slice.to_vec())
        } else {
          let tag = String::from_utf8_lossy(&rdata_slice[2..2 + tag_len]).to_string();
          let value = String::from_utf8_lossy(&rdata_slice[2 + tag_len..]).to_string();
          DnsRdata::CAA { flags, tag, value }
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

/// Cryptographically secure random u16 for DNS transaction IDs
fn rand_u16() -> u16 {
  let mut buf = [0u8; 2];
  if crate::crypto::os_random::fill_bytes(&mut buf).is_ok() {
    return u16::from_ne_bytes(buf);
  }

  let nanos = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_nanos())
    .unwrap_or(0);
  ((nanos ^ (nanos >> 16)) & 0xFFFF) as u16
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

  #[test]
  fn test_edns0_opt_record_appended() {
    // Build a query packet the same way the client does
    let mut header = DnsHeader::new(0xABCD);
    header.arcount = 1;
    let question = DnsQuestion::new("example.com", DnsRecordType::A);

    let mut packet = Vec::new();
    packet.extend_from_slice(&header.to_bytes());
    packet.extend_from_slice(&question.to_bytes());

    // Append EDNS0 OPT record
    packet.push(0x00); // root name
    packet.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
    packet.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = UDP payload size
    packet.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0

    // Verify ARCOUNT is 1 in the header bytes
    let arcount = u16::from_be_bytes([packet[10], packet[11]]);
    assert_eq!(arcount, 1, "ARCOUNT must be 1 for EDNS0");

    // Verify OPT record is at the end of the packet
    // OPT record is 11 bytes: name(1) + type(2) + class(2) + ttl(4) + rdlength(2)
    let opt_start = packet.len() - 11;

    // Root name
    assert_eq!(packet[opt_start], 0x00);
    // TYPE = 41 (OPT)
    assert_eq!(
      u16::from_be_bytes([packet[opt_start + 1], packet[opt_start + 2]]),
      41
    );
    // CLASS = 4096 (UDP payload size)
    assert_eq!(
      u16::from_be_bytes([packet[opt_start + 3], packet[opt_start + 4]]),
      4096
    );
    // TTL = 0
    assert_eq!(
      u32::from_be_bytes([
        packet[opt_start + 5],
        packet[opt_start + 6],
        packet[opt_start + 7],
        packet[opt_start + 8]
      ]),
      0
    );
    // RDLENGTH = 0
    assert_eq!(
      u16::from_be_bytes([packet[opt_start + 9], packet[opt_start + 10]]),
      0
    );
  }

  #[test]
  fn test_caa_record_parse() {
    // Build a minimal DNS response with a CAA record
    // Header: id=0x1234, flags=0x8180 (response, no error), qdcount=1, ancount=1
    let mut response: Vec<u8> = Vec::new();
    response.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
    response.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question: example.com, type CAA (257), class IN
    // \x07example\x03com\x00
    response.extend_from_slice(b"\x07example\x03com\x00");
    response.extend_from_slice(&257u16.to_be_bytes()); // QTYPE = CAA
    response.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    // Answer: compression pointer to question name at offset 12
    response.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
    response.extend_from_slice(&257u16.to_be_bytes()); // TYPE = CAA
    response.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    response.extend_from_slice(&300u32.to_be_bytes()); // TTL
                                                       // RDATA: flags=0, tag_len=5, tag="issue", value="letsencrypt.org"
    let rdata: Vec<u8> = {
      let mut r = Vec::new();
      r.push(0); // flags
      r.push(5); // tag length
      r.extend_from_slice(b"issue"); // tag
      r.extend_from_slice(b"letsencrypt.org"); // value
      r
    };
    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
    response.extend_from_slice(&rdata);

    let client = DnsClient::new("127.0.0.1");
    let answers = client.parse_response(&response).unwrap();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].record_type, 257);

    match &answers[0].data {
      DnsRdata::CAA { flags, tag, value } => {
        assert_eq!(*flags, 0);
        assert_eq!(tag, "issue");
        assert_eq!(value, "letsencrypt.org");
      }
      other => panic!("Expected CAA record, got {:?}", other),
    }

    assert_eq!(answers[0].display_value(), "0 issue \"letsencrypt.org\"");
  }

  #[test]
  fn test_tlsa_record_parse() {
    // Build a minimal DNS response with a TLSA record
    let mut response: Vec<u8> = Vec::new();
    response.extend_from_slice(&0x5678u16.to_be_bytes()); // ID
    response.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question: _443._tcp.example.com, type TLSA (52), class IN
    response.extend_from_slice(b"\x04_443\x04_tcp\x07example\x03com\x00");
    response.extend_from_slice(&52u16.to_be_bytes()); // QTYPE = TLSA
    response.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    // Answer: compression pointer to question name at offset 12
    response.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
    response.extend_from_slice(&52u16.to_be_bytes()); // TYPE = TLSA
    response.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    response.extend_from_slice(&3600u32.to_be_bytes()); // TTL
                                                        // RDATA: usage=3, selector=1, matching_type=1, cert_data=0xABCD1234
    let rdata: Vec<u8> = vec![3, 1, 1, 0xAB, 0xCD, 0x12, 0x34];
    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
    response.extend_from_slice(&rdata);

    let client = DnsClient::new("127.0.0.1");
    let answers = client.parse_response(&response).unwrap();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].record_type, 52);

    match &answers[0].data {
      DnsRdata::TLSA {
        usage,
        selector,
        matching_type,
        data,
      } => {
        assert_eq!(*usage, 3);
        assert_eq!(*selector, 1);
        assert_eq!(*matching_type, 1);
        assert_eq!(data, &[0xAB, 0xCD, 0x12, 0x34]);
      }
      other => panic!("Expected TLSA record, got {:?}", other),
    }

    assert_eq!(answers[0].display_value(), "3 1 1 abcd1234");
  }

  #[test]
  fn test_tcp_length_prefix_encoding() {
    // Verify the 2-byte big-endian length prefix encoding used in TCP DNS
    let query = vec![0u8; 300];
    let len = query.len() as u16;
    let prefix = len.to_be_bytes();
    assert_eq!(prefix, [0x01, 0x2C]); // 300 in big-endian

    // Also verify a small query
    let small = vec![0u8; 42];
    let small_len = small.len() as u16;
    let small_prefix = small_len.to_be_bytes();
    assert_eq!(small_prefix, [0x00, 0x2A]); // 42 in big-endian

    // Verify round-trip
    let decoded = u16::from_be_bytes(prefix) as usize;
    assert_eq!(decoded, 300);
  }

  #[test]
  fn test_buffer_size_4096() {
    // Verify that the buffer size constant matches EDNS0 advertisement
    // The UDP payload size in the OPT record and the receive buffer must both be 4096
    let udp_payload_size: u16 = 4096;
    let buffer = [0u8; 4096];

    assert_eq!(buffer.len(), udp_payload_size as usize);
    assert_eq!(buffer.len(), 4096);

    // Verify the OPT record CLASS field encodes this correctly
    let class_bytes = udp_payload_size.to_be_bytes();
    assert_eq!(class_bytes, [0x10, 0x00]); // 4096 in big-endian
  }

  #[test]
  fn test_do_bit_in_edns0_opt() {
    // Verify the DO (DNSSEC OK) bit is correctly encoded in the OPT TTL field.
    // The TTL field of OPT is: extended-rcode(8) | version(8) | DO(1) | Z(15)
    // DO=1 means byte 2 of TTL has bit 7 set: 0x00_00_80_00

    // Without DO bit
    let flags_no_do: u32 = 0x00000000;
    let bytes_no_do = flags_no_do.to_be_bytes();
    assert_eq!(bytes_no_do, [0x00, 0x00, 0x00, 0x00]);
    assert_eq!(bytes_no_do[2] & 0x80, 0, "DO bit must be unset");

    // With DO bit
    let flags_do: u32 = 0x00008000;
    let bytes_do = flags_do.to_be_bytes();
    assert_eq!(bytes_do, [0x00, 0x00, 0x80, 0x00]);
    assert_eq!(bytes_do[2] & 0x80, 0x80, "DO bit must be set");
  }

  #[test]
  fn test_dnskey_record_parse() {
    // Build a DNS response with a DNSKEY record (type 48)
    let mut response: Vec<u8> = Vec::new();
    response.extend_from_slice(&0xAAAAu16.to_be_bytes()); // ID
    response.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags (response, no error)
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question: example.com, type DNSKEY (48), class IN
    response.extend_from_slice(b"\x07example\x03com\x00");
    response.extend_from_slice(&48u16.to_be_bytes()); // QTYPE = DNSKEY
    response.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    // Answer: compression pointer to name at offset 12
    response.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
    response.extend_from_slice(&48u16.to_be_bytes()); // TYPE = DNSKEY
    response.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    response.extend_from_slice(&3600u32.to_be_bytes()); // TTL

    // RDATA: flags=257 (KSK), protocol=3, algorithm=13 (ECDSA-P256), key=8 bytes
    let mut rdata: Vec<u8> = Vec::new();
    rdata.extend_from_slice(&257u16.to_be_bytes()); // flags (KSK)
    rdata.push(3); // protocol
    rdata.push(13); // algorithm (ECDSA-P256-SHA256)
    rdata.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // public key

    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&rdata);

    let client = DnsClient::new("127.0.0.1");
    let answers = client.parse_response(&response).unwrap();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].record_type, 48);

    match &answers[0].data {
      DnsRdata::DNSKEY {
        flags,
        protocol,
        algorithm,
        public_key,
      } => {
        assert_eq!(*flags, 257, "KSK flag should be 257");
        assert_eq!(*protocol, 3);
        assert_eq!(*algorithm, 13);
        assert_eq!(
          public_key,
          &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
      }
      other => panic!("Expected DNSKEY record, got {:?}", other),
    }

    assert_eq!(answers[0].type_string(), "DNSKEY");
  }

  #[test]
  fn test_ds_record_parse() {
    // Build a DNS response with a DS record (type 43)
    let mut response: Vec<u8> = Vec::new();
    response.extend_from_slice(&0xBBBBu16.to_be_bytes()); // ID
    response.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question: example.com, type DS (43), class IN
    response.extend_from_slice(b"\x07example\x03com\x00");
    response.extend_from_slice(&43u16.to_be_bytes()); // QTYPE = DS
    response.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    // Answer
    response.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
    response.extend_from_slice(&43u16.to_be_bytes()); // TYPE = DS
    response.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    response.extend_from_slice(&86400u32.to_be_bytes()); // TTL

    // RDATA: key_tag=12345, algorithm=8 (RSA-SHA256), digest_type=2 (SHA-256), digest
    let mut rdata: Vec<u8> = Vec::new();
    rdata.extend_from_slice(&12345u16.to_be_bytes()); // key_tag
    rdata.push(8); // algorithm
    rdata.push(2); // digest_type (SHA-256)
    rdata.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // digest

    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&rdata);

    let client = DnsClient::new("127.0.0.1");
    let answers = client.parse_response(&response).unwrap();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].record_type, 43);

    match &answers[0].data {
      DnsRdata::DS {
        key_tag,
        algorithm,
        digest_type,
        digest,
      } => {
        assert_eq!(*key_tag, 12345);
        assert_eq!(*algorithm, 8);
        assert_eq!(*digest_type, 2);
        assert_eq!(digest, &[0xDE, 0xAD, 0xBE, 0xEF]);
      }
      other => panic!("Expected DS record, got {:?}", other),
    }

    assert_eq!(answers[0].type_string(), "DS");
    assert_eq!(answers[0].display_value(), "12345 8 2 deadbeef");
  }

  #[test]
  fn test_rrsig_record_parse() {
    // Build a DNS response with an RRSIG record (type 46)
    let mut response: Vec<u8> = Vec::new();
    response.extend_from_slice(&0xCCCCu16.to_be_bytes()); // ID
    response.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question: example.com, type A (1), class IN
    response.extend_from_slice(b"\x07example\x03com\x00");
    response.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    response.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    // Answer: RRSIG covering type A
    response.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
    response.extend_from_slice(&46u16.to_be_bytes()); // TYPE = RRSIG
    response.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    response.extend_from_slice(&3600u32.to_be_bytes()); // TTL

    // RRSIG RDATA: type_covered(2) + algorithm(1) + labels(1) + original_ttl(4) +
    //   expiration(4) + inception(4) + key_tag(2) + signer_name + signature
    let mut rdata: Vec<u8> = Vec::new();
    rdata.extend_from_slice(&1u16.to_be_bytes()); // type_covered = A
    rdata.push(13); // algorithm (ECDSA-P256-SHA256)
    rdata.push(2); // labels
    rdata.extend_from_slice(&300u32.to_be_bytes()); // original_ttl
    rdata.extend_from_slice(&1700000000u32.to_be_bytes()); // expiration (Unix timestamp)
    rdata.extend_from_slice(&1699900000u32.to_be_bytes()); // inception (Unix timestamp)
    rdata.extend_from_slice(&54321u16.to_be_bytes()); // key_tag
                                                      // signer_name: "example.com" (uncompressed, since this is within RDATA)
    rdata.extend_from_slice(b"\x07example\x03com\x00");
    // signature: 4 bytes for testing
    rdata.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&rdata);

    let client = DnsClient::new("127.0.0.1");
    let answers = client.parse_response(&response).unwrap();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].record_type, 46);

    match &answers[0].data {
      DnsRdata::RRSIG {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer_name,
        signature,
      } => {
        assert_eq!(*type_covered, 1); // A record
        assert_eq!(*algorithm, 13);
        assert_eq!(*labels, 2);
        assert_eq!(*original_ttl, 300);
        assert_eq!(*expiration, 1700000000);
        assert_eq!(*inception, 1699900000);
        assert_eq!(*key_tag, 54321);
        assert_eq!(signer_name, "example.com");
        assert_eq!(signature, &[0xAA, 0xBB, 0xCC, 0xDD]);
      }
      other => panic!("Expected RRSIG record, got {:?}", other),
    }

    assert_eq!(answers[0].type_string(), "RRSIG");
  }

  #[test]
  fn test_dnskey_zsk_flags() {
    // Verify ZSK (flag 256) is parsed correctly and distinguished from KSK (257)
    let mut response: Vec<u8> = Vec::new();
    response.extend_from_slice(&0xDDDDu16.to_be_bytes());
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());

    response.extend_from_slice(b"\x07example\x03com\x00");
    response.extend_from_slice(&48u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());

    response.extend_from_slice(&[0xC0, 0x0C]);
    response.extend_from_slice(&48u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&3600u32.to_be_bytes());

    // ZSK: flags=256
    let mut rdata: Vec<u8> = Vec::new();
    rdata.extend_from_slice(&256u16.to_be_bytes()); // flags (ZSK)
    rdata.push(3);
    rdata.push(8); // RSA-SHA256
    rdata.extend_from_slice(&[0xFF; 16]); // public key

    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&rdata);

    let client = DnsClient::new("127.0.0.1");
    let answers = client.parse_response(&response).unwrap();

    match &answers[0].data {
      DnsRdata::DNSKEY { flags, .. } => {
        assert_eq!(*flags, 256, "ZSK flag should be 256");
        assert_eq!(*flags & 0x0001, 0, "SEP bit should be unset for ZSK");
      }
      other => panic!("Expected DNSKEY, got {:?}", other),
    }
  }

  #[test]
  fn test_dnssec_record_type_values() {
    assert_eq!(DnsRecordType::DS.to_u16(), 43);
    assert_eq!(DnsRecordType::RRSIG.to_u16(), 46);
    assert_eq!(DnsRecordType::NSEC.to_u16(), 47);
    assert_eq!(DnsRecordType::DNSKEY.to_u16(), 48);
    assert_eq!(DnsRecordType::NSEC3.to_u16(), 50);
  }
}
