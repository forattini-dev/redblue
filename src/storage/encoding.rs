use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub struct DecodeError(pub &'static str);

#[inline]
pub fn write_varu32(buf: &mut Vec<u8>, mut value: u32) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

#[inline]
pub fn write_varu64(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

#[inline]
pub fn write_vari32(buf: &mut Vec<u8>, value: i32) {
    let zigzag = ((value << 1) ^ (value >> 31)) as u32;
    write_varu32(buf, zigzag);
}

#[inline]
pub fn write_vari64(buf: &mut Vec<u8>, value: i64) {
    let zigzag = ((value << 1) ^ (value >> 63)) as u64;
    write_varu64(buf, zigzag);
}

#[inline]
pub fn read_varu32(bytes: &[u8], pos: &mut usize) -> Result<u32, DecodeError> {
    let mut result = 0u32;
    let mut shift = 0u32;
    while *pos < bytes.len() {
        let byte = bytes[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 35 {
            return Err(DecodeError("varu32 overflow"));
        }
    }
    Err(DecodeError("unexpected eof (varu32)"))
}

#[inline]
pub fn read_varu64(bytes: &[u8], pos: &mut usize) -> Result<u64, DecodeError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    while *pos < bytes.len() {
        let byte = bytes[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 70 {
            return Err(DecodeError("varu64 overflow"));
        }
    }
    Err(DecodeError("unexpected eof (varu64)"))
}

#[inline]
pub fn read_vari32(bytes: &[u8], pos: &mut usize) -> Result<i32, DecodeError> {
    let raw = read_varu32(bytes, pos)?;
    Ok(((raw >> 1) as i32) ^ (-((raw & 1) as i32)))
}

#[inline]
pub fn read_vari64(bytes: &[u8], pos: &mut usize) -> Result<i64, DecodeError> {
    let raw = read_varu64(bytes, pos)?;
    Ok(((raw >> 1) as i64) ^ (-((raw & 1) as i64)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpKey {
    pub bytes: [u8; 16],
    pub len: u8,
}

impl IpKey {
    pub fn from(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => {
                let mut bytes = [0u8; 16];
                bytes[..4].copy_from_slice(&v4.octets());
                Self { bytes, len: 4 }
            }
            IpAddr::V6(v6) => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&v6.octets());
                Self { bytes, len: 16 }
            }
        }
    }

    pub fn to_ip(self) -> IpAddr {
        if self.len == 4 {
            IpAddr::V4(Ipv4Addr::new(
                self.bytes[0],
                self.bytes[1],
                self.bytes[2],
                self.bytes[3],
            ))
        } else {
            IpAddr::V6(Ipv6Addr::from(self.bytes))
        }
    }
}

#[inline]
pub fn write_ip(buf: &mut Vec<u8>, addr: &IpAddr) {
    match addr {
        IpAddr::V4(v4) => {
            buf.push(0);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(1);
            buf.extend_from_slice(&v6.octets());
        }
    }
}

#[inline]
pub fn read_ip(bytes: &[u8], pos: &mut usize) -> Result<IpAddr, DecodeError> {
    if *pos >= bytes.len() {
        return Err(DecodeError("unexpected eof (ip tag)"));
    }
    let tag = bytes[*pos];
    *pos += 1;
    match tag {
        0 => {
            if *pos + 4 > bytes.len() {
                return Err(DecodeError("unexpected eof (ipv4)"));
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&bytes[*pos..*pos + 4]);
            *pos += 4;
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        1 => {
            if *pos + 16 > bytes.len() {
                return Err(DecodeError("unexpected eof (ipv6)"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[*pos..*pos + 16]);
            *pos += 16;
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(DecodeError("invalid ip tag")),
    }
}

#[inline]
pub fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    write_varu32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

#[inline]
pub fn read_bytes<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8], DecodeError> {
    let len = read_varu32(bytes, pos)? as usize;
    if *pos + len > bytes.len() {
        return Err(DecodeError("unexpected eof (bytes)"));
    }
    let slice = &bytes[*pos..*pos + len];
    *pos += len;
    Ok(slice)
}

#[inline]
pub fn write_string(buf: &mut Vec<u8>, value: &str) {
    write_bytes(buf, value.as_bytes());
}

#[inline]
pub fn read_string<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a str, DecodeError> {
    let data = read_bytes(bytes, pos)?;
    std::str::from_utf8(data).map_err(|_| DecodeError("invalid utf8"))
}
