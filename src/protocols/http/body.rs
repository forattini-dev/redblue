use std::str;

#[derive(Debug, Clone, Copy)]
pub enum BodyStrategy {
    ContentLength(usize),
    Chunked,
    Unknown,
}

pub fn analyze_headers(buffer: &[u8]) -> (BodyStrategy, bool) {
    let mut strategy = BodyStrategy::Unknown;
    let mut can_reuse = true;
    let header_text = String::from_utf8_lossy(buffer);

    for line in header_text.lines().skip(1) {
        if let Some(colon) = line.find(':') {
            let key = line[..colon].trim().to_ascii_lowercase();
            let value = line[colon + 1..].trim().to_ascii_lowercase();

            if key == "content-length" {
                if let Ok(len) = value.parse::<usize>() {
                    strategy = BodyStrategy::ContentLength(len);
                }
            } else if key == "connection" {
                if value.contains("close") {
                    can_reuse = false;
                }
            } else if key == "transfer-encoding" {
                if value.contains("chunked") {
                    strategy = BodyStrategy::Chunked;
                } else {
                    can_reuse = false;
                }
            }
        }
    }

    (strategy, can_reuse)
}

pub fn chunked_body_complete(data: &[u8]) -> bool {
    let mut index = 0usize;
    loop {
        let line_end = match find_crlf(data, index) {
            Some(pos) => pos,
            None => return false,
        };
        let line = &data[index..line_end];
        let line_str = match str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let size_part = line_str.split(';').next().map(|s| s.trim()).unwrap_or("");
        let chunk_size = match usize::from_str_radix(size_part, 16) {
            Ok(size) => size,
            Err(_) => return false,
        };

        index = line_end + 2;
        if chunk_size == 0 {
            let trailer = &data.get(index..).unwrap_or(&[]);
            if let Some(pos) = trailer.windows(4).position(|w| w == b"\r\n\r\n") {
                return index + pos + 4 <= data.len();
            }
            return false;
        }

        let chunk_end = index + chunk_size;
        if data.len() < chunk_end + 2 {
            return false;
        }
        if &data[chunk_end..chunk_end + 2] != b"\r\n" {
            return false;
        }
        index = chunk_end + 2;
    }
}

pub fn decode_chunked_body(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut index = 0usize;
    let mut decoded = Vec::new();

    loop {
        let line_end =
            find_crlf(data, index).ok_or_else(|| "Malformed chunk header".to_string())?;
        let line = &data[index..line_end];
        let line_str = str::from_utf8(line).map_err(|_| "Non UTF-8 chunk header".to_string())?;
        let size_part = line_str.split(';').next().map(|s| s.trim()).unwrap_or("");
        let chunk_size =
            usize::from_str_radix(size_part, 16).map_err(|_| "Invalid chunk size".to_string())?;

        index = line_end + 2;
        if chunk_size == 0 {
            loop {
                let trailer_end =
                    find_crlf(data, index).ok_or_else(|| "Incomplete chunk trailer".to_string())?;
                if trailer_end == index {
                    index += 2;
                    break;
                }
                index = trailer_end + 2;
            }
            break;
        }

        let chunk_end = index + chunk_size;
        if data.len() < chunk_end + 2 {
            return Err("Incomplete chunk payload".to_string());
        }
        decoded.extend_from_slice(&data[index..chunk_end]);
        if &data[chunk_end..chunk_end + 2] != b"\r\n" {
            return Err("Missing CRLF after chunk payload".to_string());
        }
        index = chunk_end + 2;
    }

    Ok(decoded)
}

pub fn find_crlf(data: &[u8], start: usize) -> Option<usize> {
    data.get(start..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|pos| start + pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_headers_content_length() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
        let (strategy, reusable) = analyze_headers(headers);
        match strategy {
            BodyStrategy::ContentLength(len) => assert_eq!(len, 10),
            _ => panic!("expected content length"),
        }
        assert!(reusable);
    }

    #[test]
    fn test_chunked_body_helpers() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert!(chunked_body_complete(body));
        let decoded = decode_chunked_body(body).expect("decode");
        assert_eq!(decoded, b"Wikipedia");
    }

    #[test]
    fn test_chunked_detect_incomplete() {
        let incomplete = b"4\r\nWiki\r\n";
        assert!(!chunked_body_complete(incomplete));
        assert!(decode_chunked_body(incomplete).is_err());
    }
}
