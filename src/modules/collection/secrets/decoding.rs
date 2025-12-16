use crate::crypto::encoding::base64;

pub struct Decoder;

impl Decoder {
    /// Attempts to decode base64 content if it looks valid
    pub fn try_decode_base64(input: &str) -> Option<String> {
        if input.len().is_multiple_of(4)
            && input
                .chars()
                .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            if let Ok(decoded) = base64::base64_decode(input) {
                return String::from_utf8(decoded).ok();
            }
        }
        None
    }

    /// Attempts to decode hex content if it looks valid
    pub fn try_decode_hex(input: &str) -> Option<String> {
        if input.len().is_multiple_of(2) && input.chars().all(|c| c.is_ascii_hexdigit()) {
            // Simple hex decode
            let mut bytes = Vec::new();
            for i in (0..input.len()).step_by(2) {
                if let Ok(byte) = u8::from_str_radix(&input[i..i + 2], 16) {
                    bytes.push(byte);
                } else {
                    return None;
                }
            }
            return String::from_utf8(bytes).ok();
        }
        None
    }
}
