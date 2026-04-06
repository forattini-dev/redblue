//! Helper functions for crypto commands

use crate::crypto::hmac::hmac_sha256;
use crate::crypto::sha256::sha256;
use std::io::{self, Read};
use std::time::{SystemTime, UNIX_EPOCH};

/// Hex encode bytes to string
pub fn hex_encode(bytes: &[u8]) -> String {
  let mut s = String::with_capacity(bytes.len() * 2);
  for &b in bytes {
    use std::fmt::Write;
    write!(&mut s, "{:02x}", b).unwrap();
  }
  s
}

/// Read password from terminal without echoing
pub fn read_password() -> Result<String, String> {
  // Try to disable echo on Unix
  #[cfg(unix)]
  {
    use std::os::unix::io::AsRawFd;

    let stdin = io::stdin();
    let fd = stdin.as_raw_fd();

    // Get current terminal settings
    let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
    let result = unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) };

    if result == 0 {
      let mut termios = unsafe { termios.assume_init() };
      let old_termios = termios;

      // Disable echo
      termios.c_lflag &= !libc::ECHO;
      unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };

      // Read password
      let mut password = String::new();
      let result = io::stdin().read_line(&mut password);

      // Restore terminal settings
      unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old_termios) };
      eprintln!(); // New line after password

      result.map_err(|e| format!("Failed to read password: {}", e))?;
      Ok(password.trim().to_string())
    } else {
      // Fallback: read with echo
      let mut password = String::new();
      io::stdin()
        .read_line(&mut password)
        .map_err(|e| format!("Failed to read password: {}", e))?;
      Ok(password.trim().to_string())
    }
  }

  #[cfg(windows)]
  {
    // Windows fallback: read with echo (Windows terminal handling is different)
    let mut password = String::new();
    io::stdin()
      .read_line(&mut password)
      .map_err(|e| format!("Failed to read password: {}", e))?;
    Ok(password.trim().to_string())
  }
}

/// Generate cryptographically random bytes
pub fn generate_random_bytes(size: usize) -> Vec<u8> {
  // Try /dev/urandom first on Unix
  #[cfg(unix)]
  {
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
      let mut bytes = vec![0u8; size];
      if file.read_exact(&mut bytes).is_ok() {
        return bytes;
      }
    }
  }

  // Fallback: use time-based seed with multiple hash rounds
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default();

  let mut seed = Vec::new();
  seed.extend_from_slice(&now.as_nanos().to_le_bytes());
  seed.extend_from_slice(&(std::process::id() as u64).to_le_bytes());

  // Use counter mode with SHA-256 to generate bytes
  let mut output = Vec::with_capacity(size);
  let mut counter = 0u64;

  while output.len() < size {
    let mut input = seed.clone();
    input.extend_from_slice(&counter.to_le_bytes());
    let hash = sha256(&input);
    output.extend_from_slice(&hash);
    counter += 1;
  }

  output.truncate(size);
  output
}

/// PBKDF2-HMAC-SHA256 key derivation
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
  let mut result = Vec::with_capacity(key_len);
  let mut block_num = 1u32;

  while result.len() < key_len {
    // U1 = PRF(Password, Salt || INT(i))
    let mut salt_block = salt.to_vec();
    salt_block.extend_from_slice(&block_num.to_be_bytes());

    let mut u = hmac_sha256(password, &salt_block);
    let mut block = u.clone();

    // U2 ... Uc
    for _ in 1..iterations {
      u = hmac_sha256(password, &u);
      for (b, u_byte) in block.iter_mut().zip(u.iter()) {
        *b ^= u_byte;
      }
    }

    result.extend_from_slice(&block);
    block_num += 1;
  }

  result.truncate(key_len);
  result
}
