use std::io::{Read, Write};
use std::time::Duration;

use super::{ProxyResult, TrafficLogger};
use crate::debug;

pub(super) fn websocket_passthrough<S1, S2>(
  client: &mut S1,
  target: &mut S2,
  hostname: &str,
  logger: &TrafficLogger,
) -> ProxyResult<()>
where
  S1: Read + Write,
  S2: Read + Write,
{
  logger.log_info(&format!(
    "[{}] WebSocket: Entering passthrough mode",
    hostname
  ));

  let mut client_buf = [0u8; 65536];
  let mut target_buf = [0u8; 65536];
  let mut frame_count: u64 = 0;

  loop {
    let mut progress = false;

    match client.read(&mut client_buf) {
      Ok(0) => {
        debug!("[{}] WebSocket: Client closed", hostname);
        break;
      }
      Ok(n) => {
        frame_count += 1;
        let frame_type = parse_ws_frame_type(&client_buf[..n]);
        logger.log_ws_frame(hostname, "C->S", frame_count, frame_type, n);
        target.write_all(&client_buf[..n])?;
        progress = true;
      }
      Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
      Err(e) => return Err(e.into()),
    }

    match target.read(&mut target_buf) {
      Ok(0) => {
        debug!("[{}] WebSocket: Target closed", hostname);
        break;
      }
      Ok(n) => {
        frame_count += 1;
        let frame_type = parse_ws_frame_type(&target_buf[..n]);
        logger.log_ws_frame(hostname, "S->C", frame_count, frame_type, n);
        client.write_all(&target_buf[..n])?;
        progress = true;
      }
      Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
      Err(e) => return Err(e.into()),
    }

    if !progress {
      std::thread::sleep(Duration::from_millis(1));
    }
  }

  logger.log_info(&format!(
    "[{}] WebSocket: Connection closed ({} frames)",
    hostname, frame_count
  ));
  Ok(())
}

pub(super) fn parse_ws_frame_type(data: &[u8]) -> &'static str {
  if data.is_empty() {
    return "empty";
  }

  let opcode = data[0] & 0x0F;
  match opcode {
    0x0 => "continuation",
    0x1 => "text",
    0x2 => "binary",
    0x8 => "close",
    0x9 => "ping",
    0xA => "pong",
    _ => "unknown",
  }
}

#[cfg(test)]
mod tests {
  use super::parse_ws_frame_type;

  #[test]
  fn test_parse_ws_frame_type() {
    assert_eq!(parse_ws_frame_type(&[0x81, 0x05]), "text");
    assert_eq!(parse_ws_frame_type(&[0x82, 0x00]), "binary");
    assert_eq!(parse_ws_frame_type(&[0x88, 0x02]), "close");
    assert_eq!(parse_ws_frame_type(&[0x89, 0x00]), "ping");
    assert_eq!(parse_ws_frame_type(&[0x8A, 0x00]), "pong");
    assert_eq!(parse_ws_frame_type(&[0x00, 0x10]), "continuation");
    assert_eq!(parse_ws_frame_type(&[]), "empty");
  }
}
