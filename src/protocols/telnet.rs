/// Telnet Protocol Implementation (RFC 854)
///
/// Implements the Telnet protocol for remote terminal access
/// - IAC (Interpret As Command) sequences
/// - Option negotiation (WILL, WONT, DO, DONT)
/// - Terminal type negotiation
/// - Simple interactive client
///
/// Reference: https://tools.ietf.org/html/rfc854
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Telnet protocol constants
pub mod constants {
    // IAC - Interpret As Command (escape character)
    pub const IAC: u8 = 255;

    // Commands
    pub const WILL: u8 = 251; // I will use option
    pub const WONT: u8 = 252; // I won't use option
    pub const DO: u8 = 253; // Please use option
    pub const DONT: u8 = 254; // Don't use option
    pub const SB: u8 = 250; // Subnegotiation begin
    pub const SE: u8 = 240; // Subnegotiation end

    // Common options
    pub const ECHO: u8 = 1; // Echo option
    pub const SUPPRESS_GO_AHEAD: u8 = 3; // Suppress Go Ahead
    pub const STATUS: u8 = 5; // Status
    pub const TIMING_MARK: u8 = 6; // Timing Mark
    pub const TERMINAL_TYPE: u8 = 24; // Terminal Type
    pub const WINDOW_SIZE: u8 = 31; // Window Size (NAWS)
    pub const TERMINAL_SPEED: u8 = 32; // Terminal Speed
    pub const LINEMODE: u8 = 34; // Line mode
}

use constants::*;

/// Telnet command representation
#[derive(Debug, Clone, PartialEq)]
pub enum TelnetCommand {
    Will(u8),
    Wont(u8),
    Do(u8),
    Dont(u8),
    Subnegotiation { option: u8, data: Vec<u8> },
    Data(Vec<u8>),
}

impl TelnetCommand {
    /// Convert command to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TelnetCommand::Will(opt) => vec![IAC, WILL, *opt],
            TelnetCommand::Wont(opt) => vec![IAC, WONT, *opt],
            TelnetCommand::Do(opt) => vec![IAC, DO, *opt],
            TelnetCommand::Dont(opt) => vec![IAC, DONT, *opt],
            TelnetCommand::Subnegotiation { option, data } => {
                let mut bytes = vec![IAC, SB, *option];
                bytes.extend_from_slice(data);
                bytes.extend_from_slice(&[IAC, SE]);
                bytes
            }
            TelnetCommand::Data(data) => data.clone(),
        }
    }
}

/// Telnet client
pub struct TelnetClient {
    stream: TcpStream,
    timeout: Duration,
}

impl TelnetClient {
    /// Create a new telnet client
    pub fn connect(host: &str, port: u16) -> Result<Self, String> {
        let address = format!("{}:{}", host, port);

        let stream = TcpStream::connect(&address)
            .map_err(|e| format!("Failed to connect to {}: {}", address, e))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        Ok(Self {
            stream,
            timeout: Duration::from_secs(5),
        })
    }

    /// Set read timeout
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<(), String> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;
        self.timeout = timeout;
        Ok(())
    }

    /// Send a telnet command
    pub fn send_command(&mut self, cmd: TelnetCommand) -> Result<(), String> {
        let bytes = cmd.to_bytes();
        self.stream
            .write_all(&bytes)
            .map_err(|e| format!("Failed to send command: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("Failed to flush stream: {}", e))?;
        Ok(())
    }

    /// Send raw data
    pub fn send_data(&mut self, data: &[u8]) -> Result<(), String> {
        self.stream
            .write_all(data)
            .map_err(|e| format!("Failed to send data: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("Failed to flush stream: {}", e))?;
        Ok(())
    }

    /// Receive data with IAC parsing
    pub fn receive(&mut self) -> Result<Vec<TelnetCommand>, String> {
        let mut buffer = vec![0u8; 4096];
        let n = self
            .stream
            .read(&mut buffer)
            .map_err(|e| format!("Failed to read: {}", e))?;

        buffer.truncate(n);
        Ok(parse_telnet_data(&buffer))
    }

    /// Perform initial negotiation
    pub fn negotiate(&mut self) -> Result<(), String> {
        // Send WILL TERMINAL_TYPE
        self.send_command(TelnetCommand::Will(TERMINAL_TYPE))?;

        // Send WILL WINDOW_SIZE
        self.send_command(TelnetCommand::Will(WINDOW_SIZE))?;

        // Send DONT ECHO (we don't want server to echo)
        self.send_command(TelnetCommand::Dont(ECHO))?;

        // Send WILL SUPPRESS_GO_AHEAD
        self.send_command(TelnetCommand::Will(SUPPRESS_GO_AHEAD))?;

        Ok(())
    }

    /// Respond to server negotiations automatically
    pub fn auto_respond(&mut self, cmd: &TelnetCommand) -> Result<(), String> {
        match cmd {
            TelnetCommand::Do(opt) => {
                // Server asks us to enable option
                match *opt {
                    constants::TERMINAL_TYPE
                    | constants::WINDOW_SIZE
                    | constants::SUPPRESS_GO_AHEAD => {
                        // Accept these options
                        self.send_command(TelnetCommand::Will(*opt))?;
                    }
                    _ => {
                        // Refuse other options
                        self.send_command(TelnetCommand::Wont(*opt))?;
                    }
                }
            }
            TelnetCommand::Dont(opt) => {
                // Server asks us not to use option
                self.send_command(TelnetCommand::Wont(*opt))?;
            }
            TelnetCommand::Will(opt) => {
                // Server will use option
                match *opt {
                    constants::ECHO | constants::SUPPRESS_GO_AHEAD => {
                        // Accept these
                        self.send_command(TelnetCommand::Do(*opt))?;
                    }
                    _ => {
                        // Refuse others
                        self.send_command(TelnetCommand::Dont(*opt))?;
                    }
                }
            }
            TelnetCommand::Wont(opt) => {
                // Server won't use option
                self.send_command(TelnetCommand::Dont(*opt))?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Parse telnet data into commands and data
pub fn parse_telnet_data(data: &[u8]) -> Vec<TelnetCommand> {
    let mut commands = Vec::new();
    let mut i = 0;
    let mut current_data = Vec::new();

    while i < data.len() {
        if data[i] == IAC && i + 1 < data.len() {
            // Check for escaped IAC first (IAC IAC = literal 255)
            // Don't save pending data for escaped IAC since it's just data
            if data[i + 1] == IAC {
                current_data.push(IAC);
                i += 2;
                continue;
            }

            // Save any pending data before processing actual commands
            if !current_data.is_empty() {
                commands.push(TelnetCommand::Data(current_data.clone()));
                current_data.clear();
            }

            match data[i + 1] {
                WILL if i + 2 < data.len() => {
                    commands.push(TelnetCommand::Will(data[i + 2]));
                    i += 3;
                }
                WONT if i + 2 < data.len() => {
                    commands.push(TelnetCommand::Wont(data[i + 2]));
                    i += 3;
                }
                DO if i + 2 < data.len() => {
                    commands.push(TelnetCommand::Do(data[i + 2]));
                    i += 3;
                }
                DONT if i + 2 < data.len() => {
                    commands.push(TelnetCommand::Dont(data[i + 2]));
                    i += 3;
                }
                SB => {
                    // Subnegotiation
                    if i + 2 < data.len() {
                        let option = data[i + 2];
                        let mut j = i + 3;
                        let mut sub_data = Vec::new();

                        // Find IAC SE
                        while j + 1 < data.len() {
                            if data[j] == IAC && data[j + 1] == SE {
                                commands.push(TelnetCommand::Subnegotiation {
                                    option,
                                    data: sub_data,
                                });
                                i = j + 2;
                                break;
                            }
                            sub_data.push(data[j]);
                            j += 1;
                        }

                        if j + 1 >= data.len() {
                            // Incomplete subnegotiation
                            i = data.len();
                        }
                    } else {
                        i += 2;
                    }
                }
                // IAC IAC case is handled above before the match
                _ => {
                    // Unknown command, skip
                    i += 2;
                }
            }
        } else {
            // Regular data
            current_data.push(data[i]);
            i += 1;
        }
    }

    // Save any remaining data
    if !current_data.is_empty() {
        commands.push(TelnetCommand::Data(current_data));
    }

    commands
}

/// Get option name for debugging
pub fn option_name(opt: u8) -> &'static str {
    match opt {
        ECHO => "ECHO",
        SUPPRESS_GO_AHEAD => "SUPPRESS_GO_AHEAD",
        STATUS => "STATUS",
        TIMING_MARK => "TIMING_MARK",
        TERMINAL_TYPE => "TERMINAL_TYPE",
        WINDOW_SIZE => "WINDOW_SIZE",
        TERMINAL_SPEED => "TERMINAL_SPEED",
        LINEMODE => "LINEMODE",
        _ => "UNKNOWN",
    }
}

/// Get command name for debugging
pub fn command_name(cmd: u8) -> &'static str {
    match cmd {
        WILL => "WILL",
        WONT => "WONT",
        DO => "DO",
        DONT => "DONT",
        SB => "SB",
        SE => "SE",
        IAC => "IAC",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_data() {
        let data = b"Hello, World!";
        let cmds = parse_telnet_data(data);

        assert_eq!(cmds.len(), 1);
        match &cmds[0] {
            TelnetCommand::Data(d) => assert_eq!(d, data),
            _ => panic!("Expected data command"),
        }
    }

    #[test]
    fn test_parse_will_command() {
        let data = vec![IAC, WILL, ECHO];
        let cmds = parse_telnet_data(&data);

        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0], TelnetCommand::Will(ECHO));
    }

    #[test]
    fn test_parse_mixed_data() {
        let mut data = Vec::new();
        data.extend_from_slice(b"Login: ");
        data.extend_from_slice(&[IAC, WILL, ECHO]);
        data.extend_from_slice(b"\r\n");

        let cmds = parse_telnet_data(&data);

        assert_eq!(cmds.len(), 3);
        match &cmds[0] {
            TelnetCommand::Data(d) => assert_eq!(d, b"Login: "),
            _ => panic!("Expected data"),
        }
        assert_eq!(cmds[1], TelnetCommand::Will(ECHO));
        match &cmds[2] {
            TelnetCommand::Data(d) => assert_eq!(d, b"\r\n"),
            _ => panic!("Expected data"),
        }
    }

    #[test]
    fn test_escaped_iac() {
        let data = vec![b'A', IAC, IAC, b'B'];
        let cmds = parse_telnet_data(&data);

        assert_eq!(cmds.len(), 1);
        match &cmds[0] {
            TelnetCommand::Data(d) => assert_eq!(d, &vec![b'A', IAC, b'B']),
            _ => panic!("Expected data"),
        }
    }
}
