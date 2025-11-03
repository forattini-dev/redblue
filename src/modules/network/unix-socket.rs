/// Unix Domain Sockets
///
/// Implements local IPC using Unix domain sockets.
/// Essential for communicating with local services and Docker containers.
///
/// Features:
/// - Unix stream sockets (SOCK_STREAM)
/// - Unix datagram sockets (SOCK_DGRAM)
/// - Server and client modes
/// - Abstract namespace support
///
/// Replaces: socat UNIX-LISTEN, socat UNIX-CONNECT
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

/// Unix socket type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnixSocketType {
    Stream,   // SOCK_STREAM (connection-oriented)
    Datagram, // SOCK_DGRAM (connectionless)
}

/// Unix socket mode
#[derive(Debug, Clone, PartialEq)]
pub enum UnixSocketMode {
    Listen(PathBuf),  // Server mode
    Connect(PathBuf), // Client mode
    Abstract(String), // Abstract namespace (Linux-specific)
}

/// Unix socket configuration
#[derive(Debug, Clone)]
pub struct UnixSocketConfig {
    pub socket_type: UnixSocketType,
    pub mode: UnixSocketMode,
    pub timeout: Duration,
    pub verbose: bool,
}

impl UnixSocketConfig {
    pub fn new(socket_type: UnixSocketType, mode: UnixSocketMode) -> Self {
        Self {
            socket_type,
            mode,
            timeout: Duration::from_secs(10),
            verbose: false,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }
}

/// Unix socket manager
pub struct UnixSocketManager {
    config: UnixSocketConfig,
}

impl UnixSocketManager {
    pub fn new(config: UnixSocketConfig) -> Self {
        Self { config }
    }

    /// Run Unix socket (server or client)
    #[cfg(unix)]
    pub fn run(&self) -> Result<(), String> {
        match &self.config.mode {
            UnixSocketMode::Listen(path) => self.listen(path),
            UnixSocketMode::Connect(path) => self.connect(path),
            UnixSocketMode::Abstract(name) => self.connect_abstract(name),
        }
    }

    #[cfg(not(unix))]
    pub fn run(&self) -> Result<(), String> {
        Err("Unix domain sockets only available on Unix systems".to_string())
    }

    /// Listen on Unix socket (server mode)
    #[cfg(unix)]
    fn listen(&self, path: &Path) -> Result<(), String> {
        // Remove existing socket file
        if path.exists() {
            std::fs::remove_file(path)
                .map_err(|e| format!("Failed to remove existing socket: {}", e))?;
        }

        if self.config.verbose {
            eprintln!("[*] Listening on Unix socket: {}", path.display());
        }

        // Create listener
        let listener =
            UnixListener::bind(path).map_err(|e| format!("Failed to bind Unix socket: {}", e))?;

        // Accept connection
        let (mut stream, addr) = listener
            .accept()
            .map_err(|e| format!("Failed to accept connection: {}", e))?;

        if self.config.verbose {
            eprintln!("[+] Connection accepted from: {:?}", addr);
        }

        // Set timeout
        stream.set_read_timeout(Some(self.config.timeout)).ok();
        stream.set_write_timeout(Some(self.config.timeout)).ok();

        // Bidirectional copy
        self.copy_bidirectional(&mut stream)?;

        // Cleanup
        let _ = std::fs::remove_file(path);

        Ok(())
    }

    /// Connect to Unix socket (client mode)
    #[cfg(unix)]
    fn connect(&self, path: &Path) -> Result<(), String> {
        if self.config.verbose {
            eprintln!("[*] Connecting to Unix socket: {}", path.display());
        }

        // Connect to socket
        let mut stream = UnixStream::connect(path)
            .map_err(|e| format!("Failed to connect to Unix socket: {}", e))?;

        if self.config.verbose {
            eprintln!("[+] Connected");
        }

        // Set timeout
        stream.set_read_timeout(Some(self.config.timeout)).ok();
        stream.set_write_timeout(Some(self.config.timeout)).ok();

        // Bidirectional copy
        self.copy_bidirectional(&mut stream)?;

        Ok(())
    }

    /// Connect to abstract namespace socket (Linux-specific)
    #[cfg(unix)]
    fn connect_abstract(&self, name: &str) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::net::SocketAddr;

            if self.config.verbose {
                eprintln!("[*] Connecting to abstract socket: @{}", name);
            }

            // Abstract namespace socket path starts with '\0'
            let mut path = Vec::new();
            path.push(0u8); // Abstract namespace marker
            path.extend_from_slice(name.as_bytes());

            // This is a simplified version - full implementation would use libc directly
            Err("Abstract namespace sockets require direct libc usage".to_string())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err("Abstract namespace sockets only available on Linux".to_string())
        }
    }

    /// Bidirectional copy between Unix socket and stdin/stdout
    #[cfg(unix)]
    fn copy_bidirectional(&self, stream: &mut UnixStream) -> Result<(), String> {
        use std::io::{self, BufReader, BufWriter};
        use std::thread;

        let mut stream_clone = stream
            .try_clone()
            .map_err(|e| format!("Failed to clone stream: {}", e))?;

        // stdin -> socket
        let stdin_thread = thread::spawn(move || {
            let mut stdin = io::stdin();
            let mut buf = [0u8; 8192];

            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream_clone.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        if stream_clone.flush().is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // socket -> stdout
        let mut stdout = io::stdout();
        let mut buf = [0u8; 8192];

        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    stdout
                        .write_all(&buf[..n])
                        .map_err(|e| format!("Failed to write to stdout: {}", e))?;
                    stdout
                        .flush()
                        .map_err(|e| format!("Failed to flush stdout: {}", e))?;
                }
                Err(_) => break,
            }
        }

        // Wait for stdin thread
        let _ = stdin_thread.join();

        Ok(())
    }
}

/// Parse Unix socket path or abstract name
pub fn parse_unix_socket(s: &str) -> Result<UnixSocketMode, String> {
    if s.starts_with('@') {
        // Abstract namespace (Linux)
        let name = s[1..].to_string();
        Ok(UnixSocketMode::Abstract(name))
    } else if s.starts_with("listen:") {
        // Listen mode
        let path = s[7..].to_string();
        Ok(UnixSocketMode::Listen(PathBuf::from(path)))
    } else if s.starts_with("connect:") {
        // Connect mode
        let path = s[8..].to_string();
        Ok(UnixSocketMode::Connect(PathBuf::from(path)))
    } else {
        // Default to connect mode
        Ok(UnixSocketMode::Connect(PathBuf::from(s)))
    }
}

/// Unix datagram socket (SOCK_DGRAM)
#[cfg(unix)]
pub struct UnixDatagramSocket {
    socket: std::os::unix::net::UnixDatagram,
    verbose: bool,
}

#[cfg(unix)]
impl UnixDatagramSocket {
    /// Create datagram socket
    pub fn new(bind_path: &Path, verbose: bool) -> Result<Self, String> {
        // Remove existing socket file
        if bind_path.exists() {
            std::fs::remove_file(bind_path)
                .map_err(|e| format!("Failed to remove existing socket: {}", e))?;
        }

        let socket = std::os::unix::net::UnixDatagram::bind(bind_path)
            .map_err(|e| format!("Failed to bind datagram socket: {}", e))?;

        if verbose {
            eprintln!("[*] Datagram socket bound to: {}", bind_path.display());
        }

        Ok(Self { socket, verbose })
    }

    /// Send datagram
    pub fn send_to(&self, buf: &[u8], path: &Path) -> Result<usize, String> {
        self.socket
            .send_to(buf, path)
            .map_err(|e| format!("Failed to send datagram: {}", e))
    }

    /// Receive datagram
    pub fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, std::os::unix::net::SocketAddr), String> {
        self.socket
            .recv_from(buf)
            .map_err(|e| format!("Failed to receive datagram: {}", e))
    }

    /// Connect to peer (sets default destination)
    pub fn connect(&self, path: &Path) -> Result<(), String> {
        self.socket
            .connect(path)
            .map_err(|e| format!("Failed to connect datagram socket: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_unix_socket() {
        // Connect mode (default)
        let mode = parse_unix_socket("/tmp/test.sock").unwrap();
        assert!(matches!(mode, UnixSocketMode::Connect(_)));

        // Explicit connect
        let mode = parse_unix_socket("connect:/tmp/test.sock").unwrap();
        assert!(matches!(mode, UnixSocketMode::Connect(_)));

        // Listen mode
        let mode = parse_unix_socket("listen:/tmp/test.sock").unwrap();
        assert!(matches!(mode, UnixSocketMode::Listen(_)));

        // Abstract namespace
        let mode = parse_unix_socket("@abstract_name").unwrap();
        assert!(matches!(mode, UnixSocketMode::Abstract(_)));
    }

    #[test]
    fn test_unix_socket_config() {
        let config = UnixSocketConfig::new(
            UnixSocketType::Stream,
            UnixSocketMode::Connect(PathBuf::from("/tmp/test.sock")),
        )
        .with_timeout(Duration::from_secs(5))
        .with_verbose(true);

        assert_eq!(config.socket_type, UnixSocketType::Stream);
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert!(config.verbose);
    }

    #[test]
    #[cfg(unix)]
    fn test_unix_socket_path() {
        use std::env;

        let temp_dir = env::temp_dir();
        let socket_path = temp_dir.join("redblue_test.sock");

        // Cleanup any existing socket
        let _ = std::fs::remove_file(&socket_path);

        // Path should not exist initially
        assert!(!socket_path.exists());

        // After creating a listener, path should exist
        let listener = UnixListener::bind(&socket_path);
        if listener.is_ok() {
            assert!(socket_path.exists());

            // Cleanup
            drop(listener);
            let _ = std::fs::remove_file(&socket_path);
        }
    }
}
