pub mod acl; // NEW: Access Control List (IP allow/deny)
pub mod banner; // NEW: Service banner grabbing
pub mod broker; // NEW: Multi-client chat server (ncat --broker)
pub mod discovery;
pub mod extras; // NEW: Rate limiting, logging, file transfer optimization
pub mod fingerprint;
pub mod health; // Port health monitoring (check, diff, watch)
pub mod netcat;
pub mod ping;
pub mod proxy; // NEW: Proxy support (SOCKS4/5, HTTP CONNECT)
pub mod pty; // NEW: PTY/TTY support (requires libc for syscalls)
pub mod relay; // NEW: Port forwarding / relay (socat-style)
pub mod scanner;
pub mod tls; // NEW: TLS/SSL encryption (from scratch)
pub mod traceroute;
pub mod twofish; // NEW: Twofish encryption (cryptcat compatibility)
#[path = "unix-socket.rs"]
pub mod unix_socket; // NEW: Unix domain sockets
