# nc

> Netcat clone built into redblue

The `nc` domain provides a pure Rust implementation of netcat, the Swiss Army knife of networking.

## Commands

```
rb nc <verb> [args] [flags]
```

| Verb | Description |
|------|-------------|
| `listen` | Start a listener |
| `connect` | Connect to a remote host |

## Usage Examples

### Listen Mode

```bash
# Listen on port 4444
rb nc listen 4444

# Listen with verbose output
rb nc listen 4444 -v

# Listen and execute command on connection
rb nc listen 4444 -e /bin/bash
```

### Connect Mode

```bash
# Connect to remote host
rb nc connect 10.0.0.1 4444

# Connect with timeout
rb nc connect 10.0.0.1 4444 --timeout 10

# Send file
cat file.txt | rb nc connect 10.0.0.1 4444
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-v, --verbose` | Verbose output | false |
| `-e, --exec` | Execute command on connection | - |
| `-t, --timeout` | Connection timeout (seconds) | 30 |
| `-u, --udp` | Use UDP instead of TCP | false |

## Use Cases

### File Transfer

```bash
# Receiver
rb nc listen 4444 > received_file.txt

# Sender
rb nc connect 10.0.0.1 4444 < file.txt
```

### Port Scanning

```bash
# Quick port check
rb nc connect 10.0.0.1 80 -v --timeout 2
```

### Simple Chat

```bash
# Server
rb nc listen 4444

# Client
rb nc connect 10.0.0.1 4444
```

## See Also

- [Netcat Ultimate Guide](/guides/netcat-ultimate.md) - Deep dive into netcat capabilities
- [access shell](/domains/access/01-shell.md) - Session management
