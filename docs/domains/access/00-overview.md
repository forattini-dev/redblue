# access

> Remote shell session management

The `access` domain is the central hub for managing remote connections, specifically focusing on the lifecycle of reverse shells. While the `exploit` domain handles payload generation, the `access` domain is where you **catch**, **manage**, and **interact** with those shells.

## Resources

| Resource | Description |
|----------|-------------|
| **shell** | Manage remote shell sessions and listeners |

## Quick Examples

```bash
# Start a TCP listener on port 4444
rb access shell create 4444 --protocol tcp

# Start an HTTP listener (for http-shell payloads)
rb access shell listen 8080 --protocol http

# List active sessions
rb access shell sessions

# Connect to a session
rb access shell connect 1

# Kill a session
rb access shell kill 2
```

## Key Features

- **Unified Session Management**: Handle TCP and HTTP shells in one place
- **Listener Orchestration**: Start and stop listeners for various protocols
- **Interactive Shells**: Drop into a TUI-based interactive session
- **Background Management**: List, kill, and monitor background sessions

## See Also

- [shell resource](./01-shell.md) - Session and listener management
- [exploit domain](/domains/exploit/00-overview.md) - Payload generation
