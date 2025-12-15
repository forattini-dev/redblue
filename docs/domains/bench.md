# bench

> HTTP load testing and performance benchmarking

The `bench` domain provides comprehensive HTTP load testing capabilities. Replaces **wrk**, **k6**, and **ab**.

## Commands

```
rb bench load <verb> <url> [flags]
```

| Verb | Description |
|------|-------------|
| `run` | Run load test against target URL |
| `stress` | Stress test with maximum load (no think time) |

## Usage Examples

### Basic Load Test

```bash
# Default: 100 users, 60s duration, realistic mode
rb bench load run https://example.com

# With live dashboard (graphs)
rb bench load run https://example.com --live

# Custom users and duration
rb bench load run https://api.example.com --users 500 --duration 120
```

### Testing Modes

```bash
# Maximum throughput (connection reuse, no think time)
rb bench load run https://example.com --mode throughput --users 500

# Connection stress test (many concurrent connections)
rb bench load run https://example.com --mode connections --users 1000

# Realistic simulation (variable think time, session rotation)
rb bench load run https://example.com --mode realistic --users 200

# Maximum stress (5000 concurrent users)
rb bench load run https://example.com --mode stress --users 5000
```

### Stress Testing

```bash
# Aggressive load with no delays
rb bench load stress https://example.com --users 1000
```

### POST Requests with Body

```bash
# Inline body
rb bench load run https://api.example.com/login \
  --method POST \
  --body '{"username":"test","password":"test"}'

# Body from file
rb bench load run https://api.example.com/data \
  --method POST \
  --body-file payload.json
```

### Advanced Options

```bash
# Rate limiting
rb bench load run https://example.com --rate-limit 1000

# Warmup requests
rb bench load run https://example.com --warmup 100

# Custom protocol preference
rb bench load run https://example.com --protocol http2
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --users` | Concurrent users | `100` |
| `-d, --duration` | Test duration in seconds | `60` |
| `-r, --requests` | Total requests per user | - |
| `-t, --think-time` | Delay between requests (ms) | `100` |
| `--timeout` | Request timeout (seconds) | `30` |
| `--protocol` | HTTP protocol: `auto`, `http1`, `http2` | `auto` |
| `--method` | HTTP method | `GET` |
| `--body` | Inline request body | - |
| `--body-file` | File containing request body | - |
| `-k, --keep-alive` | Use connection pooling | `true` |
| `--max-idle` | Max idle connections per host | `50` |
| `-m, --mode` | Testing mode | `realistic` |
| `--new-user-ratio` | New user ratio (0.0-1.0) | `0.3` |
| `--session-length` | Requests per session | - |
| `--think-variance` | Think time variance | `0.0` |
| `--ramp-up` | Gradual ramp-up (seconds) | - |
| `--warmup` | Warmup requests to skip | `0` |
| `--rate-limit` | Target RPS limit | `0` |
| `--shared-http2-pool` | Share HTTP/2 connections | `true` |
| `--http2-connections` | Max HTTP/2 connections | `6` |
| `-l, --live` | Show real-time dashboard | `true` |
| `--no-live` | Disable live dashboard | - |

## Testing Modes

| Mode | Description |
|------|-------------|
| `throughput` | Maximum RPS with connection reuse |
| `connections` | Test concurrent connection handling |
| `realistic` | Simulate real user behavior |
| `stress` | Maximum load, no think time |

## Live Dashboard

The live dashboard shows real-time metrics:
- **RPS** - Requests per second with graph
- **Latency** - p95 latency with graph
- **CPU/RAM** - System resource usage
- **Status codes** - 2xx, 3xx, 4xx, 5xx breakdown

## Output Metrics

```
LOAD TEST RESULTS

Total Requests: 15234
Successful: 15089 (99.1%)
Failed: 145
Test Duration: 60.23s
Requests/sec: 253.12
Protocol: HTTP/2
Method: GET

Latency Distribution
  p50 (median): 45.32ms
  p95: 128.41ms
  p99: 245.67ms
  min: 12.45ms
  max: 892.34ms
  avg: 67.89ms

TTFB Distribution
  p50 (median): 23.45ms
  p95: 89.12ms
  p99: 156.78ms

Throughput
  Total Data: 45.67 MB
  Throughput: 6.07 Mbps
```

## Tool Equivalents

| Tool | redblue Command |
|------|-----------------|
| `wrk` | `rb bench load run` |
| `k6` | `rb bench load run --mode realistic` |
| `ab` | `rb bench load run --mode throughput` |
| `hey` | `rb bench load stress` |

## See Also

- [network ports](/domains/network/01-ports.md) - Port scanning
- [web asset](/domains/web/01-requests.md) - HTTP requests
