# HTTP Requests

Make HTTP requests and analyze responses - GET, POST, headers.

## Quick Start

```bash
# Simple GET
rb web get asset http://example.com

# Get headers only
rb web headers asset http://example.com

# POST with data
rb web post asset http://api.example.com --data '{"key":"value"}'
```

## Commands

### get - HTTP GET Request

Retrieve a resource from a URL.

```bash
rb web get asset <url> [flags]
```

### post - HTTP POST Request

Submit data to a URL.

```bash
rb web post asset <url> [flags]
```

### headers - HTTP Headers Only

Retrieve only HTTP headers (HEAD request).

```bash
rb web headers asset <url> [flags]
```

## Options

```rust
// HTTP request options
struct HttpRequestOptions {
    // Request timeout in seconds
    // Range: 1-300
    // Default: 10
    timeout_secs: u32,

    // Custom User-Agent string
    // Default: "redblue/1.0"
    user_agent: String,

    // Follow HTTP redirects
    // Default: true
    follow_redirects: bool,

    // Maximum redirects to follow
    // Range: 0-20
    // Default: 5
    max_redirects: u32,

    // Custom headers (key:value format)
    // Default: []
    headers: Vec<String>,

    // Request body for POST
    // Default: ""
    data: String,

    // Content-Type header
    // Default: "application/json"
    content_type: String,

    // Output format
    // Values: "text", "json", "raw"
    // Default: "text"
    output: String,

    // Show response headers
    // Default: false
    show_headers: bool,
}
```

## Flag Reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--timeout` | `-t` | Request timeout (secs) | 10 |
| `--user-agent` | `-A` | Custom User-Agent | redblue/1.0 |
| `--follow` | `-L` | Follow redirects | true |
| `--max-redirects` | | Max redirect count | 5 |
| `--header` | `-H` | Custom header (repeatable) | - |
| `--data` | `-d` | POST body data | - |
| `--content-type` | | Content-Type header | application/json |
| `--output` | `-o` | Output format | text |
| `--show-headers` | `-i` | Show response headers | false |

## Examples

### Basic GET Requests

```bash
# Simple GET
rb web get asset http://example.com

# With headers in output
rb web get asset http://example.com --show-headers

# JSON output
rb web get asset http://api.example.com -o json
```

### Custom Headers

```bash
# Authorization header
rb web get asset http://api.example.com \
  -H "Authorization: Bearer token123"

# Multiple headers
rb web get asset http://api.example.com \
  -H "Authorization: Bearer token123" \
  -H "X-Custom-Header: value"

# Custom User-Agent
rb web get asset http://example.com \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

### POST Requests

```bash
# POST JSON data
rb web post asset http://api.example.com/users \
  -d '{"name":"John","email":"john@example.com"}'

# POST form data
rb web post asset http://example.com/login \
  --content-type "application/x-www-form-urlencoded" \
  -d "username=admin&password=secret"
```

### Redirect Handling

```bash
# Follow redirects (default)
rb web get asset http://example.com -L

# Don't follow redirects
rb web get asset http://example.com --follow=false

# Limit redirect count
rb web get asset http://example.com --max-redirects 3
```

### Headers Only

```bash
# Get headers only (fast)
rb web headers asset http://example.com

# Headers with JSON output
rb web headers asset http://example.com -o json
```

## Output Examples

### Text Output

```
HTTP GET: http://example.com

Status: 200 OK
Time: 234ms

Response:
<!DOCTYPE html>
<html>
<head>
    <title>Example Domain</title>
...
```

### With Headers

```
HTTP GET: http://example.com

Status: 200 OK
Time: 234ms

Response Headers:
  Content-Type: text/html; charset=UTF-8
  Content-Length: 1256
  Server: ECS (dcb/7F84)
  Cache-Control: max-age=604800
  Date: Sun, 07 Dec 2024 12:00:00 GMT

Response Body:
<!DOCTYPE html>
...
```

### JSON Output

```json
{
  "url": "http://example.com",
  "method": "GET",
  "status": 200,
  "status_text": "OK",
  "time_ms": 234,
  "headers": {
    "content-type": "text/html; charset=UTF-8",
    "content-length": "1256",
    "server": "ECS (dcb/7F84)"
  },
  "body": "<!DOCTYPE html>..."
}
```

### Headers Only Output

```
HTTP HEAD: http://example.com

Status: 200 OK
Time: 89ms

Headers:
  Content-Type: text/html; charset=UTF-8
  Content-Length: 1256
  Server: ECS (dcb/7F84)
  Cache-Control: max-age=604800
  X-Cache: HIT
  Age: 456789
```

## Patterns

### API Testing

```bash
# GET endpoint
rb web get asset http://api.example.com/users

# POST new resource
rb web post asset http://api.example.com/users \
  -d '{"name":"John"}' \
  -H "Authorization: Bearer $TOKEN"

# Check response
rb web get asset http://api.example.com/users/123 \
  -H "Authorization: Bearer $TOKEN" \
  -o json | jq '.name'
```

### Authentication Testing

```bash
# Test login endpoint
rb web post asset http://example.com/login \
  --content-type "application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" \
  --show-headers

# Check for session cookie
rb web post asset http://example.com/login \
  -d "username=admin&password=admin" \
  -o json | jq '.headers["set-cookie"]'
```

### Redirect Analysis

```bash
# See redirect chain
rb web get asset http://example.com \
  --max-redirects 10 \
  --show-headers

# Check final URL
rb web get asset http://short.url/abc \
  -o json | jq '.final_url'
```

## Technical Notes

- **Protocol:** HTTP/1.1 implemented from scratch
- **TLS:** Uses system OpenSSL (native TLS planned)
- **Redirects:** 301, 302, 303, 307, 308 supported
- **Encoding:** UTF-8, gzip decompression planned

## Next Steps

- [Security Audit](/domains/web/02-security.md) - Analyze security headers
- [CMS Scanning](/domains/web/03-cms.md) - Detect and scan CMS
- [Configuration](/domains/web/04-configuration.md) - HTTP settings
