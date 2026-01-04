# Screenshots

> Capture web page screenshots using Chrome DevTools Protocol

## Commands

```bash
# Capture screenshot
rb collection screenshot capture <url> [flags]

# HTTP fallback (metadata only)
rb collection screenshot http <url> [flags]
```

## Usage

```bash
# Basic capture
rb collection screenshot capture https://example.com

# Custom viewport
rb collection screenshot capture https://example.com --width 1920 --height 1080

# Full page (scroll capture)
rb collection screenshot capture https://example.com --full-page

# Custom output directory
rb collection screenshot capture https://example.com --output ./screenshots

# High quality
rb collection screenshot capture https://example.com --quality 95

# Custom Chrome path
rb collection screenshot capture https://example.com --chrome /usr/bin/chromium
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output` | Output directory | `./screenshots` |
| `-w, --width` | Viewport width | `1440` |
| `-h, --height` | Viewport height | `900` |
| `-t, --timeout` | Page load timeout (seconds) | `30` |
| `--full-page` | Capture full scrollable page | `false` |
| `--quality` | JPEG quality (0-100) | `80` |
| `--chrome` | Path to Chrome binary | auto-detect |
| `--port` | Chrome debugging port | `9222` |

## Chrome DevTools Protocol

The capture process:

1. **Launch Chrome** - Headless mode with remote debugging
2. **Navigate** - Load target URL
3. **Wait** - Page load + network idle
4. **Capture** - CDP `Page.captureScreenshot`
5. **Detect** - Technology fingerprinting
6. **Save** - PNG with optional thumbnail

## Technology Detection

Automatically detects technologies from:

| Source | Detection |
|--------|-----------|
| HTTP Headers | `Server`, `X-Powered-By` |
| HTML Content | Meta generators, framework signatures |
| JavaScript | Library detection |
| Cookies | CMS patterns |

**Categories:**
- Web servers (nginx, Apache, IIS)
- Frameworks (React, Vue, Angular)
- CMS (WordPress, Drupal, Joomla)
- Languages (PHP, Python, Node.js)

## HTTP Fallback Mode

When Chrome is unavailable:

```bash
rb collection screenshot http http://example.com
```

Captures:
- Page title
- HTTP status code
- Response headers
- Technology detection
- Redirect chain

> **Note:** No JavaScript rendering or actual screenshot in HTTP mode.

## Sample Output

```
Screenshot Capture
  URL: https://example.com
  Size: 1440x900

Capturing...
  Page loaded in 1.23s
  Technologies: nginx, React, Cloudflare

Saved:
  Screenshot: ./screenshots/example.com.png
  Thumbnail: ./screenshots/example.com.thumb.png

Metadata:
  Title: Example Domain
  Status: 200
  Load time: 1234ms
```

## Troubleshooting

### Chrome Not Found

```bash
# Specify Chrome path
rb collection screenshot capture https://example.com --chrome /usr/bin/google-chrome

# Common Chrome paths:
# Linux: /usr/bin/google-chrome, /usr/bin/chromium
# macOS: /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
# Windows: C:\Program Files\Google\Chrome\Application\chrome.exe
```

### Port Already in Use

```bash
# Use different port
rb collection screenshot capture https://example.com --port 9223
```

### Sandbox Issues (Linux)

```bash
# Development only - not recommended for production
CHROME_FLAGS="--no-sandbox" rb collection screenshot capture https://example.com
```

### Timeout Issues

```bash
# Increase timeout for slow pages
rb collection screenshot capture https://example.com --timeout 60
```

## See Also

- [Batch Operations](02-batch.md) - Multiple URL capture
- [Overview](00-overview.md) - Collection domain overview
