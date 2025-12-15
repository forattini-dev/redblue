# collection

> Visual reconnaissance and screenshot capture

The `collection` domain provides web screenshot capture and visual reconnaissance. Replaces **aquatone**, **eyewitness**, and **gowitness**.

## Commands

```
rb collection screenshot <verb> <target> [flags]
```

| Verb | Description |
|------|-------------|
| `capture` | Capture screenshot of a web page |
| `batch` | Capture screenshots from a list of URLs |
| `http` | Capture using HTTP fallback (no Chrome required) |

## Usage Examples

### Single Screenshot

```bash
# Capture single screenshot
rb collection screenshot capture https://example.com

# Custom viewport size
rb collection screenshot capture https://example.com --width 1920 --height 1080

# Full page screenshot
rb collection screenshot capture https://example.com --full-page

# Custom output directory
rb collection screenshot capture https://example.com --output ./screenshots
```

### Batch Processing

```bash
# Capture from URL list
rb collection screenshot batch urls.txt

# With multiple threads
rb collection screenshot batch urls.txt --threads 10

# Generate HTML report
rb collection screenshot batch urls.txt --report

# All report formats
rb collection screenshot batch urls.txt --report --json --csv
```

### HTTP Fallback Mode

```bash
# No Chrome required (metadata only)
rb collection screenshot http http://example.com
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output` | Output directory | `./screenshots` |
| `-w, --width` | Viewport width | `1440` |
| `-h, --height` | Viewport height | `900` |
| `-t, --timeout` | Page load timeout (seconds) | `30` |
| `--threads` | Concurrent captures (batch) | `4` |
| `--full-page` | Capture full page | `false` |
| `--quality` | JPEG quality (0-100) | `80` |
| `--report` | Generate HTML report | - |
| `--json` | Generate JSON report | - |
| `--csv` | Generate CSV report | - |
| `--chrome` | Path to Chrome binary | auto-detect |
| `--port` | Chrome debugging port | `9222` |

## Chrome DevTools Protocol

The screenshot capture uses Chrome DevTools Protocol for rendering:

1. **Launches Chrome** in headless mode with remote debugging
2. **Navigates to URL** and waits for page load
3. **Captures screenshot** via CDP `Page.captureScreenshot`
4. **Detects technologies** from page content
5. **Generates reports** with thumbnails

**Requirements:**
- Chrome or Chromium installed
- Port 9222 available (configurable)

## HTTP Fallback Mode

When Chrome is unavailable, HTTP fallback mode captures:
- Page title
- HTTP status code
- Server header
- Response headers
- Technology detection
- Redirect chain

**Note:** No JavaScript rendering or actual screenshot in HTTP mode.

## Output Structure

```
screenshots/
├── example.com.png          # Screenshot
├── example.com.thumb.png    # Thumbnail
├── another-site.com.png
├── report.html              # HTML gallery
├── report.json              # JSON data
└── report.csv               # CSV export
```

## Technology Detection

Automatically detects technologies from:
- HTTP headers (Server, X-Powered-By)
- HTML content (meta generators, frameworks)
- JavaScript libraries
- CMS signatures

**Detected Categories:**
- Web servers (nginx, Apache, IIS)
- Frameworks (React, Vue, Angular)
- CMS (WordPress, Drupal, Joomla)
- Languages (PHP, Python, Node.js)

## Report Generation

### HTML Report

Interactive gallery with:
- Thumbnail grid
- Full-size previews
- Technology tags
- HTTP status badges
- Load time metrics

### JSON Report

```json
{
  "results": [
    {
      "url": "https://example.com",
      "success": true,
      "screenshot_path": "./screenshots/example.com.png",
      "title": "Example Domain",
      "status_code": 200,
      "load_time_ms": 1234,
      "technologies": ["nginx", "PHP"]
    }
  ],
  "total": 10,
  "successful": 9,
  "failed": 1
}
```

### CSV Report

```csv
url,success,status,title,load_time_ms,technologies
https://example.com,true,200,Example Domain,1234,"nginx,PHP"
```

## Tool Equivalents

| Tool | redblue Command |
|------|-----------------|
| `aquatone` | `rb collection screenshot batch --report` |
| `eyewitness` | `rb collection screenshot batch` |
| `gowitness` | `rb collection screenshot capture` |
| `webscreenshot` | `rb collection screenshot batch` |

## Troubleshooting

### Chrome Not Found

```bash
# Specify Chrome path explicitly
rb collection screenshot capture https://example.com --chrome /usr/bin/google-chrome

# Or use HTTP fallback
rb collection screenshot http http://example.com
```

### Port Already in Use

```bash
# Use different debugging port
rb collection screenshot capture https://example.com --port 9223
```

### Sandbox Issues

If Chrome fails with sandbox errors:
```bash
# Run Chrome without sandbox (development only)
CHROME_FLAGS="--no-sandbox" rb collection screenshot capture https://example.com
```

## See Also

- [web asset](/domains/web/01-requests.md) - HTTP requests
- [recon domain](/domains/recon/00-overview.md) - Target reconnaissance
