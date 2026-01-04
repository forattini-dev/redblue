# Batch Operations

> Capture screenshots from multiple URLs with report generation

## Command

```bash
rb collection screenshot batch <file> [flags]
```

## Usage

```bash
# Basic batch capture
rb collection screenshot batch urls.txt

# With multiple threads
rb collection screenshot batch urls.txt --threads 10

# Generate HTML report
rb collection screenshot batch urls.txt --report

# All report formats
rb collection screenshot batch urls.txt --report --json --csv

# Custom output
rb collection screenshot batch urls.txt --output ./batch-screenshots
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output` | Output directory | `./screenshots` |
| `-t, --threads` | Concurrent captures | `4` |
| `--timeout` | Per-page timeout (seconds) | `30` |
| `--report` | Generate HTML report | `false` |
| `--json` | Generate JSON report | `false` |
| `--csv` | Generate CSV report | `false` |
| `--width` | Viewport width | `1440` |
| `--height` | Viewport height | `900` |
| `--full-page` | Capture full page | `false` |

## Input File Format

One URL per line:

```
https://example.com
https://another-site.com
http://internal.corp:8080
https://subdomain.target.com/path
```

## Sample Output

```
Batch Screenshot Capture
  Input: urls.txt
  URLs: 15
  Threads: 4

Processing...
  [1/15] https://example.com - OK (1.2s)
  [2/15] https://another-site.com - OK (0.8s)
  [3/15] http://internal.corp:8080 - FAILED (timeout)
  ...
  [15/15] https://subdomain.target.com - OK (1.5s)

Summary:
  Successful: 14
  Failed: 1
  Total time: 12.3s

Output:
  Screenshots: ./screenshots/
  Report: ./screenshots/report.html
```

## Report Formats

### HTML Report

Interactive gallery with:
- Thumbnail grid
- Full-size previews (click to expand)
- Technology tags
- HTTP status badges
- Load time metrics
- Search/filter functionality

### JSON Report

```json
{
  "generated": "2024-01-15T10:30:00Z",
  "total": 15,
  "successful": 14,
  "failed": 1,
  "results": [
    {
      "url": "https://example.com",
      "success": true,
      "screenshot_path": "./screenshots/example.com.png",
      "thumbnail_path": "./screenshots/example.com.thumb.png",
      "title": "Example Domain",
      "status_code": 200,
      "load_time_ms": 1234,
      "technologies": ["nginx", "PHP"],
      "headers": {
        "server": "nginx/1.18.0",
        "content-type": "text/html; charset=UTF-8"
      }
    },
    {
      "url": "http://internal.corp:8080",
      "success": false,
      "error": "Connection timeout after 30s"
    }
  ]
}
```

### CSV Report

```csv
url,success,status,title,load_time_ms,technologies,error
https://example.com,true,200,Example Domain,1234,"nginx,PHP",
http://internal.corp:8080,false,,,,"Connection timeout"
```

## Pipeline Integration

### From Subdomain Enumeration

```bash
# Enumerate subdomains
rb recon subdomain enum target.com --output json | jq -r '.subdomains[]' > subs.txt

# Prepare URLs
sed 's/^/https:\/\//' subs.txt > urls.txt

# Capture all
rb collection screenshot batch urls.txt --report
```

### From Port Scan

```bash
# Scan for HTTP ports
rb network ports scan 192.168.1.0/24 --preset web --output json | \
  jq -r '.[] | "http://\(.ip):\(.port)"' > urls.txt

# Screenshot all
rb collection screenshot batch urls.txt --report --threads 10
```

### From Crawl Results

```bash
# Crawl and extract URLs
rb web crawl http://example.com --depth 3 --output json | \
  jq -r '.urls[]' > urls.txt

# Screenshot unique pages
rb collection screenshot batch urls.txt --report
```

## Performance Tips

| URLs | Recommended Threads | Notes |
|------|-------------------|-------|
| < 50 | 4 | Default is fine |
| 50-200 | 8-10 | Increase threads |
| 200+ | 10-20 | Consider rate limiting |

```bash
# High-volume batch with rate limiting
rb collection screenshot batch large-list.txt --threads 15 --timeout 20
```

## Error Handling

Common failure reasons:

| Error | Cause | Solution |
|-------|-------|----------|
| Timeout | Slow page load | Increase `--timeout` |
| Connection refused | Port closed | Verify URL accessibility |
| SSL error | Certificate issue | Try HTTP or ignore SSL |
| DNS failure | Domain not resolving | Check DNS |

Failed URLs are logged but don't stop the batch. Check the report for details.

## See Also

- [Screenshots](01-screenshots.md) - Single page capture
- [Overview](00-overview.md) - Collection domain overview
- [recon subdomain](/domains/recon/02-subdomains.md) - Subdomain enumeration
