# collection

> Visual reconnaissance and screenshot capture

The `collection` domain provides web screenshot capture and visual reconnaissance using Chrome DevTools Protocol.

## Resources

| Resource | Description |
|----------|-------------|
| `screenshot` | Web page screenshot capture |
| `batch` | Batch screenshot operations |

## Quick Reference

```bash
# Single screenshot
rb collection screenshot capture https://example.com

# Full page capture
rb collection screenshot capture https://example.com --full-page

# Batch from URL list
rb collection screenshot batch urls.txt --report

# HTTP fallback (no Chrome required)
rb collection screenshot http http://example.com
```

## Tools Replaced

| Traditional Tool | redblue Command |
|-----------------|-----------------|
| aquatone | `rb collection screenshot batch --report` |
| eyewitness | `rb collection screenshot batch` |
| gowitness | `rb collection screenshot capture` |
| webscreenshot | `rb collection screenshot batch` |

## Requirements

- **Chrome/Chromium** - For full screenshot functionality
- **Port 9222** - Default debugging port (configurable)

> **Note:** HTTP fallback mode works without Chrome but captures metadata only.

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

## See Also

- [Screenshots](01-screenshots.md) - Single page capture
- [Batch Operations](02-batch.md) - Multiple URL processing
- [web asset](/domains/web/01-requests.md) - HTTP requests
