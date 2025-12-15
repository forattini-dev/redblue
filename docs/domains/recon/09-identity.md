# Identity OSINT (rb recon identity)

Person/identity reconnaissance - username enumeration, email intelligence, and breach checking.

## Overview

The `identity` resource focuses on OSINT for **people and accounts** (vs. `domain` which focuses on infrastructure):

| Resource | Target | Examples |
|----------|--------|----------|
| `rb recon domain` | Infrastructure | Domains, IPs, ASNs, subdomains |
| `rb recon identity` | People | Usernames, emails, accounts |

## Commands

### Username Search

Search for a username across 1000+ platforms (Sherlock/Maigret-style):

```bash
# Full search across all platforms
rb recon identity username johndoe

# Filter by category
rb recon identity username johndoe --category social
rb recon identity username johndoe --category coding
rb recon identity username johndoe --category gaming

# Limit number of sites checked
rb recon identity username johndoe --max-sites 100

# Check specific platforms only
rb recon identity username johndoe --platforms github,twitter,linkedin
```

**Categories Available:**
- `social` - Social media (Twitter, Instagram, Facebook, etc.)
- `coding` / `development` - Developer platforms (GitHub, GitLab, StackOverflow)
- `gaming` - Gaming platforms (Steam, Xbox, PlayStation, Discord)
- `business` / `professional` - Professional networks (LinkedIn, AngelList)
- `creative` / `art` - Creative platforms (DeviantArt, Behance, Dribbble)
- `photography` - Photo sharing (Flickr, 500px)
- `video` - Video platforms (YouTube, Vimeo, TikTok)
- `music` - Music platforms (Spotify, SoundCloud, Bandcamp)
- `forum` - Forums and communities (Reddit, HackerNews)
- `dating` - Dating sites
- `finance` - Financial platforms
- `crypto` - Cryptocurrency platforms

### Email Intelligence

Investigate an email address (Holehe-style):

```bash
rb recon identity email user@example.com
```

**What it discovers:**
- Email provider detection
- Services where the email is registered
- Associated social profiles
- Data breaches involving the email

### Breach Checking (HIBP)

Check if passwords or emails appear in data breaches:

```bash
# Check password (uses k-Anonymity - password never sent over network)
rb recon identity breach password123

# Check email (requires HIBP API key)
rb recon identity breach user@example.com --type email --hibp-key YOUR_KEY
```

> The password check uses k-Anonymity: only the first 5 characters of the SHA-1 hash are sent to HIBP, ensuring your full password is never transmitted.

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--category` | `-c` | all | Filter platforms by category |
| `--platforms` | `-p` | - | Check specific platforms (comma-separated) |
| `--threads` | - | 50 | Concurrent threads |
| `--timeout` | - | 10000 | Request timeout in ms |
| `--max-sites` | - | 0 (unlimited) | Max platforms to check |
| `--type` | `-t` | password | Breach check type: `email` or `password` |
| `--hibp-key` | - | - | HIBP API key (required for email breach checks) |

## Output Examples

### Username Search

```
▸ Username Search: johndoe

  Category Filter : social
  Platforms       : 156
  Threads         : 50

Searching johndoe across 156 platforms ✓

  Username           : johndoe
  Platforms Checked  : 156
  Profiles Found     : 12
  Errors             : 3
  Duration           : 8.42s

─── Social (8) ───
  ✓ Twitter - https://twitter.com/johndoe
  ✓ Instagram - https://instagram.com/johndoe
  ✓ Facebook - https://facebook.com/johndoe
  ...

✓ Found 12 profiles in 8.42s
```

### Breach Check

```
▸ Breach Check (HIBP)
  Target      : pass****
  Type        : password

Checking breach databases ✓
⚠ PWNED! Password found 2031380 times in breaches
```

## Use Cases

### Reconnaissance on a Target Username

```bash
# Quick social media check
rb recon identity username target_user --category social --max-sites 50

# Full enumeration
rb recon identity username target_user
```

### Verify Credential Exposure

```bash
# Check if your password is compromised
rb recon identity breach MyP@ssw0rd!

# Check email exposure (with API key)
export HIBP_KEY="your-api-key"
rb recon identity breach myemail@company.com --type email --hibp-key $HIBP_KEY
```

### Pre-engagement Username Discovery

```bash
# Find all accounts for a target persona
rb recon identity username target_handle --threads 100

# Export to JSON for further processing
rb recon identity username target_handle -o json > profiles.json
```

## Backwards Compatibility

The legacy command `rb recon username search` still works and is aliased to `rb recon identity username`:

```bash
# Both commands are equivalent:
rb recon username search johndoe
rb recon identity username johndoe

# Legacy email command also still works:
rb recon domain email user@example.com
rb recon identity email user@example.com
```
