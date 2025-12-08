# web-fuzzing Specification

## Purpose
TBD - created by archiving change add-tool-parity-roadmap. Update Purpose after archive.
## Requirements
### Requirement: FUZZ Keyword Placement
The system SHALL support FUZZ keyword placement in URL path, query parameters, headers, POST body, and cookies.

#### Scenario: FUZZ in URL path
- **WHEN** user runs `rb web asset fuzz http://example.com/FUZZ -w wordlist.txt`
- **THEN** system replaces FUZZ with each wordlist entry
- **AND** makes HTTP request for each permutation

#### Scenario: FUZZ in header
- **WHEN** user runs `rb web asset fuzz http://example.com -H "X-Custom: FUZZ" -w wordlist.txt`
- **THEN** system replaces FUZZ in header value with wordlist entries

#### Scenario: FUZZ in POST body
- **WHEN** user runs `rb web asset fuzz http://example.com -X POST -d "user=FUZZ&pass=test" -w usernames.txt`
- **THEN** system replaces FUZZ in POST data with wordlist entries

### Requirement: Response Filtering
The system SHALL support filtering responses by size, status code, word count, line count, and regex pattern.

#### Scenario: Filter by response size
- **WHEN** user runs `rb web asset fuzz http://example.com/FUZZ -fs 4242`
- **THEN** system excludes responses with exactly 4242 bytes
- **AND** shows only non-matching responses

#### Scenario: Filter by status code
- **WHEN** user runs `rb web asset fuzz http://example.com/FUZZ -fc 404,403`
- **THEN** system excludes responses with 404 or 403 status
- **AND** shows only other status codes

#### Scenario: Match by regex
- **WHEN** user runs `rb web asset fuzz http://example.com/FUZZ -mr "admin|dashboard"`
- **THEN** system shows only responses matching regex pattern

### Requirement: Extension Appending
The system SHALL support appending file extensions to wordlist entries.

#### Scenario: Append multiple extensions
- **WHEN** user runs `rb web asset fuzz http://example.com/FUZZ -e php,html,js`
- **THEN** system tests each wordlist entry with each extension
- **AND** entry "admin" becomes "admin", "admin.php", "admin.html", "admin.js"

### Requirement: Auto-Calibration
The system SHALL automatically detect baseline responses and filter false positives.

#### Scenario: Automatic baseline detection
- **WHEN** user runs `rb web asset fuzz http://example.com/FUZZ --auto-calibrate`
- **THEN** system sends random requests to establish baseline
- **AND** automatically filters responses matching baseline

### Requirement: Multiple Wordlist Modes
The system SHALL support clusterbomb, pitchfork, and sniper modes for multiple FUZZ positions.

#### Scenario: Clusterbomb mode
- **WHEN** user runs `rb web asset fuzz http://example.com/FUZZ1/FUZZ2 -w1 dirs.txt -w2 files.txt --mode clusterbomb`
- **THEN** system tests all combinations of FUZZ1 and FUZZ2

#### Scenario: Pitchfork mode
- **WHEN** user runs `rb web asset fuzz http://example.com?user=FUZZ1&pass=FUZZ2 -w1 users.txt -w2 passes.txt --mode pitchfork`
- **THEN** system tests parallel entries (user1:pass1, user2:pass2, ...)

### Requirement: Rate Control
The system SHALL support configurable request rate and delay between requests.

#### Scenario: Rate limiting
- **WHEN** user runs `rb web asset fuzz http://example.com/FUZZ --rate 10`
- **THEN** system limits to 10 requests per second

#### Scenario: Random delay
- **WHEN** user runs `rb web asset fuzz http://example.com/FUZZ --delay 0.5-2.0`
- **THEN** system adds random delay between 0.5 and 2.0 seconds per request

### Requirement: Recursion
The system SHALL support recursive fuzzing when directories are discovered.

#### Scenario: Recursive directory discovery
- **WHEN** user runs `rb web asset fuzz http://example.com/FUZZ --recursion`
- **THEN** system discovers /admin/ directory
- **AND** automatically fuzzes http://example.com/admin/FUZZ
- **AND** continues recursively up to depth limit

