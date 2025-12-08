# Spec: Web Fuzzing

## ADDED Requirements

### Requirement: Web Directory Fuzzing
The system SHALL provide wordlist-based directory and file discovery capabilities that replace ffuf, gobuster, feroxbuster, and dirsearch.

#### Scenario: Basic directory fuzzing
- **WHEN** user runs `rb web fuzz http://target.com/FUZZ -w /path/to/wordlist.txt`
- **THEN** the system sends HTTP requests replacing FUZZ with each wordlist entry
- **AND** displays found paths with status codes

#### Scenario: Filter by status code
- **WHEN** user runs `rb web fuzz http://target.com/FUZZ -w wordlist.txt -fc 404,403`
- **THEN** the system excludes responses with status codes 404 and 403 from output

#### Scenario: Include only specific status codes
- **WHEN** user runs `rb web fuzz http://target.com/FUZZ -w wordlist.txt -mc 200,301`
- **THEN** the system only shows responses with status codes 200 or 301

#### Scenario: Filter by response size
- **WHEN** user runs `rb web fuzz http://target.com/FUZZ -w wordlist.txt -fs 1234`
- **THEN** the system excludes responses with exactly 1234 bytes

#### Scenario: Multi-threaded fuzzing
- **WHEN** user runs `rb web fuzz http://target.com/FUZZ -w wordlist.txt -t 50`
- **THEN** the system uses 50 concurrent threads for requests

### Requirement: Extension Fuzzing
The system SHALL support fuzzing with multiple file extensions appended to wordlist entries.

#### Scenario: Fuzz with extensions
- **WHEN** user runs `rb web fuzz http://target.com/FUZZ -w wordlist.txt -x php,html,js`
- **THEN** for each wordlist entry, the system tests: entry, entry.php, entry.html, entry.js

### Requirement: Recursive Fuzzing
The system SHALL support recursive directory scanning when directories are found.

#### Scenario: Enable recursive mode
- **WHEN** user runs `rb web fuzz http://target.com/FUZZ -w wordlist.txt -r`
- **AND** a directory is discovered (301/302 redirect to path/)
- **THEN** the system automatically fuzzes inside that directory

#### Scenario: Limit recursion depth
- **WHEN** user runs `rb web fuzz http://target.com/FUZZ -w wordlist.txt -r -rd 3`
- **THEN** the system limits recursive scanning to 3 levels deep

### Requirement: POST Body Fuzzing
The system SHALL support fuzzing POST request bodies.

#### Scenario: POST data fuzzing
- **WHEN** user runs `rb web fuzz http://target.com/api -w wordlist.txt -X POST -d "param=FUZZ"`
- **THEN** the system sends POST requests with FUZZ replaced in the body

### Requirement: Custom Headers
The system SHALL support custom HTTP headers in fuzzing requests.

#### Scenario: Add custom header
- **WHEN** user runs `rb web fuzz http://target.com/FUZZ -w wordlist.txt -H "Authorization: Bearer token123"`
- **THEN** the system includes the Authorization header in all requests

#### Scenario: Multiple custom headers
- **WHEN** user runs `rb web fuzz http://target.com/FUZZ -w wordlist.txt -H "X-Custom: value1" -H "X-Another: value2"`
- **THEN** the system includes both headers in all requests

### Requirement: Output Formats
The system SHALL support multiple output formats for fuzzing results.

#### Scenario: JSON output
- **WHEN** user runs `rb web fuzz http://target.com/FUZZ -w wordlist.txt -o json`
- **THEN** results are output in JSON format with url, status, size, words, lines

#### Scenario: Save results to file
- **WHEN** user runs `rb web fuzz http://target.com/FUZZ -w wordlist.txt --output-file results.json`
- **THEN** results are saved to the specified file

### Requirement: Auto-Calibration
The system SHALL support automatic baseline calibration to filter noise.

#### Scenario: Auto-calibrate filters
- **WHEN** user runs `rb web fuzz http://target.com/FUZZ -w wordlist.txt -ac`
- **THEN** the system sends probe requests with random strings
- **AND** automatically filters responses matching the baseline size/content
