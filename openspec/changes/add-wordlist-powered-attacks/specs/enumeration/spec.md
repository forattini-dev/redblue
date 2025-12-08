# Spec: Wordlist Management & Enumeration

## ADDED Requirements

### Requirement: Native Tar Extraction
The system SHALL provide native tar archive extraction using pure Rust (RFC USTAR format) to support .tar.gz wordlists like rockyou.txt.tar.gz.

#### Scenario: Extract tar.gz archive
- **WHEN** user runs `rb wordlist extract rockyou.txt.tar.gz`
- **THEN** the system decompresses with native gzip
- **AND** extracts files using native tar parser
- **AND** outputs the extracted wordlist

#### Scenario: List tar contents
- **WHEN** user runs `rb wordlist extract rockyou.txt.tar.gz --list`
- **THEN** the system lists files in the archive without extracting

#### Scenario: Extract specific file
- **WHEN** user runs `rb wordlist extract archive.tar.gz --file passwords.txt`
- **THEN** the system extracts only the specified file

### Requirement: Wordlist Information
The system SHALL provide detailed statistics about wordlist files.

#### Scenario: Show wordlist info
- **WHEN** user runs `rb wordlist info /path/to/wordlist.txt`
- **THEN** the system displays:
  - Total lines
  - Unique lines
  - File size
  - Average entry length
  - Longest/shortest entry

#### Scenario: Preview wordlist
- **WHEN** user runs `rb wordlist info /path/to/wordlist.txt --preview 10`
- **THEN** the system shows the first 10 entries

#### Scenario: Character analysis
- **WHEN** user runs `rb wordlist info /path/to/wordlist.txt --analyze`
- **THEN** the system shows character set distribution (lowercase, uppercase, digits, special)

### Requirement: Wordlist Filtering
The system SHALL provide wordlist filtering capabilities to create targeted lists.

#### Scenario: Filter by length
- **WHEN** user runs `rb wordlist filter wordlist.txt --min-length 8 --max-length 12`
- **THEN** the system outputs only entries between 8 and 12 characters

#### Scenario: Filter by pattern
- **WHEN** user runs `rb wordlist filter wordlist.txt --pattern "^[a-z]+[0-9]+$"`
- **THEN** the system outputs only entries matching the regex pattern

#### Scenario: Deduplicate wordlist
- **WHEN** user runs `rb wordlist filter wordlist.txt --unique`
- **THEN** the system outputs only unique entries (case-sensitive)

#### Scenario: Case-insensitive dedupe
- **WHEN** user runs `rb wordlist filter wordlist.txt --unique --ignore-case`
- **THEN** the system removes case-insensitive duplicates

### Requirement: Wordlist Combination
The system SHALL support combining and mutating wordlists.

#### Scenario: Merge wordlists
- **WHEN** user runs `rb wordlist merge list1.txt list2.txt -o combined.txt`
- **THEN** the system combines both lists and removes duplicates

#### Scenario: Basic mutations
- **WHEN** user runs `rb wordlist mutate wordlist.txt --capitalize --append-numbers`
- **THEN** for each entry, the system generates: original, Capitalized, original1, original123

#### Scenario: L33t speak transformation
- **WHEN** user runs `rb wordlist mutate wordlist.txt --leet`
- **THEN** the system generates l33t variants (a->4, e->3, i->1, o->0, s->5)

#### Scenario: Combination attack
- **WHEN** user runs `rb wordlist combine words.txt numbers.txt --separator ""`
- **THEN** the system outputs all combinations: word1+num1, word1+num2, ...

### Requirement: SecLists Integration
The system SHALL provide convenient access to SecLists wordlists by category and name.

#### Scenario: List SecLists by category
- **WHEN** user runs `rb wordlist seclists list --category passwords`
- **THEN** the system lists all password wordlists in SecLists

#### Scenario: Search SecLists
- **WHEN** user runs `rb wordlist seclists search "rockyou"`
- **THEN** the system finds all SecLists files matching "rockyou"

#### Scenario: Use SecLists path alias
- **WHEN** user runs `rb web fuzz http://target/FUZZ -w seclists:raft-large-directories`
- **THEN** the system resolves to `SecLists/Discovery/Web-Content/raft-large-directories.txt`

#### Scenario: Show SecLists statistics
- **WHEN** user runs `rb wordlist seclists stats`
- **THEN** the system shows: total wordlists, total entries, size on disk, top categories

### Requirement: Wordlist Output Options
The system SHALL support various output options for filtered/generated wordlists.

#### Scenario: Output to file
- **WHEN** user runs `rb wordlist filter wordlist.txt --min-length 8 -o filtered.txt`
- **THEN** results are saved to filtered.txt

#### Scenario: Output to stdout
- **WHEN** user runs `rb wordlist filter wordlist.txt --min-length 8`
- **THEN** results are printed to stdout (pipe-friendly)

#### Scenario: Limit output
- **WHEN** user runs `rb wordlist filter wordlist.txt --limit 1000`
- **THEN** the system outputs only the first 1000 matching entries
