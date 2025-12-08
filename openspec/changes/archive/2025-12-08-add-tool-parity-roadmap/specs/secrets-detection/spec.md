## ADDED Requirements

### Requirement: Repository History Scanning
The system SHALL scan entire git repository history for secrets, not just current files.

#### Scenario: Scan git history
- **WHEN** user runs `rb code secrets scan /path/to/repo --history`
- **THEN** system parses git log and diffs
- **AND** scans all historical file versions
- **AND** reports secrets with commit SHA, author, and date

#### Scenario: Scan specific branch
- **WHEN** user runs `rb code secrets scan /path/to/repo --branch feature/auth`
- **THEN** system scans only commits in specified branch

### Requirement: Credential Verification
The system SHALL optionally verify detected credentials against their respective APIs to confirm validity.

#### Scenario: Verify cloud credentials
- **WHEN** user runs `rb code secrets scan /path/to/repo --verify`
- **THEN** system detects AWS keys
- **AND** calls AWS STS GetCallerIdentity to verify
- **AND** reports "verified" or "invalid" status

#### Scenario: Verify API tokens
- **WHEN** GitHub token is detected
- **THEN** system calls GitHub API with token
- **AND** reports token validity and scopes

### Requirement: Detection Rule Configuration
The system SHALL support external configuration files defining detection rules in TOML format.

#### Scenario: Load custom rules
- **WHEN** user runs `rb code secrets scan --config rules.toml`
- **THEN** system loads custom detection patterns
- **AND** applies rules alongside built-in patterns

#### Scenario: Extend built-in rules
- **WHEN** user has `~/.config/redblue/secrets.toml`
- **THEN** system merges custom rules with defaults
- **AND** uses combined ruleset

### Requirement: Allowlist and Ignore System
The system SHALL support allowlisting false positives via inline comments and configuration.

#### Scenario: Inline ignore comment
- **WHEN** source file contains `// redblue:ignore` before a line
- **THEN** system skips that line for secrets detection

#### Scenario: Allowlist in config
- **WHEN** config file lists known false positive patterns
- **THEN** system excludes matches from results

### Requirement: Archive Extraction
The system SHALL extract and scan contents of archive files (.zip, .tar.gz, .rar).

#### Scenario: Scan zip archive
- **WHEN** user runs `rb code secrets scan archive.zip`
- **THEN** system extracts archive contents
- **AND** scans all extracted files
- **AND** reports findings with archive path context

### Requirement: Encoded Content Detection
The system SHALL detect secrets in base64, hex, and URL-encoded content.

#### Scenario: Detect base64 encoded secrets
- **WHEN** file contains base64-encoded API key
- **THEN** system decodes base64 content
- **AND** applies secret detection rules
- **AND** reports original encoded location

### Requirement: Comprehensive Rule Library
The system SHALL include 800+ detection patterns covering major cloud providers, SaaS services, and common secret types, with phased expansion (30+ → 60+ → 200+ → 800+).

#### Scenario: Detect cloud provider keys
- **WHEN** scanning a file with AWS, GCP, or Azure credentials
- **THEN** system matches provider-specific patterns
- **AND** reports credential type and affected service

#### Scenario: Detect private keys
- **WHEN** scanning a file with SSH or PGP private keys
- **THEN** system detects key headers and structure
- **AND** reports key type and security risk

### Requirement: Output Formats
The system SHALL support multiple output formats: text, JSON, CSV, and SARIF for CI integration.

#### Scenario: SARIF output for CI
- **WHEN** user runs `rb code secrets scan --format sarif`
- **THEN** system outputs SARIF format
- **AND** compatible with GitHub Code Scanning
