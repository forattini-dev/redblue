## ADDED Requirements

### Requirement: Security Headers Grader
The system SHALL analyze HTTP security headers and provide a grade (A+ to F) with detailed recommendations.

#### Scenario: Grade a website's security
- **WHEN** user runs `rb web asset grade https://example.com`
- **THEN** the system fetches the URL and analyzes response headers
- **AND** displays a grade (A+, A, B, C, D, F)
- **AND** displays a score (0-100)
- **AND** lists each header with pass/warn/fail status

#### Scenario: Security headers analysis
- **WHEN** analyzing headers
- **THEN** the system checks for:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - X-XSS-Protection (deprecated but checked)
  - Referrer-Policy
  - Permissions-Policy
  - Cross-Origin-Opener-Policy (COOP)
  - Cross-Origin-Embedder-Policy (COEP)
  - Cross-Origin-Resource-Policy (CORP)

#### Scenario: CSP deep analysis
- **WHEN** Content-Security-Policy header is present
- **THEN** the system parses all directives
- **AND** identifies dangerous values ('unsafe-inline', 'unsafe-eval', *)
- **AND** reports missing recommended directives
- **AND** calculates CSP-specific score

#### Scenario: Missing critical headers
- **WHEN** HSTS or CSP headers are missing
- **THEN** the system marks them as failed
- **AND** provides specific recommendations

#### Scenario: HSTS validation
- **WHEN** HSTS header is present
- **THEN** the system checks max-age value
- **AND** warns if max-age is too short (< 1 year)
- **AND** notes presence of includeSubDomains and preload

#### Scenario: Grade calculation
- **WHEN** all headers are analyzed
- **THEN** the system calculates score:
  - A+ (100): All critical headers present and well-configured
  - A (90-99): All critical headers, minor issues
  - B (80-89): Most headers present
  - C (70-79): Some headers missing
  - D (60-69): Many headers missing
  - F (< 60): Critical headers missing

#### Scenario: Output with recommendations
- **WHEN** grade is below A
- **THEN** the system provides specific recommendations
- **AND** shows example header values to add
