# Spec: Subdomain Brute-Force & Credential Testing

## ADDED Requirements

### Requirement: DNS Subdomain Brute-Force
The system SHALL provide wordlist-based subdomain enumeration via DNS queries that replaces amass brute, fierce, and dnsrecon brute-force capabilities.

#### Scenario: Basic subdomain brute-force
- **WHEN** user runs `rb recon subdomain bruteforce example.com -w /path/to/subdomains.txt`
- **THEN** the system queries DNS for each subdomain (e.g., www.example.com, api.example.com)
- **AND** displays found subdomains with their IP addresses

#### Scenario: Multi-threaded DNS resolution
- **WHEN** user runs `rb recon subdomain bruteforce example.com -w wordlist.txt -t 100`
- **THEN** the system uses 100 concurrent DNS queries for speed

#### Scenario: Wildcard detection
- **WHEN** user runs `rb recon subdomain bruteforce example.com -w wordlist.txt`
- **AND** the domain has wildcard DNS (*.example.com resolves to an IP)
- **THEN** the system detects this and filters false positives
- **AND** warns the user about wildcard DNS

#### Scenario: Custom resolvers
- **WHEN** user runs `rb recon subdomain bruteforce example.com -w wordlist.txt --resolvers 8.8.8.8,1.1.1.1,9.9.9.9`
- **THEN** the system distributes queries across specified DNS resolvers

#### Scenario: Use SecLists wordlist by name
- **WHEN** user runs `rb recon subdomain bruteforce example.com -w seclists:dns-jhaddix`
- **THEN** the system automatically uses `SecLists/Discovery/DNS/dns-Jhaddix.txt`

### Requirement: Subdomain Result Enrichment
The system SHALL enrich discovered subdomains with additional DNS information.

#### Scenario: Show CNAME chains
- **WHEN** a subdomain resolves to a CNAME
- **THEN** the system follows the CNAME chain and displays the full resolution path

#### Scenario: Multiple IP addresses
- **WHEN** a subdomain resolves to multiple A records
- **THEN** the system displays all IP addresses

#### Scenario: IPv6 support
- **WHEN** user runs `rb recon subdomain bruteforce example.com -w wordlist.txt --ipv6`
- **THEN** the system also queries AAAA records

### Requirement: HTTP Basic Authentication Testing
The system SHALL provide credential testing against HTTP Basic authentication endpoints.

#### Scenario: Test credentials against HTTP Basic auth
- **WHEN** user runs `rb auth test http://target.com/admin -u users.txt -p passwords.txt --type basic`
- **THEN** the system tests each user:password combination
- **AND** reports successful authentications (200 OK)

#### Scenario: Single user multiple passwords
- **WHEN** user runs `rb auth test http://target.com/admin -u admin -p passwords.txt --type basic`
- **THEN** the system tests the single user against all passwords in the list

#### Scenario: Credential file (user:pass format)
- **WHEN** user runs `rb auth test http://target.com/admin -c credentials.txt --type basic`
- **THEN** the system reads user:password pairs from the file

### Requirement: Form-Based Authentication Testing
The system SHALL support testing form-based login pages.

#### Scenario: Test form login
- **WHEN** user runs `rb auth test http://target.com/login -u users.txt -p passwords.txt --type form --user-field username --pass-field password`
- **THEN** the system sends POST requests to the login form
- **AND** detects successful logins by response analysis

#### Scenario: CSRF token extraction
- **WHEN** the login form contains a CSRF token
- **THEN** the system extracts and includes the token in each request

#### Scenario: Success detection by redirect
- **WHEN** user runs `rb auth test http://target.com/login ... --success-redirect /dashboard`
- **THEN** the system considers a 302 redirect to /dashboard as successful login

#### Scenario: Failure detection by string
- **WHEN** user runs `rb auth test http://target.com/login ... --failure-string "Invalid credentials"`
- **THEN** the system considers responses containing that string as failed attempts

### Requirement: Credential Testing Safety
The system SHALL include safety features to prevent account lockouts.

#### Scenario: Rate limiting
- **WHEN** user runs `rb auth test ... --delay 1000`
- **THEN** the system waits 1000ms between each attempt

#### Scenario: Lockout detection
- **WHEN** the target returns 429 (Too Many Requests) or similar lockout indicators
- **THEN** the system pauses testing and warns the user

#### Scenario: Max attempts per user
- **WHEN** user runs `rb auth test ... --max-attempts 5`
- **THEN** the system stops testing each user after 5 failed attempts

### Requirement: Credential Testing Output
The system SHALL provide clear output of testing results.

#### Scenario: Found credential display
- **WHEN** valid credentials are found
- **THEN** the system displays `[+] FOUND: admin:password123` prominently

#### Scenario: Progress display
- **WHEN** credential testing is in progress
- **THEN** the system shows progress: tested/total, speed (attempts/sec), ETA

#### Scenario: Save found credentials
- **WHEN** user runs `rb auth test ... --output-file found.txt`
- **THEN** found credentials are saved to the specified file
