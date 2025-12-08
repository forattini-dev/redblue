# screenshots Specification

## Purpose
TBD - created by archiving change add-tool-parity-roadmap. Update Purpose after archive.
## Requirements
### Requirement: Web Page Screenshot Capture
The system SHALL capture screenshots of web pages using headless browser automation.

#### Scenario: Capture single page
- **WHEN** user runs `rb collect screenshot http://example.com`
- **THEN** system launches headless browser
- **AND** captures full page screenshot as PNG
- **AND** saves to specified output directory

#### Scenario: Batch capture from file
- **WHEN** user runs `rb collect screenshot -f urls.txt -o screenshots/`
- **THEN** system processes all URLs concurrently
- **AND** captures each page with consistent viewport
- **AND** names files based on URL

### Requirement: Viewport Configuration
The system SHALL support configurable viewport dimensions and device emulation.

#### Scenario: Custom viewport
- **WHEN** user runs `rb collect screenshot http://example.com --viewport 1920x1080`
- **THEN** system renders page at specified dimensions

#### Scenario: Mobile emulation
- **WHEN** user runs `rb collect screenshot http://example.com --device mobile`
- **THEN** system emulates mobile viewport and user-agent

### Requirement: Report Generation
The system SHALL generate HTML reports aggregating captured screenshots with metadata.

#### Scenario: Generate HTML report
- **WHEN** user runs `rb collect screenshot -f urls.txt --report`
- **THEN** system captures all pages
- **AND** generates interactive HTML report
- **AND** includes thumbnails, response info, and headers

### Requirement: Similarity Clustering
The system SHALL group visually similar pages to reduce noise in large scans.

#### Scenario: Cluster similar pages
- **WHEN** user runs `rb collect screenshot -f urls.txt --cluster`
- **THEN** system analyzes DOM structure
- **AND** groups similar pages together
- **AND** shows representative screenshot per cluster

### Requirement: Service Categorization
The system SHALL categorize discovered services by type (web server, CMS, router, database, etc.).

#### Scenario: Auto-categorize services
- **WHEN** user runs `rb collect screenshot -f urls.txt --categorize`
- **THEN** system analyzes page content and headers
- **AND** assigns category labels (25+ categories)
- **AND** organizes report by category

### Requirement: Session Persistence
The system SHALL persist scan state for resume capability and incremental updates.

#### Scenario: Resume interrupted scan
- **WHEN** user runs `rb collect screenshot -f urls.txt --session scan1`
- **AND** scan is interrupted
- **THEN** running `rb collect screenshot --resume scan1` continues from last point

#### Scenario: Update existing scan
- **WHEN** user runs `rb collect screenshot -f urls.txt --session scan1 --update`
- **THEN** system re-captures changed pages only
- **AND** preserves historical screenshots

### Requirement: Timeout and Error Handling
The system SHALL handle page load timeouts and errors gracefully.

#### Scenario: Handle timeout
- **WHEN** page does not load within timeout
- **THEN** system records error state
- **AND** continues with remaining URLs
- **AND** includes timeout in report

#### Scenario: Handle JavaScript errors
- **WHEN** page throws JavaScript errors
- **THEN** system still captures available content
- **AND** logs errors for debugging

### Requirement: Header and Response Capture
The system SHALL capture HTTP headers and response metadata alongside screenshots.

#### Scenario: Capture response data
- **WHEN** user runs `rb collect screenshot http://example.com --headers`
- **THEN** system saves response headers
- **AND** saves page title and status code
- **AND** includes in report output

### Requirement: Default Credential Detection
The system SHALL maintain a database of default credentials for common web interfaces and flag potential matches.

#### Scenario: Detect default login forms
- **WHEN** user runs `rb collect screenshot -f urls.txt --detect-defaults`
- **THEN** system identifies login pages
- **AND** matches against 50+ known default credential sets
- **AND** flags potential default credential vulnerabilities

#### Scenario: Test default credentials (authorized)
- **WHEN** user runs `rb collect screenshot http://router.local --test-defaults`
- **THEN** system identifies device/application type
- **AND** attempts known default credentials
- **AND** reports successful authentications
- **AND** requires explicit authorization flag

