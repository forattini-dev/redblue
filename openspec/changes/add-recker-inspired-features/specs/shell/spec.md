## ADDED Requirements

### Requirement: Session Variables
The system SHALL allow users to set, list, and use variables within the shell session.

#### Scenario: Set a variable
- **WHEN** user runs `:set token=abc123`
- **THEN** the system stores `token` with value `abc123`
- **AND** displays confirmation message

#### Scenario: List all variables
- **WHEN** user runs `:vars`
- **THEN** the system displays all set variables
- **AND** shows key-value pairs in a formatted table

#### Scenario: Use variable in command
- **WHEN** user has set `port=8080`
- **AND** runs `:scan ports --port $port`
- **THEN** the system expands `$port` to `8080`
- **AND** executes the command with expanded value

#### Scenario: Unset a variable
- **WHEN** user runs `:unset token`
- **THEN** the system removes the variable
- **AND** displays confirmation message

#### Scenario: Variable persistence
- **WHEN** variables are set during session
- **THEN** they persist until session ends or unset
- **AND** are NOT persisted to disk between sessions

### Requirement: Dynamic Target Change
The system SHALL allow users to change the current target without restarting the shell.

#### Scenario: Change target
- **WHEN** user runs `:target google.com`
- **THEN** the system updates the current target to `google.com`
- **AND** updates the header to show new context
- **AND** clears cached scan data

#### Scenario: Target with URL
- **WHEN** user runs `:target https://api.example.com`
- **THEN** the system extracts hostname `api.example.com`
- **AND** sets it as current target

#### Scenario: Show current target
- **WHEN** user runs `:target` without arguments
- **THEN** the system displays the current target

#### Scenario: New session file creation
- **WHEN** target is changed to a new domain
- **THEN** the system creates/loads appropriate session file
- **AND** loads existing data if session file exists

#### Scenario: Commands use new target
- **WHEN** target is changed to `newdomain.com`
- **AND** user runs `:scan ports`
- **THEN** the scan runs against `newdomain.com`

### Requirement: URL Command (Base URL)
The system SHALL support setting a base URL for relative path commands.

#### Scenario: Set base URL
- **WHEN** user runs `:url https://api.example.com`
- **THEN** the system sets base URL for HTTP commands
- **AND** updates prompt to show hostname

#### Scenario: Relative path request
- **WHEN** base URL is set to `https://api.example.com`
- **AND** user runs `:get /users`
- **THEN** the system requests `https://api.example.com/users`

#### Scenario: Full URL overrides base
- **WHEN** base URL is set
- **AND** user runs `:get https://other.com/path`
- **THEN** the system requests `https://other.com/path`
- **AND** does NOT use the base URL
