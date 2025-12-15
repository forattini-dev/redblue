# Playbooks Capability

## ADDED Requirements

### Requirement: Playbook Executor
The system SHALL execute playbooks step-by-step with progress tracking and evidence collection.

#### Scenario: Execute playbook with all steps passing
- **WHEN** operator runs `rb exploit payload run reverse-shell-linux 192.168.1.100`
- **THEN** each step executes sequentially with status output
- **AND** evidence is collected at each step
- **AND** final summary shows success/failure count

#### Scenario: Handle step failure gracefully
- **WHEN** a playbook step fails during execution
- **THEN** execution stops at the failed step
- **AND** error message explains what failed
- **AND** operator can retry or skip the step

### Requirement: Playbook Variables
The system SHALL support variable substitution in playbook definitions.

#### Scenario: Substitute target variable
- **WHEN** playbook contains `{{ target }}` placeholder
- **THEN** the target argument replaces the placeholder at runtime

#### Scenario: Use environment variables
- **WHEN** playbook references `{{ env.LHOST }}`
- **THEN** the corresponding environment variable value is used

### Requirement: Playbook Chaining
The system SHALL support triggering one playbook from another based on results.

#### Scenario: Chain on success
- **WHEN** playbook A completes successfully with `next_on_success: playbook-b`
- **THEN** playbook B is automatically executed with the same context

#### Scenario: Prevent infinite loops
- **WHEN** playbook chain depth exceeds 10
- **THEN** execution stops with a warning about potential infinite loop

### Requirement: Playbook Recommender Integration
The system SHALL recommend playbooks based on reconnaissance data.

#### Scenario: Recommend based on open ports
- **WHEN** target has port 22 open
- **THEN** SSH-related playbooks receive higher scores

#### Scenario: Handle missing recon data
- **WHEN** no reconnaissance data exists for target
- **THEN** helpful message suggests running recon first
- **AND** example commands are provided
