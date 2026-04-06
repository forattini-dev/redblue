# redblue CLI / SDK Architecture Plan

This document captures the current architectural direction for the `rb` CLI, the Rust command layer, and the `redblue-cli` JavaScript/TypeScript wrapper.

The goal is to make the CLI contract explicit, machine-safe, evolvable, and shared across:

- the Rust binary (`rb`)
- the npm wrapper (`redblue-cli`)
- the JS/TS SDK
- help, completion, and docs generation

This plan is intended to survive context resets and serve as the working reference for the next implementation steps.

## 0. Status Snapshot

This section reflects the current state of the work, not the original intent only.

### 0.1 What is already implemented

The architecture is no longer just a proposal. These pieces are already in place:

- a real schema/manifest foundation in Rust
- canonical grammar metadata exposed from the CLI
- manifest emission for the JS/TS wrapper
- route-level machine-output metadata
- shared renderer infrastructure for `human/json/yaml`-style branching
- significant migration of commands away from ad hoc JSON printing
- alias-aware discovery and suggestion in both Rust and JS/TS
- wrapper-side manifest-driven route lookup, suggestion, schema building, and `runJson`
- integration of `cli-args-parser` via manifest-derived schema construction
- a new `system host` domain/resource with local host inspection and environment inference

### 0.1.1 Concrete work already delivered

The following are materially implemented in the codebase already, not just planned:

- schema/manifest metadata in the Rust CLI, including canonical paths, aliases, examples, route metadata, and global options
- canonical-first route resolution in the parser, with compatibility kept as explicit fallback rather than primary behavior
- manifest-driven route discovery in the JS/TS wrapper, including alias-aware lookup and suggestion
- manifest-derived wrapper helpers such as `runJson(...)`, `createClient(...)`, `$findRoute(...)`, `$suggest(...)`, `$cliSchema`, and `$createCLI(...)`
- prefix-aware alias matching in both Rust and JS/TS suggestion flows
- shared renderer usage across multiple automation-critical domains:
  - `dns`
  - `network`
  - `tls`
  - `recon`
  - `web`
  - `intel`
  - `service`
  - `password`
  - `docs`
  - `config`
  - `access`
  - `collection`
  - `trace`
- a Linux-first `system host` capability with:
  - `rb system host inspect`
  - `rb system host summary`
  - JSON-safe output
  - local inventory collection from `/proc` and `/sys`
  - environment inference for `host`, `container`, `vm`, and `sandbox`
  - domain/resource/verb aliases such as `sys machine inventory`

### 0.2 What is materially better now

Compared to the initial state:

- `rb` and `redblue-cli` are much closer semantically
- manifest and schema are now real runtime artifacts, not just a plan
- many routes already encode whether machine output is safe/guaranteed
- the wrapper is much less dependent on hardcoded route knowledge
- aliases, help, suggestion, and examples are increasingly driven from shared metadata

### 0.3 What is still incomplete

The migration is not finished.

The main remaining gaps are:

- not all commands are migrated to shared renderers and explicit route metadata
- Rust dispatch/help are not yet fully schema-driven
- parser compatibility still exists and legacy surface area is not fully reduced
- wrapper behavior is manifest-driven in many places, but not fully generated end-to-end
- `cli-args-parser` is integrated as a schema consumer, but shell-like completion/help UX is still not where it should be
- the target top-level hierarchy is only partially normalized

### 0.4 Honest maturity assessment

Current state, pragmatically:

- direction: strong
- architectural foundation: solid
- migration completeness: partial
- wrapper maturity: good, but not final
- whole-CLI consistency: improved, but still uneven

### 0.5 Current sharp edges

The most important remaining pain points are now narrower and more concrete:

- some commands still mix business logic and rendering instead of returning clean payloads first
- help and dispatch are improved, but still not fully driven from the schema tree
- compatibility aliases are healthier now, but legacy routing logic still exists in the stack
- the wrapper is strongly manifest-guided, but not yet fully generated from the manifest end-to-end
- `system host` is already useful, but still below the depth of a best-in-class local inventory tool
- shell completion and interactive CLI UX still lag behind the target experience inspired by `cli-args-parser`

### 0.6 Phase status right now

Looking at the migration phases defined later in this document, the current state is roughly:

- Phase 1: largely complete
- Phase 2: partially complete
- Phase 3: materially in progress
- Phase 4: materially in progress
- Phase 5: materially in progress
- Phase 6: partially complete
- Phase 7: not complete

This is not a claim that each phase is done end-to-end. It is a practical status marker for resuming work.

## 1. Current Problems

The current CLI works, but its architecture has structural issues that will keep causing regressions as the surface area grows.

### 1.1 Parser ambiguity

The current parser in `src/cli/parser.rs` tries to support multiple command orders by heuristic:

- `rb <domain> <verb> <resource>`
- `rb <domain> <resource> <verb>`

This has already produced real routing bugs and makes correctness depend on:

- hardcoded verb lists
- registry lookups during parse
- fallback behavior that becomes harder to reason about over time

### 1.2 Command contracts are scattered

A command currently spreads its contract across:

- `routes()`
- `flags()`
- `examples()`
- `execute()`
- ad hoc JSON rendering
- ad hoc validation and output behavior

This means there is no single source of truth for:

- syntax
- types
- output guarantees
- aliases
- deprecations
- machine-consumable behavior

### 1.3 Output is not consistently machine-safe

Some commands already support `-o json`, but the architecture does not guarantee:

- JSON-only stdout
- progress-only stderr
- consistent JSON schema
- renderer reuse across commands

This is a blocker for robust JS/TS integration.

### 1.4 The JS/TS wrapper knows too much

`redblue-cli` is useful, but the wrapper still risks becoming a second source of semantics if it has to hardcode:

- routes
- validation rules
- command behavior
- output assumptions

That path creates drift between the Rust binary and the JS/TS ecosystem.

### 1.5 Domain hierarchy has historical drift

The current top-level CLI shape contains multiple concepts mixed together:

- product domains
- workflows
- internal implementation artifacts
- historical aliases promoted to top-level commands

Examples of drift:

- `tls` and `tls_intel`
- `recon` and `recon_identity`
- `auth_test`
- `dns_server`
- `magic`
- `scan`
- `health`

This increases cognitive load and weakens the long-term CLI map.

## 2. Target Principles

The redesign should follow these principles:

1. One canonical grammar.
2. One command schema as the source of truth.
3. Parser without heuristics.
4. Output contracts explicit and testable.
5. JS/TS wrapper driven by manifest, not by duplicated semantics.
6. Backward compatibility through aliases and compat layers, not parser magic.
7. Incremental migration without breaking `rb` or `redblue-cli`.

## 3. Canonical CLI Grammar

The canonical form should be:

```text
rb <domain> <resource> <verb> [target] [args...] [flags]
```

This becomes the official command grammar for all new commands.

Examples:

```text
rb dns record lookup example.com --type MX
rb tls security audit example.com
rb recon domain subdomains example.com --resolve -o json
rb network ports scan 192.168.1.1 --preset common
```

Rules:

- No heuristic reordering at parse time.
- No hardcoded special-verb list to determine structure.
- Legacy orders remain supported only through an explicit compatibility layer.

## 4. Target Domain Hierarchy

If we normalize the CLI from scratch, the recommended top-level domains are:

- `target`
- `network`
- `dns`
- `web`
- `tls`
- `auth`
- `recon`
- `intel`
- `exploit`
- `proxy`
- `data`
- `system`

This is not a requirement to rename everything immediately. It is the target shape.

### 4.1 Recommended mapping direction

Examples of intended normalization:

- `tls_intel` -> merge under `tls`
- `recon_identity` -> merge under `recon`
- `auth_test` -> merge under `auth`
- `dns_server` -> merge under `dns`
- `health` -> likely merge under `network`
- `scan` -> likely merge into specific domains or `target`
- `magic` -> keep as compatibility or move under `target`
- storage/query concerns -> move under `data`
- service/persistence/runtime concerns -> move under `system`

### 4.2 Resource and verb philosophy

Top-level domains should represent stable mental models.
Resources should represent concrete nouns.
Verbs should represent operations on those nouns.

Good examples:

- `rb tls endpoint audit`
- `rb auth credential test`
- `rb data store query`
- `rb system service install`

## 5. Schema-First Command Model

Introduce a single declarative command schema for the CLI.

Each command definition should contain at least:

- canonical path: `domain/resource/verb`
- aliases
- positional arguments
- additional args
- flags/options
- types
- defaults
- validators
- examples
- output modes supported
- machine-safety metadata
- stability/deprecation metadata
- handler or use-case binding

### 5.1 What the schema must generate

The schema should generate or drive:

- parsing
- command dispatch
- help text
- shell completion
- manifest for SDK/wrapper
- docs fragments
- compatibility checks

### 5.2 What should stop being manual

The following should no longer be hand-maintained independently per command:

- route parsing logic
- JSON capability discovery
- CLI manifesting
- alias handling
- completion definitions
- SDK route duplication

## 6. Rust Architecture Target

The Rust CLI should be split into clearer layers.

Suggested structure:

```text
src/app/              # use-cases and application logic
src/cli/schema/       # declarative command tree
src/cli/parse/        # parser from argv -> typed invocation
src/cli/dispatch/     # invocation -> use-case
src/cli/render/       # human/json/yaml renderers
src/platform/         # linux/windows/macos-specific concerns
src/sdk/manifest/     # manifest emission for wrapper/SDK
```

### 6.1 Layer responsibilities

- `schema`: defines command contracts
- `parse`: resolves argv using only schema
- `dispatch`: routes typed invocations to use-cases
- `app`: business logic, no CLI formatting assumptions
- `render`: output formatting and stdout/stderr policy
- `platform`: OS-specific implementations
- `sdk/manifest`: export machine-readable CLI contract

### 6.2 Anti-patterns to eliminate

Over time, remove:

- parser heuristics based on verb lists
- commands manually printing JSON bodies
- commands mixing business logic and presentation logic
- commands deciding ad hoc stdout/stderr behavior
- `CliContext` acting as parser result plus config loader plus output policy object

## 7. Output Contract

Output behavior must become explicit and enforceable.

### 7.1 Required guarantees

For commands that support machine output:

- progress and status go to `stderr`
- result goes to `stdout`
- `-o json` means JSON-only stdout
- `-o yaml` means YAML-only stdout
- human mode can remain rich and interactive

### 7.2 Renderer policy

Renderers should be shared infrastructure, not command-local conditionals.

Each command should declare what it can render:

- `human`
- `json`
- `yaml`

The renderer layer should handle serialization consistently.

### 7.3 JSON-safe command metadata

Manifest metadata should expose whether a route is safe for programmatic consumption.

Examples:

- `json_safe: true`
- `stdout_contract: "json_only"`
- `stderr_may_contain_progress: true`

This allows the JS/TS wrapper to fail early on unsupported routes.

## 8. Manifest Strategy

The Rust binary should expose a generated, versioned manifest of the CLI.

This can be surfaced through a command such as:

```text
rb sdk manifest
```

### 8.1 Manifest contents

At minimum:

- command path
- aliases
- descriptions
- examples
- positional definitions
- flag definitions
- types
- defaults
- supported output formats
- deprecation metadata
- JSON safety metadata
- version metadata

### 8.2 Manifest consumers

The manifest becomes the contract for:

- `redblue-cli`
- generated SDK bindings
- docs generation
- command inspection
- compatibility tests

## 9. JS/TS Wrapper Plan

The JS/TS wrapper must be part of the target architecture, not a sidecar.

The wrapper should become schema-driven and manifest-driven.

### 9.1 Wrapper responsibilities

Split `redblue-cli` into three concerns:

- `installer`
- `runner`
- `sdk`

#### installer

Responsible for:

- resolving platform-specific binaries
- downloading or provisioning releases
- verifying install state
- performing upgrades

#### runner

Responsible for:

- finding the binary
- spawning `rb`
- preserving stdout/stderr semantics
- exposing raw execution results

#### sdk

Responsible for:

- typed, ergonomic JS/TS APIs
- manifest-driven route resolution
- JSON parsing and validation
- command composition for programmatic callers

### 9.2 Use `cli-args-parser` as the JS/TS frontend

Use `~/Work/tetis/libs/cli-args-parser` as the parsing and dispatch layer for the wrapper.

That library already has the right properties:

- schema-first
- nested subcommands
- explicit dispatch
- strong validation
- help generation

The wrapper should not hardcode command semantics when the manifest can provide them.

The intended flow is:

1. Load manifest from installed binary or bundled metadata.
2. Build JS/TS command schema from manifest.
3. Parse wrapper inputs with `cli-args-parser`.
4. Validate route/flags before process spawn.
5. Execute `rb` with the canonical argument vector.

### 9.3 Wrapper contract

The wrapper should provide:

- `runCli(args, options?)`
- `runJson(args, options?)`
- `createClient(options?)`

Expected behavior:

- `runCli` returns raw `stdout`, `stderr`, `exitCode`
- `runJson` requires JSON-only stdout and fails otherwise
- `createClient` uses manifest-driven route discovery and typed helpers

### 9.4 Generated SDK direction

The JS/TS SDK should eventually be generated from the manifest.

Examples:

- `rb.dns.record.lookup({...})`
- `rb.tls.security.audit({...})`
- `rb.recon.domain.subdomains({...})`

Generated SDK methods should carry:

- route path
- input types
- JSON parsing expectations
- route availability metadata

## 10. JS/TS Installation and Binary Strategy

The current install story needs to be clarified.

### 10.1 Official supported modes

These should all work predictably:

- `npm install redblue-cli`
- `npx redblue-cli ...`
- `npm exec --package redblue-cli rb -- ...`
- `npm i -g redblue-cli`

### 10.2 Postinstall vs autodownload

Define roles clearly:

- `postinstall` is the primary provisioning step
- autodownload is a fallback, not the default mental model

Desired behavior:

- if postinstall already provisioned the correct binary, the wrapper should use it
- wrapper should not redownload unnecessarily
- fallback download should happen only when:
  - binary is missing
  - user explicitly requests install/upgrade
  - package manager skipped scripts

### 10.3 Global install expectation

After:

```text
npm i -g redblue-cli
```

the user should be able to run:

```text
rb ...
```

without needing package-specific workarounds.

This must remain a supported, tested path.

## 11. Compatibility Layer

Compatibility is required, but it must be explicit.

### 11.1 Rust compat layer

The Rust CLI should:

- accept canonical commands
- map legacy forms through explicit aliases
- expose deprecation metadata
- stop relying on parser ambiguity

### 11.2 JS/TS compat layer

The wrapper should:

- accept legacy forms where needed
- translate them to canonical form before spawn
- surface warnings when a route is deprecated

### 11.3 Migration rule

Backward compatibility should be implemented via alias/translation tables, not via central parser guesswork.

## 12. Migration Strategy

This should be done incrementally.

### Phase 1: Schema and manifest foundation

Goals:

- define the schema model
- generate a CLI manifest
- keep current commands working

Deliverables:

- schema types
- manifest generation command
- tests for manifest completeness

Current status:

- largely complete
- schema and manifest are real runtime artifacts now
- completeness and regression tests already exist
- remaining work is mostly refinement, not foundational creation

### Phase 2: Parser replacement in parallel

Goals:

- build schema-driven parser
- run it alongside existing parser in tests
- validate canonical routing behavior

Deliverables:

- new parser module
- golden tests for route parsing
- compatibility translation layer

Current status:

- partially complete
- canonical-first behavior is already in place
- alias-aware and prefix-aware resolution exists
- compatibility still exists in the stack and full parser simplification is not finished

### Phase 3: Shared renderers and output policy

Goals:

- centralize human/json/yaml rendering
- enforce stdout/stderr contracts
- remove command-local JSON formatting over time

Deliverables:

- renderer interfaces
- JSON-safe route metadata
- regression tests for stdout purity

Current status:

- materially in progress
- shared renderer infrastructure exists
- many important domains are already migrated
- route-level metadata exists for many commands
- full stdout purity coverage and full-command migration are still pending

### Phase 4: Pilot domain migration

Start with the domains that matter most for automation:

- `dns`
- `tls`
- `recon`
- `network`

Goals:

- move pilot domains to schema-driven dispatch
- validate JSON and compat behavior
- prove manifest quality

Current status:

- materially in progress
- `dns`, `tls`, `recon`, and `network` have all advanced substantially
- these pilot domains are already strong enough to validate the architecture direction
- some commands inside those domains still need cleanup to fully remove local output branching

### Phase 5: JS/TS wrapper migration

Goals:

- make `redblue-cli` consume the manifest
- use `cli-args-parser` for wrapper parsing/dispatch
- reduce hardcoded wrapper semantics

Deliverables:

- manifest loader
- parser integration
- `runCli`, `runJson`, `createClient` refactor

Current status:

- materially in progress
- manifest loading, route lookup, route suggestion, `runJson`, and client creation are already in place
- `cli-args-parser` integration exists through manifest-derived schema building
- the wrapper still has some hardcoded behavior that should keep being removed

### Phase 6: SDK generation

Goals:

- generate JS/TS client surfaces from manifest
- reduce manual SDK maintenance

Deliverables:

- generated route helpers
- typed declarations
- route coverage tests

Current status:

- partially complete
- the current wrapper already exposes a manifest-driven client surface and useful helper APIs
- type declarations exist and tests cover route behavior
- full end-to-end SDK generation from manifest is not complete yet

### Phase 7: Full migration and cleanup

Goals:

- move remaining domains
- retire parser heuristics
- keep compat aliases where needed

Deliverables:

- reduced legacy path surface
- deprecation policy
- removal of obsolete parser branches

Current status:

- not complete
- this remains the long tail after more renderer migration, schema-driven help/dispatch, and wrapper cleanup land

## 13. Priority Order

If implementation starts immediately, the recommended order is:

1. manifest foundation
2. parser replacement
3. shared renderers
4. `dns` migration
5. `tls` migration
6. `recon` migration
7. `network` migration
8. wrapper manifest integration
9. wrapper `cli-args-parser` integration
10. generated SDK

## 14. Success Criteria

This effort is successful when all of the following are true:

### Core CLI

- Canonical command grammar is explicit and stable.
- Parser no longer depends on heuristic verb ordering.
- New commands are added through schema, not parser edits.
- Commands no longer hand-roll their own JSON logic.

### Output

- Any route declaring `-o json` support emits JSON-only stdout.
- Progress and status are on stderr.
- JSON-safe behavior is testable and encoded in metadata.

### Wrapper

- `redblue-cli` is driven by the manifest, not duplicated route logic.
- `cli-args-parser` is used as the JS/TS parse/dispatch layer.
- `npm install`, `npx`, `npm exec`, and global install are all first-class paths.
- Postinstall and autodownload have clear, non-overlapping roles.

### SDK

- JS/TS SDK routes come from manifest generation.
- Typed client helpers reflect the real CLI contract.
- Wrapper and Rust binary do not drift semantically.

## 14.1 Definition of done by workstream

To avoid vague progress, each major stream should use a concrete definition of done.

### Renderer and output work

A command or route is only considered migrated when:

- it exposes route-level machine-output metadata
- it uses shared renderer helpers instead of ad hoc JSON printing
- `--json` produces JSON-only stdout
- human diagnostics and progress remain on stderr in machine mode
- at least one regression test covers the route or the shared path it depends on

### Schema and parser work

A parser or schema task is only considered done when:

- canonical routing works without heuristic guesswork
- aliases resolve through explicit metadata rather than implicit parser magic
- suggestion behavior is aligned between Rust and JS/TS
- help and manifest surfaces both reflect the same route contract

### Wrapper and SDK work

A wrapper task is only considered done when:

- behavior comes from manifest data rather than wrapper-local assumptions
- route lookup and validation behave the same way as the Rust core
- JSON execution paths fail explicitly on non-machine-safe routes
- tests cover canonical routes, aliases, and invalid input behavior

### `system host` work

The `system host` domain is only considered truly mature when:

- `inspect` and `summary` are stable and JSON-safe
- host/container/vm/sandbox inference is explainable via returned reasons
- missing platform capabilities are represented explicitly in payloads
- the domain is useful without external binaries on Linux
- macOS and Windows have a documented path forward, even if implemented later

## 14.2 Testing strategy

The migration should keep using a layered test strategy.

### Core Rust tests

- unit tests beside helpers and schema logic
- parser tests for canonical and alias forms
- manifest tests for command and route coverage
- renderer tests for JSON-safe behavior where practical

### CLI behavior tests

- golden or assertion-style tests for route resolution
- explicit checks for stdout purity on `--json`
- checks that stderr may contain diagnostics while stdout stays machine-safe

### Wrapper tests

- fake manifest tests for route lookup and alias behavior
- wrapper tests for `runCli`, `runJson`, `$findRoute`, `$suggest`, `$createCLI`
- tests that generated schema remains compatible with `cli-args-parser`

### Cross-layer tests

The most valuable regression tests are the ones that prove the same command contract through multiple layers:

- Rust manifest emits route metadata
- wrapper consumes that route metadata
- client helper composes canonical argv correctly
- machine output is parseable exactly once, without regex cleanup

## 14.3 Risk register

The main ongoing risks are:

- partial migration creates uneven UX, where some domains feel modern and others feel legacy
- wrapper convenience can accidentally reintroduce duplicated semantics if manifest coverage stalls
- compatibility layers can become permanent if not deliberately reduced
- `system host` can drift into a Linux-only snowflake if cross-platform expectations are not documented early
- route metadata can become optimistic if `json_support=guaranteed` is declared faster than behavior is actually verified

Mitigation direction:

- keep marking route guarantees conservatively
- prefer small, verified migrations over broad but shallow annotations
- add regression coverage whenever a route is promoted to `guaranteed`
- keep the manifest as the source of truth rather than letting wrapper behavior evolve independently

## 14.4 Architectural decisions already made

The following decisions should now be treated as settled unless a deliberate reversal is proposed:

- canonical grammar is `rb <domain> <resource> <verb> [target] [args...] [flags]`
- backward compatibility should come from aliases and explicit translation, not parser guesswork
- route metadata belongs in shared schema/manifest structures, not only in local command code
- machine output must be described per route, not only per command
- `--json` is a global machine-output contract, even if some routes still need migration work
- JS/TS should consume manifest data rather than maintain its own independent command model
- `cli-args-parser` is the target UX reference for nested command discovery and validation
- `system host` is a first-class domain/resource, not just an incidental utility command

## 14.5 Parallel workstreams

Work can continue in parallel across these streams as long as each stream keeps the manifest contract coherent.

### Workstream A: Rust schema and parser

Focus:

- schema tree quality
- alias normalization
- help and dispatch behavior
- parser simplification

Good tasks for this stream:

- move more command navigation logic into schema helpers
- reduce legacy branches in the parser
- improve route suggestion and canonical correction messages

### Workstream B: Rust output and renderers

Focus:

- route metadata
- shared renderers
- stdout/stderr guarantees
- JSON-safe route validation

Good tasks for this stream:

- migrate remaining commands off local JSON branches
- add regression tests for JSON purity
- tighten `guaranteed` vs `best_effort` classifications

### Workstream C: `system host`

Focus:

- local host inventory depth
- environment inference quality
- platform portability path

Good tasks for this stream:

- improve Linux depth
- document macOS and Windows collection strategy
- make capability gaps explicit in JSON payloads

### Workstream D: JS/TS wrapper and SDK

Focus:

- manifest-native UX
- `cli-args-parser` integration
- client ergonomics
- install/runtime behavior

Good tasks for this stream:

- remove route hardcoding
- improve help and completion behavior
- align wrapper validation more tightly with manifest types

## 15. Immediate Next Steps

The next concrete steps now should be:

1. finish migrating the remaining medium-size commands to shared renderers and explicit route metadata
2. move more help and dispatch behavior in Rust to the schema layer instead of manual command logic
3. continue tightening stdout/stderr guarantees and route-level JSON safety with regression coverage
4. deepen `system host` into a genuinely strong local inventory primitive:
   - richer display/EDID data
   - better memory topology
   - stronger NVMe and mount detail
   - better cross-platform story for macOS and Windows
5. continue reducing hardcoded behavior in `redblue-cli` and drive more UX from the manifest
6. improve manifest-derived help, examples, aliases, validation, and autocomplete behavior to better match the `cli-args-parser` experience
7. keep shrinking legacy parser/compat complexity in favor of explicit alias translation

### 15.1 Most strategic next implementation order

If work resumes after a context reset, the most valuable sequence is:

1. keep migrating remaining commands to shared renderers
2. push more help/dispatch into the schema tree
3. strengthen route-level JSON-safety tests
4. deepen `system host`
5. keep removing wrapper hardcode in favor of manifest-derived UX

### 15.2 Concrete `system host` backlog

The `system host` domain should continue growing into a best-in-class local inventory primitive.

Most valuable next additions:

- richer display data:
  - EDID parsing where available
  - refresh rate and connector state
  - internal vs external panel inference
- deeper storage data:
  - stronger NVMe identification when available from sysfs
  - removable vs fixed media
  - mount-to-device correlation improvements
- deeper memory inventory:
  - physical slot and module topology when readable
  - memory type and configured speed when available
- richer runtime classification:
  - stronger heuristics for nested container-in-VM and sandbox-in-container situations
  - more explicit confidence scoring by signal family
- cross-platform path:
  - macOS implementation strategy
  - Windows implementation strategy
  - graceful capability gaps encoded in payload instead of silent omissions

### 15.3 Concrete wrapper and SDK backlog

The `redblue-cli` wrapper should keep moving toward a manifest-native frontend.

Most valuable next additions:

- derive more help output from manifest data instead of wrapper-local formatting assumptions
- derive validation for flags and positionals more aggressively from the manifest
- reduce fallback hardcode in route normalization
- improve completion and suggestion UX to feel closer to `cli-args-parser`
- keep shaping the client surface so future generated SDK output can replace it cleanly
- add more regression tests for:
  - JSON-only stdout expectations
  - alias translation behavior
  - global option handling
  - install/runtime binary resolution behavior

### 15.4 Concrete CLI UX backlog

To get closer to the `cli-args-parser` level of UX, the CLI itself still needs:

- richer context-aware help for partial command paths
- stronger next-token suggestions directly from the schema tree
- examples and aliases shown consistently in help output
- better error messages for wrong resource/verb order when a canonical route exists
- eventual shell completion generated from the same schema and manifest data

### 15.5 Resume checklist after context reset

If work resumes in a fresh context, the first practical steps should be:

1. read this `PLAN.md`
2. inspect `src/cli/schema.rs`
3. inspect `src/cli/commands/mod.rs`
4. inspect `sdk/redblue-sdk.js`
5. inspect `src/cli/commands/system.rs`
6. run:
   - `cargo fmt`
   - `cargo check`
   - `cargo clippy --all -- -D warnings`
   - `npm test`
7. pick one active workstream instead of mixing unrelated migrations in the same patch

## 15.6 Recommended near-term milestones

The next milestones that would move the architecture forward most visibly are:

### Milestone A: Remaining renderer migration

Done when:

- remaining medium-size commands stop hand-rolling JSON
- route-level metadata is present for the migrated set
- stdout purity regressions are tested for the most important JSON routes

### Milestone B: Schema-driven help and dispatch

Done when:

- help output depends more on schema tree traversal than command-local formatting
- route suggestions and canonical corrections are consistent across the CLI
- manual dispatch glue is reduced further

### Milestone C: Wrapper manifest-native UX

Done when:

- wrapper help is primarily derived from manifest content
- wrapper validation is primarily derived from manifest content
- route lookup, suggestion, and client generation share the same manifest interpretation path

### Milestone D: `system host` maturity

Done when:

- Linux inventory is strong enough to replace ad hoc workstation scripts for most local diagnostics
- JSON payload clearly explains host/container/vm/sandbox inference
- platform expansion plan is documented and implementation-ready

## 16. Non-Goals for the First Iteration

To keep migration realistic, these are not required in the first wave:

- renaming every domain immediately
- deleting all legacy commands
- generating perfect docs from day one
- fully auto-generating every SDK surface before the manifest is stable

The first iteration is about getting the architecture right, not performing every cleanup at once.

## 17. Final Direction

The long-term direction is:

- Rust owns the command contract
- the contract is emitted as a manifest
- the wrapper and SDK consume that contract
- the CLI becomes schema-first, not heuristic-first
- JSON output becomes operationally reliable for machine use

That is the path to make redblue stronger than ad hoc wrappers, easier to extend, and genuinely first-class in both shell and JS/TS ecosystems.
