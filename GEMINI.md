<!-- OPENSPEC:START -->
# OpenSpec Instructions

These instructions are for AI assistants working in this project.

Always open `@/openspec/AGENTS.md` when the request:
- Mentions planning or proposals (words like proposal, spec, change, plan)
- Introduces new capabilities, breaking changes, architecture shifts, or big performance/security work
- Sounds ambiguous and you need the authoritative spec before coding

Use `@/openspec/AGENTS.md` to learn:
- How to create and apply change proposals
- Spec format and conventions
- Project structure and guidelines

Keep this managed block so 'openspec update' can refresh the instructions.

<!-- OPENSPEC:END -->

# GEMINI.md

## Project Overview

This project, named `redblue`, is a comprehensive security toolkit written in Rust. It aims to be a self-contained, single-binary replacement for over 30 common security tools. The philosophy of the project is to have zero external dependencies for network protocols, implementing them from scratch in pure Rust. This includes protocols like TCP, DNS, HTTP, and WHOIS.

The primary goal is to provide a unified and consistent command-line interface for a wide range of security tasks, including:

*   Network scanning and host discovery
*   DNS reconnaissance and enumeration
*   Web security testing and CMS scanning
*   TLS/SSL auditing and vulnerability checking
*   OSINT and data harvesting
*   Exploitation and post-exploitation techniques

The command-line interface is designed to be similar to `kubectl`, with a `domain > verb > resource` structure.

## Building and Running

The project uses `cargo`, the standard Rust build tool. A `Makefile` is also provided for convenience.

### Key Commands

*   **Build (Debug):**
    ```bash
    cargo build
    # or
    make build
    ```

*   **Build (Release):**
    ```bash
    cargo build --release
    # or
    make release
    ```

*   **Run Tests:**
    ```bash
    cargo test
    # or
    make test
    ```

*   **Run the application:**
    The main executable is `rb`.
    ```bash
    # Using cargo
    cargo run -- <domain> <verb> <resource> [target] [flags]

    # Example
    cargo run -- network scan ports 127.0.0.1 --preset common

    # Using the Makefile
    make run ARGS='network scan ports 127.0.0.1 --preset common'

    # Using the release binary
    ./target/release/redblue network scan ports 127.0.0.1 --preset common
    ```

*   **Install:**
    ```bash
    make install
    ```
    This will install the `rb` binary to `~/.cargo/bin`.

## Development Conventions

*   **Zero Protocol Dependencies:** The project strictly avoids external crates for network protocol implementations. All protocols are implemented from scratch in the `src/protocols` directory.
*   **Vendored OpenSSL:** The only exception to the dependency rule is a vendored version of OpenSSL, used for TLS 1.3 and HTTP/2 support.
*   **Code Style:** The project uses `rustfmt` for code formatting (`make fmt`) and `clippy` for linting (`make lint`).
*   **Command-Line Interface:** The CLI is built around a `kubectl`-style grammar, with commands structured as `rb <domain> <verb> <resource>`. The parsing logic is located in `src/cli/parser.rs`.
*   **Modularity:** The codebase is organized into modules based on security domains (e.g., `network`, `dns`, `web`).
*   **Documentation:** The `docs` directory contains extensive documentation on the various features and domains of the tool.
