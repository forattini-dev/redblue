.PHONY: build release test clean run help install patch minor major link unlink dev which embeddings docs

# Paths
LOCAL_BIN := $(HOME)/.local/bin
CARGO_BIN := $(HOME)/.cargo/bin
LOCAL_BINARY := $(PWD)/target/release/redblue

# Default target
help:
	@echo "RedBlue CLI - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make build      - Build debug version"
	@echo "  make release    - Build optimized release version"
	@echo "  make test       - Run all tests"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make run        - Run debug version (use ARGS='...')"
	@echo "  make install    - Install to ~/.cargo/bin"
	@echo "  make fmt        - Format code"
	@echo "  make lint       - Run clippy"
	@echo "  make check      - Quick compile check"
	@echo ""
	@echo "Local Development:"
	@echo "  make link       - Use local binary (symlink to ~/.local/bin/rb)"
	@echo "  make unlink     - Use GitHub-installed version (remove local symlink)"
	@echo "  make dev        - Build release + link local binary"
	@echo "  make which      - Show which rb binary is in use"
	@echo "  make embeddings - Build documentation embeddings for MCP search"
	@echo "  make docs       - Serve documentation locally at http://localhost:3000"
	@echo ""
	@echo "Release:"
	@echo "  make patch      - Bump patch version (0.1.0 → 0.1.1)"
	@echo "  make minor      - Bump minor version (0.1.0 → 0.2.0)"
	@echo "  make major      - Bump major version (0.1.0 → 1.0.0)"
	@echo ""
	@echo "Examples:"
	@echo "  make run ARGS='dns record lookup google.com'"
	@echo "  make run ARGS='network ports scan 127.0.0.1 --preset common'"
	@echo "  make dev        # then: rb --version"

# Build debug version
build:
	cargo build

# Build release version (optimized)
release:
	cargo build --release
	@echo ""
	@echo "Release binary: ./target/release/redblue"
	@echo "Size: $$(du -h ./target/release/redblue | cut -f1)"

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean

# Run debug version
run:
	cargo run -- $(ARGS)

# Install to system
install: release
	cargo install --path .

# Format code
fmt:
	cargo fmt

# Run clippy linter
lint:
	cargo clippy

# Quick compile check
check:
	cargo check

# Run specific examples
dns:
	cargo run -- dns record lookup $(DOMAIN)

scan:
	cargo run -- network ports scan $(TARGET) --preset common

http:
	cargo run -- web asset get $(URL)

# Benchmarks
bench-scan:
	@echo "Benchmarking port scan..."
	time ./target/release/redblue network ports range 127.0.0.1 1 1000

# Version management (triggers GitHub release)
patch:
	@./scripts/release.sh patch

minor:
	@./scripts/release.sh minor

major:
	@./scripts/release.sh major

# Build static binary (if musl is available)
static:
	cargo build --release --target x86_64-unknown-linux-musl

# ============================================================================
# Documentation & Embeddings
# ============================================================================

# Build documentation embeddings for MCP search
embeddings:
	@echo "Building documentation embeddings..."
	@if [ ! -d "venv" ]; then \
		echo "Creating virtual environment..."; \
		python3 -m venv venv; \
	fi
	@. venv/bin/activate && pip install -q fastembed && python scripts/build-embeddings.py
	@echo "✓ Embeddings built: src/mcp/data/embeddings.json"

# Serve documentation locally (requires docsify index.html in docs/)
docs:
	@echo "Serving documentation at http://localhost:3000"
	@echo "Press Ctrl+C to stop"
	@cd docs && python3 -m http.server 3000

# ============================================================================
# Local Development Workflow
# ============================================================================

# Link local binary to ~/.local/bin/rb (takes precedence over ~/.cargo/bin)
link: release
	@mkdir -p $(LOCAL_BIN)
	@if [ -L "$(LOCAL_BIN)/rb" ]; then \
		rm "$(LOCAL_BIN)/rb"; \
	fi
	@ln -sf "$(LOCAL_BINARY)" "$(LOCAL_BIN)/rb"
	@echo "✓ Linked: $(LOCAL_BIN)/rb → $(LOCAL_BINARY)"
	@echo ""
	@echo "Now using LOCAL binary. Verify with:"
	@echo "  which rb"
	@echo "  rb --version"

# Remove local symlink to use GitHub-installed version from ~/.cargo/bin
unlink:
	@if [ -L "$(LOCAL_BIN)/rb" ]; then \
		rm "$(LOCAL_BIN)/rb"; \
		echo "✓ Removed local symlink: $(LOCAL_BIN)/rb"; \
		echo ""; \
		echo "Now using INSTALLED binary from ~/.cargo/bin"; \
		echo "  which rb"; \
		echo "  rb --version"; \
	else \
		echo "No local symlink found at $(LOCAL_BIN)/rb"; \
		echo "Already using installed version."; \
	fi

# Build and link in one step
dev: link
	@echo ""
	@echo "Development environment ready!"
	@echo "Binary: $$(which rb)"
	@echo "Version: $$(rb --version 2>/dev/null || echo 'run rb --version')"

# Show which rb binary is currently in use
which:
	@echo "Current rb binary:"
	@which rb 2>/dev/null || echo "  rb not found in PATH"
	@echo ""
	@if [ -L "$(LOCAL_BIN)/rb" ]; then \
		echo "Local symlink: $(LOCAL_BIN)/rb → $$(readlink $(LOCAL_BIN)/rb)"; \
		echo "Status: Using LOCAL development binary"; \
	elif [ -f "$(CARGO_BIN)/rb" ]; then \
		echo "Installed binary: $(CARGO_BIN)/rb"; \
		echo "Status: Using INSTALLED binary"; \
	else \
		echo "Status: rb not installed"; \
	fi
