.PHONY: build release test clean run help install patch minor major

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
	@echo "Release:"
	@echo "  make patch      - Bump patch version (0.1.0 → 0.1.1)"
	@echo "  make minor      - Bump minor version (0.1.0 → 0.2.0)"
	@echo "  make major      - Bump major version (0.1.0 → 1.0.0)"
	@echo ""
	@echo "Examples:"
	@echo "  make run ARGS='dns record lookup google.com'"
	@echo "  make run ARGS='network ports scan 127.0.0.1 --preset common'"

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
