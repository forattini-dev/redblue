#!/usr/bin/env bash
#
# redblue multi-arch installer script
# Downloads and installs redblue from GitHub releases
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash -s -- --channel next
#   curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash -s -- --version v0.1.0
#
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
REPO="forattini-dev/redblue"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="rb"
CHANNEL="stable"  # stable, next, latest
VERSION=""
STATIC=""  # Use static (musl) build if available
VERBOSE=""  # Verbose mode
BUILD_FROM_SOURCE=""  # Build from source if no releases available

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --channel)
            CHANNEL="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --static)
            STATIC="true"
            shift
            ;;
        --verbose|-v)
            VERBOSE="true"
            shift
            ;;
        --build)
            BUILD_FROM_SOURCE="true"
            shift
            ;;
        -h|--help)
            echo "redblue installer"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --channel <stable|next|latest>  Release channel (default: stable)"
            echo "  --version <version>             Install specific version (e.g., v0.1.0)"
            echo "  --install-dir <path>            Installation directory (default: ~/.local/bin)"
            echo "  --static                        Use static build (musl, useful for Alpine/Docker)"
            echo "  --verbose, -v                   Enable verbose output"
            echo "  --build                         Build from source instead of downloading binary"
            echo "  -h, --help                      Show this help message"
            echo ""
            echo "Channels:"
            echo "  stable   Latest stable release (recommended)"
            echo "  next     Latest pre-release from main branch"
            echo "  latest   Absolute latest release (stable or pre-release)"
            echo ""
            echo "Examples:"
            echo "  $0                              # Install latest stable"
            echo "  $0 --channel next               # Install latest next (pre-release)"
            echo "  $0 --channel latest             # Install absolute latest"
            echo "  $0 --version v0.1.0             # Install specific version"
            echo "  $0 --static                     # Install static build (for Alpine/Docker)"
            echo "  $0 --verbose                    # Install with verbose output"
            echo "  $0 --build                      # Build from source (requires Rust)"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Verbose logging
log_verbose() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "${BLUE}[VERBOSE]${NC} $*"
    fi
}

# Print banner
print_banner() {
    echo -e "${BOLD}${BLUE}"
    echo "╔═══════════════════════════════════════╗"
    echo "║                                       ║"
    echo "║           redblue installer           ║"
    echo "║   ONE Tool to Replace Them ALL        ║"
    echo "║                                       ║"
    echo "╚═══════════════════════════════════════╝"
    echo -e "${NC}"
}

# Detect OS and architecture
detect_platform() {
    echo -e "${BLUE}Detecting platform...${NC}"

    local os=$(uname -s)
    local arch=$(uname -m)

    case "$os" in
        Linux*)
            OS="linux"
            ;;
        Darwin*)
            OS="macos"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            OS="windows"
            ;;
        *)
            echo -e "${RED}Unsupported operating system: $os${NC}"
            exit 1
            ;;
    esac

    case "$arch" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            ;;
        armv7l|armv7)
            ARCH="armv7"
            ;;
        *)
            echo -e "${RED}Unsupported architecture: $arch${NC}"
            echo -e "${YELLOW}Supported architectures: x86_64, aarch64, armv7${NC}"
            exit 1
            ;;
    esac

    # Build platform string
    if [ "$OS" = "linux" ] && [ "$STATIC" = "true" ] && [ "$ARCH" = "aarch64" ]; then
        # Use static musl build for Alpine/Docker on ARM64
        PLATFORM="${OS}-${ARCH}-static"
        echo -e "${GREEN}✓ Platform: $PLATFORM (static/musl)${NC}"
    else
        PLATFORM="${OS}-${ARCH}"
        echo -e "${GREEN}✓ Platform: $PLATFORM${NC}"
    fi

    # Detect if running in Alpine/musl environment
    if [ "$OS" = "linux" ] && [ -z "$STATIC" ]; then
        if [ -f /etc/alpine-release ] || ldd --version 2>&1 | grep -q musl; then
            echo -e "${YELLOW}⚠ Detected musl/Alpine environment${NC}"
            if [ "$ARCH" = "aarch64" ]; then
                echo -e "${YELLOW}  Switching to static build...${NC}"
                PLATFORM="${OS}-${ARCH}-static"
            fi
        fi
    fi
}

# Simple JSON value extractor (no jq dependency)
# Usage: json_get_value "$json" "key"
json_get_value() {
    local json="$1"
    local key="$2"
    echo "$json" | sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

# Extract tag_name from a release object in JSON array
# Handles finding first matching release (prerelease or not)
extract_release_tag() {
    local json="$1"
    local prerelease_only="$2"

    if [ "$prerelease_only" = "true" ]; then
        # Find releases where prerelease is true and extract tag_name
        # This awk script parses the JSON array properly
        echo "$json" | awk '
        BEGIN { in_release=0; prerelease=0; tag="" }
        /"tag_name"/ { gsub(/.*"tag_name"[[:space:]]*:[[:space:]]*"/, ""); gsub(/".*/, ""); tag=$0 }
        /"prerelease"[[:space:]]*:[[:space:]]*true/ { prerelease=1 }
        /^\s*\}/ {
            if (prerelease == 1 && tag != "") {
                print tag
                exit
            }
            prerelease=0
            tag=""
        }
        ' | head -1
    else
        # Get first tag_name from the array (latest release)
        echo "$json" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/'
    fi
}

# Get release information
get_release_info() {
    echo -e "${BLUE}Fetching release information...${NC}"

    local api_url
    local releases_json

    if [ -n "$VERSION" ]; then
        # Specific version requested
        api_url="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
        echo -e "${BLUE}  Channel: custom version ($VERSION)${NC}"
    elif [ "$CHANNEL" = "stable" ]; then
        # Stable release only (GitHub's /latest endpoint)
        api_url="https://api.github.com/repos/$REPO/releases/latest"
        echo -e "${BLUE}  Channel: stable${NC}"
    else
        # Both 'latest' and 'next' need to fetch all releases
        api_url="https://api.github.com/repos/$REPO/releases"
        if [ "$CHANNEL" = "next" ]; then
            echo -e "${BLUE}  Channel: next (pre-release)${NC}"
        else
            echo -e "${BLUE}  Channel: latest (any release)${NC}"
        fi
    fi

    # Fetch release data
    log_verbose "Fetching from: $api_url"
    local fetch_exit_code=0
    
    # Temporarily disable exit on error for the fetch operation
    set +e
    if command -v curl >/dev/null 2>&1; then
        log_verbose "Using curl to fetch release data"
        releases_json=$(curl -fsSL "$api_url" 2>&1)
        fetch_exit_code=$?
        log_verbose "curl exit code: $fetch_exit_code"
        if [ $fetch_exit_code -ne 0 ]; then
            log_verbose "curl error output: $releases_json"
        fi
    elif command -v wget >/dev/null 2>&1; then
        log_verbose "Using wget to fetch release data"
        releases_json=$(wget -qO- "$api_url" 2>&1)
        fetch_exit_code=$?
        log_verbose "wget exit code: $fetch_exit_code"
        if [ $fetch_exit_code -ne 0 ]; then
            log_verbose "wget error output: $releases_json"
        fi
    else
        echo -e "${RED}Error: curl or wget is required${NC}"
        set -e
        exit 1
    fi
    # Re-enable exit on error
    set -e

    log_verbose "Fetch completed with exit code: $fetch_exit_code"
    log_verbose "Response length: ${#releases_json} bytes"
    
    if [ -z "$releases_json" ] || echo "$releases_json" | grep -q "404"; then
        echo -e "${RED}Error: Could not fetch release information${NC}"
        echo -e "${YELLOW}No releases found at: https://github.com/$REPO/releases${NC}"
        echo ""
        echo -e "${BLUE}This repository doesn't have any published releases yet.${NC}"
        echo -e "${BLUE}You can build from source instead using:${NC}"
        echo -e "  ${GREEN}$0 --build${NC}"
        echo ""
        echo "Or manually build with:"
        echo -e "  ${GREEN}cargo build --release${NC}"
        echo -e "  ${GREEN}cargo install --path .${NC}"
        exit 1
    fi

    # Check for rate limiting
    if echo "$releases_json" | grep -q "API rate limit exceeded"; then
        echo -e "${RED}Error: GitHub API rate limit exceeded${NC}"
        echo -e "${YELLOW}Try again later or set GITHUB_TOKEN environment variable${NC}"
        exit 1
    fi

    # Extract tag based on channel
    if [ -n "$VERSION" ] || [ "$CHANNEL" = "stable" ]; then
        # Single release object - extract tag_name directly
        RELEASE_TAG=$(json_get_value "$releases_json" "tag_name")
    elif [ "$CHANNEL" = "next" ]; then
        # Find first pre-release
        RELEASE_TAG=$(extract_release_tag "$releases_json" "true")
        if [ -z "$RELEASE_TAG" ]; then
            echo -e "${YELLOW}No pre-release found, falling back to latest stable${NC}"
            RELEASE_TAG=$(extract_release_tag "$releases_json" "false")
        fi
    else
        # 'latest' channel - get absolute first release
        RELEASE_TAG=$(extract_release_tag "$releases_json" "false")
    fi

    if [ -z "$RELEASE_TAG" ]; then
        echo -e "${RED}Error: Could not determine release version${NC}"
        echo -e "${YELLOW}Make sure releases exist at: https://github.com/$REPO/releases${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ Version: $RELEASE_TAG${NC}"
}

# Download binary
download_binary() {
    local binary_name="rb-${PLATFORM}"
    if [ "$OS" = "windows" ]; then
        binary_name="${binary_name}.exe"
    fi

    local url="https://github.com/$REPO/releases/download/$RELEASE_TAG/$binary_name"
    local tmp_file="/tmp/$binary_name"

    echo -e "${BLUE}Downloading redblue $RELEASE_TAG for $PLATFORM...${NC}"
    echo -e "${BLUE}  URL: $url${NC}"

    if command -v curl >/dev/null 2>&1; then
        if ! curl -fL --progress-bar -o "$tmp_file" "$url"; then
            echo -e "${RED}Error: Download failed${NC}"
            exit 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget --show-progress -O "$tmp_file" "$url"; then
            echo -e "${RED}Error: Download failed${NC}"
            exit 1
        fi
    fi

    if [ ! -f "$tmp_file" ]; then
        echo -e "${RED}Error: Downloaded file not found${NC}"
        exit 1
    fi

    DOWNLOADED_FILE="$tmp_file"
    echo -e "${GREEN}✓ Downloaded successfully${NC}"
}

# Verify checksum (MANDATORY for security)
verify_checksum() {
    local binary_name="rb-${PLATFORM}"
    if [ "$OS" = "windows" ]; then
        binary_name="${binary_name}.exe"
    fi

    local checksum_url="https://github.com/$REPO/releases/download/$RELEASE_TAG/${binary_name}.sha256"
    local checksum_file="/tmp/${binary_name}.sha256"

    echo -e "${BLUE}Verifying integrity...${NC}"

    # Download checksum file from release
    if command -v curl >/dev/null 2>&1; then
        if ! curl -fsSL -o "$checksum_file" "$checksum_url" 2>/dev/null; then
            echo -e "${YELLOW}⚠ Checksum file not available for this release${NC}"
            echo -e "${YELLOW}  Skipping verification (use --no-verify to suppress this warning)${NC}"
            return 0
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -qO "$checksum_file" "$checksum_url" 2>/dev/null; then
            echo -e "${YELLOW}⚠ Checksum file not available for this release${NC}"
            return 0
        fi
    fi

    # Read expected hash from checksum file
    # Format: "hash  filename" or just "hash"
    local expected_hash=$(cat "$checksum_file" | awk '{print $1}' | tr -d '[:space:]')

    if [ -z "$expected_hash" ]; then
        echo -e "${YELLOW}⚠ Could not read expected hash${NC}"
        rm -f "$checksum_file"
        return 0
    fi

    # Calculate actual hash of downloaded binary
    local actual_hash=""
    if command -v sha256sum >/dev/null 2>&1; then
        actual_hash=$(sha256sum "$DOWNLOADED_FILE" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual_hash=$(shasum -a 256 "$DOWNLOADED_FILE" | awk '{print $1}')
    else
        echo -e "${YELLOW}⚠ Cannot verify checksum (sha256sum/shasum not found)${NC}"
        rm -f "$checksum_file"
        return 0
    fi

    # Compare hashes
    echo -e "${BLUE}  Expected: ${expected_hash}${NC}"
    echo -e "${BLUE}  Actual:   ${actual_hash}${NC}"

    if [ "$expected_hash" = "$actual_hash" ]; then
        echo -e "${GREEN}✓ Integrity verified - SHA256 checksum matches${NC}"
    else
        echo -e "${RED}✗ CHECKSUM MISMATCH - Binary may be corrupted or tampered!${NC}"
        echo -e "${RED}  Expected: ${expected_hash}${NC}"
        echo -e "${RED}  Got:      ${actual_hash}${NC}"
        echo ""
        echo -e "${RED}For security, aborting installation.${NC}"
        echo -e "${YELLOW}If this persists, please report at: https://github.com/$REPO/issues${NC}"
        rm -f "$DOWNLOADED_FILE" "$checksum_file"
        exit 1
    fi

    rm -f "$checksum_file"
}

# Install binary
install_binary() {
    echo -e "${BLUE}Installing to $INSTALL_DIR/$BINARY_NAME...${NC}"

    # Create install directory if it doesn't exist
    mkdir -p "$INSTALL_DIR"

    # Move binary to install directory
    if [ "$OS" = "windows" ]; then
        mv "$DOWNLOADED_FILE" "$INSTALL_DIR/${BINARY_NAME}.exe"
    else
        mv "$DOWNLOADED_FILE" "$INSTALL_DIR/$BINARY_NAME"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
    fi

    echo -e "${GREEN}✓ Installation complete!${NC}"
}

# Check if install directory is in PATH
check_path() {
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo ""
        echo -e "${YELLOW}⚠ Warning: $INSTALL_DIR is not in your PATH${NC}"
        echo ""
        echo "Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
        echo -e "  ${BLUE}export PATH=\"\$PATH:$INSTALL_DIR\"${NC}"
        echo ""
        echo "Then reload your shell:"
        echo -e "  ${BLUE}source ~/.bashrc${NC}  # or ~/.zshrc"
        echo ""
    fi
}

# Build from source
build_from_source() {
    echo -e "${BLUE}Building redblue from source...${NC}"
    echo ""
    
    # Check if we're in the right directory
    if [ ! -f "Cargo.toml" ]; then
        echo -e "${RED}Error: Cargo.toml not found${NC}"
        echo -e "${YELLOW}This script must be run from the redblue source directory, or${NC}"
        echo -e "${YELLOW}you need to clone the repository first:${NC}"
        echo ""
        echo -e "  ${GREEN}git clone https://github.com/$REPO.git${NC}"
        echo -e "  ${GREEN}cd redblue${NC}"
        echo -e "  ${GREEN}./install.sh --build${NC}"
        exit 1
    fi
    
    # Check if cargo is installed
    if ! command -v cargo >/dev/null 2>&1; then
        echo -e "${RED}Error: Rust/Cargo is not installed${NC}"
        echo ""
        echo "Install Rust from: https://rustup.rs/"
        echo "Or run:"
        echo -e "  ${GREEN}curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
        exit 1
    fi
    
    log_verbose "Rust version: $(rustc --version)"
    log_verbose "Cargo version: $(cargo --version)"
    
    # Check for required build tools
    local missing_tools=()
    if ! command -v cmake >/dev/null 2>&1; then
        missing_tools+=("cmake")
    fi
    if ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
        missing_tools+=("gcc or clang")
    fi
    if ! command -v make >/dev/null 2>&1; then
        missing_tools+=("make")
    fi
    
    # Check for libclang (needed for bindgen/boring-sys)
    if ! ldconfig -p 2>/dev/null | grep -q libclang; then
        if [ ! -f /usr/lib/libclang.so ] && [ ! -f /usr/lib64/libclang.so ] && [ ! -f /usr/lib/x86_64-linux-gnu/libclang.so ]; then
            missing_tools+=("libclang-dev")
        fi
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}Error: Missing required build tools${NC}"
        echo ""
        echo "Required tools: ${missing_tools[*]}"
        echo ""
        echo "Install them with:"
        if [ -f /etc/debian_version ]; then
            echo -e "  ${GREEN}sudo apt-get update && sudo apt-get install -y cmake build-essential libclang-dev${NC}"
        elif [ -f /etc/redhat-release ]; then
            echo -e "  ${GREEN}sudo yum install -y cmake gcc-c++ make clang-devel${NC}"
        elif [ -f /etc/alpine-release ]; then
            echo -e "  ${GREEN}sudo apk add cmake gcc g++ make musl-dev clang-dev${NC}"
        else
            echo -e "  ${YELLOW}Install cmake, gcc/clang, make, and libclang-dev for your distribution${NC}"
        fi
        exit 1
    fi
    
    log_verbose "Build tools check passed"
    
    echo -e "${BLUE}Building release binary...${NC}"
    echo -e "${YELLOW}This may take several minutes on first build...${NC}"
    echo ""
    
    if [ "$VERBOSE" = "true" ]; then
        cargo build --release
    else
        cargo build --release 2>&1 | grep -E "(Compiling|Finished|error|warning:)" || cargo build --release
    fi
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Build failed${NC}"
        exit 1
    fi
    
    # Check if binary exists (try both 'redblue' and 'rb' names)
    if [ -f "target/release/rb" ]; then
        DOWNLOADED_FILE="target/release/rb"
    elif [ -f "target/release/redblue" ]; then
        DOWNLOADED_FILE="target/release/redblue"
    else
        echo -e "${RED}Error: Binary not found after build${NC}"
        echo -e "${YELLOW}Expected to find target/release/rb or target/release/redblue${NC}"
        exit 1
    fi
    
    RELEASE_TAG="source-build"
    log_verbose "Built binary: $DOWNLOADED_FILE"
    echo -e "${GREEN}✓ Build successful${NC}"
}

# Print success message
print_success() {
    echo ""
    echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║    Installation successful! 🎉        ║${NC}"
    echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}Installed:${NC}"
    echo -e "  Version: ${GREEN}$RELEASE_TAG${NC}"
    echo -e "  Binary:  ${BLUE}$INSTALL_DIR/$BINARY_NAME${NC}"
    echo ""
    echo -e "${BOLD}Quick Start:${NC}"
    echo -e "  ${BLUE}rb --version${NC}                # Check version"
    echo -e "  ${BLUE}rb help${NC}                     # Show help"
    echo -e "  ${BLUE}rb network ports scan <ip>${NC}   # Scan ports"
    echo -e "  ${BLUE}rb dns record lookup <domain>${NC} # DNS lookup"
    echo ""
    echo -e "${BOLD}Optional - Install Wordlists:${NC}"
    echo -e "  ${BLUE}rb wordlist collection list${NC}              # Show available wordlists"
    echo -e "  ${BLUE}rb wordlist collection install seclists${NC}  # Install SecLists (~1.2GB)"
    echo -e "  ${BLUE}rb wordlist collection install assetnote-dns${NC} # Install Assetnote DNS (~15MB)"
    echo ""
    echo -e "${YELLOW}Note:${NC} redblue includes embedded wordlists for offline use."
    echo -e "      Install additional collections for advanced fuzzing/enumeration."
    echo ""
    echo "Documentation: https://github.com/$REPO"
}

# Main installation flow
main() {
    print_banner
    
    if [ "$BUILD_FROM_SOURCE" = "true" ]; then
        # Build from source path
        log_verbose "Build from source mode enabled"
        detect_platform
        build_from_source
        install_binary
        check_path
        print_success
    else
        # Download binary path
        log_verbose "Binary download mode"
        detect_platform
        get_release_info
        download_binary
        verify_checksum
        install_binary
        check_path
        print_success
    fi
}

main "$@"
