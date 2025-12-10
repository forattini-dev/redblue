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
        -h|--help)
            echo "redblue installer"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --channel <stable|next|latest>  Release channel (default: stable)"
            echo "  --version <version>               Install specific version (e.g., v0.1.0)"
            echo "  --install-dir <path>              Installation directory (default: ~/.local/bin)"
            echo "  -h, --help                        Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                # Install latest stable"
            echo "  $0 --channel next                # Install latest next"
            echo "  $0 --version v0.1.0               # Install specific version"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

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
        *)
            echo -e "${RED}Unsupported architecture: $arch${NC}"
            exit 1
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
    echo -e "${GREEN}✓ Platform: $PLATFORM${NC}"
}

# Get release information
get_release_info() {
    echo -e "${BLUE}Fetching release information...${NC}"

    local api_url

    if [ -n "$VERSION" ]; then
        # Specific version requested
        api_url="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
        echo -e "${BLUE}  Channel: custom version ($VERSION)${NC}"
    elif [ "$CHANNEL" = "latest" ]; then
        # Latest release (including pre-releases)
        api_url="https://api.github.com/repos/$REPO/releases"
        echo -e "${BLUE}  Channel: latest (any release)${NC}"
    elif [ "$CHANNEL" = "next" ]; then
        # Latest next pre-release
        api_url="https://api.github.com/repos/$REPO/releases"
        echo -e "${BLUE}  Channel: next (pre-release)${NC}"
    else
        # Stable release only
        api_url="https://api.github.com/repos/$REPO/releases/latest"
        echo -e "${BLUE}  Channel: stable${NC}"
    fi

    if command -v curl >/dev/null 2>&1; then
        if [ "$CHANNEL" = "latest" ] || [ "$CHANNEL" = "next" ]; then
            # Get first release (latest or next)
            local releases=$(curl -fsSL "$api_url")
            if [ "$CHANNEL" = "next" ]; then
                # Find first pre-release
                RELEASE_DATA=$(echo "$releases" | grep -A 100 '"prerelease": true' | head -100)
            else
                # Get absolute latest
                RELEASE_DATA=$(echo "$releases" | head -100)
            fi
        else
            RELEASE_DATA=$(curl -fsSL "$api_url")
        fi
    elif command -v wget >/dev/null 2>&1; then
        if [ "$CHANNEL" = "latest" ] || [ "$CHANNEL" = "next" ]; then
            local releases=$(wget -qO- "$api_url")
            if [ "$CHANNEL" = "next" ]; then
                RELEASE_DATA=$(echo "$releases" | grep -A 100 '"prerelease": true' | head -100)
            else
                RELEASE_DATA=$(echo "$releases" | head -100)
            fi
        else
            RELEASE_DATA=$(wget -qO- "$api_url")
        fi
    else
        echo -e "${RED}Error: curl or wget is required${NC}"
        exit 1
    fi

    if [ -z "$RELEASE_DATA" ]; then
        echo -e "${RED}Error: Could not fetch release information${NC}"
        exit 1
    fi

    # Extract tag name
    RELEASE_TAG=$(echo "$RELEASE_DATA" | grep '"tag_name":' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')

    if [ -z "$RELEASE_TAG" ]; then
        echo -e "${RED}Error: Could not determine release version${NC}"
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

# Verify checksum
verify_checksum() {
    local binary_name="rb-${PLATFORM}"
    if [ "$OS" = "windows" ]; then
        binary_name="${binary_name}.exe"
    fi

    local checksum_url="https://github.com/$REPO/releases/download/$RELEASE_TAG/${binary_name}.sha256"
    local checksum_file="/tmp/${binary_name}.sha256"

    echo -e "${BLUE}Verifying checksum...${NC}"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$checksum_file" "$checksum_url" 2>/dev/null || true
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$checksum_file" "$checksum_url" 2>/dev/null || true
    fi

    if [ -f "$checksum_file" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            (cd /tmp && sha256sum -c "$checksum_file" --status)
            echo -e "${GREEN}✓ Checksum verified${NC}"
        elif command -v shasum >/dev/null 2>&1; then
            (cd /tmp && shasum -a 256 -c "$checksum_file" --status)
            echo -e "${GREEN}✓ Checksum verified${NC}"
        else
            echo -e "${YELLOW}⚠ Warning: Cannot verify checksum (sha256sum not found)${NC}"
        fi
        rm -f "$checksum_file"
    else
        echo -e "${YELLOW}⚠ Warning: Checksum file not available${NC}"
    fi
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
    detect_platform
    get_release_info
    download_binary
    verify_checksum
    install_binary
    check_path
    print_success
}

main "$@"
