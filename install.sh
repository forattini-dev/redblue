#!/usr/bin/env bash
#
# redblue installer script
# Downloads and installs the latest release of redblue
#
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REPO="forattini-dev/redblue"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="rb"

# Detect OS and architecture
detect_platform() {
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
}

# Get latest release version
get_latest_version() {
    echo -e "${BLUE}Fetching latest release...${NC}"

    if command -v curl >/dev/null 2>&1; then
        VERSION=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget >/dev/null 2>&1; then
        VERSION=$(wget -qO- "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        echo -e "${RED}Error: curl or wget is required${NC}"
        exit 1
    fi

    if [ -z "$VERSION" ]; then
        echo -e "${RED}Error: Could not fetch latest version${NC}"
        exit 1
    fi

    echo -e "${GREEN}Latest version: $VERSION${NC}"
}

# Download binary
download_binary() {
    local binary_name="rb-${PLATFORM}"
    if [ "$OS" = "windows" ]; then
        binary_name="${binary_name}.exe"
    fi

    local url="https://github.com/$REPO/releases/download/$VERSION/$binary_name"
    local tmp_file="/tmp/$binary_name"

    echo -e "${BLUE}Downloading redblue $VERSION for $PLATFORM...${NC}"

    if command -v curl >/dev/null 2>&1; then
        curl -L -o "$tmp_file" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$tmp_file" "$url"
    fi

    if [ ! -f "$tmp_file" ]; then
        echo -e "${RED}Error: Download failed${NC}"
        exit 1
    fi

    DOWNLOADED_FILE="$tmp_file"
}

# Verify checksum
verify_checksum() {
    local binary_name="rb-${PLATFORM}"
    if [ "$OS" = "windows" ]; then
        binary_name="${binary_name}.exe"
    fi

    local checksum_url="https://github.com/$REPO/releases/download/$VERSION/${binary_name}.sha256"
    local checksum_file="/tmp/${binary_name}.sha256"

    echo -e "${BLUE}Verifying checksum...${NC}"

    if command -v curl >/dev/null 2>&1; then
        curl -sL -o "$checksum_file" "$checksum_url" || true
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$checksum_file" "$checksum_url" || true
    fi

    if [ -f "$checksum_file" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            (cd /tmp && sha256sum -c "$checksum_file")
        elif command -v shasum >/dev/null 2>&1; then
            (cd /tmp && shasum -a 256 -c "$checksum_file")
        else
            echo -e "${YELLOW}Warning: Cannot verify checksum (sha256sum not found)${NC}"
        fi
        rm -f "$checksum_file"
    else
        echo -e "${YELLOW}Warning: Checksum file not found${NC}"
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
        echo -e "${YELLOW}Warning: $INSTALL_DIR is not in your PATH${NC}"
        echo -e "Add this line to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
        echo -e "  ${BLUE}export PATH=\"\$PATH:$INSTALL_DIR\"${NC}"
    fi
}

# Main installation flow
main() {
    echo -e "${GREEN}redblue installer${NC}"
    echo ""

    detect_platform
    get_latest_version
    download_binary
    verify_checksum
    install_binary
    check_path

    echo ""
    echo -e "${GREEN}Installation successful!${NC}"
    echo ""
    echo "Run 'rb --help' to get started"
    echo "Run 'rb help' for command documentation"
}

main "$@"
