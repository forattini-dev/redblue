#!/usr/bin/env bash
#
# redblue uninstaller script
# Removes redblue from your system
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
BINARY_NAME="rb"
COMMON_INSTALL_DIRS=(
    "$HOME/.local/bin"
    "/usr/local/bin"
    "/usr/bin"
    "$HOME/bin"
)

# Print banner
print_banner() {
    echo -e "${BOLD}${RED}"
    echo "╔═══════════════════════════════════════╗"
    echo "║                                       ║"
    echo "║        redblue uninstaller            ║"
    echo "║                                       ║"
    echo "╚═══════════════════════════════════════╝"
    echo -e "${NC}"
}

# Find installed binaries
find_installations() {
    echo -e "${BLUE}Searching for redblue installations...${NC}"

    FOUND_INSTALLATIONS=()

    for dir in "${COMMON_INSTALL_DIRS[@]}"; do
        if [ -f "$dir/$BINARY_NAME" ]; then
            FOUND_INSTALLATIONS+=("$dir/$BINARY_NAME")
            echo -e "  ${YELLOW}Found:${NC} $dir/$BINARY_NAME"
        fi
    done

    # Also check if 'rb' is in PATH but in a different location
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        BINARY_PATH=$(command -v "$BINARY_NAME")
        if [[ ! " ${FOUND_INSTALLATIONS[@]} " =~ " ${BINARY_PATH} " ]]; then
            FOUND_INSTALLATIONS+=("$BINARY_PATH")
            echo -e "  ${YELLOW}Found:${NC} $BINARY_PATH (from PATH)"
        fi
    fi

    if [ ${#FOUND_INSTALLATIONS[@]} -eq 0 ]; then
        echo -e "${YELLOW}No redblue installations found.${NC}"
        return 1
    fi

    echo ""
    return 0
}

# Show version info
show_version_info() {
    for installation in "${FOUND_INSTALLATIONS[@]}"; do
        if [ -x "$installation" ]; then
            echo -e "${BLUE}Version info for $installation:${NC}"
            "$installation" --version 2>/dev/null || echo "  (unable to get version)"
            echo ""
        fi
    done
}

# Confirm uninstallation
confirm_uninstall() {
    echo -e "${BOLD}The following will be removed:${NC}"
    for installation in "${FOUND_INSTALLATIONS[@]}"; do
        echo "  - $installation"
    done
    echo ""

    # Check if running in interactive mode
    if [ -t 0 ]; then
        read -p "Do you want to continue? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Uninstallation cancelled.${NC}"
            exit 0
        fi
    else
        echo -e "${YELLOW}Running in non-interactive mode, assuming yes...${NC}"
    fi
}

# Remove binary
remove_binary() {
    local binary_path=$1
    local dir=$(dirname "$binary_path")

    echo -e "${BLUE}Removing $binary_path...${NC}"

    # Check if we need sudo
    if [ -w "$binary_path" ]; then
        rm -f "$binary_path"
        echo -e "  ${GREEN}✓ Removed${NC}"
    else
        # Need sudo
        if command -v sudo >/dev/null 2>&1; then
            echo -e "  ${YELLOW}Need sudo permission...${NC}"
            sudo rm -f "$binary_path"
            echo -e "  ${GREEN}✓ Removed${NC}"
        else
            echo -e "  ${RED}✗ Failed: No write permission and sudo not available${NC}"
            return 1
        fi
    fi
}

# Clean up config files (optional)
clean_config_files() {
    echo ""
    echo -e "${BLUE}Checking for configuration files...${NC}"

    local config_files=()

    # Check for config files in current directory
    if [ -f ".redblue.toml" ]; then
        config_files+=(".redblue.toml")
    fi

    if [ -f ".redblue.yaml" ]; then
        config_files+=(".redblue.yaml")
    fi

    if [ -f ".redblue.yml" ]; then
        config_files+=(".redblue.yml")
    fi

    # Check for .rdb files
    local rdb_files=$(find . -maxdepth 1 -name "*.rdb" 2>/dev/null)

    if [ ${#config_files[@]} -eq 0 ] && [ -z "$rdb_files" ]; then
        echo -e "  ${GREEN}No configuration files found in current directory${NC}"
        return 0
    fi

    echo ""
    echo -e "${YELLOW}Found configuration/data files in current directory:${NC}"

    for file in "${config_files[@]}"; do
        echo "  - $file"
    done

    if [ -n "$rdb_files" ]; then
        echo "$rdb_files" | while read -r file; do
            echo "  - $file"
        done
    fi

    echo ""
    if [ -t 0 ]; then
        read -p "Do you want to remove these files? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            for file in "${config_files[@]}"; do
                rm -f "$file" && echo -e "  ${GREEN}✓ Removed $file${NC}"
            done

            if [ -n "$rdb_files" ]; then
                echo "$rdb_files" | while read -r file; do
                    rm -f "$file" && echo -e "  ${GREEN}✓ Removed $file${NC}"
                done
            fi
        else
            echo -e "${YELLOW}Configuration files kept.${NC}"
        fi
    else
        echo -e "${YELLOW}Non-interactive mode: Configuration files kept.${NC}"
        echo -e "${YELLOW}To remove them manually, run: rm -f .redblue.* *.rdb${NC}"
    fi
}

# Print success message
print_success() {
    echo ""
    echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║   Uninstallation complete! 👋         ║${NC}"
    echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}redblue has been removed from your system.${NC}"
    echo ""
    echo "Thanks for using redblue!"
    echo ""
    echo "To reinstall:"
    echo -e "  ${BLUE}curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash${NC}"
    echo ""
}

# Main uninstallation flow
main() {
    print_banner

    if ! find_installations; then
        echo -e "${GREEN}Nothing to uninstall.${NC}"
        exit 0
    fi

    show_version_info
    confirm_uninstall

    echo ""
    echo -e "${BOLD}Uninstalling...${NC}"
    echo ""

    # Remove each installation
    for installation in "${FOUND_INSTALLATIONS[@]}"; do
        remove_binary "$installation"
    done

    # Ask about config files
    clean_config_files

    print_success
}

# Handle --force flag
if [ "$1" = "--force" ] || [ "$1" = "-f" ]; then
    echo "Force mode: skipping confirmations"
    export FORCE_MODE=1
fi

main "$@"
