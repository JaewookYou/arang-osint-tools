#!/bin/bash
# Red Iris Info Gather - Initial Setup Script
# Sets up setuid bits for network tools to run without sudo
#
# SECURITY WARNING: This script modifies system binaries to run with elevated privileges.
# Only run this on dedicated security testing machines.
#
# Usage: sudo ./setup.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
    echo "Usage: sudo ./setup.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
TOOLS_BIN="$PROJECT_DIR/tools/bin"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   🔴 RED IRIS INFO GATHER - Initial Setup                    ║"
echo "║   Setting up permissions for network scanning tools          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ============================================
# 1. Set capabilities on local tools (preferred over setuid)
# ============================================
print_status "Setting capabilities on local tools..."

# Check if setcap is available
if command -v setcap &> /dev/null; then
    # naabu - needs raw socket access
    if [ -f "$TOOLS_BIN/naabu" ]; then
        setcap cap_net_raw,cap_net_admin+eip "$TOOLS_BIN/naabu" 2>/dev/null || \
        chmod u+s "$TOOLS_BIN/naabu"
        print_success "naabu: capabilities set"
    fi
    
    # subfinder - no special permissions needed
    if [ -f "$TOOLS_BIN/subfinder" ]; then
        print_success "subfinder: no special permissions needed"
    fi
    
    # nuclei - no special permissions needed
    if [ -f "$TOOLS_BIN/nuclei" ]; then
        print_success "nuclei: no special permissions needed"
    fi
    
    # httpx - no special permissions needed
    if [ -f "$TOOLS_BIN/httpx" ]; then
        print_success "httpx: no special permissions needed"
    fi
else
    print_warning "setcap not found, using setuid instead"
    
    # Fallback to setuid
    if [ -f "$TOOLS_BIN/naabu" ]; then
        chmod u+s "$TOOLS_BIN/naabu"
        chown root:root "$TOOLS_BIN/naabu"
        print_success "naabu: setuid bit set"
    fi
fi

# ============================================
# 2. Set capabilities on system nmap
# ============================================
print_status "Setting up nmap permissions..."

NMAP_PATH=$(which nmap 2>/dev/null || echo "")

if [ -n "$NMAP_PATH" ] && [ -f "$NMAP_PATH" ]; then
    if command -v setcap &> /dev/null; then
        # Set capabilities (preferred, more secure than setuid)
        setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP_PATH" 2>/dev/null && \
        print_success "nmap: capabilities set on $NMAP_PATH" || \
        print_warning "Could not set capabilities on nmap (may need to disable SIP on macOS)"
    else
        print_warning "setcap not available, nmap will require sudo"
    fi
else
    print_warning "nmap not found in PATH"
fi

# ============================================
# 3. Create .env file if not exists
# ============================================
print_status "Setting up environment configuration..."

ENV_FILE="$PROJECT_DIR/.env"
ENV_EXAMPLE="$PROJECT_DIR/.env.example"

if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        chmod 600 "$ENV_FILE"
        print_success "Created .env from .env.example"
        print_warning "Please edit .env and add your API keys"
    else
        print_warning ".env.example not found"
    fi
else
    print_success ".env already exists"
fi

# ============================================
# 4. Set correct permissions on project files
# ============================================
print_status "Setting project file permissions..."

# Make scripts executable
chmod +x "$PROJECT_DIR/tools/install_tools.sh" 2>/dev/null || true
chmod +x "$PROJECT_DIR/setup.sh" 2>/dev/null || true
chmod +x "$PROJECT_DIR/main.py" 2>/dev/null || true

# Protect .env file
chmod 600 "$PROJECT_DIR/.env" 2>/dev/null || true

print_success "Permissions set"

# ============================================
# 5. Verify setup
# ============================================
echo ""
print_status "Verifying setup..."
echo ""
echo "Tool Status:"
echo "─────────────────────────────────────"

verify_tool() {
    local tool_path="$1"
    local tool_name="$2"
    
    if [ -f "$tool_path" ]; then
        local perms=$(ls -la "$tool_path" | awk '{print $1}')
        local caps=$(getcap "$tool_path" 2>/dev/null || echo "no caps")
        
        if echo "$perms" | grep -q "s"; then
            echo -e "  ${GREEN}✓${NC} $tool_name: setuid enabled"
        elif echo "$caps" | grep -q "cap_net"; then
            echo -e "  ${GREEN}✓${NC} $tool_name: capabilities set"
        else
            echo -e "  ${YELLOW}!${NC} $tool_name: may need sudo"
        fi
    else
        echo -e "  ${RED}✗${NC} $tool_name: not found"
    fi
}

verify_tool "$TOOLS_BIN/naabu" "naabu (local)"
verify_tool "$NMAP_PATH" "nmap (system)"

echo ""
echo "─────────────────────────────────────"
print_success "Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit .env with your API keys:"
echo "     nano $PROJECT_DIR/.env"
echo ""
echo "  2. Run the tool (no sudo needed now):"
echo "     cd $PROJECT_DIR"
echo "     source .venv/bin/activate"
echo "     python main.py --input targets.txt --verbose"
echo ""

# macOS specific note
if [[ "$OSTYPE" == "darwin"* ]]; then
    print_warning "macOS Note: System Integrity Protection (SIP) may prevent"
    print_warning "setting capabilities on system binaries like nmap."
    print_warning "The tool will fall back to TCP connect scans if needed."
fi
