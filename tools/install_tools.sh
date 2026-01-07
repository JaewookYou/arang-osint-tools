#!/bin/bash
# Red Iris Info Gather - Tool Installation Script
# Clones and builds all required tools locally in the project directory.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TOOLS_DIR="$PROJECT_DIR/tools/bin"
REPOS_DIR="$PROJECT_DIR/tools/repos"

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

# Create directories
mkdir -p "$TOOLS_DIR"
mkdir -p "$REPOS_DIR"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   🔴 RED IRIS INFO GATHER - Tool Installer                   ║"
echo "║   Installing all dependencies locally                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check prerequisites
print_status "Checking prerequisites..."

# Check Go
if ! command -v go &> /dev/null; then
    print_error "Go is not installed. Please install Go first:"
    echo "    brew install go"
    echo "    or download from https://golang.org/dl/"
    exit 1
fi
GO_VERSION=$(go version | awk '{print $3}')
print_success "Go found: $GO_VERSION"

# Check Python
if ! command -v python3 &> /dev/null; then
    print_error "Python3 is not installed."
    exit 1
fi
PYTHON_VERSION=$(python3 --version)
print_success "Python found: $PYTHON_VERSION"

# Check Git
if ! command -v git &> /dev/null; then
    print_error "Git is not installed."
    exit 1
fi
print_success "Git found"

echo ""
print_status "Installing Go tools..."

# ============================================
# Subfinder - Subdomain enumeration
# ============================================
print_status "Installing subfinder..."
if [ ! -f "$TOOLS_DIR/subfinder" ]; then
    cd "$REPOS_DIR"
    if [ ! -d "subfinder" ]; then
        git clone --depth 1 https://github.com/projectdiscovery/subfinder.git
    fi
    cd subfinder/cmd/subfinder
    go build -o "$TOOLS_DIR/subfinder" .
    print_success "subfinder installed"
else
    print_success "subfinder already installed"
fi

# ============================================
# Naabu - Port scanner
# ============================================
print_status "Installing naabu..."
if [ ! -f "$TOOLS_DIR/naabu" ]; then
    cd "$REPOS_DIR"
    if [ ! -d "naabu" ]; then
        git clone --depth 1 https://github.com/projectdiscovery/naabu.git
    fi
    cd naabu/cmd/naabu
    go build -o "$TOOLS_DIR/naabu" .
    print_success "naabu installed"
else
    print_success "naabu already installed"
fi

# ============================================
# Nuclei - Vulnerability scanner
# ============================================
print_status "Installing nuclei..."
if [ ! -f "$TOOLS_DIR/nuclei" ]; then
    cd "$REPOS_DIR"
    if [ ! -d "nuclei" ]; then
        git clone --depth 1 https://github.com/projectdiscovery/nuclei.git
    fi
    cd nuclei/cmd/nuclei
    go build -o "$TOOLS_DIR/nuclei" .
    print_success "nuclei installed"
else
    print_success "nuclei already installed"
fi

# ============================================
# httpx - HTTP probing (optional, useful)
# ============================================
print_status "Installing httpx..."
if [ ! -f "$TOOLS_DIR/httpx" ]; then
    cd "$REPOS_DIR"
    if [ ! -d "httpx" ]; then
        git clone --depth 1 https://github.com/projectdiscovery/httpx.git
    fi
    cd httpx/cmd/httpx
    go build -o "$TOOLS_DIR/httpx" .
    print_success "httpx installed"
else
    print_success "httpx already installed"
fi

echo ""
print_status "Installing Python tools..."

# ============================================
# Dirsearch - Directory scanner
# ============================================
print_status "Installing dirsearch..."
cd "$REPOS_DIR"
if [ ! -d "dirsearch" ]; then
    git clone --depth 1 https://github.com/maurosoria/dirsearch.git
    print_success "dirsearch cloned"
else
    print_success "dirsearch already cloned"
fi

# ============================================
# Sublist3r - Subdomain enumeration
# ============================================
print_status "Installing Sublist3r..."
cd "$REPOS_DIR"
if [ ! -d "Sublist3r" ]; then
    git clone --depth 1 https://github.com/aboul3la/Sublist3r.git
    print_success "Sublist3r cloned"
else
    print_success "Sublist3r already cloned"
fi

echo ""
print_status "Installing Python dependencies..."

# Install Python requirements
cd "$PROJECT_DIR"
if [ -f "requirements.txt" ]; then
    if [ -d ".venv" ]; then
        source .venv/bin/activate
        pip install -q -r requirements.txt 2>/dev/null || true
        # Install dirsearch dependencies
        if [ -f "$REPOS_DIR/dirsearch/requirements.txt" ]; then
            pip install -q -r "$REPOS_DIR/dirsearch/requirements.txt" 2>/dev/null || true
        fi
        # Install Sublist3r dependencies
        pip install -q dnspython requests argparse 2>/dev/null || true
        print_success "Python dependencies installed"
    else
        print_warning "Virtual environment not found. Create with: python3 -m venv .venv"
    fi
fi

echo ""
print_status "Checking installations..."
echo ""

# Verify installations
echo "Tool Status:"
echo "─────────────────────────────────────"

check_tool() {
    if [ -f "$TOOLS_DIR/$1" ]; then
        echo -e "  ${GREEN}✓${NC} $1"
    else
        echo -e "  ${RED}✗${NC} $1"
    fi
}

check_repo() {
    if [ -d "$REPOS_DIR/$1" ]; then
        echo -e "  ${GREEN}✓${NC} $1"
    else
        echo -e "  ${RED}✗${NC} $1"
    fi
}

echo "Go tools (in $TOOLS_DIR):"
check_tool "subfinder"
check_tool "naabu"
check_tool "nuclei"
check_tool "httpx"

echo ""
echo "Python tools (in $REPOS_DIR):"
check_repo "dirsearch"
check_repo "Sublist3r"

echo ""
echo "─────────────────────────────────────"
print_success "Installation complete!"
echo ""
echo "Tools are installed in: $TOOLS_DIR"
echo "Repos are cloned in: $REPOS_DIR"
echo ""
echo "To use the tool:"
echo "  cd $PROJECT_DIR"
echo "  source .venv/bin/activate"
echo "  sudo python main.py --input targets.txt --verbose"
echo ""
