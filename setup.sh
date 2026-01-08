#!/bin/bash
# Red Iris Info Gather - Comprehensive Setup Script
#
# 이 스크립트는 모든 의존성을 자동으로 확인하고 설치합니다:
# - Python 가상환경 및 패키지
# - Go 도구: subfinder, naabu, nuclei, httpx
# - Python 도구: dirsearch, Sublist3r
# - 시스템 도구: nmap, chrome
#
# Usage: ./setup.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_header() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}\n"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
TOOLS_BIN="$PROJECT_DIR/tools/bin"
TOOLS_REPOS="$PROJECT_DIR/tools/repos"
VENV_DIR="$PROJECT_DIR/.venv"

# Create directories
mkdir -p "$TOOLS_BIN" "$TOOLS_REPOS"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   🔴 RED IRIS INFO GATHER - Comprehensive Setup              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ============================================
# 1. Check system prerequisites
# ============================================
print_header "시스템 요구사항 확인"

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    print_success "Python $PYTHON_VERSION"
else
    print_error "Python3이 설치되어 있지 않습니다."
    echo "설치: brew install python3 (macOS) 또는 apt install python3 (Linux)"
    exit 1
fi

# Check Go
GO_INSTALLED=false
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | cut -d' ' -f3)
    print_success "Go $GO_VERSION"
    GO_INSTALLED=true
else
    print_warning "Go가 설치되어 있지 않습니다. Go 도구 설치를 건너뜁니다."
    echo "설치: brew install go (macOS) 또는 apt install golang-go (Linux)"
fi

# Check Git
if command -v git &> /dev/null; then
    print_success "Git $(git --version | cut -d' ' -f3)"
else
    print_error "Git이 설치되어 있지 않습니다."
    exit 1
fi

# Check nmap
if command -v nmap &> /dev/null; then
    print_success "nmap $(nmap --version | head -1 | cut -d' ' -f3)"
else
    print_warning "nmap이 설치되어 있지 않습니다."
    echo "설치: brew install nmap (macOS) 또는 apt install nmap (Linux)"
fi

# Check Chrome
CHROME_FOUND=false
if [[ "$OSTYPE" == "darwin"* ]]; then
    if [ -d "/Applications/Google Chrome.app" ]; then
        print_success "Chrome 설치됨"
        CHROME_FOUND=true
    fi
else
    if command -v google-chrome &> /dev/null || command -v chromium-browser &> /dev/null; then
        print_success "Chrome/Chromium 설치됨"
        CHROME_FOUND=true
    fi
fi
if [ "$CHROME_FOUND" = false ]; then
    print_warning "Chrome이 설치되어 있지 않습니다. 스크린샷 기능이 제한됩니다."
fi

# ============================================
# 2. Python Virtual Environment
# ============================================
print_header "Python 가상환경 설정"

if [ ! -d "$VENV_DIR" ]; then
    print_status "가상환경 생성 중..."
    python3 -m venv "$VENV_DIR"
    print_success "가상환경 생성 완료"
else
    print_success "가상환경 이미 존재"
fi

# Activate venv
source "$VENV_DIR/bin/activate"

# Install Python packages
print_status "Python 패키지 설치 중..."
pip install --quiet --upgrade pip
pip install --quiet -r "$PROJECT_DIR/requirements.txt" 2>/dev/null || {
    print_warning "일부 패키지 설치 실패, 개별 설치 시도..."
    pip install --quiet langgraph langchain langchain-core tldextract python-nmap selenium webdriver-manager aiohttp requests shodan Jinja2 click python-Wappalyzer webtech nvdlib dnspython
}
print_success "Python 패키지 설치 완료"

# ============================================
# 3. Go Tools Installation
# ============================================
print_header "Go 도구 설치"

install_go_tool() {
    local name=$1
    local repo=$2
    local build_path=$3
    
    if [ -f "$TOOLS_BIN/$name" ]; then
        print_success "$name 이미 설치됨"
        return 0
    fi
    
    if [ "$GO_INSTALLED" = false ]; then
        print_warning "$name 건너뜀 (Go 미설치)"
        return 0
    fi
    
    print_status "$name 설치 중..."
    
    local repo_dir="$TOOLS_REPOS/$name"
    
    # Clone if not exists
    if [ ! -d "$repo_dir" ]; then
        git clone --quiet --depth 1 "$repo" "$repo_dir" 2>/dev/null || {
            print_error "$name 클론 실패"
            return 1
        }
    fi
    
    # Build
    cd "$repo_dir/$build_path"
    go build -o "$TOOLS_BIN/$name" . 2>/dev/null || {
        print_error "$name 빌드 실패"
        cd "$PROJECT_DIR"
        return 1
    }
    cd "$PROJECT_DIR"
    
    if [ -f "$TOOLS_BIN/$name" ]; then
        print_success "$name 설치 완료"
    else
        print_error "$name 설치 실패"
    fi
}

# Install Go tools
install_go_tool "subfinder" "https://github.com/projectdiscovery/subfinder.git" "cmd/subfinder"
install_go_tool "naabu" "https://github.com/projectdiscovery/naabu.git" "cmd/naabu"
install_go_tool "nuclei" "https://github.com/projectdiscovery/nuclei.git" "cmd/nuclei"
install_go_tool "httpx" "https://github.com/projectdiscovery/httpx.git" "cmd/httpx"

# ============================================
# 4. Python Tools Installation
# ============================================
print_header "Python 도구 설치"

# Dirsearch
if [ -f "$TOOLS_REPOS/dirsearch/dirsearch.py" ]; then
    print_success "dirsearch 이미 설치됨"
else
    print_status "dirsearch 설치 중..."
    git clone --quiet --depth 1 https://github.com/maurosoria/dirsearch.git "$TOOLS_REPOS/dirsearch" 2>/dev/null && \
    print_success "dirsearch 설치 완료" || print_error "dirsearch 설치 실패"
fi

# Sublist3r
if [ -f "$TOOLS_REPOS/Sublist3r/sublist3r.py" ]; then
    print_success "Sublist3r 이미 설치됨"
else
    print_status "Sublist3r 설치 중..."
    git clone --quiet --depth 1 https://github.com/aboul3la/Sublist3r.git "$TOOLS_REPOS/Sublist3r" 2>/dev/null && \
    pip install --quiet -r "$TOOLS_REPOS/Sublist3r/requirements.txt" 2>/dev/null
    print_success "Sublist3r 설치 완료" || print_error "Sublist3r 설치 실패"
fi

# ============================================
# 5. Environment Configuration
# ============================================
print_header "환경 설정"

# Create .env file
if [ ! -f "$PROJECT_DIR/.env" ]; then
    if [ -f "$PROJECT_DIR/.env.example" ]; then
        cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
        chmod 600 "$PROJECT_DIR/.env"
        print_success ".env 파일 생성됨"
    fi
else
    print_success ".env 파일 이미 존재"
fi

# Make scripts executable
chmod +x "$PROJECT_DIR/main.py" 2>/dev/null || true
chmod +x "$PROJECT_DIR/setup.sh" 2>/dev/null || true

# ============================================
# 6. Execution Mode Selection
# ============================================
print_header "실행 모드 선택"

echo "스캔 도구 실행 방식을 선택하세요:"
echo ""
echo "  [1] Root 실행 (권장)"
echo "      - sudo python main.py로 실행"
echo "      - SYN 스캔 사용 (빠르고 스텔시)"
echo ""
echo "  [2] Non-root 실행 (setcap 설정, Linux만)"
echo "      - 일반 사용자로 실행 가능"
echo "      - 이 스크립트를 sudo로 다시 실행해야 함"
echo ""
read -p "선택 (1 또는 2, 기본값=1): " choice
choice=${choice:-1}

if [ "$choice" == "2" ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        print_error "macOS는 setcap을 지원하지 않습니다."
        print_warning "sudo로 실행하세요."
    elif [[ $EUID -ne 0 ]]; then
        print_warning "setcap 설정을 위해 sudo로 다시 실행하세요:"
        echo "sudo ./setup.sh"
    else
        if command -v setcap &> /dev/null; then
            if [ -f "$TOOLS_BIN/naabu" ]; then
                setcap cap_net_raw,cap_net_admin+eip "$TOOLS_BIN/naabu" && \
                print_success "naabu: capabilities 설정 완료"
            fi
            NMAP_PATH=$(which nmap 2>/dev/null || echo "")
            if [ -n "$NMAP_PATH" ]; then
                setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP_PATH" 2>/dev/null && \
                print_success "nmap: capabilities 설정 완료"
            fi
        else
            print_error "setcap이 설치되어 있지 않습니다."
        fi
    fi
fi

# ============================================
# 7. Installation Summary
# ============================================
print_header "설치 완료"

echo "설치된 도구:"
echo "─────────────────────────────────────"

check_tool() {
    local name=$1
    local path=$2
    if [ -f "$path" ]; then
        echo -e "  ${GREEN}✓${NC} $name"
    else
        echo -e "  ${RED}✗${NC} $name (미설치)"
    fi
}

check_tool "subfinder" "$TOOLS_BIN/subfinder"
check_tool "naabu" "$TOOLS_BIN/naabu"
check_tool "nuclei" "$TOOLS_BIN/nuclei"
check_tool "httpx" "$TOOLS_BIN/httpx"
check_tool "dirsearch" "$TOOLS_REPOS/dirsearch/dirsearch.py"
check_tool "Sublist3r" "$TOOLS_REPOS/Sublist3r/sublist3r.py"

# Check system tools
echo ""
echo "시스템 도구:"
echo "─────────────────────────────────────"
command -v nmap &> /dev/null && echo -e "  ${GREEN}✓${NC} nmap" || echo -e "  ${YELLOW}!${NC} nmap (미설치)"
command -v python3 &> /dev/null && echo -e "  ${GREEN}✓${NC} python3" || echo -e "  ${RED}✗${NC} python3"
command -v go &> /dev/null && echo -e "  ${GREEN}✓${NC} go" || echo -e "  ${YELLOW}!${NC} go (미설치)"

echo ""
echo "─────────────────────────────────────"
echo ""
echo "사용법:"
echo "  1. API 키 설정 (선택사항):"
echo "     nano $PROJECT_DIR/.env"
echo ""
echo "  2. 실행:"
if [ "$choice" == "1" ]; then
    echo -e "     ${GREEN}sudo python main.py --input targets.txt --verbose${NC}"
else
    echo -e "     ${GREEN}python main.py --input targets.txt --verbose${NC}"
fi
echo ""
echo "─────────────────────────────────────"
