#!/bin/bash
# Red Iris Info Gather - Initial Setup Script
#
# 이 스크립트는 두 가지 모드를 지원합니다:
# 1. Root 실행 모드 (권장): sudo로 직접 실행
# 2. Non-root 모드: setcap으로 권한 설정 후 일반 사용자로 실행
#
# Usage: ./setup.sh

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
TOOLS_BIN="$PROJECT_DIR/tools/bin"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   🔴 RED IRIS INFO GATHER - Initial Setup                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ============================================
# Ask user about execution mode
# ============================================
echo "스캔 도구 실행 방식을 선택하세요:"
echo ""
echo "  [1] Root 실행 (권장)"
echo "      - sudo python main.py로 실행"
echo "      - SYN 스캔 사용 (빠르고 스텔시)"
echo "      - 별도 설정 불필요"
echo ""
echo "  [2] Non-root 실행 (setcap 설정)"
echo "      - 일반 사용자로 실행 가능"
echo "      - setcap으로 naabu에 권한 부여"
echo "      - Linux에서만 작동 (macOS 미지원)"
echo ""
read -p "선택 (1 또는 2, 기본값=1): " choice
choice=${choice:-1}

if [ "$choice" == "1" ]; then
    # ============================================
    # Mode 1: Root execution (recommended)
    # ============================================
    echo ""
    print_success "Root 실행 모드를 선택했습니다."
    echo ""
    print_status "설정 중..."
    
    # Create .env file if not exists
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
    chmod +x "$PROJECT_DIR/tools/install_tools.sh" 2>/dev/null || true
    chmod +x "$PROJECT_DIR/main.py" 2>/dev/null || true
    
    echo ""
    echo "─────────────────────────────────────"
    print_success "설정 완료!"
    echo ""
    echo "사용법:"
    echo "  1. API 키 설정 (선택사항):"
    echo "     nano $PROJECT_DIR/.env"
    echo ""
    echo "  2. 실행 (sudo 필수):"
    echo -e "     ${GREEN}sudo python main.py --input targets.txt --verbose${NC}"
    echo ""
    echo "─────────────────────────────────────"

elif [ "$choice" == "2" ]; then
    # ============================================
    # Mode 2: Non-root with setcap
    # ============================================
    echo ""
    print_status "Non-root 모드를 선택했습니다. setcap 설정을 진행합니다."
    echo ""
    
    # Check if running as root (needed for setcap)
    if [[ $EUID -ne 0 ]]; then
        print_error "setcap 설정을 위해 root 권한이 필요합니다."
        echo "다시 실행하세요: sudo ./setup.sh"
        exit 1
    fi
    
    # Check OS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        print_error "macOS는 setcap을 지원하지 않습니다."
        print_warning "macOS에서는 sudo로 실행하거나 TCP Connect 폴백을 사용하세요."
        exit 1
    fi
    
    # Check if setcap is available
    if ! command -v setcap &> /dev/null; then
        print_error "setcap이 설치되어 있지 않습니다."
        echo "설치: sudo apt install libcap2-bin (Debian/Ubuntu)"
        echo "      sudo yum install libcap (RHEL/CentOS)"
        exit 1
    fi
    
    # Set capabilities on naabu
    if [ -f "$TOOLS_BIN/naabu" ]; then
        setcap cap_net_raw,cap_net_admin+eip "$TOOLS_BIN/naabu"
        print_success "naabu: capabilities 설정 완료"
    else
        print_warning "naabu 바이너리를 찾을 수 없습니다."
        print_warning "먼저 ./tools/install_tools.sh를 실행하세요."
    fi
    
    # Set capabilities on system nmap if exists
    NMAP_PATH=$(which nmap 2>/dev/null || echo "")
    if [ -n "$NMAP_PATH" ] && [ -f "$NMAP_PATH" ]; then
        setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP_PATH" 2>/dev/null && \
        print_success "nmap: capabilities 설정 완료" || \
        print_warning "nmap capabilities 설정 실패 (TCP 폴백 사용)"
    fi
    
    # Create .env file
    if [ ! -f "$PROJECT_DIR/.env" ]; then
        if [ -f "$PROJECT_DIR/.env.example" ]; then
            cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
            chmod 600 "$PROJECT_DIR/.env"
            print_success ".env 파일 생성됨"
        fi
    fi
    
    echo ""
    echo "─────────────────────────────────────"
    print_success "설정 완료!"
    echo ""
    echo "사용법 (sudo 없이):"
    echo "  1. API 키 설정 (선택사항):"
    echo "     nano $PROJECT_DIR/.env"
    echo ""
    echo "  2. 실행:"
    echo -e "     ${GREEN}python main.py --input targets.txt --verbose${NC}"
    echo ""
    echo "─────────────────────────────────────"
    
else
    print_error "잘못된 선택입니다. 1 또는 2를 입력하세요."
    exit 1
fi
