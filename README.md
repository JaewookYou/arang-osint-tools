# Red Iris Info Gather

🔴 **LangGraph 기반 모의해킹 정보수집 자동화 도구**

모든 외부 도구를 프로젝트 내에서 빌드하여 사용하는 독립형 정보수집 파이프라인입니다.

## 주요 기능

| 기능 | 도구 | 설명 |
|------|------|------|
| 서브도메인 열거 | subfinder, Sublist3r, Shodan | 다중 소스 서브도메인 수집 |
| 호스트 발견 | naabu | SYN/TCP 기반 호스트 생존 확인 |
| 포트 스캔 | nmap, TCP probe | 주요 포트 스캐닝 및 HTTP 감지 |
| 기술 스택 탐지 | Wappalyzer, WebTech | 서버/프레임워크 식별 |
| CVE 조회 | NVD, OSV, CISA-KEV | 다중 소스 1-day 취약점 검색 |
| LLM 분석 | Gemini, Claude, GPT | CVE 우선순위 및 한국어 요약 |
| 디렉터리 스캔 | dirsearch | 11,000+ 워드리스트 기반 경로 탐색 |
| 취약점 스캔 | nuclei | 커스텀 템플릿 기반 취약점 탐지 |
| 스크린샷 | Selenium | 웹 서버 스크린샷 캡처 |
| 리포트 | Jinja2 | 다크 테마 인터랙티브 HTML 리포트 |

## 설치

### 원클릭 설치

```bash
cd rediris-info-gather
./setup.sh
```

이 스크립트가 자동으로:
- Python 가상환경 생성 및 패키지 설치
- Go 도구 빌드 (subfinder, naabu, nuclei, httpx)
- Python 도구 클론 (dirsearch, Sublist3r)
- `.env` 파일 생성

### 사전 요구사항

- **Go 1.18+**: `brew install go`
- **Python 3.9+**
- **nmap**: `brew install nmap`
- **Chrome**: 스크린샷 캡처용

## 사용법

### 🔴 권장: Root로 실행

```bash
source .venv/bin/activate
sudo python main.py --input targets.txt --verbose
```

> ⚡ **SYN 스캔**을 사용하여 빠르고 스텔시한 스캔이 가능합니다.

### 실행 시 설정 표시

```
╔══════════════════════════════════════════════════════════════╗
║   🔴 RED IRIS INFO GATHER                                    ║
╚══════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────┐
│  📋 현재 설정                                               │
├─────────────────────────────────────────────────────────────┤
│  🔌 포트 스캔: TOP1000 (1,000개 포트)
│  🧵 최대 스레드: 100
│  ⏱️  타임아웃: 2초
├─────────────────────────────────────────────────────────────┤
│  🔍 Shodan API: ✅ 활성
│  📚 NVD API: ⚠️ 미설정 (느린 검색)
│  🤖 LLM 분석: ✅ 활성 (gemini-2.5-flash)
└─────────────────────────────────────────────────────────────┘
```

### 옵션

| 옵션 | 설명 |
|------|------|
| `-i, --input` | 타겟 파일 (필수) |
| `-o, --output` | 결과 디렉터리 (기본: ./output) |
| `--ports` | 포트 범위: `top100`(기본), `top1000`, `full`(1-65535) |
| `--skip-screenshots` | 스크린샷 건너뛰기 |
| `--skip-nuclei` | Nuclei 스캔 건너뛰기 |
| `-v, --verbose` | 상세 출력 |

## 환경 변수 (.env)

```bash
cp .env.example .env
nano .env
```

```ini
# API Keys
SHODAN_API_KEY=your_key    # 서브도메인/호스트 정보
NVD_API_KEY=your_key       # CVE 조회 (10배 빠름)

# LLM 설정 (선택)
LLM_MODE=on                # on/off
LLM_API_KEY=your_key
LLM_MODEL=gemini-2.5-flash # 아래 지원 모델 참고

# 스캔 설정
PORT_SCAN_MODE=top1000     # top100, top1000, full
MAX_THREADS=100
SCAN_TIMEOUT=2
```

### 지원 LLM 모델

| Provider | 모델 |
|----------|------|
| **Gemini** | `gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-2.0-flash` |
| **Claude** | `claude-opus-4`, `claude-sonnet-4` |
| **OpenAI** | `gpt-5.2-pro`, `gpt-5.2`, `gpt-5-nano` |

## CVE 조회 및 LLM 분석

### 다중 소스 CVE 검색

| 소스 | 설명 |
|------|------|
| NVD | CPE 기반 정확한 검색 |
| OSV | 오픈소스 취약점 DB |
| CISA-KEV | 실제 공격에 사용된 취약점 |

### LLM 활성화 시 추가 기능

- **우선순위 분석**: CVSS가 아닌 실제 공격 가능성 기준 정렬
- **한국어 요약**: CVE 설명을 한국어로 요약
- **공격 벡터 제안**: 실질적인 공격 방법 분석
- **대응 방안**: 즉각 적용 가능한 완화 조치

### HTML 리포트 CVE 표시

```
▶ CVE-2024-38475 | Apache | CRITICAL | mod_rewrite 취약점...
   ↓ 클릭하면 펼쳐짐
▼ CVE-2024-38475 | Apache | CRITICAL | mod_rewrite 취약점...
   ┌─────────────────────────────────────────────────────────┐
   │ 🇰🇷 한국어 요약                                          │
   │ [RCE] [mod_rewrite]                                     │
   │ URL 이스케이핑 취약점으로 공격자가 원격 코드 실행 가능    │
   │ ⚠️ 영향: 서버 완전 장악 가능                             │
   ├─────────────────────────────────────────────────────────┤
   │ 📝 전체 설명                                             │
   │ Apache HTTP Server contains an improper escaping...     │
   └─────────────────────────────────────────────────────────┘
```

## 입력 파일 형식

```
# 도메인
example.com
sub.example.com

# IP 주소
192.168.1.1
10.0.0.100

# CIDR (주석 처리된 예시)
# 10.0.0.0/24
```

## 파이프라인 흐름

```
Input Parser → Subdomain Scanner → Host Discovery → Port Scanner
                                                           ↓
                                                    Tech Detector
                                                           ↓
                                                    CVE Lookup ← LLM Analysis
                                                           ↓
    Report ← Screenshot ← Nuclei ← Directory Scanner ←─────┘
```

## 디렉터리 구조

```
rediris-info-gather/
├── main.py                 # 메인 진입점
├── config.py               # 설정 및 도구 경로
├── state.py                # LangGraph 상태 스키마
├── setup.sh                # 원클릭 설치
├── .env.example            # 환경변수 템플릿
├── nodes/                  # 스캐너 노드
│   ├── input_parser.py
│   ├── subdomain_scanner.py
│   ├── host_discovery.py
│   ├── port_scanner.py
│   ├── tech_detector.py    # 기술 스택 탐지
│   ├── cve_lookup.py       # 다중 소스 CVE 조회
│   ├── directory_scanner.py
│   ├── nuclei_scanner.py
│   └── web_screenshot.py
├── utils/                  # 유틸리티
│   ├── report_generator.py # 인터랙티브 HTML 리포트
│   ├── llm_utils.py        # LLM 통합 (Gemini/Claude/GPT)
│   └── progress.py         # 진행 표시
├── data/                   # 데이터 파일
│   ├── endpoints.txt
│   └── nuclei_templates/
├── tools/                  # 외부 도구
│   ├── bin/
│   ├── repos/
│   └── install_tools.sh
└── output/                 # 결과 출력
    ├── screenshots/
    └── reports/
```

## 커스터마이징

### 커스텀 엔드포인트

`data/endpoints.txt`에 경로 추가:
```
/api/v2/admin
/.env.backup
/debug/pprof
```

### 커스텀 Nuclei 템플릿

`data/nuclei_templates/`에 YAML 템플릿 추가:
```yaml
id: custom-check
info:
  name: Custom Security Check
  severity: medium
requests:
  - method: GET
    path:
      - "{{BaseURL}}/custom-path"
    matchers:
      - type: status
        status: [200]
```

## 라이선스

MIT License

## 면책조항

이 도구는 교육 및 합법적인 보안 테스트 목적으로만 사용해야 합니다.
허가 없이 타인의 시스템을 스캔하는 것은 불법입니다.
