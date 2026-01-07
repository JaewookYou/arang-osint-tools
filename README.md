# Red Iris Info Gather

🔴 **LangGraph 기반 모의해킹 정보수집 자동화 도구**

모든 외부 도구를 프로젝트 내에서 빌드하여 사용하는 독립형 정보수집 파이프라인입니다.

## 주요 기능

| 기능 | 도구 | 설명 |
|------|------|------|
| 서브도메인 열거 | subfinder, Sublist3r, Shodan | 다중 소스 서브도메인 수집 |
| 호스트 발견 | naabu | SYN/TCP 기반 호스트 생존 확인 |
| 포트 스캔 | nmap, TCP probe | 주요 포트 스캐닝 및 HTTP 감지 |
| 디렉터리 스캔 | dirsearch | 11,000+ 워드리스트 기반 경로 탐색 |
| 취약점 스캔 | nuclei | 커스텀 템플릿 기반 취약점 탐지 |
| 스크린샷 | Selenium | 웹 서버 스크린샷 캡처 |
| 리포트 | Jinja2 | 다크 테마 HTML 리포트 생성 |

## 설치

### 1. 가상환경 생성

```bash
cd rediris-info-gather
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. 외부 도구 설치

```bash
./tools/install_tools.sh
```

이 스크립트는 다음 도구를 `tools/` 디렉터리에 설치합니다:
- **Go 바이너리** (`tools/bin/`): subfinder, naabu, nuclei, httpx
- **Python 스크립트** (`tools/repos/`): dirsearch, Sublist3r

### 3. 사전 요구사항

- **Go 1.18+**: `brew install go`
- **Python 3.9+**
- **nmap**: `brew install nmap`
- **Chrome**: 스크린샷 캡처용

## 사용법

### 기본 실행

```bash
source .venv/bin/activate
sudo python main.py --input targets.txt --verbose
```

### 옵션

| 옵션 | 설명 |
|------|------|
| `-i, --input` | 타겟 파일 (필수) |
| `-o, --output` | 결과 디렉터리 (기본: ./output) |
| `--skip-screenshots` | 스크린샷 건너뛰기 |
| `--skip-nuclei` | Nuclei 스캔 건너뛰기 |
| `-v, --verbose` | 상세 출력 |

### Shodan 사용

```bash
export SHODAN_API_KEY="your_api_key"
sudo python main.py --input targets.txt --verbose
```

> ⚠️ **sudo 권한**: naabu의 SYN 스캔을 위해 root 권한이 필요합니다.

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

## 디렉터리 구조

```
rediris-info-gather/
├── main.py                 # 메인 진입점
├── config.py               # 설정 및 도구 경로
├── state.py                # LangGraph 상태 스키마
├── requirements.txt        # Python 의존성
├── nodes/                  # 스캐너 노드
│   ├── input_parser.py     # 입력 파싱
│   ├── subdomain_scanner.py
│   ├── host_discovery.py
│   ├── port_scanner.py
│   ├── directory_scanner.py
│   ├── nuclei_scanner.py
│   └── web_screenshot.py
├── utils/                  # 유틸리티
│   ├── network.py
│   ├── http_utils.py
│   └── report_generator.py
├── data/                   # 데이터 파일
│   ├── endpoints.txt       # 커스텀 디렉터리 워드리스트
│   └── nuclei_templates/   # 커스텀 Nuclei 템플릿
├── tools/                  # 외부 도구
│   ├── bin/                # 컴파일된 Go 바이너리
│   ├── repos/              # 클론된 레포지토리
│   └── install_tools.sh    # 설치 스크립트
└── output/                 # 결과 출력
    ├── screenshots/
    └── reports/
```

## 파이프라인 흐름

```
Input Parser → Subdomain Scanner → Host Discovery → Port Scanner
                                                          ↓
                         Report ← Screenshot ← Nuclei ← Directory Scanner
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
