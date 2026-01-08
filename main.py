#!/usr/bin/env python3
"""
Red Iris Info Gather - Main Entry Point

LangGraph 기반 모의해킹 정보수집 자동화 도구

사용법:
    python main.py --input targets.txt [--output ./output]
    python main.py -i targets.txt -o ./results

입력 파일 형식 (줄바꿈으로 구분):
    example.com
    api.example.com
    192.168.1.1
    10.0.0.0/24
"""
import warnings
# Suppress noisy warnings from dependencies BEFORE any imports
warnings.filterwarnings("ignore", category=UserWarning, module="Wappalyzer")
warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")
warnings.filterwarnings("ignore", message=".*pkg_resources.*")
warnings.filterwarnings("ignore", message=".*NotOpenSSLWarning.*")
warnings.filterwarnings("ignore", message=".*urllib3.*OpenSSL.*")
warnings.filterwarnings("ignore", message=".*LibreSSL.*")

# Also suppress at module level
import urllib3
urllib3.disable_warnings()

import argparse
import sys
from pathlib import Path
from datetime import datetime

from langgraph.graph import StateGraph, END

from state import ScanState, create_initial_state
from nodes import (
    parse_input,
    scan_subdomains,
    discover_hosts,
    scan_ports,
    detect_tech,
    lookup_cves,
    take_screenshots,
    scan_directories,
    run_nuclei
)
from utils.report_generator import generate_report
import config


def should_scan_subdomains(state: ScanState) -> str:
    """서브도메인 스캔 여부 결정"""
    if state.get('base_domains'):
        return "scan_subdomains"
    return "discover_hosts"


def should_take_screenshots(state: ScanState) -> str:
    """스크린샷 촬영 여부 결정"""
    if state.get('web_servers'):
        return "take_screenshots"
    return "generate_report"


def should_scan_directories(state: ScanState) -> str:
    """디렉터리 스캔 여부 결정"""
    if state.get('web_servers'):
        return "scan_directories"
    return "generate_report"


def build_workflow() -> StateGraph:
    """LangGraph 워크플로우 구성"""
    
    # StateGraph 생성
    workflow = StateGraph(ScanState)
    
    # 노드 추가
    workflow.add_node("parse_input", parse_input)
    workflow.add_node("scan_subdomains", scan_subdomains)
    workflow.add_node("discover_hosts", discover_hosts)
    workflow.add_node("scan_ports", scan_ports)
    workflow.add_node("detect_tech", detect_tech)
    workflow.add_node("lookup_cves", lookup_cves)
    workflow.add_node("take_screenshots", take_screenshots)
    workflow.add_node("scan_directories", scan_directories)
    workflow.add_node("run_nuclei", run_nuclei)
    workflow.add_node("generate_report", generate_report)
    
    # 엔트리 포인트 설정
    workflow.set_entry_point("parse_input")
    
    # 엣지 정의 (파이프라인 흐름)
    workflow.add_conditional_edges(
        "parse_input",
        should_scan_subdomains,
        {
            "scan_subdomains": "scan_subdomains",
            "discover_hosts": "discover_hosts"
        }
    )
    
    workflow.add_edge("scan_subdomains", "discover_hosts")
    workflow.add_edge("discover_hosts", "scan_ports")
    workflow.add_edge("scan_ports", "detect_tech")  # 포트스캔 후 기술 탐지
    workflow.add_edge("detect_tech", "lookup_cves")  # 기술 탐지 후 CVE 검색
    
    # CVE 검색 후 디렉터리 스캔
    workflow.add_conditional_edges(
        "lookup_cves",
        should_scan_directories,
        {
            "scan_directories": "scan_directories",
            "generate_report": "generate_report"
        }
    )
    
    workflow.add_edge("scan_directories", "run_nuclei")
    workflow.add_edge("run_nuclei", "take_screenshots")
    
    workflow.add_conditional_edges(
        "take_screenshots",
        lambda _: "generate_report",
        {
            "generate_report": "generate_report"
        }
    )
    
    workflow.add_edge("generate_report", END)
    
    return workflow


def print_banner():
    """배너 출력"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   🔴 RED IRIS INFO GATHER                                    ║
    ║   Automated Penetration Testing Information Gathering Tool   ║
    ║                                                              ║
    ║   LangGraph-based scanning pipeline                          ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_config():
    """현재 설정 정보 출력"""
    import os
    from utils.llm_utils import is_llm_enabled
    
    # Port scan mode info
    port_count = len(config.WELLKNOWN_PORTS)
    port_mode = config.PORT_SCAN_MODE.upper()
    
    # API status
    shodan_status = "✅ 활성" if config.SHODAN_API_KEY else "❌ 미설정"
    nvd_status = "✅ 활성 (빠른 검색)" if config.NVD_API_KEY else "⚠️ 미설정 (느린 검색)"
    
    # LLM status
    llm_mode = os.environ.get("LLM_MODE", "off")
    llm_model = os.environ.get("LLM_MODEL", "없음")
    if is_llm_enabled():
        llm_status = f"✅ 활성 ({llm_model})"
    else:
        llm_status = "❌ 비활성"
    
    print("    ┌─────────────────────────────────────────────────────────────┐")
    print("    │  📋 현재 설정                                               │")
    print("    ├─────────────────────────────────────────────────────────────┤")
    print(f"    │  🔌 포트 스캔: {port_mode} ({port_count:,}개 포트)")
    print(f"    │  🧵 최대 스레드: {config.MAX_THREADS}")
    print(f"    │  ⏱️  타임아웃: {config.SCAN_TIMEOUT}초")
    print("    ├─────────────────────────────────────────────────────────────┤")
    print(f"    │  🔍 Shodan API: {shodan_status}")
    print(f"    │  📚 NVD API: {nvd_status}")
    print(f"    │  🤖 LLM 분석: {llm_status}")
    print("    └─────────────────────────────────────────────────────────────┘")
    print()



def print_status(message: str, level: str = "info"):
    """상태 메시지 출력"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    symbols = {
        "info": "ℹ️ ",
        "success": "✅",
        "warning": "⚠️ ",
        "error": "❌",
        "progress": "🔄"
    }
    symbol = symbols.get(level, "•")
    print(f"[{timestamp}] {symbol} {message}")


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description="Red Iris Info Gather - 모의해킹 정보수집 자동화 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예제:
    python main.py --input targets.txt
    python main.py -i targets.txt -o ./results
    python main.py --input targets.txt --skip-screenshots

입력 파일 형식:
    example.com
    sub.example.com
    192.168.1.1
    10.0.0.0/24
        """
    )
    
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="스캔 대상이 포함된 입력 파일 경로"
    )
    
    parser.add_argument(
        "-o", "--output",
        default=str(config.OUTPUT_DIR),
        help=f"결과 저장 디렉터리 (기본값: {config.OUTPUT_DIR})"
    )
    
    parser.add_argument(
        "--skip-screenshots",
        action="store_true",
        help="스크린샷 촬영 건너뛰기"
    )
    
    parser.add_argument(
        "--skip-nuclei",
        action="store_true",
        help="Nuclei 취약점 스캔 건너뛰기"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="상세 출력 모드"
    )
    
    parser.add_argument(
        "--ports",
        choices=["top100", "top1000", "full"],
        default=None,  # Use .env PORT_SCAN_MODE if not specified
        help="포트 스캔 범위: top100(기본), top1000, full(1-65535)"
    )
    
    args = parser.parse_args()
    
    # Set port scan mode (CLI > .env > default)
    port_mode = args.ports if args.ports else config.PORT_SCAN_MODE
    config.set_port_mode(port_mode)
    
    # 배너 및 설정 출력
    print_banner()
    print_config()
    
    # 입력 파일 확인
    input_file = Path(args.input)
    if not input_file.exists():
        print_status(f"입력 파일을 찾을 수 없습니다: {input_file}", "error")
        sys.exit(1)
    
    print_status(f"입력 파일: {input_file}", "info")
    print_status(f"출력 디렉터리: {args.output}", "info")
    
    # 출력 디렉터리 설정
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    config.OUTPUT_DIR = output_dir
    config.SCREENSHOTS_DIR = output_dir / "screenshots"
    config.REPORTS_DIR = output_dir / "reports"
    config.SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # 워크플로우 구성
    print_status("워크플로우 구성 중...", "progress")
    workflow = build_workflow()
    
    # 그래프 컴파일
    app = workflow.compile()
    
    # 데이터베이스 초기화
    from utils.database import init_database, get_database
    db = init_database()
    scan_id = db.create_scan(str(input_file.absolute()), target_count=0)
    print_status(f"데이터베이스: {db.db_path.name}", "success")
    
    # 초기 상태 생성
    initial_state = create_initial_state(str(input_file.absolute()))
    
    print()
    print("=" * 60)
    print("  🚀 스캔 시작")
    print("=" * 60)
    
    # Node descriptions
    NODE_INFO = {
        'parse_input': ('📝', '입력 파싱', '타겟 도메인/IP 분석'),
        'scan_subdomains': ('🔍', '서브도메인 스캔', 'subfinder, sublist3r, shodan'),
        'discover_hosts': ('🌐', '호스트 발견', 'TCP/SYN 프로브'),
        'scan_ports': ('🔌', '포트 스캔', f'{config.PORT_SCAN_MODE} 포트'),
        'detect_tech': ('🔧', '기술 스택 탐지', 'Wappalyzer, WebTech'),
        'lookup_cves': ('🔥', 'CVE 조회', 'NVD, OSV, CISA-KEV'),
        'scan_directories': ('📁', '디렉터리 스캔', 'dirsearch'),
        'run_nuclei': ('⚠️', '취약점 스캔', 'nuclei templates'),
        'take_screenshots': ('📸', '스크린샷', 'Selenium'),
        'generate_report': ('📊', '리포트 생성', 'HTML 리포트'),
    }
    
    try:
        # 워크플로우 실행
        final_state = None
        for output in app.stream(initial_state):
            for node_name, node_output in output.items():
                icon, title, desc = NODE_INFO.get(node_name, ('•', node_name, ''))
                
                # Process output
                logs = node_output.get('logs', [])
                errors = node_output.get('errors', [])
                
                # Build result summary
                result_counts = []
                if 'subdomains' in node_output and node_output['subdomains']:
                    result_counts.append(f"서브도메인 {len(node_output['subdomains'])}개")
                if 'alive_hosts' in node_output and node_output['alive_hosts']:
                    result_counts.append(f"호스트 {len(node_output['alive_hosts'])}개")
                if 'open_ports' in node_output and node_output['open_ports']:
                    result_counts.append(f"포트 {len(node_output['open_ports'])}개")
                if 'web_servers' in node_output and node_output['web_servers']:
                    result_counts.append(f"웹서버 {len(node_output['web_servers'])}개")
                if 'tech_results' in node_output and node_output['tech_results']:
                    tech_count = sum(len(r.get('technologies', [])) for r in node_output['tech_results'])
                    result_counts.append(f"기술 {tech_count}개")
                if 'cve_results' in node_output and node_output['cve_results']:
                    result_counts.append(f"CVE {len(node_output['cve_results'])}개")
                if 'discovered_paths' in node_output and node_output['discovered_paths']:
                    result_counts.append(f"경로 {len(node_output['discovered_paths'])}개")
                if 'vulnerabilities' in node_output and node_output['vulnerabilities']:
                    result_counts.append(f"취약점 {len(node_output['vulnerabilities'])}개")
                if 'screenshots' in node_output and node_output['screenshots']:
                    result_counts.append(f"스크린샷 {len(node_output['screenshots'])}개")
                
                result_str = " | ".join(result_counts) if result_counts else "완료"
                
                # Print status with color
                status = "✓" if len(errors) == 0 else "✗"
                color = "\033[92m" if len(errors) == 0 else "\033[91m"
                reset = "\033[0m"
                
                print(f"{color}{status}{reset} {icon} {title}: {result_str}")
                
                # Show substeps in verbose mode
                if args.verbose and logs:
                    for log in logs[-3:]:
                        log_clean = log.split(']')[-1].strip() if ']' in log else log
                        print(f"      └─ {log_clean}")
                
                # Save data to database
                try:
                    # Subdomains/hosts
                    if 'subdomains' in node_output and node_output['subdomains']:
                        hosts = [{'hostname': h, 'is_alive': False} for h in node_output['subdomains']]
                        db.add_hosts_batch(scan_id, hosts)
                    
                    if 'alive_hosts' in node_output and node_output['alive_hosts']:
                        for h in node_output['alive_hosts']:
                            db.add_host(scan_id, h, is_alive=True)
                    
                    # Ports
                    if 'open_ports' in node_output and node_output['open_ports']:
                        db.add_ports_batch(scan_id, node_output['open_ports'])
                    
                    # Technologies
                    if 'tech_results' in node_output and node_output['tech_results']:
                        for result in node_output['tech_results']:
                            url = result.get('url', '')
                            for tech in result.get('technologies', []):
                                db.add_technology(
                                    scan_id, url,
                                    tech.get('name', ''),
                                    tech.get('version'),
                                    tech.get('category'),
                                    tech.get('source')
                                )
                    
                    # CVEs
                    if 'cve_results' in node_output and node_output['cve_results']:
                        db.add_cves_batch(scan_id, node_output['cve_results'])
                    
                    # Endpoints
                    if 'discovered_paths' in node_output and node_output['discovered_paths']:
                        db.add_endpoints_batch(scan_id, node_output['discovered_paths'])
                    
                    # Vulnerabilities
                    if 'vulnerabilities' in node_output and node_output['vulnerabilities']:
                        db.add_vulnerabilities_batch(scan_id, node_output['vulnerabilities'])
                except Exception as db_error:
                    if args.verbose:
                        print(f"      └─ DB 저장 오류: {db_error}")
                
                final_state = node_output
        
        # Mark scan as complete
        db.complete_scan(scan_id)
        
        print()
        print("=" * 60)
        
        # 결과 요약
        if final_state and final_state.get('report_path'):
            print(f"  📊 리포트: {final_state['report_path']}")
        
        print(f"  💾 데이터베이스: {db.db_path}")
        
        print("  ✅ 스캔 완료!")
        print("=" * 60)
        
    except KeyboardInterrupt:
        print_status("사용자에 의해 중단됨", "warning")
        sys.exit(130)
    except Exception as e:
        print_status(f"오류 발생: {str(e)}", "error")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
