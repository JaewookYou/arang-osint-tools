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
    
    # 포트스캔 후 병렬 처리 (스크린샷 + 디렉터리 스캔)
    workflow.add_conditional_edges(
        "scan_ports",
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
    ║   Automated Penetration Testing Information Gathering Tool  ║
    ║                                                              ║
    ║   LangGraph-based scanning pipeline                          ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


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
    
    args = parser.parse_args()
    
    # 배너 출력
    print_banner()
    
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
    
    # 초기 상태 생성
    initial_state = create_initial_state(str(input_file.absolute()))
    
    print_status("스캔 시작!", "success")
    print("-" * 60)
    
    try:
        # 워크플로우 실행
        final_state = None
        for output in app.stream(initial_state):
            # 각 노드의 실행 결과 출력
            for node_name, node_output in output.items():
                if args.verbose:
                    logs = node_output.get('logs', [])
                    for log in logs:
                        print_status(log, "info")
                    
                    errors = node_output.get('errors', [])
                    for error in errors:
                        print_status(error, "error")
                else:
                    # 간단한 진행 상태만 출력
                    print_status(f"[{node_name}] 완료", "progress")
                
                final_state = node_output
        
        print("-" * 60)
        
        # 결과 요약
        if final_state and final_state.get('report_path'):
            print_status(f"리포트 생성 완료: {final_state['report_path']}", "success")
        
        print_status("스캔 완료!", "success")
        
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
