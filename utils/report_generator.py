"""
Red Iris Info Gather - HTML Report Generator

Generates comprehensive HTML reports from scan results.
Uses Jinja2 templating for clean, styled output.
"""
import base64
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from jinja2 import Template

from state import ScanState
import config


# HTML Report Template
REPORT_TEMPLATE = '''<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Red Iris - 정보수집 리포트</title>
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1a1a25;
            --text-primary: #e8e8f0;
            --text-secondary: #8888a0;
            --accent-red: #ff3366;
            --accent-blue: #3366ff;
            --accent-green: #33ff99;
            --accent-yellow: #ffcc33;
            --accent-orange: #ff9933;
            --border-color: #2a2a3a;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', 'Noto Sans KR', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 40px;
        }
        
        header h1 {
            font-size: 2.5rem;
            color: var(--accent-red);
            margin-bottom: 10px;
        }
        
        header .subtitle {
            color: var(--text-secondary);
            font-size: 1.1rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }
        
        .stat-card .number {
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--accent-blue);
        }
        
        .stat-card .label {
            color: var(--text-secondary);
            margin-top: 5px;
        }
        
        .section {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            margin-bottom: 30px;
            overflow: hidden;
        }
        
        .section-header {
            background: var(--bg-card);
            padding: 15px 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .section-header h2 {
            font-size: 1.3rem;
            color: var(--accent-red);
        }
        
        .section-header .count {
            background: var(--accent-blue);
            color: white;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.9rem;
        }
        
        .section-content {
            padding: 20px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        th {
            background: var(--bg-card);
            color: var(--text-secondary);
            font-weight: 600;
        }
        
        tr:hover {
            background: var(--bg-card);
        }
        
        .severity-critical { color: #ff3333; font-weight: bold; }
        .severity-high { color: var(--accent-orange); font-weight: bold; }
        .severity-medium { color: var(--accent-yellow); }
        .severity-low { color: var(--accent-green); }
        .severity-info { color: var(--accent-blue); }
        
        .status-200 { color: var(--accent-green); }
        .status-301, .status-302 { color: var(--accent-blue); }
        .status-403 { color: var(--accent-orange); }
        .status-500 { color: var(--accent-red); }
        
        .screenshots-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 20px;
        }
        
        .screenshot-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .screenshot-card img {
            width: 100%;
            height: 250px;
            object-fit: cover;
            border-bottom: 1px solid var(--border-color);
        }
        
        .screenshot-card .url {
            padding: 12px;
            font-size: 0.9rem;
            word-break: break-all;
            color: var(--text-secondary);
        }
        
        .log-entry {
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85rem;
            padding: 5px 0;
            border-bottom: 1px solid var(--border-color);
        }
        
        .log-entry:last-child {
            border-bottom: none;
        }
        
        .error-log {
            color: var(--accent-red);
        }
        
        .tag {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            margin-right: 5px;
        }
        
        .tag-http { background: #1a4d1a; color: var(--accent-green); }
        .tag-port { background: #1a1a4d; color: var(--accent-blue); }
        
        a {
            color: var(--accent-blue);
            text-decoration: none;
        }
        
        a:hover {
            text-decoration: underline;
        }
        
        .collapsible {
            cursor: pointer;
        }
        
        .collapsible:after {
            content: ' ▼';
            font-size: 0.8rem;
        }
        
        footer {
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔴 Red Iris Info Gather</h1>
            <p class="subtitle">정보수집 스캔 리포트 | {{ scan_time }}</p>
        </header>
        
        <!-- Stats Summary -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">{{ stats.targets }}</div>
                <div class="label">총 타겟</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.alive_hosts }}</div>
                <div class="label">활성 호스트</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.open_ports }}</div>
                <div class="label">열린 포트</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.web_servers }}</div>
                <div class="label">웹 서버</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.discovered_paths }}</div>
                <div class="label">발견된 경로</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: {% if stats.vulnerabilities > 0 %}var(--accent-red){% else %}var(--accent-green){% endif %};">{{ stats.vulnerabilities }}</div>
                <div class="label">취약점</div>
            </div>
        </div>
        
        {% if vulnerabilities %}
        <!-- Vulnerabilities -->
        <div class="section">
            <div class="section-header">
                <h2>⚠️ 발견된 취약점</h2>
                <span class="count">{{ vulnerabilities|length }}</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>심각도</th>
                            <th>템플릿</th>
                            <th>이름</th>
                            <th>대상 URL</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for vuln in vulnerabilities %}
                        <tr>
                            <td class="severity-{{ vuln.severity }}">{{ vuln.severity|upper }}</td>
                            <td>{{ vuln.template_id }}</td>
                            <td>{{ vuln.template_name }}</td>
                            <td><a href="{{ vuln.matched_url }}" target="_blank">{{ vuln.matched_url }}</a></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}
        
        {% if web_servers %}
        <!-- Web Servers -->
        <div class="section">
            <div class="section-header">
                <h2>🌐 웹 서버</h2>
                <span class="count">{{ web_servers|length }}</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>URL</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for url in web_servers %}
                        <tr>
                            <td><a href="{{ url }}" target="_blank">{{ url }}</a></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}
        
        {% if screenshots %}
        <!-- Screenshots -->
        <div class="section">
            <div class="section-header">
                <h2>📸 스크린샷</h2>
                <span class="count">{{ screenshots|length }}</span>
            </div>
            <div class="section-content">
                <div class="screenshots-grid">
                    {% for ss in screenshots %}
                    {% if ss.success %}
                    <div class="screenshot-card">
                        <img src="{{ ss.data }}" alt="{{ ss.url }}">
                        <div class="url">{{ ss.url }}</div>
                    </div>
                    {% endif %}
                    {% endfor %}
                </div>
            </div>
        </div>
        {% endif %}
        
        {% if open_ports %}
        <!-- Open Ports -->
        <div class="section">
            <div class="section-header">
                <h2>🔓 열린 포트</h2>
                <span class="count">{{ open_ports|length }}</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>호스트</th>
                            <th>포트</th>
                            <th>서비스</th>
                            <th>타입</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for port in open_ports %}
                        <tr>
                            <td>{{ port.host }}</td>
                            <td><span class="tag tag-port">{{ port.port }}</span></td>
                            <td>{{ port.service or 'unknown' }}</td>
                            <td>{% if port.is_http %}<span class="tag tag-http">HTTP</span>{% endif %}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}
        
        {% if discovered_paths %}
        <!-- Discovered Paths -->
        <div class="section">
            <div class="section-header">
                <h2>📂 발견된 경로</h2>
                <span class="count">{{ discovered_paths|length }}</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>경로</th>
                            <th>상태 코드</th>
                            <th>크기</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for path in discovered_paths %}
                        <tr>
                            <td>{{ path.url }}</td>
                            <td>{{ path.path }}</td>
                            <td class="status-{{ path.status_code }}">{{ path.status_code }}</td>
                            <td>{{ path.content_length }} bytes</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}
        
        {% if subdomains %}
        <!-- Subdomains -->
        <div class="section">
            <div class="section-header">
                <h2>🔍 서브도메인</h2>
                <span class="count">{{ subdomains|length }}</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>서브도메인</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for subdomain in subdomains %}
                        <tr>
                            <td>{{ subdomain }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}
        
        {% if alive_hosts %}
        <!-- Alive Hosts -->
        <div class="section">
            <div class="section-header">
                <h2>✅ 활성 호스트</h2>
                <span class="count">{{ alive_hosts|length }}</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>호스트</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for host in alive_hosts %}
                        <tr>
                            <td>{{ host }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}
        
        {% if logs or errors %}
        <!-- Logs -->
        <div class="section">
            <div class="section-header">
                <h2>📋 로그</h2>
                <span class="count">{{ logs|length + errors|length }}</span>
            </div>
            <div class="section-content">
                {% for error in errors %}
                <div class="log-entry error-log">{{ error }}</div>
                {% endfor %}
                {% for log in logs[-50:] %}
                <div class="log-entry">{{ log }}</div>
                {% endfor %}
            </div>
        </div>
        {% endif %}
        
        <footer>
            <p>Generated by Red Iris Info Gather</p>
            <p>{{ scan_time }}</p>
        </footer>
    </div>
</body>
</html>'''


def encode_image_base64(image_path: str) -> str:
    """Encode image to base64 data URL"""
    try:
        with open(image_path, 'rb') as f:
            data = f.read()
        
        # Detect format
        ext = Path(image_path).suffix.lower()
        mime_types = {
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.webp': 'image/webp'
        }
        mime = mime_types.get(ext, 'image/png')
        
        encoded = base64.b64encode(data).decode('utf-8')
        return f"data:{mime};base64,{encoded}"
    except Exception:
        return ""


def generate_report(state: ScanState) -> dict:
    """
    Generate HTML Report Node - Entry point
    
    Creates a comprehensive HTML report from all scan results.
    """
    logs = []
    errors = []
    
    logs.append("[ReportGenerator] Generating HTML report")
    
    # Prepare data for template
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Statistics
    all_targets = set()
    all_targets.update(state.get('raw_domains', []))
    all_targets.update(state.get('raw_ips', []))
    all_targets.update(state.get('subdomains', []))
    
    stats = {
        'targets': len(all_targets),
        'alive_hosts': len(state.get('alive_hosts', [])),
        'open_ports': len(state.get('open_ports', [])),
        'web_servers': len(state.get('web_servers', [])),
        'discovered_paths': len(state.get('discovered_paths', [])),
        'vulnerabilities': len(state.get('vulnerabilities', []))
    }
    
    # Prepare screenshots with embedded images
    screenshots_data = []
    for ss in state.get('screenshots', []):
        ss_copy = dict(ss)
        if ss.get('success') and ss.get('path') and os.path.exists(ss.get('path', '')):
            ss_copy['data'] = encode_image_base64(ss['path'])
        else:
            ss_copy['data'] = ''
        screenshots_data.append(ss_copy)
    
    # Render template
    template = Template(REPORT_TEMPLATE)
    html_content = template.render(
        scan_time=scan_time,
        stats=stats,
        vulnerabilities=state.get('vulnerabilities', []),
        web_servers=state.get('web_servers', []),
        screenshots=screenshots_data,
        open_ports=state.get('open_ports', []),
        discovered_paths=state.get('discovered_paths', []),
        subdomains=state.get('subdomains', []),
        alive_hosts=state.get('alive_hosts', []),
        logs=state.get('logs', []),
        errors=state.get('errors', [])
    )
    
    # Save report
    report_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_path = config.REPORTS_DIR / report_filename
    
    try:
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logs.append(f"[ReportGenerator] Report saved to: {report_path}")
    except Exception as e:
        errors.append(f"[ReportGenerator] Error saving report: {str(e)}")
        report_path = None
    
    return {
        'report_path': str(report_path) if report_path else None,
        'errors': errors,
        'logs': logs
    }
