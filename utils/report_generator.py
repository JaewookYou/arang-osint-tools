"""
Red Iris Info Gather - Report Generator

Generates an interactive HTML report with:
- Tab-based navigation by host/domain
- Search and filtering functionality
- Embedded screenshots
- Vulnerability summary
"""
import base64
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict

from jinja2 import Template

from state import ScanState
import config


# Modern HTML template with tabs, search, and filtering
REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Red Iris - 정보수집 리포트</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #f85149;
            --accent-secondary: #58a6ff;
            --success: #3fb950;
            --warning: #d29922;
            --border: #30363d;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid var(--border);
        }
        
        .header h1 {
            color: var(--accent);
            font-size: 2rem;
            margin-bottom: 10px;
        }
        
        .header .meta {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid var(--border);
            transition: transform 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
        }
        
        .stat-card .number {
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent-secondary);
        }
        
        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-top: 5px;
        }
        
        /* Tabs */
        .tabs {
            background: var(--bg-secondary);
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid var(--border);
            overflow: hidden;
        }
        
        .tab-list {
            display: flex;
            flex-wrap: wrap;
            border-bottom: 1px solid var(--border);
        }
        
        .tab-btn {
            padding: 12px 24px;
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 0.95rem;
            transition: all 0.2s;
            border-bottom: 2px solid transparent;
        }
        
        .tab-btn:hover {
            color: var(--text-primary);
            background: var(--bg-tertiary);
        }
        
        .tab-btn.active {
            color: var(--accent);
            border-bottom-color: var(--accent);
        }
        
        .tab-content {
            display: none;
            padding: 20px;
        }
        
        .tab-content.active {
            display: block;
        }
        
        /* Search & Filter */
        .controls {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .search-box {
            flex: 1;
            min-width: 250px;
            position: relative;
        }
        
        .search-box input {
            width: 100%;
            padding: 12px 15px 12px 40px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-primary);
            font-size: 0.95rem;
        }
        
        .search-box::before {
            content: "🔍";
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
        }
        
        .filter-select {
            padding: 12px 15px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-primary);
            font-size: 0.95rem;
            cursor: pointer;
        }
        
        /* Tables */
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        .data-table th, .data-table td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        .data-table th {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.5px;
        }
        
        .data-table tr:hover {
            background: var(--bg-tertiary);
        }
        
        .data-table a {
            color: var(--accent-secondary);
            text-decoration: none;
        }
        
        .data-table a:hover {
            text-decoration: underline;
        }
        
        /* Badges */
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .badge-success { background: rgba(63, 185, 80, 0.2); color: var(--success); }
        .badge-warning { background: rgba(210, 153, 34, 0.2); color: var(--warning); }
        .badge-danger { background: rgba(248, 81, 73, 0.2); color: var(--accent); }
        .badge-info { background: rgba(88, 166, 255, 0.2); color: var(--accent-secondary); }
        
        /* Host Cards */
        .host-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
        }
        
        .host-header {
            padding: 15px 20px;
            background: var(--bg-tertiary);
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }
        
        .host-header h3 {
            color: var(--accent-secondary);
            font-size: 1.1rem;
        }
        
        .host-body {
            padding: 20px;
            display: none;
        }
        
        .host-body.expanded {
            display: block;
        }
        
        /* Screenshots */
        .screenshots-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 15px;
        }
        
        .screenshot-card {
            background: var(--bg-tertiary);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border);
        }
        
        .screenshot-card img {
            width: 100%;
            height: 200px;
            object-fit: cover;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        
        .screenshot-card img:hover {
            opacity: 0.8;
        }
        
        .screenshot-card .caption {
            padding: 12px;
            font-size: 0.85rem;
            color: var(--text-secondary);
            word-break: break-all;
        }
        
        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.9);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        
        .modal.active {
            display: flex;
        }
        
        .modal img {
            max-width: 90%;
            max-height: 90%;
        }
        
        .modal-close {
            position: absolute;
            top: 20px;
            right: 30px;
            font-size: 2rem;
            color: white;
            cursor: pointer;
        }
        
        /* Severity */
        .severity-critical { color: #ff4444; }
        .severity-high { color: #ff8800; }
        .severity-medium { color: #ffcc00; }
        .severity-low { color: #00ccff; }
        .severity-info { color: #888888; }
        
        /* Section */
        .section {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid var(--border);
        }
        
        .section h2 {
            color: var(--text-primary);
            margin-bottom: 15px;
            font-size: 1.3rem;
        }
        
        /* Empty state */
        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
        }
        
        /* Port list */
        .port-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        
        .port-badge {
            display: inline-block;
            padding: 4px 10px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            font-size: 0.85rem;
            border: 1px solid var(--border);
        }
        
        .port-badge.http { border-color: var(--success); color: var(--success); }
        .port-badge.https { border-color: var(--accent-secondary); color: var(--accent-secondary); }
        
        /* Logs section */
        .logs-container {
            background: var(--bg-tertiary);
            border-radius: 6px;
            padding: 15px;
            font-family: monospace;
            font-size: 0.85rem;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .log-line {
            padding: 3px 0;
            border-bottom: 1px solid var(--border);
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .tab-btn {
                padding: 10px 15px;
                font-size: 0.85rem;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔴 Red Iris Info Gather</h1>
            <div class="meta">
                <strong>스캔 일시:</strong> {{ scan_date }}<br>
                <strong>포트 스캔 모드:</strong> {{ port_mode }}
            </div>
        </div>
        
        <!-- Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">{{ stats.total_targets }}</div>
                <div class="label">Total Targets</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.alive_hosts }}</div>
                <div class="label">Alive Hosts</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.open_ports }}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.web_servers }}</div>
                <div class="label">Web Servers</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.discovered_paths }}</div>
                <div class="label">Paths Found</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ stats.vulnerabilities }}</div>
                <div class="label">Vulnerabilities</div>
            </div>
        </div>
        
        <!-- Main Tabs -->
        <div class="tabs">
            <div class="tab-list">
                <button class="tab-btn active" onclick="showTab('overview')">📊 Overview</button>
                <button class="tab-btn" onclick="showTab('hosts')">🖥️ Hosts ({{ stats.alive_hosts }})</button>
                <button class="tab-btn" onclick="showTab('tech')">🔧 Tech Stack ({{ tech_results|length }})</button>
                <button class="tab-btn" onclick="showTab('cves')">🔥 CVEs ({{ cve_results|length }})</button>
                <button class="tab-btn" onclick="showTab('ports')">🔌 Ports ({{ stats.open_ports }})</button>
                <button class="tab-btn" onclick="showTab('paths')">📁 Paths ({{ stats.discovered_paths }})</button>
                <button class="tab-btn" onclick="showTab('vulns')">⚠️ Vulns ({{ stats.vulnerabilities }})</button>
                <button class="tab-btn" onclick="showTab('screenshots')">📸 Screenshots ({{ screenshots|length }})</button>
                <button class="tab-btn" onclick="showTab('logs')">📝 Logs</button>
            </div>
            
            <!-- Overview Tab -->
            <div id="overview" class="tab-content active">
                <h2>스캔 개요</h2>
                
                <div class="section">
                    <h3>🌐 발견된 서브도메인</h3>
                    {% if subdomains %}
                    <div style="margin-top: 10px;">
                        {% for subdomain in subdomains[:20] %}
                        <span class="port-badge">{{ subdomain }}</span>
                        {% endfor %}
                        {% if subdomains|length > 20 %}
                        <span class="badge badge-info">+{{ subdomains|length - 20 }} more</span>
                        {% endif %}
                    </div>
                    {% else %}
                    <p class="empty-state">발견된 서브도메인이 없습니다.</p>
                    {% endif %}
                </div>
                
                <div class="section">
                    <h3>🌍 웹 서버</h3>
                    {% if web_servers %}
                    <table class="data-table">
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
                    {% else %}
                    <p class="empty-state">발견된 웹 서버가 없습니다.</p>
                    {% endif %}
                </div>
            </div>
            
            <!-- Hosts Tab -->
            <div id="hosts" class="tab-content">
                <div class="controls">
                    <div class="search-box">
                        <input type="text" id="host-search" placeholder="호스트 검색..." onkeyup="filterHosts()">
                    </div>
                </div>
                
                {% for host, data in hosts_data.items() %}
                <div class="host-card" data-host="{{ host }}">
                    <div class="host-header" onclick="toggleHost(this)">
                        <h3>{{ host }}</h3>
                        <span class="badge badge-info">{{ data.ports|length }} ports</span>
                    </div>
                    <div class="host-body">
                        <h4>열린 포트</h4>
                        <div class="port-list" style="margin: 10px 0;">
                            {% for port in data.ports %}
                            <span class="port-badge {{ 'https' if port.service == 'https' else 'http' if port.is_http else '' }}">
                                {{ port.port }}/{{ port.service }}
                            </span>
                            {% endfor %}
                        </div>
                        
                        {% if data.paths %}
                        <h4 style="margin-top: 15px;">발견된 경로</h4>
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>경로</th>
                                    <th>상태</th>
                                    <th>크기</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for path in data.paths[:10] %}
                                <tr>
                                    <td>{{ path.path }}</td>
                                    <td><span class="badge {{ 'badge-success' if path.status_code == 200 else 'badge-warning' if path.status_code == 301 or path.status_code == 302 else 'badge-danger' if path.status_code == 403 else 'badge-info' }}">{{ path.status_code }}</span></td>
                                    <td>{{ path.content_length }} bytes</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                        {% if data.paths|length > 10 %}
                        <p style="color: var(--text-secondary); margin-top: 10px;">+{{ data.paths|length - 10 }} more paths</p>
                        {% endif %}
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
                
                {% if not hosts_data %}
                <p class="empty-state">발견된 호스트가 없습니다.</p>
                {% endif %}
            </div>
            
            <!-- Tech Stack Tab -->
            <div id="tech" class="tab-content">
                <h2>🔧 기술 스택 분석</h2>
                <div class="controls">
                    <div class="search-box">
                        <input type="text" id="tech-search" placeholder="기술 검색..." onkeyup="filterTechCards()">
                    </div>
                </div>
                
                {% for tech_result in tech_results %}
                <div class="host-card" data-host="{{ tech_result.url }}">
                    <div class="host-header" onclick="toggleHost(this)">
                        <h3>{{ tech_result.url }}</h3>
                        <span class="badge badge-info">{{ tech_result.technologies|length }} technologies</span>
                    </div>
                    <div class="host-body">
                        {% if tech_result.server %}
                        <p><strong>Server:</strong> {{ tech_result.server }}</p>
                        {% endif %}
                        {% if tech_result.powered_by %}
                        <p><strong>X-Powered-By:</strong> {{ tech_result.powered_by }}</p>
                        {% endif %}
                        
                        {% if tech_result.technologies %}
                        <h4 style="margin-top: 15px;">탐지된 기술</h4>
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>기술</th>
                                    <th>카테고리</th>
                                    <th>버전</th>
                                    <th>소스</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for tech in tech_result.technologies %}
                                <tr>
                                    <td><strong>{{ tech.name }}</strong></td>
                                    <td><span class="badge badge-info">{{ tech.category }}</span></td>
                                    <td>{{ tech.version or '-' }}</td>
                                    <td>{{ tech.source }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                        {% endif %}
                        
                        {% if tech_result.ssl_info and tech_result.ssl_info.issuer %}
                        <h4 style="margin-top: 15px;">SSL 정보</h4>
                        <div style="background: var(--bg-tertiary); padding: 10px; border-radius: 6px; font-size: 0.9rem;">
                            <p><strong>발급자:</strong> {{ tech_result.ssl_info.issuer.organizationName or 'N/A' }}</p>
                            {% if tech_result.ssl_info.not_after %}
                            <p><strong>만료일:</strong> {{ tech_result.ssl_info.not_after }}</p>
                            {% endif %}
                            {% if tech_result.ssl_info.cipher %}
                            <p><strong>암호:</strong> {{ tech_result.ssl_info.cipher.name }} ({{ tech_result.ssl_info.cipher.bits }} bits)</p>
                            {% endif %}
                        </div>
                        {% endif %}
                        
                        {% if tech_result.shodan_info and tech_result.shodan_info.org %}
                        <h4 style="margin-top: 15px;">Shodan 정보</h4>
                        <div style="background: var(--bg-tertiary); padding: 10px; border-radius: 6px; font-size: 0.9rem;">
                            <p><strong>조직:</strong> {{ tech_result.shodan_info.org }}</p>
                            {% if tech_result.shodan_info.isp %}
                            <p><strong>ISP:</strong> {{ tech_result.shodan_info.isp }}</p>
                            {% endif %}
                            {% if tech_result.shodan_info.country %}
                            <p><strong>위치:</strong> {{ tech_result.shodan_info.city or '' }} {{ tech_result.shodan_info.country }}</p>
                            {% endif %}
                            {% if tech_result.shodan_info.os %}
                            <p><strong>OS:</strong> {{ tech_result.shodan_info.os }}</p>
                            {% endif %}
                            {% if tech_result.shodan_info.vulns %}
                            <p><strong>알려진 취약점:</strong> 
                                {% for vuln in tech_result.shodan_info.vulns[:5] %}
                                <span class="badge badge-danger">{{ vuln }}</span>
                                {% endfor %}
                            </p>
                            {% endif %}
                        </div>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
                
                {% if not tech_results %}
                <p class="empty-state">기술 스택 정보가 없습니다.</p>
                {% endif %}
            </div>
            
            <!-- CVEs Tab -->
            <div id="cves" class="tab-content">
                <h2>🔥 알려진 취약점 (CVE)</h2>
                <div class="controls">
                    <div class="search-box">
                        <input type="text" id="cve-search" placeholder="CVE 검색..." onkeyup="filterTable('cves-table', 'cve-search')">
                    </div>
                    <select class="filter-select" onchange="filterCVEBySeverity(this.value)">
                        <option value="">모든 심각도</option>
                        <option value="critical">Critical (9.0+)</option>
                        <option value="high">High (7.0-8.9)</option>
                        <option value="medium">Medium (4.0-6.9)</option>
                        <option value="low">Low (0.1-3.9)</option>
                    </select>
                </div>
                
                {% if cve_results %}
                <table class="data-table" id="cves-table">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>제품</th>
                            <th>CVSS</th>
                            <th>심각도</th>
                            <th>발견 위치</th>
                            <th>설명</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for cve in cve_results %}
                        <tr data-severity="{{ cve.severity }}">
                            <td><a href="{{ cve.url }}" target="_blank">{{ cve.cve_id }}</a></td>
                            <td><strong>{{ cve.product }}</strong>{% if cve.version %} {{ cve.version }}{% endif %}</td>
                            <td>{{ cve.cvss_score or '-' }}</td>
                            <td>
                                <span class="badge {{ 'badge-danger' if cve.severity in ['critical', 'high'] else 'badge-warning' if cve.severity == 'medium' else 'badge-info' }}">
                                    {{ cve.severity|upper }}
                                </span>
                            </td>
                            <td style="font-size: 0.85rem;">{{ cve.detected_on }}</td>
                            <td style="font-size: 0.85rem; max-width: 300px;">{{ cve.description[:150] }}{% if cve.description|length > 150 %}...{% endif %}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p class="empty-state">발견된 CVE가 없습니다. ✅</p>
                {% endif %}
            </div>
            
            <!-- Ports Tab -->
            <div id="ports" class="tab-content">
                <div class="controls">
                    <div class="search-box">
                        <input type="text" id="port-search" placeholder="포트 또는 서비스 검색..." onkeyup="filterTable('ports-table', 'port-search')">
                    </div>
                    <select class="filter-select" onchange="filterByService(this.value)">
                        <option value="">모든 서비스</option>
                        <option value="http">HTTP</option>
                        <option value="https">HTTPS</option>
                        <option value="ssh">SSH</option>
                        <option value="ftp">FTP</option>
                    </select>
                </div>
                
                <table class="data-table" id="ports-table">
                    <thead>
                        <tr>
                            <th>호스트</th>
                            <th>포트</th>
                            <th>서비스</th>
                            <th>HTTP</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for port in open_ports %}
                        <tr data-service="{{ port.service }}">
                            <td>{{ port.host }}</td>
                            <td>{{ port.port }}</td>
                            <td>{{ port.service }}</td>
                            <td>{{ '✅' if port.is_http else '❌' }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                
                {% if not open_ports %}
                <p class="empty-state">발견된 열린 포트가 없습니다.</p>
                {% endif %}
            </div>
            
            <!-- Paths Tab -->
            <div id="paths" class="tab-content">
                <div class="controls">
                    <div class="search-box">
                        <input type="text" id="path-search" placeholder="경로 검색..." onkeyup="filterTable('paths-table', 'path-search')">
                    </div>
                    <select class="filter-select" onchange="filterByStatus(this.value)">
                        <option value="">모든 상태</option>
                        <option value="200">200 OK</option>
                        <option value="301">301 Redirect</option>
                        <option value="302">302 Redirect</option>
                        <option value="403">403 Forbidden</option>
                    </select>
                </div>
                
                <table class="data-table" id="paths-table">
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
                        <tr data-status="{{ path.status_code }}">
                            <td>{{ path.url }}</td>
                            <td>{{ path.path }}</td>
                            <td>
                                <span class="badge {{ 'badge-success' if path.status_code == 200 else 'badge-warning' if path.status_code in [301, 302] else 'badge-danger' if path.status_code == 403 else 'badge-info' }}">
                                    {{ path.status_code }}
                                </span>
                            </td>
                            <td>{{ path.content_length }} bytes</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                
                {% if not discovered_paths %}
                <p class="empty-state">발견된 경로가 없습니다.</p>
                {% endif %}
            </div>
            
            <!-- Vulnerabilities Tab -->
            <div id="vulns" class="tab-content">
                <div class="controls">
                    <div class="search-box">
                        <input type="text" id="vuln-search" placeholder="취약점 검색..." onkeyup="filterTable('vulns-table', 'vuln-search')">
                    </div>
                    <select class="filter-select" onchange="filterBySeverity(this.value)">
                        <option value="">모든 심각도</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="info">Info</option>
                    </select>
                </div>
                
                <table class="data-table" id="vulns-table">
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
                        <tr data-severity="{{ vuln.severity }}">
                            <td class="severity-{{ vuln.severity }}">{{ vuln.severity|upper }}</td>
                            <td>{{ vuln.template_id }}</td>
                            <td>{{ vuln.template_name }}</td>
                            <td><a href="{{ vuln.matched_url }}" target="_blank">{{ vuln.matched_url }}</a></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                
                {% if not vulnerabilities %}
                <p class="empty-state">발견된 취약점이 없습니다. ✅</p>
                {% endif %}
            </div>
            
            <!-- Screenshots Tab -->
            <div id="screenshots" class="tab-content">
                <div class="controls">
                    <div class="search-box">
                        <input type="text" id="screenshot-search" placeholder="URL 검색..." onkeyup="filterScreenshots()">
                    </div>
                </div>
                
                <div class="screenshots-grid">
                    {% for screenshot in screenshots %}
                    {% if screenshot.success %}
                    <div class="screenshot-card" data-url="{{ screenshot.url }}">
                        <img src="data:image/png;base64,{{ screenshot.base64 }}" alt="{{ screenshot.url }}" onclick="openModal(this.src)">
                        <div class="caption">{{ screenshot.url }}</div>
                    </div>
                    {% endif %}
                    {% endfor %}
                </div>
                
                {% if not screenshots %}
                <p class="empty-state">캡처된 스크린샷이 없습니다.</p>
                {% endif %}
            </div>
            
            <!-- Logs Tab -->
            <div id="logs" class="tab-content">
                <h2>스캔 로그</h2>
                <div class="logs-container">
                    {% for log in logs %}
                    <div class="log-line">{{ log }}</div>
                    {% endfor %}
                </div>
                
                {% if errors %}
                <h2 style="margin-top: 20px; color: var(--accent);">오류</h2>
                <div class="logs-container" style="border-color: var(--accent);">
                    {% for error in errors %}
                    <div class="log-line" style="color: var(--accent);">{{ error }}</div>
                    {% endfor %}
                </div>
                {% endif %}
            </div>
        </div>
    </div>
    
    <!-- Image Modal -->
    <div class="modal" id="imageModal" onclick="closeModal()">
        <span class="modal-close">&times;</span>
        <img id="modalImage" src="">
    </div>
    
    <script>
        // Tab switching
        function showTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
        }
        
        // Host card toggle
        function toggleHost(header) {
            const body = header.nextElementSibling;
            body.classList.toggle('expanded');
        }
        
        // Filter hosts
        function filterHosts() {
            const query = document.getElementById('host-search').value.toLowerCase();
            document.querySelectorAll('.host-card').forEach(card => {
                const host = card.dataset.host.toLowerCase();
                card.style.display = host.includes(query) ? 'block' : 'none';
            });
        }
        
        // Filter table
        function filterTable(tableId, searchId) {
            const query = document.getElementById(searchId).value.toLowerCase();
            const rows = document.querySelectorAll(`#${tableId} tbody tr`);
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(query) ? '' : 'none';
            });
        }
        
        // Filter by service
        function filterByService(service) {
            const rows = document.querySelectorAll('#ports-table tbody tr');
            rows.forEach(row => {
                if (!service || row.dataset.service === service) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
        
        // Filter by status
        function filterByStatus(status) {
            const rows = document.querySelectorAll('#paths-table tbody tr');
            rows.forEach(row => {
                if (!status || row.dataset.status === status) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
        
        // Filter by severity
        function filterBySeverity(severity) {
            const rows = document.querySelectorAll('#vulns-table tbody tr');
            rows.forEach(row => {
                if (!severity || row.dataset.severity === severity) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
        
        // Filter screenshots
        function filterScreenshots() {
            const query = document.getElementById('screenshot-search').value.toLowerCase();
            document.querySelectorAll('.screenshot-card').forEach(card => {
                const url = card.dataset.url.toLowerCase();
                card.style.display = url.includes(query) ? 'block' : 'none';
            });
        }
        
        // Filter tech cards
        function filterTechCards() {
            const query = document.getElementById('tech-search').value.toLowerCase();
            document.querySelectorAll('#tech .host-card').forEach(card => {
                const text = card.textContent.toLowerCase();
                card.style.display = text.includes(query) ? 'block' : 'none';
            });
        }
        
        // Filter CVE by severity
        function filterCVEBySeverity(severity) {
            const rows = document.querySelectorAll('#cves-table tbody tr');
            rows.forEach(row => {
                if (!severity || row.dataset.severity === severity) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
        
        // Modal
        function openModal(src) {
            document.getElementById('modalImage').src = src;
            document.getElementById('imageModal').classList.add('active');
        }
        
        function closeModal() {
            document.getElementById('imageModal').classList.remove('active');
        }
        
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') closeModal();
        });
        
        // Auto-expand first host
        const firstHost = document.querySelector('.host-body');
        if (firstHost) firstHost.classList.add('expanded');
    </script>
</body>
</html>
"""


def load_screenshot_as_base64(screenshot_path: str) -> str:
    """Load a screenshot file and convert to base64"""
    try:
        path = Path(screenshot_path)
        if path.exists():
            with open(path, 'rb') as f:
                return base64.b64encode(f.read()).decode('utf-8')
    except Exception:
        pass
    return ""


def organize_data_by_host(state: ScanState) -> Dict[str, Dict]:
    """Organize all data by host for easier display"""
    hosts_data = defaultdict(lambda: {'ports': [], 'paths': [], 'vulnerabilities': []})
    
    # Organize ports by host
    for port in state.get('open_ports', []):
        host = port.get('host', 'unknown')
        hosts_data[host]['ports'].append(port)
    
    # Organize paths by host
    for path in state.get('discovered_paths', []):
        # Extract host from URL
        url = path.get('url', '')
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.netloc
            if ':' in host:
                host = host.split(':')[0]
            hosts_data[host]['paths'].append(path)
        except:
            pass
    
    # Organize vulnerabilities by host
    for vuln in state.get('vulnerabilities', []):
        matched_url = vuln.get('matched_url', '')
        try:
            from urllib.parse import urlparse
            parsed = urlparse(matched_url)
            host = parsed.netloc
            if ':' in host:
                host = host.split(':')[0]
            hosts_data[host]['vulnerabilities'].append(vuln)
        except:
            pass
    
    return dict(hosts_data)


def generate_report(state: ScanState) -> dict:
    """
    Generate an interactive HTML report.
    
    Features:
    - Tab-based navigation by host/domain
    - Search and filtering
    - Embedded screenshots
    """
    logs = [f"[ReportGenerator] Generating HTML report"]
    errors = []
    
    try:
        # Calculate statistics
        stats = {
            'total_targets': len(set(
                state.get('raw_domains', []) + 
                state.get('raw_ips', []) + 
                state.get('subdomains', [])
            )),
            'alive_hosts': len(state.get('alive_hosts', [])),
            'open_ports': len(state.get('open_ports', [])),
            'web_servers': len(state.get('web_servers', [])),
            'discovered_paths': len(state.get('discovered_paths', [])),
            'vulnerabilities': len(state.get('vulnerabilities', []))
        }
        
        # Prepare screenshots with base64 encoding
        screenshots = []
        for ss in state.get('screenshots', []):
            if ss.get('success') and ss.get('path'):
                base64_data = load_screenshot_as_base64(ss['path'])
                if base64_data:
                    screenshots.append({
                        'url': ss.get('url', ''),
                        'base64': base64_data,
                        'success': True
                    })
        
        # Organize data by host
        hosts_data = organize_data_by_host(state)
        
        # Render template
        template = Template(REPORT_TEMPLATE)
        html_content = template.render(
            scan_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            port_mode=config.PORT_SCAN_MODE.upper(),
            stats=stats,
            subdomains=state.get('subdomains', []),
            web_servers=state.get('web_servers', []),
            hosts_data=hosts_data,
            tech_results=state.get('tech_results', []),
            cve_results=state.get('cve_results', []),
            open_ports=state.get('open_ports', []),
            discovered_paths=state.get('discovered_paths', []),
            vulnerabilities=state.get('vulnerabilities', []),
            screenshots=screenshots,
            logs=state.get('logs', []),
            errors=state.get('errors', [])
        )
        
        # Save report
        report_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = config.REPORTS_DIR / report_filename
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logs.append(f"[ReportGenerator] Report saved to: {report_path}")
        
        return {
            'report_path': str(report_path),
            'errors': errors,
            'logs': logs
        }
        
    except Exception as e:
        errors.append(f"[ReportGenerator] Error generating report: {str(e)}")
        return {
            'report_path': None,
            'errors': errors,
            'logs': logs
        }
