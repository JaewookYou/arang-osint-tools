"""
Red Iris Info Gather - SQLite Database Module

Manages scan data persistence using SQLite.
Stores:
- Scan sessions
- Hosts and subdomains
- Ports
- Technologies
- CVEs
- Endpoints with response data
- Vulnerabilities
"""
import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from contextlib import contextmanager

import config


class ScanDatabase:
    """SQLite database manager for scan data"""
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file. If None, creates in output dir.
        """
        if db_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.db_path = config.OUTPUT_DIR / f"scan_{timestamp}.db"
        else:
            self.db_path = Path(db_path)
        
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    
    def _init_schema(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Scan sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    input_file TEXT,
                    target_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'running'
                )
            ''')
            
            # Hosts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    hostname TEXT NOT NULL,
                    ip_address TEXT,
                    is_alive BOOLEAN DEFAULT 0,
                    discovered_at TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')
            
            # Ports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    service TEXT,
                    is_http BOOLEAN DEFAULT 0,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')
            
            # Technologies table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS technologies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    url TEXT NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT,
                    category TEXT,
                    source TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')
            
            # CVEs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cves (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    cve_id TEXT NOT NULL,
                    product TEXT,
                    version TEXT,
                    cvss_score REAL,
                    severity TEXT,
                    description TEXT,
                    url TEXT,
                    source TEXT,
                    korean_summary TEXT,
                    vuln_type TEXT,
                    affected_versions TEXT,
                    conditions TEXT,
                    attack_method TEXT,
                    impact TEXT,
                    exploit_url TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')
            
            # Endpoints table (with response data)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    base_url TEXT NOT NULL,
                    path TEXT NOT NULL,
                    full_url TEXT NOT NULL,
                    status_code INTEGER,
                    content_length INTEGER,
                    content_type TEXT,
                    response_time REAL,
                    response_headers TEXT,
                    response_body TEXT,
                    discovered_at TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')
            
            # Vulnerabilities table (Nuclei results)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    template_id TEXT,
                    template_name TEXT,
                    severity TEXT,
                    matched_url TEXT,
                    matched_at TEXT,
                    extracted_results TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')
            
            # Create indexes for common queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_scan ON cves(scan_id)')
    
    # ============================================
    # Scan Session Management
    # ============================================
    
    def create_scan(self, input_file: str, target_count: int = 0) -> int:
        """Create a new scan session and return its ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scans (created_at, input_file, target_count, status)
                VALUES (?, ?, ?, 'running')
            ''', (datetime.now().isoformat(), input_file, target_count))
            return cursor.lastrowid
    
    def complete_scan(self, scan_id: int):
        """Mark scan as completed"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE scans SET status = 'completed' WHERE id = ?
            ''', (scan_id,))
    
    # ============================================
    # Hosts
    # ============================================
    
    def add_host(self, scan_id: int, hostname: str, ip_address: str = None, is_alive: bool = False):
        """Add a discovered host"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO hosts (scan_id, hostname, ip_address, is_alive, discovered_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_id, hostname, ip_address, is_alive, datetime.now().isoformat()))
    
    def add_hosts_batch(self, scan_id: int, hosts: List[Dict]):
        """Add multiple hosts at once"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            cursor.executemany('''
                INSERT INTO hosts (scan_id, hostname, ip_address, is_alive, discovered_at)
                VALUES (?, ?, ?, ?, ?)
            ''', [(scan_id, h.get('hostname'), h.get('ip_address'), h.get('is_alive', False), now) for h in hosts])
    
    def get_hosts(self, scan_id: int) -> List[Dict]:
        """Get all hosts for a scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM hosts WHERE scan_id = ?', (scan_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    # ============================================
    # Ports
    # ============================================
    
    def add_port(self, scan_id: int, host: str, port: int, service: str = None, is_http: bool = False):
        """Add an open port"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO ports (scan_id, host, port, service, is_http)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_id, host, port, service, is_http))
    
    def add_ports_batch(self, scan_id: int, ports: List[Dict]):
        """Add multiple ports at once"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany('''
                INSERT INTO ports (scan_id, host, port, service, is_http)
                VALUES (?, ?, ?, ?, ?)
            ''', [(scan_id, p.get('host'), p.get('port'), p.get('service'), p.get('is_http', False)) for p in ports])
    
    def get_ports(self, scan_id: int) -> List[Dict]:
        """Get all ports for a scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM ports WHERE scan_id = ?', (scan_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    # ============================================
    # Technologies
    # ============================================
    
    def add_technology(self, scan_id: int, url: str, name: str, version: str = None, 
                       category: str = None, source: str = None):
        """Add a detected technology"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO technologies (scan_id, url, name, version, category, source)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (scan_id, url, name, version, category, source))
    
    def add_technologies_batch(self, scan_id: int, techs: List[Dict]):
        """Add multiple technologies at once"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany('''
                INSERT INTO technologies (scan_id, url, name, version, category, source)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', [(scan_id, t.get('url'), t.get('name'), t.get('version'), 
                   t.get('category'), t.get('source')) for t in techs])
    
    def get_technologies(self, scan_id: int) -> List[Dict]:
        """Get all technologies for a scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM technologies WHERE scan_id = ?', (scan_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    # ============================================
    # CVEs
    # ============================================
    
    def add_cve(self, scan_id: int, cve_data: Dict):
        """Add a CVE result"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO cves (scan_id, cve_id, product, version, cvss_score, severity,
                                  description, url, source, korean_summary, vuln_type,
                                  affected_versions, conditions, attack_method, impact, exploit_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                cve_data.get('cve_id'),
                cve_data.get('product'),
                cve_data.get('version'),
                cve_data.get('cvss_score'),
                cve_data.get('severity'),
                cve_data.get('description'),
                cve_data.get('url'),
                cve_data.get('source'),
                cve_data.get('korean_summary'),
                cve_data.get('vuln_type'),
                cve_data.get('affected_versions'),
                cve_data.get('conditions'),
                cve_data.get('attack_method'),
                cve_data.get('impact'),
                cve_data.get('exploit_url')
            ))
    
    def add_cves_batch(self, scan_id: int, cves: List[Dict]):
        """Add multiple CVEs at once"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany('''
                INSERT INTO cves (scan_id, cve_id, product, version, cvss_score, severity,
                                  description, url, source, korean_summary, vuln_type,
                                  affected_versions, conditions, attack_method, impact, exploit_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', [(
                scan_id,
                c.get('cve_id'),
                c.get('product'),
                c.get('version'),
                c.get('cvss_score'),
                c.get('severity'),
                c.get('description'),
                c.get('url'),
                c.get('source'),
                c.get('korean_summary'),
                c.get('vuln_type'),
                c.get('affected_versions'),
                c.get('conditions'),
                c.get('attack_method'),
                c.get('impact'),
                c.get('exploit_url')
            ) for c in cves])
    
    def get_cves(self, scan_id: int) -> List[Dict]:
        """Get all CVEs for a scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM cves WHERE scan_id = ?', (scan_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    # ============================================
    # Endpoints (with response data)
    # ============================================
    
    def add_endpoint(self, scan_id: int, endpoint_data: Dict):
        """Add a discovered endpoint with response data"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Serialize headers to JSON
            headers = endpoint_data.get('response_headers', {})
            headers_json = json.dumps(headers, ensure_ascii=False) if headers else None
            
            # Truncate body to 50KB max
            body = endpoint_data.get('response_body', '')
            if body and len(body) > 51200:
                body = body[:51200] + '\n[TRUNCATED...]'
            
            cursor.execute('''
                INSERT INTO endpoints (scan_id, base_url, path, full_url, status_code,
                                       content_length, content_type, response_time,
                                       response_headers, response_body, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                endpoint_data.get('base_url', endpoint_data.get('url', '')),
                endpoint_data.get('path', ''),
                endpoint_data.get('full_url', ''),
                endpoint_data.get('status_code'),
                endpoint_data.get('content_length'),
                endpoint_data.get('content_type'),
                endpoint_data.get('response_time'),
                headers_json,
                body,
                datetime.now().isoformat()
            ))
    
    def add_endpoints_batch(self, scan_id: int, endpoints: List[Dict]):
        """Add multiple endpoints at once"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            
            rows = []
            for e in endpoints:
                headers = e.get('response_headers', {})
                headers_json = json.dumps(headers, ensure_ascii=False) if headers else None
                
                body = e.get('response_body', '')
                if body and len(body) > 51200:
                    body = body[:51200] + '\n[TRUNCATED...]'
                
                rows.append((
                    scan_id,
                    e.get('base_url', e.get('url', '')),
                    e.get('path', ''),
                    e.get('full_url', ''),
                    e.get('status_code'),
                    e.get('content_length'),
                    e.get('content_type'),
                    e.get('response_time'),
                    headers_json,
                    body,
                    now
                ))
            
            cursor.executemany('''
                INSERT INTO endpoints (scan_id, base_url, path, full_url, status_code,
                                       content_length, content_type, response_time,
                                       response_headers, response_body, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', rows)
    
    def get_endpoints(self, scan_id: int) -> List[Dict]:
        """Get all endpoints for a scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM endpoints WHERE scan_id = ?', (scan_id,))
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                # Parse headers JSON
                if d.get('response_headers'):
                    try:
                        d['response_headers'] = json.loads(d['response_headers'])
                    except:
                        d['response_headers'] = {}
                results.append(d)
            return results
    
    def get_endpoint_by_id(self, endpoint_id: int) -> Optional[Dict]:
        """Get a single endpoint by ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM endpoints WHERE id = ?', (endpoint_id,))
            row = cursor.fetchone()
            if row:
                d = dict(row)
                if d.get('response_headers'):
                    try:
                        d['response_headers'] = json.loads(d['response_headers'])
                    except:
                        d['response_headers'] = {}
                return d
            return None
    
    # ============================================
    # Vulnerabilities
    # ============================================
    
    def add_vulnerability(self, scan_id: int, vuln_data: Dict):
        """Add a vulnerability result"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            extracted = vuln_data.get('extracted_results', [])
            extracted_json = json.dumps(extracted) if extracted else None
            
            cursor.execute('''
                INSERT INTO vulnerabilities (scan_id, template_id, template_name, severity,
                                             matched_url, matched_at, extracted_results)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                vuln_data.get('template_id'),
                vuln_data.get('template_name'),
                vuln_data.get('severity'),
                vuln_data.get('matched_url'),
                vuln_data.get('matched_at'),
                extracted_json
            ))
    
    def add_vulnerabilities_batch(self, scan_id: int, vulns: List[Dict]):
        """Add multiple vulnerabilities at once"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany('''
                INSERT INTO vulnerabilities (scan_id, template_id, template_name, severity,
                                             matched_url, matched_at, extracted_results)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', [(
                scan_id,
                v.get('template_id'),
                v.get('template_name'),
                v.get('severity'),
                v.get('matched_url'),
                v.get('matched_at'),
                json.dumps(v.get('extracted_results', [])) if v.get('extracted_results') else None
            ) for v in vulns])
    
    def get_vulnerabilities(self, scan_id: int) -> List[Dict]:
        """Get all vulnerabilities for a scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                if d.get('extracted_results'):
                    try:
                        d['extracted_results'] = json.loads(d['extracted_results'])
                    except:
                        d['extracted_results'] = []
                results.append(d)
            return results
    
    # ============================================
    # Statistics
    # ============================================
    
    def get_scan_stats(self, scan_id: int) -> Dict:
        """Get statistics for a scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            cursor.execute('SELECT COUNT(*) FROM hosts WHERE scan_id = ?', (scan_id,))
            stats['total_hosts'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM hosts WHERE scan_id = ? AND is_alive = 1', (scan_id,))
            stats['alive_hosts'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM ports WHERE scan_id = ?', (scan_id,))
            stats['open_ports'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM technologies WHERE scan_id = ?', (scan_id,))
            stats['technologies'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM cves WHERE scan_id = ?', (scan_id,))
            stats['cves'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM endpoints WHERE scan_id = ?', (scan_id,))
            stats['endpoints'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
            stats['vulnerabilities'] = cursor.fetchone()[0]
            
            return stats


# Global database instance
_db: Optional[ScanDatabase] = None


def get_database() -> Optional[ScanDatabase]:
    """Get the global database instance"""
    return _db


def init_database(db_path: Optional[Path] = None) -> ScanDatabase:
    """Initialize the global database instance"""
    global _db
    _db = ScanDatabase(db_path)
    return _db
