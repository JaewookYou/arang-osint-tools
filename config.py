"""
Red Iris Info Gather - Configuration Settings
"""
import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.absolute()
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"
SCREENSHOTS_DIR = OUTPUT_DIR / "screenshots"
REPORTS_DIR = OUTPUT_DIR / "reports"

# Local tools directory (cloned/built from git)
TOOLS_BIN_DIR = BASE_DIR / "tools" / "bin"
TOOLS_REPOS_DIR = BASE_DIR / "tools" / "repos"

# Ensure directories exist
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
TOOLS_BIN_DIR.mkdir(parents=True, exist_ok=True)

# API Keys
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")

# Scan settings
SCAN_TIMEOUT = 2  # seconds for socket connections
MAX_THREADS = 100  # max concurrent threads for scanning
HOST_DISCOVERY_PORTS = [80, 443, 22, 21, 8080, 8443]

# Well-known ports to scan (Top 100)
WELLKNOWN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
    5901, 5902, 5903, 6379, 8000, 8080, 8443, 8888, 9000, 9090,
    9200, 9300, 10000, 27017, 27018, 28017, 1433, 1434, 1521, 2049,
    2181, 2375, 2376, 4443, 4444, 5000, 5001, 5222, 5269, 5672,
    6000, 6001, 6066, 6443, 7001, 7002, 7070, 7077, 7443, 7474,
    7687, 8001, 8002, 8008, 8009, 8010, 8081, 8082, 8083, 8084,
    8085, 8086, 8087, 8088, 8089, 8090, 8091, 8161, 8172, 8180,
    8181, 8200, 8222, 8333, 8400, 8500, 8600, 8800, 8880, 8983,
    9001, 9002, 9042, 9043, 9060, 9080, 9091, 9092, 9100, 9443
]

# HTTP detection patterns
HTTP_SIGNATURES = [b'HTTP/', b'<!DOCTYPE', b'<html', b'<HTML']


def find_local_tool(name: str) -> str:
    """Find tool in local bin directory first, then PATH"""
    # Check local tools/bin first
    local_path = TOOLS_BIN_DIR / name
    if local_path.exists():
        return str(local_path)
    
    # Check PATH
    import shutil
    path = shutil.which(name)
    if path:
        return path
    
    # Check Go bin as fallback
    go_path = os.path.expanduser(f"~/go/bin/{name}")
    if os.path.exists(go_path):
        return go_path
    
    return str(local_path)  # Return local path even if not exists


# Tool paths - prefer local installations
SUBFINDER_PATH = find_local_tool("subfinder")
NAABU_PATH = find_local_tool("naabu")
NUCLEI_PATH = find_local_tool("nuclei")
HTTPX_PATH = find_local_tool("httpx")
NMAP_PATH = find_local_tool("nmap")  # nmap is usually system-wide

# Python-based tools (repos)
DIRSEARCH_DIR = TOOLS_REPOS_DIR / "dirsearch"
DIRSEARCH_SCRIPT = DIRSEARCH_DIR / "dirsearch.py"
DIRSEARCH_WORDLIST = DIRSEARCH_DIR / "db" / "dicc.txt"

SUBLIST3R_DIR = TOOLS_REPOS_DIR / "Sublist3r"
SUBLIST3R_SCRIPT = SUBLIST3R_DIR / "sublist3r.py"

# Custom data files
CUSTOM_ENDPOINTS_FILE = DATA_DIR / "endpoints.txt"
NUCLEI_TEMPLATES_DIR = DATA_DIR / "nuclei_templates"

# Report settings
REPORT_TEMPLATE_NAME = "report_template.html"


def check_tools_installed() -> dict:
    """Check which tools are installed"""
    return {
        'subfinder': Path(SUBFINDER_PATH).exists(),
        'naabu': Path(NAABU_PATH).exists(),
        'nuclei': Path(NUCLEI_PATH).exists(),
        'httpx': Path(HTTPX_PATH).exists(),
        'dirsearch': DIRSEARCH_SCRIPT.exists(),
        'sublist3r': SUBLIST3R_SCRIPT.exists(),
        'nmap': Path(NMAP_PATH).exists() if NMAP_PATH != str(TOOLS_BIN_DIR / "nmap") else False,
    }
