"""
Red Iris Info Gather - LangGraph State Schema

Defines the shared state structure that flows through all nodes in the pipeline.
Uses TypedDict with Annotated types for proper state accumulation.
"""
from typing import TypedDict, List, Optional, Annotated
import operator


class PortScanResult(TypedDict):
    """Individual port scan result"""
    host: str
    port: int
    service: Optional[str]
    is_http: bool


class ScreenshotResult(TypedDict):
    """Screenshot capture result"""
    url: str
    path: str
    success: bool
    error: Optional[str]


class DirectoryScanResult(TypedDict):
    """Directory scan result"""
    url: str
    path: str
    status_code: int
    content_length: int


class NucleiResult(TypedDict):
    """Nuclei vulnerability scan result"""
    template_id: str
    template_name: str
    severity: str
    matched_url: str
    matched_at: str
    extracted_results: Optional[List[str]]


class ScanState(TypedDict):
    """
    Main state schema for the scanning pipeline.
    
    Uses Annotated types with operator.add to enable state accumulation
    across multiple node executions.
    """
    # === Input Data ===
    input_file: str                                    # Path to input file
    raw_domains: List[str]                             # Raw domain entries from input
    raw_ips: List[str]                                 # Raw IP/CIDR entries from input
    
    # === Parsed Data ===
    base_domains: Annotated[List[str], operator.add]   # Extracted base domains (e.g., example.com)
    subdomains: Annotated[List[str], operator.add]     # Discovered subdomains
    all_targets: Annotated[List[str], operator.add]    # All targets (IPs + resolved domains)
    
    # === Host Discovery ===
    alive_hosts: Annotated[List[str], operator.add]    # Hosts that responded to probes
    
    # === Port Scan Results ===
    open_ports: Annotated[List[PortScanResult], operator.add]  # Open port details
    web_servers: Annotated[List[str], operator.add]            # HTTP/HTTPS server URLs
    
    # === Screenshots ===
    screenshots: Annotated[List[ScreenshotResult], operator.add]  # Captured screenshots
    
    # === Directory Scan ===
    discovered_paths: Annotated[List[DirectoryScanResult], operator.add]  # Found paths
    
    # === Nuclei Results ===
    vulnerabilities: Annotated[List[NucleiResult], operator.add]  # Detected vulnerabilities
    
    # === Report ===
    report_path: Optional[str]                         # Generated report path
    
    # === Logging ===
    errors: Annotated[List[str], operator.add]         # Error messages
    logs: Annotated[List[str], operator.add]           # General log messages


def create_initial_state(input_file: str) -> ScanState:
    """Create initial state with default values"""
    return ScanState(
        input_file=input_file,
        raw_domains=[],
        raw_ips=[],
        base_domains=[],
        subdomains=[],
        all_targets=[],
        alive_hosts=[],
        open_ports=[],
        web_servers=[],
        screenshots=[],
        discovered_paths=[],
        vulnerabilities=[],
        report_path=None,
        errors=[],
        logs=[]
    )
