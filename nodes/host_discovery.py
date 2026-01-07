"""
Red Iris Info Gather - Host Discovery Node

Checks if hosts are alive using:
1. Naabu (preferred - fast ProjectDiscovery tool)
2. Fallback: Multithreaded TCP socket probing
"""
import subprocess
import socket
from typing import List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from state import ScanState
import config


def tcp_probe(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a host:port is reachable via TCP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.timeout, socket.error, OSError):
        return False


def check_host_alive(host: str, ports: List[int] = None) -> bool:
    """Check if host is alive by probing common ports"""
    if ports is None:
        ports = config.HOST_DISCOVERY_PORTS
    
    for port in ports:
        if tcp_probe(host, port, config.SCAN_TIMEOUT):
            return True
    return False


def run_naabu(targets: List[str]) -> List[str]:
    """Run naabu for fast host discovery"""
    alive_hosts = []
    
    if not targets:
        return alive_hosts
    
    try:
        # Create temp file with targets
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            target_file = f.name
        
        # Run naabu with host discovery mode
        result = subprocess.run(
            [
                config.NAABU_PATH,
                '-l', target_file,
                '-p', ','.join(map(str, config.HOST_DISCOVERY_PORTS)),
                '-silent',
                '-json'
            ],
            capture_output=True,
            text=True,
            timeout=600
        )
        
        import json
        seen_hosts = set()
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    host = data.get('host', data.get('ip', ''))
                    if host and host not in seen_hosts:
                        seen_hosts.add(host)
                        alive_hosts.append(host)
                except json.JSONDecodeError:
                    pass
        
        # Cleanup
        import os
        os.unlink(target_file)
        
    except FileNotFoundError:
        raise  # Let caller handle fallback
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        raise
    
    return alive_hosts


def run_multithreaded_probe(targets: List[str]) -> List[str]:
    """Fallback: Multithreaded TCP probing"""
    alive_hosts = []
    
    with ThreadPoolExecutor(max_workers=config.MAX_THREADS) as executor:
        futures = {
            executor.submit(check_host_alive, host): host 
            for host in targets
        }
        
        for future in as_completed(futures):
            host = futures[future]
            try:
                if future.result():
                    alive_hosts.append(host)
            except Exception:
                pass
    
    return alive_hosts


def resolve_domain(domain: str) -> str:
    """Resolve domain to IP address"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def run(state: ScanState) -> dict:
    """
    Host Discovery Node - Entry point
    
    Checks which hosts are alive using naabu or multithreaded TCP probing.
    """
    # Combine all targets: raw IPs + subdomains + raw domains
    all_targets = set()
    all_targets.update(state.get('raw_ips', []))
    all_targets.update(state.get('subdomains', []))
    all_targets.update(state.get('raw_domains', []))
    all_targets.update(state.get('all_targets', []))
    
    targets = list(all_targets)
    
    logs = []
    errors = []
    alive_hosts: Set[str] = set()
    
    logs.append(f"[HostDiscovery] Checking {len(targets)} targets for alive hosts")
    
    if not targets:
        logs.append("[HostDiscovery] No targets to probe")
        return {
            'alive_hosts': [],
            'errors': errors,
            'logs': logs
        }
    
    # Try naabu first (faster)
    try:
        logs.append("[HostDiscovery] Attempting naabu for fast host discovery")
        naabu_results = run_naabu(targets)
        alive_hosts.update(naabu_results)
        logs.append(f"[HostDiscovery] Naabu found {len(naabu_results)} alive hosts")
        
        # If naabu returned no results, fallback to TCP probe (may happen due to permission issues)
        if len(naabu_results) == 0:
            logs.append("[HostDiscovery] Naabu returned 0 results, falling back to TCP probe")
            probe_results = run_multithreaded_probe(targets)
            alive_hosts.update(probe_results)
            logs.append(f"[HostDiscovery] TCP probe found {len(probe_results)} alive hosts")
            
    except FileNotFoundError:
        logs.append("[HostDiscovery] Naabu not found, falling back to multithreaded TCP probe")
        # Fallback to multithreaded probe
        probe_results = run_multithreaded_probe(targets)
        alive_hosts.update(probe_results)
        logs.append(f"[HostDiscovery] TCP probe found {len(probe_results)} alive hosts")
    except Exception as e:
        errors.append(f"[HostDiscovery] Naabu error: {str(e)}, falling back to TCP probe")
        probe_results = run_multithreaded_probe(targets)
        alive_hosts.update(probe_results)
    
    logs.append(f"[HostDiscovery] Total alive hosts: {len(alive_hosts)}")
    
    return {
        'alive_hosts': list(alive_hosts),
        'errors': errors,
        'logs': logs
    }
