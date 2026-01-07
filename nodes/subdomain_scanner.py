"""
Red Iris Info Gather - Subdomain Scanner Node

Performs subdomain enumeration using multiple tools:
- Subfinder (local binary from tools/bin)
- Sublist3r (local script from tools/repos)
- Shodan (if API key is available)
"""
import subprocess
import os
import sys
import json
from typing import List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from state import ScanState
import config


def run_subfinder(domain: str) -> List[str]:
    """Run local subfinder for subdomain enumeration"""
    subdomains = []
    
    subfinder_path = config.SUBFINDER_PATH
    if not Path(subfinder_path).exists():
        return subdomains
    
    try:
        result = subprocess.run(
            [subfinder_path, '-d', domain, '-silent', '-json'],
            capture_output=True,
            text=True,
            timeout=300
        )
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    if 'host' in data:
                        subdomains.append(data['host'].lower())
                except json.JSONDecodeError:
                    # Plain text output
                    if '.' in line:
                        subdomains.append(line.strip().lower())
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return subdomains


def run_sublist3r(domain: str) -> List[str]:
    """Run local sublist3r script from tools/repos/Sublist3r"""
    subdomains = []
    
    sublist3r_script = config.SUBLIST3R_SCRIPT
    sublist3r_dir = config.SUBLIST3R_DIR
    
    if not sublist3r_script.exists():
        return subdomains
    
    try:
        # Run sublist3r.py
        result = subprocess.run(
            [sys.executable, str(sublist3r_script), '-d', domain, '-o', '/dev/stdout'],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(sublist3r_dir)
        )
        for line in result.stdout.strip().split('\n'):
            if line and '.' in line and not line.startswith('['):
                subdomains.append(line.strip().lower())
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    
    return subdomains


def run_shodan(domain: str) -> List[str]:
    """Query Shodan for subdomains (requires API key)"""
    subdomains = []
    if not config.SHODAN_API_KEY:
        return subdomains
    
    try:
        import shodan
        api = shodan.Shodan(config.SHODAN_API_KEY)
        
        # Search for hostnames containing the domain
        results = api.search(f'hostname:{domain}')
        for result in results.get('matches', []):
            hostnames = result.get('hostnames', [])
            for hostname in hostnames:
                if domain in hostname.lower():
                    subdomains.append(hostname.lower())
    except Exception:
        pass
    return subdomains


def enumerate_domain(domain: str) -> tuple:
    """Run all enumeration tools for a single domain"""
    all_subdomains = set()
    
    # Run subfinder
    subfinder_results = run_subfinder(domain)
    all_subdomains.update(subfinder_results)
    
    # Run sublist3r
    sublist3r_results = run_sublist3r(domain)
    all_subdomains.update(sublist3r_results)
    
    # Run shodan if API key is available
    if config.SHODAN_API_KEY:
        shodan_results = run_shodan(domain)
        all_subdomains.update(shodan_results)
    
    return domain, list(all_subdomains)


def run(state: ScanState) -> dict:
    """
    Subdomain Scanner Node - Entry point
    
    Enumerates subdomains for all base domains using local tools.
    """
    base_domains = state.get('base_domains', [])
    logs = []
    errors = []
    all_subdomains: Set[str] = set()
    all_targets: List[str] = []
    
    logs.append(f"[SubdomainScanner] Starting subdomain enumeration for {len(base_domains)} base domains")
    
    if not base_domains:
        logs.append("[SubdomainScanner] No base domains to enumerate")
        return {
            'subdomains': [],
            'all_targets': [],
            'errors': errors,
            'logs': logs
        }
    
    # Check available tools
    tools_available = []
    if Path(config.SUBFINDER_PATH).exists():
        tools_available.append('subfinder')
    if config.SUBLIST3R_SCRIPT.exists():
        tools_available.append('sublist3r')
    if config.SHODAN_API_KEY:
        tools_available.append('shodan')
    
    logs.append(f"[SubdomainScanner] Available tools: {', '.join(tools_available) if tools_available else 'None'}")
    
    if not tools_available:
        errors.append("[SubdomainScanner] No subdomain enumeration tools available. Run: ./tools/install_tools.sh")
        return {
            'subdomains': [],
            'all_targets': [],
            'errors': errors,
            'logs': logs
        }
    
    # Run enumeration in parallel for each domain
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(enumerate_domain, domain): domain 
            for domain in base_domains
        }
        
        for future in as_completed(futures):
            domain = futures[future]
            try:
                _, subdomains = future.result()
                all_subdomains.update(subdomains)
                logs.append(f"[SubdomainScanner] Found {len(subdomains)} subdomains for {domain}")
            except Exception as e:
                errors.append(f"[SubdomainScanner] Error enumerating {domain}: {str(e)}")
    
    # Add subdomains to targets
    all_targets = list(all_subdomains)
    
    logs.append(f"[SubdomainScanner] Total unique subdomains found: {len(all_subdomains)}")
    
    return {
        'subdomains': list(all_subdomains),
        'all_targets': all_targets,
        'errors': errors,
        'logs': logs
    }
