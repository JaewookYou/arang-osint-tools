"""
Red Iris Info Gather - Input Parser Node

Parses input file containing domains and IP addresses.
Extracts base domains using tldextract and expands CIDR ranges.
"""
import re
import ipaddress
from pathlib import Path
from typing import List, Tuple

import tldextract

from state import ScanState


def parse_line(line: str) -> Tuple[str, str]:
    """
    Parse a single line to determine if it's a domain or IP.
    Returns: (value, type) where type is 'domain', 'ip', or 'cidr'
    """
    line = line.strip().lower()
    
    # Skip empty lines and comments
    if not line or line.startswith('#'):
        return ('', 'skip')
    
    # Remove protocol prefix if present
    line = re.sub(r'^https?://', '', line)
    # Remove trailing path
    line = line.split('/')[0]
    # Remove port
    line = line.split(':')[0]
    
    # Check if it's a CIDR notation
    if '/' in line:
        try:
            ipaddress.ip_network(line, strict=False)
            return (line, 'cidr')
        except ValueError:
            pass
    
    # Check if it's an IP address
    try:
        ipaddress.ip_address(line)
        return (line, 'ip')
    except ValueError:
        pass
    
    # Assume it's a domain
    if line:
        return (line, 'domain')
    
    return ('', 'skip')


def extract_base_domain(domain: str) -> str:
    """Extract the base domain (e.g., api.example.com -> example.com)"""
    extracted = tldextract.extract(domain)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return domain


def expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR notation to list of IP addresses"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # Limit expansion to prevent memory issues
        if network.num_addresses > 65536:
            # For large networks, just return the network notation
            return [cidr]
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def run(state: ScanState) -> dict:
    """
    Input Parser Node - Entry point
    
    Reads the input file, parses domains and IPs,
    extracts base domains for subdomain enumeration.
    """
    input_file = state.get('input_file', '')
    logs = []
    errors = []
    
    raw_domains = []
    raw_ips = []
    base_domains = set()
    all_targets = []
    
    logs.append(f"[InputParser] Starting to parse input file: {input_file}")
    
    if not input_file or not Path(input_file).exists():
        errors.append(f"[InputParser] Input file not found: {input_file}")
        return {
            'raw_domains': [],
            'raw_ips': [],
            'base_domains': [],
            'all_targets': [],
            'errors': errors,
            'logs': logs
        }
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        for line in lines:
            value, entry_type = parse_line(line)
            
            if entry_type == 'skip':
                continue
            elif entry_type == 'domain':
                raw_domains.append(value)
                all_targets.append(value)
                # Extract base domain
                base = extract_base_domain(value)
                base_domains.add(base)
                logs.append(f"[InputParser] Domain: {value} -> Base: {base}")
            elif entry_type == 'ip':
                raw_ips.append(value)
                all_targets.append(value)
                logs.append(f"[InputParser] IP: {value}")
            elif entry_type == 'cidr':
                expanded = expand_cidr(value)
                raw_ips.extend(expanded)
                all_targets.extend(expanded)
                logs.append(f"[InputParser] CIDR: {value} -> {len(expanded)} IPs")
        
        logs.append(f"[InputParser] Parsed {len(raw_domains)} domains, {len(raw_ips)} IPs")
        logs.append(f"[InputParser] Extracted {len(base_domains)} base domains for subdomain enumeration")
        
    except Exception as e:
        errors.append(f"[InputParser] Error reading file: {str(e)}")
    
    return {
        'raw_domains': raw_domains,
        'raw_ips': raw_ips,
        'base_domains': list(base_domains),
        'all_targets': all_targets,
        'errors': errors,
        'logs': logs
    }
