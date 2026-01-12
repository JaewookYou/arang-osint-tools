"""
Red Iris Info Gather - Port Scanner Node

Performs port scanning on alive hosts:
1. Uses nmap if available
2. Falls back to multithreaded TCP scanning

Detects HTTP services and stores web server URLs separately.
Preserves domain names for virtual host routing support.
"""
import subprocess
import socket
import ssl
import json
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from state import ScanState, PortScanResult
import config


def tcp_connect(host: str, port: int, timeout: float = 2.0) -> Tuple[bool, bytes]:
    """
    Connect to host:port and return (success, banner)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Try to grab banner
        banner = b''
        try:
            # Send minimal HTTP request to trigger response
            sock.send(b'GET / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
            sock.settimeout(2)
            banner = sock.recv(1024)
        except:
            pass
        
        sock.close()
        return (True, banner)
    except (socket.timeout, socket.error, OSError):
        return (False, b'')


def check_https(host: str, port: int, timeout: float = 3.0) -> Tuple[bool, bytes]:
    """
    Check HTTPS connection and grab response.
    Uses SNI (Server Name Indication) for proper virtual host support.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Use SNI - server_hostname is important for virtual hosting
        ssock = context.wrap_socket(sock, server_hostname=host)
        ssock.connect((host, port))
        
        # Send HTTP request with Host header for virtual host routing
        request = f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'
        ssock.send(request.encode())
        ssock.settimeout(3)
        
        # Read response
        banner = b''
        try:
            while True:
                chunk = ssock.recv(1024)
                if not chunk:
                    break
                banner += chunk
                if len(banner) > 2048:
                    break
        except:
            pass
        
        ssock.close()
        return (True, banner)
    except Exception as e:
        return (False, b'')


def is_http_response(banner: bytes) -> bool:
    """Check if the response looks like HTTP"""
    if not banner:
        return False
    for sig in config.HTTP_SIGNATURES:
        if banner.startswith(sig) or sig in banner[:500]:
            return True
    return False


def format_binary_preview(data: bytes, max_length: int = 1000) -> str:
    """
    Format binary data for display.
    Non-ASCII bytes are displayed as <XX> where XX is the hex value.
    """
    if not data:
        return ""
    
    result = []
    for i, byte in enumerate(data[:max_length]):
        if 32 <= byte < 127:  # Printable ASCII
            result.append(chr(byte))
        elif byte == 10:  # Newline
            result.append('\n')
        elif byte == 13:  # Carriage return
            result.append('')  # Skip CR
        elif byte == 9:  # Tab
            result.append('\t')
        else:
            result.append(f'<{byte:02X}>')
    
    preview = ''.join(result)
    if len(data) > max_length:
        preview += f'\n... [{len(data)} bytes total]'
    
    return preview


def try_https_on_port(host: str, port: int) -> Tuple[bool, bool]:
    """
    Try HTTPS connection on any port.
    Returns: (is_open, is_https)
    """
    success, banner = check_https(host, port)
    if success:
        return (True, True)
    return (False, False)


def scan_port(host: str, port: int) -> Optional[PortScanResult]:
    """
    Scan a single port and return result if open.
    Tries both HTTP and HTTPS detection on all ports.
    """
    # Known HTTPS ports - try HTTPS first
    https_ports = [443, 8443, 9443, 4443, 8444, 9000, 9443]
    
    if port in https_ports:
        # Try HTTPS first for known HTTPS ports
        success, banner = check_https(host, port)
        if success:
            return PortScanResult(
                host=host,
                port=port,
                service='https',
                is_http=True,
                response_preview=format_binary_preview(banner)
            )
        # Fallback to plain TCP
        success, banner = tcp_connect(host, port)
        if success:
            is_http = is_http_response(banner)
            return PortScanResult(
                host=host,
                port=port,
                service='http' if is_http else 'unknown',
                is_http=is_http,
                response_preview=format_binary_preview(banner)
            )
    else:
        # Try plain TCP first
        success, banner = tcp_connect(host, port)
        if success:
            is_http = is_http_response(banner)
            
            # If we got HTTP response on non-standard port, check if it might be HTTPS
            if not is_http and port not in [80, 8080, 8000, 8888]:
                # Try HTTPS as well
                https_success, https_banner = check_https(host, port)
                if https_success:
                    return PortScanResult(
                        host=host,
                        port=port,
                        service='https',
                        is_http=True,
                        response_preview=format_binary_preview(https_banner)
                    )
            
            return PortScanResult(
                host=host,
                port=port,
                service='http' if is_http else 'unknown',
                is_http=is_http,
                response_preview=format_binary_preview(banner)
            )
        else:
            # Port didn't respond to TCP, try HTTPS anyway (some servers only respond to SSL)
            https_success, https_banner = check_https(host, port)
            if https_success:
                return PortScanResult(
                    host=host,
                    port=port,
                    service='https',
                    is_http=True,
                    response_preview=format_binary_preview(https_banner)
                )
    
    return None


def run_nmap(hosts: List[str]) -> List[PortScanResult]:
    """Run nmap for port scanning - preserves hostnames for virtual host support"""
    results = []
    
    if not hosts:
        return results
    
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(hosts))
            target_file = f.name
        
        # Run nmap with service detection (use -sT for non-root, -sS requires root)
        ports_str = ','.join(map(str, config.WELLKNOWN_PORTS))
        result = subprocess.run(
            [
                config.NMAP_PATH,
                '-sT', '-sV',  # TCP connect scan (doesn't require root)
                '--open',
                '-p', ports_str,
                '-iL', target_file,
                '-oX', '-'  # XML output to stdout
            ],
            capture_output=True,
            text=True,
            timeout=1800  # 30 min timeout
        )
        
        # Parse XML output
        import xml.etree.ElementTree as ET
        
        # Create a mapping of IP to hostname for preservation
        ip_to_hostname = {}
        for host in hosts:
            try:
                ip = socket.gethostbyname(host)
                if ip != host:  # It's a domain
                    ip_to_hostname[ip] = host
            except:
                pass
        
        try:
            root = ET.fromstring(result.stdout)
            for host_elem in root.findall('.//host'):
                addr_elem = host_elem.find('.//address[@addrtype="ipv4"]')
                if addr_elem is None:
                    addr_elem = host_elem.find('.//address')
                if addr_elem is None:
                    continue
                ip = addr_elem.get('addr', '')
                
                # Try to get hostname from nmap output
                hostname_elem = host_elem.find('.//hostname')
                if hostname_elem is not None:
                    display_host = hostname_elem.get('name', ip)
                elif ip in ip_to_hostname:
                    display_host = ip_to_hostname[ip]
                else:
                    display_host = ip
                
                for port_elem in host_elem.findall('.//port'):
                    state = port_elem.find('state')
                    if state is not None and state.get('state') == 'open':
                        port = int(port_elem.get('portid', 0))
                        service_elem = port_elem.find('service')
                        service = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                        is_http = service in ['http', 'https', 'http-alt', 'http-proxy', 'https-alt', 'ssl/http', 'ssl/https']
                        
                        # Determine if it's HTTPS
                        tunnel = service_elem.get('tunnel', '') if service_elem is not None else ''
                        if tunnel == 'ssl' or 'ssl' in service or 'https' in service:
                            service = 'https'
                            is_http = True
                        
                        results.append(PortScanResult(
                            host=display_host,  # Use domain if available
                            port=port,
                            service=service,
                            is_http=is_http,
                            response_preview=None  # nmap doesn't capture response
                        ))
        except ET.ParseError:
            pass
        
        import os
        os.unlink(target_file)
        
    except FileNotFoundError:
        raise
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        raise
    
    return results


def run_multithreaded_scan(hosts: List[str]) -> List[PortScanResult]:
    """Fallback: Multithreaded TCP port scanning - preserves hostnames"""
    results = []
    tasks = [(host, port) for host in hosts for port in config.WELLKNOWN_PORTS]
    
    with ThreadPoolExecutor(max_workers=config.MAX_THREADS) as executor:
        futures = {
            executor.submit(scan_port, host, port): (host, port)
            for host, port in tasks
        }
        
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception:
                pass
    
    return results


def run(state: ScanState) -> dict:
    """
    Port Scanner Node - Entry point
    
    Scans well-known ports on alive hosts.
    Detects HTTP/HTTPS services and stores web server URLs.
    Preserves domain names for virtual host routing support.
    """
    alive_hosts = state.get('alive_hosts', [])
    
    logs = []
    errors = []
    open_ports: List[PortScanResult] = []
    web_servers: List[str] = []
    
    logs.append(f"[PortScanner] Scanning {len(alive_hosts)} alive hosts on {len(config.WELLKNOWN_PORTS)} ports")
    
    if not alive_hosts:
        logs.append("[PortScanner] No alive hosts to scan")
        return {
            'open_ports': [],
            'web_servers': [],
            'errors': errors,
            'logs': logs
        }
    
    # Try nmap first
    try:
        logs.append("[PortScanner] Attempting nmap scan")
        open_ports = run_nmap(alive_hosts)
        logs.append(f"[PortScanner] Nmap found {len(open_ports)} open ports")
        
        # If nmap returned no results, fallback to multithreaded scan
        if len(open_ports) == 0:
            logs.append("[PortScanner] Nmap returned no results, falling back to multithreaded TCP scan")
            open_ports = run_multithreaded_scan(alive_hosts)
            logs.append(f"[PortScanner] TCP scan found {len(open_ports)} open ports")
        else:
            # Fetch responses for nmap results (nmap doesn't capture responses)
            logs.append("[PortScanner] Fetching responses for nmap-discovered ports...")
            open_ports = fetch_port_responses(open_ports)
            logs.append("[PortScanner] Response fetching complete")
            
    except FileNotFoundError:
        logs.append("[PortScanner] Nmap not found, falling back to multithreaded TCP scan")
        open_ports = run_multithreaded_scan(alive_hosts)
        logs.append(f"[PortScanner] TCP scan found {len(open_ports)} open ports")
    except Exception as e:
        errors.append(f"[PortScanner] Nmap error: {str(e)}, falling back to TCP scan")
        open_ports = run_multithreaded_scan(alive_hosts)
    
    # Extract web servers - preserve domain names for virtual host routing
    https_ports = {443, 8443, 9443, 4443, 8444}
    for result in open_ports:
        if result['is_http']:
            # Check if service is HTTPS
            is_https = result['service'] == 'https' or result['port'] in https_ports
            protocol = 'https' if is_https else 'http'
            
            # Don't add port suffix for standard ports
            if (protocol == 'http' and result['port'] == 80) or (protocol == 'https' and result['port'] == 443):
                port_suffix = ''
            else:
                port_suffix = f":{result['port']}"
            
            url = f"{protocol}://{result['host']}{port_suffix}"
            if url not in web_servers:
                web_servers.append(url)
    
    logs.append(f"[PortScanner] Found {len(web_servers)} web servers")
    
    return {
        'open_ports': open_ports,
        'web_servers': web_servers,
        'errors': errors,
        'logs': logs
    }


def fetch_port_responses(ports: List[PortScanResult]) -> List[PortScanResult]:
    """
    Fetch HTTP responses for open ports that don't have response data.
    Used after nmap scan which doesn't capture responses.
    """
    https_ports = {443, 8443, 9443, 4443, 8444}
    
    def fetch_single_response(port_result: PortScanResult) -> PortScanResult:
        if port_result.get('response_preview'):
            return port_result  # Already has response
        
        host = port_result['host']
        port = port_result['port']
        service = port_result.get('service', 'unknown')
        
        # Determine if we should try HTTPS
        is_https = service == 'https' or port in https_ports
        
        banner = b''
        if is_https:
            success, banner = check_https(host, port)
            if not success:
                # Try plain TCP as fallback
                success, banner = tcp_connect(host, port)
        else:
            success, banner = tcp_connect(host, port)
            if not success and port not in [80, 8080, 8000]:
                # Try HTTPS as fallback for non-standard ports
                success, banner = check_https(host, port)
        
        # Update result with response
        port_result['response_preview'] = format_binary_preview(banner) if banner else None
        return port_result
    
    # Fetch responses in parallel
    with ThreadPoolExecutor(max_workers=min(len(ports), 20)) as executor:
        futures = {executor.submit(fetch_single_response, p): p for p in ports}
        results = []
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except:
                results.append(futures[future])
    
    return results

