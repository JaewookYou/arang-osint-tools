"""
Red Iris Info Gather - Network Utilities

TCP socket operations, DNS resolution, and CIDR expansion.
"""
import socket
import ipaddress
from typing import List, Optional, Tuple


def tcp_check(host: str, port: int, timeout: float = 2.0) -> bool:
    """
    Check if a TCP port is open on a host.
    
    Args:
        host: Target hostname or IP
        port: Target port number
        timeout: Connection timeout in seconds
    
    Returns:
        True if port is open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.timeout, socket.error, OSError):
        return False


def tcp_connect_with_banner(host: str, port: int, timeout: float = 2.0) -> Tuple[bool, bytes]:
    """
    Connect to a TCP port and attempt to grab banner.
    
    Args:
        host: Target hostname or IP
        port: Target port number
        timeout: Connection timeout in seconds
    
    Returns:
        Tuple of (success, banner_bytes)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Try to send probe and receive banner
        try:
            sock.send(b'\r\n')
            sock.settimeout(timeout)
            banner = sock.recv(1024)
        except:
            banner = b''
        
        sock.close()
        return (True, banner)
    except (socket.timeout, socket.error, OSError):
        return (False, b'')


def resolve_host(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address.
    
    Args:
        hostname: Hostname to resolve
    
    Returns:
        IP address string or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def resolve_host_all(hostname: str) -> List[str]:
    """
    Resolve hostname to all IP addresses.
    
    Args:
        hostname: Hostname to resolve
    
    Returns:
        List of IP address strings
    """
    try:
        _, _, ips = socket.gethostbyname_ex(hostname)
        return ips
    except socket.gaierror:
        return []


def expand_cidr(cidr: str, max_hosts: int = 65536) -> List[str]:
    """
    Expand CIDR notation to list of IP addresses.
    
    Args:
        cidr: CIDR notation (e.g., "192.168.1.0/24")
        max_hosts: Maximum number of hosts to return
    
    Returns:
        List of IP address strings
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.num_addresses > max_hosts:
            # Return first max_hosts IPs for large networks
            return [str(ip) for i, ip in enumerate(network.hosts()) if i < max_hosts]
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr_str: str) -> bool:
    """Check if string is a valid CIDR notation"""
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False


def get_hostname_from_ip(ip: str) -> Optional[str]:
    """Reverse DNS lookup - get hostname from IP"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None
