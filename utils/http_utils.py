"""
Red Iris Info Gather - HTTP Utilities

HTTP service detection and response analysis.
"""
import socket
import ssl
from typing import Tuple, Optional

# Common HTTP response signatures
HTTP_SIGNATURES = [
    b'HTTP/1.0',
    b'HTTP/1.1',
    b'HTTP/2',
    b'<!DOCTYPE',
    b'<!doctype',
    b'<html',
    b'<HTML',
    b'<head',
    b'<HEAD',
]

# Common HTTP ports
HTTP_PORTS = {80, 8080, 8000, 8008, 8888, 3000, 5000, 8081, 8082, 8083}
HTTPS_PORTS = {443, 8443, 9443, 4443, 8444}


def is_http_response(data: bytes) -> bool:
    """
    Check if response data looks like HTTP.
    
    Args:
        data: Response bytes from server
    
    Returns:
        True if data appears to be HTTP response
    """
    if not data:
        return False
    
    # Check for common HTTP signatures
    data_lower = data[:500].lower()
    for sig in HTTP_SIGNATURES:
        if sig.lower() in data_lower:
            return True
    
    return False


def detect_http_service(host: str, port: int, timeout: float = 3.0) -> Tuple[bool, Optional[str]]:
    """
    Detect if a service is HTTP/HTTPS.
    
    Args:
        host: Target hostname or IP
        port: Target port
        timeout: Connection timeout
    
    Returns:
        Tuple of (is_http, protocol) where protocol is 'http', 'https', or None
    """
    # Try HTTPS first for known HTTPS ports
    if port in HTTPS_PORTS:
        success, _ = check_https(host, port, timeout)
        if success:
            return (True, 'https')
    
    # Try HTTP
    success, response = check_http(host, port, timeout)
    if success and is_http_response(response):
        return (True, 'http')
    
    # Try HTTPS as fallback
    if port not in HTTPS_PORTS:
        success, _ = check_https(host, port, timeout)
        if success:
            return (True, 'https')
    
    return (False, None)


def check_http(host: str, port: int, timeout: float = 3.0) -> Tuple[bool, bytes]:
    """
    Send HTTP request and get response.
    
    Returns:
        Tuple of (success, response_bytes)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Send minimal HTTP request
        request = f'GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n'
        sock.send(request.encode())
        
        # Receive response
        response = b''
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 8192:  # Limit response size
                    break
            except socket.timeout:
                break
        
        sock.close()
        return (True, response)
        
    except (socket.timeout, socket.error, OSError):
        return (False, b'')


def check_https(host: str, port: int, timeout: float = 3.0) -> Tuple[bool, bytes]:
    """
    Send HTTPS request and get response.
    
    Returns:
        Tuple of (success, response_bytes)
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ssock = context.wrap_socket(sock, server_hostname=host)
        ssock.connect((host, port))
        
        # Send minimal HTTP request
        request = f'GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n'
        ssock.send(request.encode())
        
        # Receive response
        response = b''
        while True:
            try:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 8192:
                    break
            except socket.timeout:
                break
        
        ssock.close()
        return (True, response)
        
    except (socket.timeout, socket.error, ssl.SSLError, OSError):
        return (False, b'')


def extract_http_headers(response: bytes) -> dict:
    """
    Extract HTTP headers from response.
    
    Returns:
        Dictionary of header name -> value
    """
    headers = {}
    try:
        # Split headers from body
        if b'\r\n\r\n' in response:
            header_section = response.split(b'\r\n\r\n')[0]
        elif b'\n\n' in response:
            header_section = response.split(b'\n\n')[0]
        else:
            return headers
        
        lines = header_section.decode('utf-8', errors='ignore').split('\n')
        for line in lines[1:]:  # Skip status line
            if ':' in line:
                name, value = line.split(':', 1)
                headers[name.strip().lower()] = value.strip()
    except:
        pass
    
    return headers


def get_server_header(host: str, port: int, use_ssl: bool = False) -> Optional[str]:
    """
    Get Server header from HTTP response.
    
    Returns:
        Server header value or None
    """
    if use_ssl:
        success, response = check_https(host, port)
    else:
        success, response = check_http(host, port)
    
    if success:
        headers = extract_http_headers(response)
        return headers.get('server')
    
    return None
