"""
Red Iris Info Gather - Technology Detector Node

Detects web technologies and server information using multiple sources:
1. HTTP Response Headers (Server, X-Powered-By, etc.)
2. Shodan API data
3. Wappalyzer fingerprints (python-Wappalyzer)
4. WebTech analysis
"""
import re
import ssl
import socket
import requests
from typing import List, Dict, Set, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3

from state import ScanState
import config

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TechResult:
    """Technology detection result"""
    def __init__(self, url: str):
        self.url = url
        self.technologies: List[Dict[str, Any]] = []
        self.headers: Dict[str, str] = {}
        self.server: Optional[str] = None
        self.powered_by: Optional[str] = None
        self.cms: Optional[str] = None
        self.framework: Optional[str] = None
        self.ssl_info: Dict[str, Any] = {}
        self.shodan_info: Dict[str, Any] = {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'url': self.url,
            'technologies': self.technologies,
            'server': self.server,
            'powered_by': self.powered_by,
            'cms': self.cms,
            'framework': self.framework,
            'ssl_info': self.ssl_info,
            'shodan_info': self.shodan_info,
            'headers': self.headers
        }


# Common technology patterns in HTTP headers
HEADER_PATTERNS = {
    'server': {
        'nginx': r'nginx[/\s]?([\d.]+)?',
        'apache': r'Apache[/\s]?([\d.]+)?',
        'iis': r'Microsoft-IIS[/\s]?([\d.]+)?',
        'gunicorn': r'gunicorn[/\s]?([\d.]+)?',
        'uvicorn': r'uvicorn',
        'lighttpd': r'lighttpd[/\s]?([\d.]+)?',
        'caddy': r'Caddy',
        'cloudflare': r'cloudflare',
        'litespeed': r'LiteSpeed',
        'openresty': r'openresty[/\s]?([\d.]+)?',
    },
    'x-powered-by': {
        'php': r'PHP[/\s]?([\d.]+)?',
        'asp.net': r'ASP\.NET',
        'express': r'Express',
        'next.js': r'Next\.js',
        'nuxt': r'Nuxt',
        'laravel': r'Laravel',
        'django': r'Django',
        'flask': r'Flask',
        'ruby': r'Ruby',
        'rails': r'Phusion Passenger',
    },
    'x-generator': {
        'wordpress': r'WordPress[/\s]?([\d.]+)?',
        'drupal': r'Drupal[/\s]?([\d.]+)?',
        'joomla': r'Joomla',
        'hugo': r'Hugo[/\s]?([\d.]+)?',
        'jekyll': r'Jekyll',
        'ghost': r'Ghost',
    }
}

# Body content patterns for technology detection
BODY_PATTERNS = {
    'wordpress': [
        r'/wp-content/',
        r'/wp-includes/',
        r'wp-json',
        r'WordPress',
    ],
    'drupal': [
        r'Drupal\.settings',
        r'/sites/default/',
        r'drupal\.js',
    ],
    'joomla': [
        r'/components/com_',
        r'/media/jui/',
        r'Joomla!',
    ],
    'react': [
        r'react\.production\.min\.js',
        r'__REACT_DEVTOOLS',
        r'reactroot',
    ],
    'vue.js': [
        r'vue\.runtime',
        r'Vue\.js',
        r'v-bind:',
        r'v-if=',
    ],
    'angular': [
        r'ng-version=',
        r'angular\.js',
        r'ng-app=',
    ],
    'jquery': [
        r'jquery[.-][\d.]+\.min\.js',
        r'jquery\.min\.js',
    ],
    'bootstrap': [
        r'bootstrap[.-][\d.]+\.min\.css',
        r'bootstrap\.min\.css',
    ],
    'tailwindcss': [
        r'tailwindcss',
        r'tailwind\.css',
    ],
    'next.js': [
        r'_next/static',
        r'__NEXT_DATA__',
    ],
    'nuxt.js': [
        r'_nuxt/',
        r'__NUXT__',
    ],
    'laravel': [
        r'laravel_session',
        r'XSRF-TOKEN',
    ],
    'django': [
        r'csrfmiddlewaretoken',
        r'__admin_media_prefix__',
    ],
    'flask': [
        r'Werkzeug',
    ],
    'spring': [
        r'JSESSIONID',
        r'spring',
    ],
    'cloudflare': [
        r'cf-ray',
        r'cloudflare',
    ],
    'aws': [
        r'x-amz-',
        r'AmazonS3',
    ],
    'google-cloud': [
        r'x-goog-',
        r'googleapis',
    ],
}


def detect_from_headers(url: str, timeout: int = 10) -> TechResult:
    """Detect technologies from HTTP headers and response body"""
    result = TechResult(url)
    
    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        )
        
        # Store headers
        result.headers = dict(response.headers)
        
        # Parse Server header
        server = response.headers.get('Server', '')
        result.server = server
        for tech_name, pattern in HEADER_PATTERNS['server'].items():
            match = re.search(pattern, server, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else None
                result.technologies.append({
                    'name': tech_name.title(),
                    'category': 'Web Server',
                    'version': version,
                    'source': 'headers'
                })
        
        # Parse X-Powered-By header
        powered_by = response.headers.get('X-Powered-By', '')
        result.powered_by = powered_by
        for tech_name, pattern in HEADER_PATTERNS['x-powered-by'].items():
            match = re.search(pattern, powered_by, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else None
                result.technologies.append({
                    'name': tech_name.upper() if tech_name in ['php', 'asp.net'] else tech_name.title(),
                    'category': 'Programming Language' if tech_name in ['php', 'ruby'] else 'Framework',
                    'version': version,
                    'source': 'headers'
                })
        
        # Parse X-Generator header
        generator = response.headers.get('X-Generator', '')
        for tech_name, pattern in HEADER_PATTERNS['x-generator'].items():
            match = re.search(pattern, generator, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else None
                result.technologies.append({
                    'name': tech_name.title(),
                    'category': 'CMS',
                    'version': version,
                    'source': 'headers'
                })
                result.cms = tech_name.title()
        
        # Check response body for technology patterns
        body = response.text[:50000]  # Limit to first 50KB
        for tech_name, patterns in BODY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    # Avoid duplicates
                    existing = [t['name'].lower() for t in result.technologies]
                    if tech_name not in existing:
                        category = 'CMS' if tech_name in ['wordpress', 'drupal', 'joomla'] else \
                                   'JavaScript Framework' if tech_name in ['react', 'vue.js', 'angular', 'jquery'] else \
                                   'CSS Framework' if tech_name in ['bootstrap', 'tailwindcss'] else \
                                   'Framework' if tech_name in ['laravel', 'django', 'flask', 'spring', 'next.js', 'nuxt.js'] else \
                                   'CDN/Cloud' if tech_name in ['cloudflare', 'aws', 'google-cloud'] else \
                                   'Technology'
                        result.technologies.append({
                            'name': tech_name.title(),
                            'category': category,
                            'version': None,
                            'source': 'body'
                        })
                    break
        
        # Check for common cookies
        cookies = response.cookies.get_dict()
        if 'PHPSESSID' in cookies:
            if not any(t['name'].upper() == 'PHP' for t in result.technologies):
                result.technologies.append({
                    'name': 'PHP',
                    'category': 'Programming Language',
                    'version': None,
                    'source': 'cookies'
                })
        if 'JSESSIONID' in cookies:
            if not any(t['name'].lower() == 'java' for t in result.technologies):
                result.technologies.append({
                    'name': 'Java',
                    'category': 'Programming Language',
                    'version': None,
                    'source': 'cookies'
                })
        if 'ASP.NET_SessionId' in cookies:
            if not any(t['name'].upper() == 'ASP.NET' for t in result.technologies):
                result.technologies.append({
                    'name': 'ASP.NET',
                    'category': 'Framework',
                    'version': None,
                    'source': 'cookies'
                })
        
    except Exception as e:
        pass
    
    return result


def detect_with_wappalyzer(url: str) -> List[Dict[str, Any]]:
    """Use python-Wappalyzer for technology detection"""
    technologies = []
    
    try:
        from Wappalyzer import Wappalyzer, WebPage
        
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url, verify=False, timeout=15)
        detected = wappalyzer.analyze_with_versions_and_categories(webpage)
        
        for tech_name, details in detected.items():
            tech_info = {
                'name': tech_name,
                'category': ', '.join(details.get('categories', ['Unknown'])),
                'version': list(details.get('versions', [None]))[0] if details.get('versions') else None,
                'source': 'wappalyzer'
            }
            technologies.append(tech_info)
            
    except ImportError:
        pass
    except Exception as e:
        pass
    
    return technologies


def detect_with_webtech(url: str) -> List[Dict[str, Any]]:
    """Use WebTech for technology detection"""
    technologies = []
    
    try:
        from webtech import WebTech
        
        wt = WebTech(options={'json': True})
        report = wt.start_from_url(url, timeout=15)
        
        for tech in report.get('tech', []):
            tech_info = {
                'name': tech.get('name', 'Unknown'),
                'category': tech.get('category', 'Unknown'),
                'version': tech.get('version'),
                'source': 'webtech'
            }
            technologies.append(tech_info)
            
    except ImportError:
        pass
    except Exception as e:
        pass
    
    return technologies


def get_ssl_info(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Get SSL certificate information"""
    ssl_info = {}
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    ssl_info = {
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'version': cert.get('version'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'serial_number': cert.get('serialNumber'),
                    }
                
                # Get cipher info
                cipher = ssock.cipher()
                if cipher:
                    ssl_info['cipher'] = {
                        'name': cipher[0],
                        'version': cipher[1],
                        'bits': cipher[2]
                    }
    except Exception:
        pass
    
    return ssl_info


def get_shodan_tech_info(ip: str) -> Dict[str, Any]:
    """Get technology info from Shodan"""
    shodan_info = {}
    
    if not config.SHODAN_API_KEY:
        return shodan_info
    
    try:
        import shodan
        api = shodan.Shodan(config.SHODAN_API_KEY)
        host = api.host(ip)
        
        shodan_info = {
            'os': host.get('os'),
            'ports': host.get('ports', []),
            'hostnames': host.get('hostnames', []),
            'org': host.get('org'),
            'isp': host.get('isp'),
            'asn': host.get('asn'),
            'country': host.get('country_name'),
            'city': host.get('city'),
            'vulns': list(host.get('vulns', {}).keys()) if host.get('vulns') else [],
            'tags': host.get('tags', []),
        }
        
        # Extract technologies from banners
        for item in host.get('data', []):
            product = item.get('product')
            version = item.get('version')
            if product:
                if 'products' not in shodan_info:
                    shodan_info['products'] = []
                shodan_info['products'].append({
                    'name': product,
                    'version': version,
                    'port': item.get('port')
                })
                
    except Exception:
        pass
    
    return shodan_info


def detect_url_technologies(url: str, include_shodan: bool = True) -> TechResult:
    """Run all detection methods for a URL"""
    result = detect_from_headers(url)
    
    # Add Wappalyzer results
    wappalyzer_techs = detect_with_wappalyzer(url)
    for tech in wappalyzer_techs:
        # Avoid duplicates
        existing_names = [t['name'].lower() for t in result.technologies]
        if tech['name'].lower() not in existing_names:
            result.technologies.append(tech)
    
    # Add WebTech results
    webtech_techs = detect_with_webtech(url)
    for tech in webtech_techs:
        existing_names = [t['name'].lower() for t in result.technologies]
        if tech['name'].lower() not in existing_names:
            result.technologies.append(tech)
    
    # Get SSL info for HTTPS URLs
    parsed = urlparse(url)
    if parsed.scheme == 'https':
        port = parsed.port or 443
        result.ssl_info = get_ssl_info(parsed.hostname, port)
    
    # Get Shodan info
    if include_shodan and config.SHODAN_API_KEY:
        try:
            import socket
            ip = socket.gethostbyname(parsed.hostname)
            result.shodan_info = get_shodan_tech_info(ip)
            
            # Add Shodan products to technologies
            for product in result.shodan_info.get('products', []):
                existing_names = [t['name'].lower() for t in result.technologies]
                if product['name'].lower() not in existing_names:
                    result.technologies.append({
                        'name': product['name'],
                        'category': 'Service',
                        'version': product.get('version'),
                        'source': 'shodan'
                    })
        except Exception:
            pass
    
    return result


def run(state: ScanState) -> dict:
    """
    Technology Detector Node - Entry point
    
    Detects web technologies for all discovered web servers.
    """
    web_servers = state.get('web_servers', [])
    
    logs = []
    errors = []
    tech_results: List[Dict[str, Any]] = []
    
    logs.append(f"[TechDetector] Analyzing {len(web_servers)} web servers")
    
    if not web_servers:
        logs.append("[TechDetector] No web servers to analyze")
        return {
            'tech_results': [],
            'errors': errors,
            'logs': logs
        }
    
    # Detect technologies in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(detect_url_technologies, url): url
            for url in web_servers
        }
        
        for future in as_completed(futures):
            url = futures[future]
            try:
                result = future.result()
                tech_results.append(result.to_dict())
                tech_count = len(result.technologies)
                logs.append(f"[TechDetector] {url}: {tech_count} technologies detected")
            except Exception as e:
                errors.append(f"[TechDetector] Error analyzing {url}: {str(e)}")
    
    logs.append(f"[TechDetector] Analysis complete for {len(tech_results)} servers")
    
    return {
        'tech_results': tech_results,
        'errors': errors,
        'logs': logs
    }
