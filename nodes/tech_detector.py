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
    """
    Use Selenium + Wappalyzer JSON fingerprints for technology detection.
    Loads the page with headless Chrome and analyzes DOM, scripts, meta tags, etc.
    """
    technologies = []
    
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        import json
        from pathlib import Path
        
        # Load Wappalyzer technologies and categories
        wappalyzer_dir = Path(__file__).parent.parent / "data" / "wappalyzer"
        categories = {}
        tech_patterns = {}
        
        # Load categories
        categories_file = wappalyzer_dir / "categories.json"
        if categories_file.exists():
            with open(categories_file, 'r', encoding='utf-8') as f:
                categories = json.load(f)
        
        # Load all technology files (a.json, b.json, ... z.json)
        for tech_file in wappalyzer_dir.glob("*.json"):
            if tech_file.name == "categories.json":
                continue
            try:
                with open(tech_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    tech_patterns.update(data)
            except:
                pass
        
        if not tech_patterns:
            return technologies
        
        # Setup headless Chrome
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--disable-web-security")
        chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        
        driver = None
        try:
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(30)
            driver.get(url)
            
            # Wait for page to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Collect page data
            page_data = {
                'url': url,
                'html': driver.page_source[:100000],  # Limit HTML size
                'scripts': [],
                'meta': {},
                'headers': {},
                'cookies': {},
            }
            
            # Get all script sources
            scripts = driver.find_elements(By.TAG_NAME, "script")
            for script in scripts:
                src = script.get_attribute("src")
                if src:
                    page_data['scripts'].append(src)
                else:
                    # Inline script content
                    content = script.get_attribute("innerHTML") or ""
                    if content:
                        page_data['scripts'].append(content[:1000])  # First 1000 chars
            
            # Get meta tags
            metas = driver.find_elements(By.TAG_NAME, "meta")
            for meta in metas:
                name = meta.get_attribute("name") or meta.get_attribute("property") or ""
                content = meta.get_attribute("content") or ""
                if name and content:
                    page_data['meta'][name.lower()] = content
            
            # Get cookies
            for cookie in driver.get_cookies():
                page_data['cookies'][cookie['name']] = cookie['value']
            
            # Analyze with Wappalyzer patterns
            detected = analyze_with_patterns(page_data, tech_patterns, categories)
            technologies.extend(detected)
            
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
                    
    except ImportError:
        # Selenium not installed, skip
        pass
    except Exception as e:
        pass
    
    return technologies


def analyze_with_patterns(page_data: Dict, tech_patterns: Dict, categories: Dict) -> List[Dict[str, Any]]:
    """
    Analyze page data against Wappalyzer technology patterns.
    """
    import re
    detected = []
    html = page_data.get('html', '')
    scripts = page_data.get('scripts', [])
    meta = page_data.get('meta', {})
    cookies = page_data.get('cookies', {})
    
    scripts_combined = ' '.join(str(s) for s in scripts)
    
    for tech_name, tech_data in tech_patterns.items():
        if not isinstance(tech_data, dict):
            continue
            
        matched = False
        version = None
        
        # Check HTML patterns
        html_patterns = tech_data.get('html', [])
        if isinstance(html_patterns, str):
            html_patterns = [html_patterns]
        for pattern in html_patterns:
            try:
                pattern_str, version_group = parse_pattern(pattern)
                if re.search(pattern_str, html, re.IGNORECASE):
                    matched = True
                    if version_group:
                        match = re.search(pattern_str, html, re.IGNORECASE)
                        if match and match.lastindex:
                            version = match.group(1)
                    break
            except:
                pass
        
        # Check script patterns
        if not matched:
            script_patterns = tech_data.get('scriptSrc', [])
            if isinstance(script_patterns, str):
                script_patterns = [script_patterns]
            for pattern in script_patterns:
                try:
                    pattern_str, version_group = parse_pattern(pattern)
                    if re.search(pattern_str, scripts_combined, re.IGNORECASE):
                        matched = True
                        break
                except:
                    pass
        
        # Check meta patterns
        if not matched:
            meta_patterns = tech_data.get('meta', {})
            if isinstance(meta_patterns, dict):
                for meta_name, pattern in meta_patterns.items():
                    meta_value = meta.get(meta_name.lower(), '')
                    if meta_value:
                        try:
                            pattern_str, version_group = parse_pattern(pattern)
                            if re.search(pattern_str, meta_value, re.IGNORECASE):
                                matched = True
                                break
                        except:
                            pass
        
        # Check cookie patterns
        if not matched:
            cookie_patterns = tech_data.get('cookies', {})
            if isinstance(cookie_patterns, dict):
                for cookie_name, pattern in cookie_patterns.items():
                    if cookie_name in cookies:
                        try:
                            if pattern == "":
                                matched = True
                            else:
                                pattern_str, version_group = parse_pattern(pattern)
                                if re.search(pattern_str, cookies[cookie_name], re.IGNORECASE):
                                    matched = True
                            break
                        except:
                            pass
        
        # Check JavaScript variables (in inline scripts)
        if not matched:
            js_patterns = tech_data.get('js', {})
            if isinstance(js_patterns, dict):
                for js_var, pattern in js_patterns.items():
                    # Simple check - look for variable name in scripts
                    if js_var in scripts_combined:
                        matched = True
                        break
        
        if matched:
            # Get category
            cat_ids = tech_data.get('cats', [])
            cat_names = []
            for cat_id in cat_ids:
                cat_info = categories.get(str(cat_id), {})
                cat_name = cat_info.get('name', 'Unknown')
                cat_names.append(cat_name)
            
            detected.append({
                'name': tech_name,
                'category': ', '.join(cat_names) if cat_names else 'Unknown',
                'version': version,
                'source': 'wappalyzer-selenium'
            })
    
    return detected


def parse_pattern(pattern: str) -> tuple:
    """
    Parse Wappalyzer pattern format.
    Patterns can have modifiers like \\;version:\\1
    Returns (regex_pattern, has_version_group)
    """
    if not pattern:
        return ('', False)
    
    # Split by \; to separate pattern from modifiers
    parts = pattern.split('\\;')
    regex_pattern = parts[0]
    
    has_version = False
    if len(parts) > 1:
        for modifier in parts[1:]:
            if modifier.startswith('version:'):
                has_version = True
    
    # Escape special regex chars that Wappalyzer uses differently
    # Wappalyzer uses \; for literal semicolon, etc.
    regex_pattern = regex_pattern.replace('\\;', ';')
    
    return (regex_pattern, has_version)


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
