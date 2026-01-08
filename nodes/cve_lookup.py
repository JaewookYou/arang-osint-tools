"""
Red Iris Info Gather - CVE Lookup Node

Searches for known CVEs (1-day vulnerabilities) for detected technologies using:
1. NVD (National Vulnerability Database) API via nvdlib
2. Caches results to avoid rate limiting
"""
import time
import re
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

from state import ScanState
import config


# Cache for CVE lookups (product -> CVEs)
_cve_cache: Dict[str, List[Dict]] = {}

# Rate limiting for NVD API
# Without key: 5 requests per 30 seconds (6s delay)
# With key: 50 requests per 30 seconds (0.6s delay)
_last_request_time = 0
_request_interval = 0.6 if config.NVD_API_KEY else 6


def normalize_product_name(name: str) -> str:
    """Normalize product name for CVE search"""
    # Remove version info and special characters
    normalized = re.sub(r'[.\-_]', ' ', name.lower())
    normalized = re.sub(r'\s+', ' ', normalized).strip()
    return normalized


def search_nvd_cves(product: str, version: Optional[str] = None, max_results: int = 10) -> List[Dict[str, Any]]:
    """
    Search NVD for CVEs related to a product.
    
    Uses nvdlib to query the National Vulnerability Database.
    Rate limited to avoid API throttling.
    """
    global _last_request_time
    
    # Check cache
    cache_key = f"{product}:{version}" if version else product
    if cache_key in _cve_cache:
        return _cve_cache[cache_key]
    
    cves = []
    
    try:
        import nvdlib
        
        # Rate limiting
        elapsed = time.time() - _last_request_time
        if elapsed < _request_interval:
            time.sleep(_request_interval - elapsed)
        
        _last_request_time = time.time()
        
        # Build search keyword
        keyword = product
        if version:
            keyword = f"{product} {version}"
        
        # Search NVD
        # Limit to CVEs from last 2 years for relevance
        end_date = datetime.now()
        start_date = end_date - timedelta(days=730)  # 2 years
        
        # Build search parameters
        search_params = {
            'keywordSearch': keyword,
            'pubStartDate': start_date,
            'pubEndDate': end_date,
            'limit': max_results
        }
        
        # Add API key if available (faster rate limiting)
        if config.NVD_API_KEY:
            search_params['key'] = config.NVD_API_KEY
        
        results = nvdlib.searchCVE(**search_params)
        
        for cve in results:
            cve_id = cve.id
            
            # Get CVSS score
            cvss_score = None
            severity = "unknown"
            
            # Try CVSS v3.1 first, then v3.0, then v2
            if hasattr(cve, 'v31score'):
                cvss_score = cve.v31score
                severity = cve.v31severity if hasattr(cve, 'v31severity') else "unknown"
            elif hasattr(cve, 'v30score'):
                cvss_score = cve.v30score
                severity = cve.v30severity if hasattr(cve, 'v30severity') else "unknown"
            elif hasattr(cve, 'v2score'):
                cvss_score = cve.v2score
                severity = cve.v2severity if hasattr(cve, 'v2severity') else "unknown"
            
            # Get description
            description = ""
            if hasattr(cve, 'descriptions'):
                for desc in cve.descriptions:
                    if desc.lang == 'en':
                        description = desc.value[:500]  # Limit length
                        break
            
            # Get published date
            published = ""
            if hasattr(cve, 'published'):
                published = str(cve.published)[:10]
            
            cves.append({
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity.lower() if severity else 'unknown',
                'published': published,
                'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                'product': product,
                'version': version
            })
        
        # Cache results
        _cve_cache[cache_key] = cves
        
    except ImportError:
        pass
    except Exception as e:
        # Log error but don't fail
        pass
    
    return cves


def lookup_technology_cves(tech_name: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Look up CVEs for a specific technology.
    
    Handles common technology name variations.
    """
    # Normalize name
    name = normalize_product_name(tech_name)
    
    # Common mappings for better search results
    name_mappings = {
        'nginx': 'nginx',
        'apache': 'apache http server',
        'iis': 'microsoft iis',
        'php': 'php',
        'wordpress': 'wordpress',
        'drupal': 'drupal',
        'joomla': 'joomla',
        'react': 'react',
        'vue': 'vue.js',
        'angular': 'angular',
        'jquery': 'jquery',
        'bootstrap': 'bootstrap',
        'node': 'node.js',
        'express': 'express.js',
        'django': 'django',
        'flask': 'flask',
        'laravel': 'laravel',
        'spring': 'spring framework',
        'tomcat': 'apache tomcat',
        'mysql': 'mysql',
        'postgresql': 'postgresql',
        'mongodb': 'mongodb',
        'redis': 'redis',
        'elasticsearch': 'elasticsearch',
        'openssl': 'openssl',
        'openssh': 'openssh',
    }
    
    # Use mapped name if available
    search_name = name_mappings.get(name, name)
    
    return search_nvd_cves(search_name, version, max_results=5)


def analyze_tech_results(tech_results: List[Dict]) -> List[Dict[str, Any]]:
    """
    Analyze all detected technologies and look up CVEs.
    
    Returns aggregated CVE results grouped by technology.
    """
    all_cves = []
    searched_techs: Set[str] = set()
    
    for result in tech_results:
        url = result.get('url', '')
        
        for tech in result.get('technologies', []):
            tech_name = tech.get('name', '')
            version = tech.get('version')
            
            # Create unique key to avoid duplicate searches
            tech_key = f"{tech_name.lower()}:{version}" if version else tech_name.lower()
            if tech_key in searched_techs:
                continue
            searched_techs.add(tech_key)
            
            # Skip generic categories
            skip_categories = ['JavaScript Framework', 'CSS Framework', 'Font script']
            if tech.get('category') in skip_categories and not version:
                continue
            
            # Look up CVEs
            cves = lookup_technology_cves(tech_name, version)
            
            for cve in cves:
                cve['detected_on'] = url
                all_cves.append(cve)
    
    # Sort by CVSS score (highest first)
    all_cves.sort(key=lambda x: x.get('cvss_score', 0) or 0, reverse=True)
    
    return all_cves


def run(state: ScanState) -> dict:
    """
    CVE Lookup Node - Entry point
    
    Searches NVD for known vulnerabilities in detected technologies.
    """
    tech_results = state.get('tech_results', [])
    
    logs = []
    errors = []
    cve_results: List[Dict[str, Any]] = []
    
    logs.append(f"[CVELookup] Analyzing {len(tech_results)} technology results")
    
    if not tech_results:
        logs.append("[CVELookup] No technology results to analyze")
        return {
            'cve_results': [],
            'errors': errors,
            'logs': logs
        }
    
    # Count unique technologies
    unique_techs = set()
    for result in tech_results:
        for tech in result.get('technologies', []):
            unique_techs.add(tech.get('name', '').lower())
    
    logs.append(f"[CVELookup] Found {len(unique_techs)} unique technologies to check")
    
    try:
        import nvdlib
        logs.append("[CVELookup] Using NVD API for CVE lookups")
        
        # Analyze and lookup CVEs
        cve_results = analyze_tech_results(tech_results)
        
        # Count by severity
        severity_counts = {}
        for cve in cve_results:
            sev = cve.get('severity', 'unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        logs.append(f"[CVELookup] Found {len(cve_results)} CVEs")
        for sev, count in sorted(severity_counts.items()):
            logs.append(f"[CVELookup]   - {sev.upper()}: {count}")
        
    except ImportError:
        errors.append("[CVELookup] nvdlib not installed. Run: pip install nvdlib")
    except Exception as e:
        errors.append(f"[CVELookup] Error: {str(e)}")
    
    return {
        'cve_results': cve_results,
        'errors': errors,
        'logs': logs
    }
