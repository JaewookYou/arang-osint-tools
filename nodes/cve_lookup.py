"""
Red Iris Info Gather - CVE Lookup Node

Searches for known CVEs (1-day vulnerabilities) using multiple sources:
1. NVD (National Vulnerability Database) - CPE-based search
2. OSV (Open Source Vulnerabilities) - Google's vulnerability DB
3. VulnCheck / Vulners API (free tier)

Merges results and removes duplicates.
"""
import time
import re
import requests
from typing import List, Dict, Any, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

from state import ScanState
import config


# Cache for CVE lookups
_cve_cache: Dict[str, List[Dict]] = {}

# Rate limiting
_last_nvd_request = 0
_nvd_interval = 0.6 if config.NVD_API_KEY else 6


# ============================================
# CPE (Common Platform Enumeration) Mappings
# ============================================
# Format: cpe:2.3:part:vendor:product:version:...
CPE_MAPPINGS = {
    'apache': ('a', 'apache', 'http_server'),
    'nginx': ('a', 'f5', 'nginx'),
    'iis': ('a', 'microsoft', 'internet_information_services'),
    'php': ('a', 'php', 'php'),
    'mysql': ('a', 'oracle', 'mysql'),
    'postgresql': ('a', 'postgresql', 'postgresql'),
    'mongodb': ('a', 'mongodb', 'mongodb'),
    'redis': ('a', 'redis', 'redis'),
    'wordpress': ('a', 'wordpress', 'wordpress'),
    'drupal': ('a', 'drupal', 'drupal'),
    'joomla': ('a', 'joomla', 'joomla'),
    'tomcat': ('a', 'apache', 'tomcat'),
    'node.js': ('a', 'nodejs', 'node.js'),
    'express': ('a', 'expressjs', 'express'),
    'django': ('a', 'djangoproject', 'django'),
    'flask': ('a', 'palletsprojects', 'flask'),
    'laravel': ('a', 'laravel', 'laravel'),
    'spring': ('a', 'vmware', 'spring_framework'),
    'jquery': ('a', 'jquery', 'jquery'),
    'angular': ('a', 'angular', 'angular'),
    'react': ('a', 'facebook', 'react'),
    'vue': ('a', 'vuejs', 'vue.js'),
    'openssl': ('a', 'openssl', 'openssl'),
    'openssh': ('a', 'openbsd', 'openssh'),
    'elasticsearch': ('a', 'elastic', 'elasticsearch'),
    'ubuntu': ('o', 'canonical', 'ubuntu_linux'),
    'centos': ('o', 'centos', 'centos'),
    'debian': ('o', 'debian', 'debian_linux'),
}


def build_cpe(product: str, version: Optional[str] = None) -> Optional[str]:
    """Build CPE 2.3 string for a product"""
    product_lower = product.lower().strip()
    
    if product_lower in CPE_MAPPINGS:
        part, vendor, prod = CPE_MAPPINGS[product_lower]
        ver = version if version else '*'
        # Escape special characters in version
        ver = ver.replace('.', r'\.') if ver != '*' else '*'
        return f"cpe:2.3:{part}:{vendor}:{prod}:{version if version else '*'}:*:*:*:*:*:*:*"
    
    return None


def normalize_severity(score: float) -> str:
    """Convert CVSS score to severity string"""
    if score >= 9.0:
        return 'critical'
    elif score >= 7.0:
        return 'high'
    elif score >= 4.0:
        return 'medium'
    elif score > 0:
        return 'low'
    return 'unknown'


# ============================================
# NVD API Search (CPE-based)
# ============================================
def search_nvd(product: str, version: Optional[str] = None, max_results: int = 20) -> List[Dict[str, Any]]:
    """Search NVD using CPE matching for accurate results"""
    global _last_nvd_request
    
    cves = []
    
    try:
        import nvdlib
        
        # Rate limiting
        elapsed = time.time() - _last_nvd_request
        if elapsed < _nvd_interval:
            time.sleep(_nvd_interval - elapsed)
        _last_nvd_request = time.time()
        
        # Build CPE string
        cpe = build_cpe(product, version)
        
        # Search parameters
        search_params = {
            'limit': max_results,
        }
        
        if config.NVD_API_KEY:
            search_params['key'] = config.NVD_API_KEY
        
        # Try CPE-based search first (more accurate)
        if cpe:
            search_params['cpeName'] = cpe
            search_params['isVulnerable'] = True
        else:
            # Fallback to keyword search
            keyword = f"{product} {version}" if version else product
            search_params['keywordSearch'] = keyword
        
        # Search last 5 years for more complete results
        search_params['pubStartDate'] = datetime.now() - timedelta(days=1825)
        search_params['pubEndDate'] = datetime.now()
        
        results = nvdlib.searchCVE(**search_params)
        
        for cve in results:
            cve_id = cve.id
            
            # Extract CVSS score
            cvss_score = None
            severity = 'unknown'
            
            if hasattr(cve, 'v31score') and cve.v31score:
                cvss_score = cve.v31score
                severity = cve.v31severity.lower() if hasattr(cve, 'v31severity') else normalize_severity(cvss_score)
            elif hasattr(cve, 'v30score') and cve.v30score:
                cvss_score = cve.v30score
                severity = cve.v30severity.lower() if hasattr(cve, 'v30severity') else normalize_severity(cvss_score)
            elif hasattr(cve, 'v2score') and cve.v2score:
                cvss_score = cve.v2score
                severity = normalize_severity(cvss_score)
            
            # Extract description
            description = ""
            if hasattr(cve, 'descriptions'):
                for desc in cve.descriptions:
                    if desc.lang == 'en':
                        description = desc.value[:500]
                        break
            
            # Published date
            published = str(cve.published)[:10] if hasattr(cve, 'published') else ""
            
            cves.append({
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity,
                'published': published,
                'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                'product': product,
                'version': version,
                'source': 'NVD'
            })
            
    except Exception as e:
        pass
    
    return cves


# ============================================
# OSV (Open Source Vulnerabilities) API
# ============================================
def search_osv(product: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
    """Search Google's OSV database"""
    cves = []
    
    try:
        # OSV API endpoint
        url = "https://api.osv.dev/v1/query"
        
        # Build package query
        payload = {
            "package": {
                "name": product.lower(),
            }
        }
        
        if version:
            payload["version"] = version
        
        response = requests.post(url, json=payload, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            for vuln in data.get('vulns', []):
                vuln_id = vuln.get('id', '')
                
                # Get CVE ID if available
                cve_id = vuln_id
                for alias in vuln.get('aliases', []):
                    if alias.startswith('CVE-'):
                        cve_id = alias
                        break
                
                # Get severity
                severity = 'unknown'
                cvss_score = None
                
                for sev in vuln.get('severity', []):
                    if sev.get('type') == 'CVSS_V3':
                        score_str = sev.get('score', '')
                        try:
                            # Extract score from CVSS vector or score field
                            if '/' in score_str:
                                cvss_score = float(score_str.split('/')[0].replace('CVSS:3.1', '').replace('CVSS:3.0', '').strip())
                            else:
                                cvss_score = float(score_str)
                            severity = normalize_severity(cvss_score)
                        except:
                            pass
                
                # Get description
                description = vuln.get('summary', '') or vuln.get('details', '')[:500]
                
                # Published date
                published = vuln.get('published', '')[:10] if vuln.get('published') else ''
                
                cves.append({
                    'cve_id': cve_id,
                    'description': description,
                    'cvss_score': cvss_score,
                    'severity': severity,
                    'published': published,
                    'url': f"https://osv.dev/vulnerability/{vuln_id}",
                    'product': product,
                    'version': version,
                    'source': 'OSV'
                })
                
    except Exception as e:
        pass
    
    return cves


# ============================================
# VulnCheck KEV (Known Exploited Vulnerabilities)
# ============================================
def search_vulncheck_kev(product: str) -> List[Dict[str, Any]]:
    """Search for known exploited vulnerabilities (CISA KEV list)"""
    cves = []
    
    try:
        # CISA KEV catalog
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            product_lower = product.lower()
            
            for vuln in data.get('vulnerabilities', []):
                vendor = vuln.get('vendorProject', '').lower()
                prod = vuln.get('product', '').lower()
                
                if product_lower in vendor or product_lower in prod:
                    cve_id = vuln.get('cveID', '')
                    
                    cves.append({
                        'cve_id': cve_id,
                        'description': vuln.get('shortDescription', ''),
                        'cvss_score': None,
                        'severity': 'critical',  # KEV = actively exploited
                        'published': vuln.get('dateAdded', ''),
                        'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        'product': product,
                        'version': None,
                        'source': 'CISA-KEV'
                    })
                    
    except Exception as e:
        pass
    
    return cves


# ============================================
# Merge and Deduplicate
# ============================================
def merge_cve_results(all_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge CVE results from multiple sources and remove duplicates"""
    seen_cves: Dict[str, Dict] = {}
    
    for cve in all_results:
        cve_id = cve.get('cve_id', '')
        if not cve_id:
            continue
        
        if cve_id in seen_cves:
            # Merge: prefer entry with more info
            existing = seen_cves[cve_id]
            
            # Update with better data
            if cve.get('cvss_score') and not existing.get('cvss_score'):
                existing['cvss_score'] = cve['cvss_score']
                existing['severity'] = cve['severity']
            
            if len(cve.get('description', '')) > len(existing.get('description', '')):
                existing['description'] = cve['description']
            
            # Add source
            sources = existing.get('sources', [existing.get('source', 'unknown')])
            if cve.get('source') and cve['source'] not in sources:
                sources.append(cve['source'])
            existing['sources'] = sources
            existing['source'] = ', '.join(sources)
        else:
            cve['sources'] = [cve.get('source', 'unknown')]
            seen_cves[cve_id] = cve
    
    # Sort by CVSS score (highest first)
    result = list(seen_cves.values())
    result.sort(key=lambda x: (x.get('cvss_score') or 0), reverse=True)
    
    return result


# ============================================
# Main Lookup Function
# ============================================
def lookup_technology_cves(tech_name: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Look up CVEs for a technology from multiple sources.
    """
    cache_key = f"{tech_name.lower()}:{version}" if version else tech_name.lower()
    
    if cache_key in _cve_cache:
        return _cve_cache[cache_key]
    
    all_cves = []
    
    # Search NVD (primary source)
    nvd_results = search_nvd(tech_name, version)
    all_cves.extend(nvd_results)
    
    # Search OSV for open source packages
    osv_results = search_osv(tech_name, version)
    all_cves.extend(osv_results)
    
    # Check CISA KEV for actively exploited vulnerabilities
    kev_results = search_vulncheck_kev(tech_name)
    all_cves.extend(kev_results)
    
    # Merge and deduplicate
    merged = merge_cve_results(all_cves)
    
    # Cache results
    _cve_cache[cache_key] = merged
    
    return merged


def analyze_tech_results(tech_results: List[Dict], logs: List[str]) -> List[Dict[str, Any]]:
    """
    Analyze all detected technologies and look up CVEs from multiple sources.
    """
    all_cves = []
    searched_techs: Set[str] = set()
    
    for result in tech_results:
        url = result.get('url', '')
        
        for tech in result.get('technologies', []):
            tech_name = tech.get('name', '')
            version = tech.get('version')
            
            # Skip if already searched
            tech_key = f"{tech_name.lower()}:{version}" if version else tech_name.lower()
            if tech_key in searched_techs:
                continue
            searched_techs.add(tech_key)
            
            # Skip generic categories without version
            skip_categories = ['Font script', 'Tag manager']
            if tech.get('category') in skip_categories and not version:
                continue
            
            logs.append(f"[CVELookup] Searching: {tech_name} {version or ''}")
            
            # Look up CVEs
            cves = lookup_technology_cves(tech_name, version)
            
            for cve in cves:
                cve['detected_on'] = url
                all_cves.append(cve)
    
    # Final merge and deduplicate
    return merge_cve_results(all_cves)


def run(state: ScanState) -> dict:
    """
    CVE Lookup Node - Entry point
    
    Searches multiple vulnerability databases for known CVEs.
    """
    tech_results = state.get('tech_results', [])
    
    logs = []
    errors = []
    cve_results: List[Dict[str, Any]] = []
    llm_analysis: Dict[str, Any] = {}
    
    logs.append(f"[CVELookup] Analyzing {len(tech_results)} technology results")
    logs.append("[CVELookup] Sources: NVD, OSV, CISA-KEV")
    
    if not tech_results:
        logs.append("[CVELookup] No technology results to analyze")
        return {
            'cve_results': [],
            'llm_analysis': {},
            'errors': errors,
            'logs': logs
        }
    
    # Count unique technologies
    unique_techs = set()
    tech_stack_str = ""
    for result in tech_results:
        for tech in result.get('technologies', []):
            name = tech.get('name', '')
            version = tech.get('version', '')
            unique_techs.add(f"{name} {version}".strip())
    
    tech_stack_str = ", ".join(list(unique_techs)[:10])
    logs.append(f"[CVELookup] Found {len(unique_techs)} unique technologies")
    
    try:
        # Analyze and lookup CVEs
        cve_results = analyze_tech_results(tech_results, logs)
        
        # Count by severity
        severity_counts = {}
        for cve in cve_results:
            sev = cve.get('severity', 'unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        logs.append(f"[CVELookup] Total CVEs found: {len(cve_results)}")
        for sev in ['critical', 'high', 'medium', 'low', 'unknown']:
            if sev in severity_counts:
                logs.append(f"[CVELookup]   - {sev.upper()}: {severity_counts[sev]}")
        
        # LLM-enhanced analysis if enabled
        try:
            from utils.llm_utils import is_llm_enabled, analyze_cves_with_llm
            
            if is_llm_enabled() and cve_results:
                logs.append("[CVELookup] LLM mode enabled, performing enhanced analysis...")
                llm_analysis = analyze_cves_with_llm(cve_results, tech_stack_str)
                
                if llm_analysis:
                    logs.append("[CVELookup] LLM analysis complete")
                    
                    # Log priority CVEs from LLM
                    priority_cves = llm_analysis.get('priority_cves', [])
                    if priority_cves:
                        logs.append("[CVELookup] LLM Priority CVEs:")
                        for pcve in priority_cves[:3]:
                            logs.append(f"[CVELookup]   - {pcve.get('id')}: {pcve.get('reason', '')[:50]}")
        except ImportError:
            pass
        except Exception as e:
            logs.append(f"[CVELookup] LLM analysis skipped: {str(e)[:50]}")
        
    except Exception as e:
        errors.append(f"[CVELookup] Error: {str(e)}")
    
    return {
        'cve_results': cve_results,
        'llm_analysis': llm_analysis,
        'errors': errors,
        'logs': logs
    }
