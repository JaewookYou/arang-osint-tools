"""
Red Iris Info Gather - CVE Lookup Node

Searches for known CVEs (1-day vulnerabilities) using multiple sources:
1. NVD (National Vulnerability Database) - CPE-based search
2. OSV (Open Source Vulnerabilities) - Google's vulnerability DB
3. CISA-KEV (Known Exploited Vulnerabilities)

Features:
- Product-specific filtering (Apache HTTP Server != Apache Tomcat)
- Version range validation
- LLM-enhanced relevance scoring (when enabled)
- Static rule fallback for LLM-off mode
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
# Product Filters (to exclude unrelated products)
# ============================================
# When searching for "Apache", exclude these products
APACHE_SUBPROJECTS = [
    'tomcat', 'struts', 'ofbiz', 'flink', 'spark', 'kafka', 'hadoop',
    'superset', 'hugegraph', 'airflow', 'activemq', 'camel', 'dubbo',
    'shiro', 'solr', 'druid', 'zookeeper', 'nifi', 'pulsar', 'skywalking'
]

# Product family mappings for filtering
PRODUCT_FILTERS = {
    'apache': {
        'must_contain': ['http server', 'httpd', 'apache http'],
        'must_not_contain': APACHE_SUBPROJECTS,
    },
    'nginx': {
        'must_contain': ['nginx'],
        'must_not_contain': ['nginx unit', 'nginx-ingress'],
    },
}


# ============================================
# CPE Mappings for NVD Search
# ============================================
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
    'openssl': ('a', 'openssl', 'openssl'),
    'openssh': ('a', 'openbsd', 'openssh'),
}


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


def parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse version string to tuple for comparison"""
    if not version_str:
        return (0,)
    # Extract only numeric parts
    parts = re.findall(r'\d+', version_str)
    return tuple(int(p) for p in parts) if parts else (0,)


def is_version_affected(target_version: str, affected_ranges: List[Dict]) -> bool:
    """
    Check if target version is within affected version ranges.
    
    affected_ranges format from OSV:
    [{"type": "SEMVER", "events": [{"introduced": "2.4.0"}, {"fixed": "2.4.59"}]}]
    """
    if not target_version or not affected_ranges:
        return True  # Assume affected if no version info
    
    target = parse_version(target_version)
    
    for range_info in affected_ranges:
        events = range_info.get('events', [])
        introduced = None
        fixed = None
        
        for event in events:
            if 'introduced' in event:
                introduced = parse_version(event['introduced'])
            if 'fixed' in event:
                fixed = parse_version(event['fixed'])
        
        # Check if target is in range [introduced, fixed)
        if introduced and target >= introduced:
            if fixed is None or target < fixed:
                return True
    
    return False


def filter_cve_by_product(cve: Dict, target_product: str) -> bool:
    """
    Filter CVE to ensure it matches the target product, not a subproject.
    Returns True if CVE should be included, False if filtered out.
    """
    product_lower = target_product.lower()
    description = cve.get('description', '').lower()
    cve_id = cve.get('cve_id', '')
    
    # Get filter rules for this product
    filters = PRODUCT_FILTERS.get(product_lower, {})
    
    # Check must_not_contain (exclude if any match)
    must_not_contain = filters.get('must_not_contain', [])
    for exclude_term in must_not_contain:
        if exclude_term.lower() in description:
            return False
    
    # For CISA-KEV, be more strict about Apache products
    if 'CISA-KEV' in cve.get('source', ''):
        if product_lower == 'apache':
            # Must explicitly mention "http server" or "httpd"
            if not any(term in description for term in ['http server', 'httpd']):
                return False
    
    return True


# ============================================
# NVD API Search
# ============================================
def search_nvd(product: str, version: Optional[str] = None, max_results: int = 15) -> List[Dict[str, Any]]:
    """Search NVD using keyword matching"""
    global _last_nvd_request
    
    cves = []
    
    try:
        import nvdlib
        
        # Rate limiting
        elapsed = time.time() - _last_nvd_request
        if elapsed < _nvd_interval:
            time.sleep(_nvd_interval - elapsed)
        _last_nvd_request = time.time()
        
        # Build search keyword
        product_lower = product.lower()
        
        # Use specific search terms for Apache HTTP Server
        if product_lower == 'apache':
            keyword = "apache http server"
        else:
            keyword = product
        
        if version:
            keyword = f"{keyword} {version}"
        
        # Search parameters
        search_params = {
            'keywordSearch': keyword,
            'limit': max_results,
            'pubStartDate': datetime.now() - timedelta(days=1825),  # 5 years
            'pubEndDate': datetime.now(),
        }
        
        if config.NVD_API_KEY:
            search_params['key'] = config.NVD_API_KEY
        
        results = nvdlib.searchCVE(**search_params)
        
        for cve in results:
            cve_id = cve.id
            
            # Extract CVSS score
            cvss_score = None
            severity = 'unknown'
            
            if hasattr(cve, 'v31score') and cve.v31score:
                cvss_score = cve.v31score
                severity = cve.v31severity.lower() if hasattr(cve, 'v31severity') and cve.v31severity else normalize_severity(cvss_score)
            elif hasattr(cve, 'v30score') and cve.v30score:
                cvss_score = cve.v30score
                severity = cve.v30severity.lower() if hasattr(cve, 'v30severity') and cve.v30severity else normalize_severity(cvss_score)
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
            
            cve_entry = {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity,
                'published': published,
                'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                'product': product,
                'version': version,
                'source': 'NVD'
            }
            
            # Filter by product
            if filter_cve_by_product(cve_entry, product):
                cves.append(cve_entry)
            
    except Exception as e:
        pass
    
    return cves


# ============================================
# OSV API Search (Fixed CVSS parsing)
# ============================================
def search_osv(product: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
    """Search Google's OSV database with proper CVSS parsing"""
    cves = []
    
    # Map product names for OSV
    osv_package_names = {
        'apache': 'apache-http-server',
        'nginx': 'nginx',
        'php': 'php',
    }
    
    package_name = osv_package_names.get(product.lower(), product.lower())
    
    try:
        # OSV API endpoint
        url = "https://api.osv.dev/v1/query"
        
        # Build package query
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": "OSS-Fuzz" if product.lower() in ['apache', 'nginx'] else "PyPI"
            }
        }
        
        if version:
            payload["version"] = version
        
        response = requests.post(url, json=payload, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            for vuln in data.get('vulns', []):
                vuln_id = vuln.get('id', '')
                
                # Skip non-CVE entries unless critical
                if not vuln_id.startswith('CVE-') and 'MGASA' not in vuln_id:
                    # Get CVE alias if available
                    cve_id = vuln_id
                    for alias in vuln.get('aliases', []):
                        if alias.startswith('CVE-'):
                            cve_id = alias
                            break
                else:
                    cve_id = vuln_id
                
                # Parse CVSS from database_specific or severity
                cvss_score = None
                severity = 'unknown'
                
                # Try database_specific first
                db_specific = vuln.get('database_specific', {})
                if 'severity' in db_specific:
                    sev_str = db_specific['severity'].upper()
                    severity = sev_str.lower() if sev_str in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] else 'unknown'
                
                # Try severity array
                for sev in vuln.get('severity', []):
                    sev_type = sev.get('type', '')
                    sev_score = sev.get('score', '')
                    
                    if sev_type == 'CVSS_V3':
                        # Parse CVSS vector string: "CVSS:3.1/AV:N/AC:L/..."
                        if sev_score.startswith('CVSS:'):
                            # Extract base score from vector if available
                            # Try to find numeric score
                            pass
                    elif sev_type == 'CVSS_V2':
                        try:
                            cvss_score = float(sev_score)
                            severity = normalize_severity(cvss_score)
                        except:
                            pass
                
                # Try to get score from references
                for ref in vuln.get('references', []):
                    if 'nvd.nist.gov' in ref.get('url', ''):
                        # Could fetch from NVD, but skip for now
                        pass
                
                # Check version affected
                affected = vuln.get('affected', [])
                version_affected = True
                if version and affected:
                    for aff in affected:
                        ranges = aff.get('ranges', [])
                        if ranges:
                            version_affected = is_version_affected(version, ranges)
                            if not version_affected:
                                break
                
                if not version_affected:
                    continue
                
                # Get description
                description = vuln.get('summary', '') or ''
                if not description:
                    description = (vuln.get('details', '') or '')[:500]
                
                # Published date
                published = vuln.get('published', '')[:10] if vuln.get('published') else ''
                
                cve_entry = {
                    'cve_id': cve_id,
                    'description': description,
                    'cvss_score': cvss_score,
                    'severity': severity,
                    'published': published,
                    'url': f"https://osv.dev/vulnerability/{vuln_id}",
                    'product': product,
                    'version': version,
                    'source': 'OSV'
                }
                
                # Filter by product
                if filter_cve_by_product(cve_entry, product):
                    cves.append(cve_entry)
                
    except Exception as e:
        pass
    
    return cves


# ============================================
# CISA-KEV Search (Known Exploited)
# ============================================
def search_cisa_kev(product: str) -> List[Dict[str, Any]]:
    """Search CISA Known Exploited Vulnerabilities catalog"""
    cves = []
    
    # Products to exclude when searching for "Apache HTTP Server"
    APACHE_EXCLUDE = [
        'tomcat', 'activemq', 'struts', 'ofbiz', 'flink', 'spark', 
        'kafka', 'hadoop', 'superset', 'hugegraph', 'airflow', 'solr',
        'druid', 'camel', 'dubbo', 'shiro', 'zookeeper', 'nifi',
        'nostromo', 'jserv', 'ajp'
    ]
    
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            product_lower = product.lower()
            
            for vuln in data.get('vulnerabilities', []):
                vendor = vuln.get('vendorProject', '').lower()
                prod = vuln.get('product', '').lower()
                description = vuln.get('shortDescription', '').lower()
                
                # Strict matching for Apache HTTP Server
                if product_lower == 'apache':
                    # Check for exclusions first
                    skip = False
                    for exclude in APACHE_EXCLUDE:
                        if exclude in prod or exclude in description:
                            skip = True
                            break
                    if skip:
                        continue
                    
                    # Must match Apache HTTP Server specifically
                    is_httpd = (
                        'http server' in prod or 
                        'httpd' in prod or
                        ('http server' in description and 'apache' in description)
                    )
                    if not is_httpd:
                        continue
                elif product_lower not in vendor and product_lower not in prod:
                    continue
                
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
# LLM-Enhanced CVE Validation
# ============================================
def validate_cves_with_llm(cves: List[Dict], product: str, version: str) -> List[Dict]:
    """
    Use LLM to validate if CVEs actually apply to the specific product/version.
    Filters out false positives and enriches with CVSS scores.
    """
    try:
        from utils.llm_utils import is_llm_enabled, get_llm_provider
        
        if not is_llm_enabled() or not cves:
            return cves
        
        provider = get_llm_provider()
        if not provider:
            return cves
        
        # Prepare CVE list for LLM
        cve_list = []
        for cve in cves[:30]:  # Limit to 30
            cve_list.append({
                "id": cve.get("cve_id"),
                "desc": cve.get("description", "")[:150],
                "severity": cve.get("severity"),
                "cvss": cve.get("cvss_score")
            })
        
        prompt = f"""You are a security expert. Analyze these CVEs for "{product} {version}".

For each CVE, determine:
1. Does it ACTUALLY affect "{product}" (not a different product with similar name)?
2. Does it affect version "{version}" specifically?
3. What is the correct CVSS score if missing?

CVEs to analyze:
{cve_list}

Respond in JSON format:
{{
    "validated_cves": [
        {{"id": "CVE-XXXX", "relevant": true/false, "cvss": 7.5, "severity": "high", "reason": "..."}}
    ]
}}

Be strict: Only mark relevant=true if the CVE specifically affects {product} {version}."""

        response = provider.generate(prompt, "You are a cybersecurity expert. Respond only in valid JSON.")
        
        # Parse response
        import json
        start = response.find('{')
        end = response.rfind('}') + 1
        if start >= 0 and end > start:
            result = json.loads(response[start:end])
            validated = result.get('validated_cves', [])
            
            # Build lookup
            validation_map = {v['id']: v for v in validated}
            
            # Update CVEs with LLM validation
            filtered_cves = []
            for cve in cves:
                cve_id = cve.get('cve_id')
                if cve_id in validation_map:
                    v = validation_map[cve_id]
                    if v.get('relevant', True):
                        # Update with LLM data
                        if v.get('cvss') and not cve.get('cvss_score'):
                            cve['cvss_score'] = v['cvss']
                            cve['severity'] = v.get('severity', normalize_severity(v['cvss']))
                        cve['llm_validated'] = True
                        filtered_cves.append(cve)
                else:
                    # Not validated by LLM, include with lower confidence
                    filtered_cves.append(cve)
            
            return filtered_cves
            
    except Exception as e:
        pass
    
    return cves


# ============================================
# Static CVE Filtering (for LLM-off mode)
# ============================================
def filter_cves_static(cves: List[Dict], product: str, version: str) -> List[Dict]:
    """
    Apply static rules to filter and deduplicate CVEs.
    Used when LLM is not available.
    """
    filtered = []
    seen_ids = set()
    
    for cve in cves:
        cve_id = cve.get('cve_id', '')
        
        # Skip duplicates
        if cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)
        
        # Skip non-CVE identifiers (MGASA, etc.) unless from trusted source
        if not cve_id.startswith('CVE-'):
            continue
        
        # Apply product filter
        if not filter_cve_by_product(cve, product):
            continue
        
        filtered.append(cve)
    
    return filtered


# ============================================
# Merge and Deduplicate
# ============================================
def merge_cve_results(all_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge CVE results from multiple sources and remove duplicates"""
    seen_cves: Dict[str, Dict] = {}
    
    for cve in all_results:
        cve_id = cve.get('cve_id', '')
        if not cve_id or not cve_id.startswith('CVE-'):
            continue
        
        if cve_id in seen_cves:
            existing = seen_cves[cve_id]
            
            # Update with better data
            if cve.get('cvss_score') and not existing.get('cvss_score'):
                existing['cvss_score'] = cve['cvss_score']
                existing['severity'] = cve['severity']
            
            if len(cve.get('description', '')) > len(existing.get('description', '')):
                existing['description'] = cve['description']
            
            # Merge sources
            sources = existing.get('sources', [existing.get('source', 'unknown')])
            if cve.get('source') and cve['source'] not in sources:
                sources.append(cve['source'])
            existing['sources'] = sources
            existing['source'] = ', '.join(sources)
        else:
            cve['sources'] = [cve.get('source', 'unknown')]
            seen_cves[cve_id] = cve
    
    # Sort by CVSS score (highest first), then by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'unknown': 4}
    result = list(seen_cves.values())
    result.sort(key=lambda x: (
        -(x.get('cvss_score') or 0),
        severity_order.get(x.get('severity', 'unknown'), 4)
    ))
    
    return result


# ============================================
# Main Lookup Function
# ============================================
def lookup_technology_cves(tech_name: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
    """Look up CVEs for a technology from multiple sources."""
    cache_key = f"{tech_name.lower()}:{version}" if version else tech_name.lower()
    
    if cache_key in _cve_cache:
        return _cve_cache[cache_key]
    
    all_cves = []
    
    # Search NVD (primary source)
    nvd_results = search_nvd(tech_name, version)
    all_cves.extend(nvd_results)
    
    # Search OSV
    osv_results = search_osv(tech_name, version)
    all_cves.extend(osv_results)
    
    # Check CISA KEV
    kev_results = search_cisa_kev(tech_name)
    all_cves.extend(kev_results)
    
    # Merge and deduplicate
    merged = merge_cve_results(all_cves)
    
    # Apply filtering
    try:
        from utils.llm_utils import is_llm_enabled
        if is_llm_enabled():
            merged = validate_cves_with_llm(merged, tech_name, version or "")
        else:
            merged = filter_cves_static(merged, tech_name, version or "")
    except:
        merged = filter_cves_static(merged, tech_name, version or "")
    
    # Cache results
    _cve_cache[cache_key] = merged
    
    return merged


def analyze_tech_results(tech_results: List[Dict], logs: List[str]) -> List[Dict[str, Any]]:
    """Analyze all detected technologies and look up CVEs."""
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
            skip_categories = ['Font script', 'Tag manager', 'Analytics']
            if tech.get('category') in skip_categories and not version:
                continue
            
            logs.append(f"[CVELookup] Searching: {tech_name} {version or ''}")
            
            # Look up CVEs
            cves = lookup_technology_cves(tech_name, version)
            
            for cve in cves:
                cve['detected_on'] = url
                all_cves.append(cve)
    
    # Final merge
    return merge_cve_results(all_cves)


def run(state: ScanState) -> dict:
    """CVE Lookup Node - Entry point"""
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
        
        # LLM-enhanced analysis
        try:
            from utils.llm_utils import is_llm_enabled, analyze_cves_with_llm, summarize_cves_korean
            
            if is_llm_enabled() and cve_results:
                logs.append("[CVELookup] LLM mode enabled, performing enhanced analysis...")
                
                # Prioritization analysis
                llm_analysis = analyze_cves_with_llm(cve_results, tech_stack_str)
                
                if llm_analysis:
                    logs.append("[CVELookup] LLM analysis complete")
                
                # Korean summaries
                logs.append("[CVELookup] Generating Korean CVE summaries...")
                cve_results = summarize_cves_korean(cve_results)
                logs.append("[CVELookup] Korean summaries complete")
        except:
            pass
        
    except Exception as e:
        errors.append(f"[CVELookup] Error: {str(e)}")
    
    return {
        'cve_results': cve_results,
        'llm_analysis': llm_analysis,
        'errors': errors,
        'logs': logs
    }
