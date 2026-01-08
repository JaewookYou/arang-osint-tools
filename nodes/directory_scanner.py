"""
Red Iris Info Gather - Directory Scanner Node

Performs directory/path discovery using local dirsearch (cloned from git).
Uses dirsearch default wordlist + custom endpoints.
"""
import subprocess
import json
import os
import tempfile
import sys
from typing import List, Set
from pathlib import Path

from state import ScanState, DirectoryScanResult
import config


def load_custom_endpoints() -> List[str]:
    """Load custom endpoint wordlist"""
    endpoints = []
    
    if config.CUSTOM_ENDPOINTS_FILE.exists():
        try:
            with open(config.CUSTOM_ENDPOINTS_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        endpoints.append(line)
        except Exception:
            pass
    
    return endpoints


def run_dirsearch(url: str) -> List[DirectoryScanResult]:
    """
    Run local dirsearch from tools/repos/dirsearch.
    Uses the default wordlist that comes with dirsearch.
    """
    results = []
    
    dirsearch_script = config.DIRSEARCH_SCRIPT
    dirsearch_dir = config.DIRSEARCH_DIR
    
    if not dirsearch_script.exists():
        raise FileNotFoundError(f"dirsearch not found at {dirsearch_script}. Run: ./tools/install_tools.sh")
    
    try:
        # Run dirsearch.py from its directory
        cmd = [
            sys.executable,
            str(dirsearch_script),
            '-u', url,
            '-q',  # Quiet mode
            '-t', '25',  # 25 threads
            '--timeout=5',
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 min timeout
            cwd=str(dirsearch_dir)
        )
        
        # Parse output
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Skip timestamp lines like [13:20:53] Starting:
            if 'Starting:' in line or 'Target:' in line or line.startswith('  _'):
                continue
            
            # Format: [TIMESTAMP] STATUS - SIZE - PATH -> REDIRECT
            # or just: STATUS - SIZE - PATH
            if ']' in line:
                # Remove timestamp prefix
                parts = line.split(']', 1)
                if len(parts) > 1:
                    line = parts[1].strip()
            
            # Parse: 301 -  303B  - /js  ->  https://...
            # or: 200 -   14KB - /css.php
            parts = line.split()
            if len(parts) >= 3:
                try:
                    status = int(parts[0])
                    
                    # Find path
                    path = None
                    for i, part in enumerate(parts):
                        if part.startswith('/'):
                            path = part
                            break
                    
                    # Also try to find path from URL
                    if not path:
                        base_url = url.rstrip('/')
                        for part in parts:
                            if base_url in part:
                                path = part.replace(base_url, '')
                                if not path:
                                    path = '/'
                                break
                    
                    if path and 200 <= status < 500 and status != 404:
                        # Parse size
                        content_length = 0
                        for part in parts:
                            if 'B' in part and any(c.isdigit() for c in part):
                                size_str = part
                                try:
                                    if 'KB' in size_str:
                                        num = float(size_str.replace('KB', ''))
                                        content_length = int(num * 1024)
                                    elif 'MB' in size_str:
                                        num = float(size_str.replace('MB', ''))
                                        content_length = int(num * 1024 * 1024)
                                    elif 'B' in size_str:
                                        num = float(size_str.replace('B', ''))
                                        content_length = int(num)
                                except:
                                    pass
                                break
                        
                        # Deduplicate
                        existing = [r['path'] for r in results]
                        if path not in existing:
                            results.append(DirectoryScanResult(
                                url=url,
                                path=path,
                                status_code=status,
                                content_length=content_length
                            ))
                except (ValueError, IndexError):
                    pass
        
    except subprocess.TimeoutExpired:
        pass
    
    return results


def simple_dir_check(url: str, endpoints: List[str]) -> List[DirectoryScanResult]:
    """Fallback: Simple HTTP requests to check custom endpoints"""
    import requests
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import urllib3
    import time
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    results = []
    
    def check_path(path: str) -> DirectoryScanResult:
        full_url = url.rstrip('/') + '/' + path.lstrip('/')
        try:
            start_time = time.time()
            resp = requests.get(
                full_url, 
                timeout=5, 
                verify=False, 
                allow_redirects=False,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            response_time = time.time() - start_time
            
            if resp.status_code != 404:
                # Get response body (truncate to 50KB)
                body = ''
                try:
                    body = resp.text[:51200] if resp.text else ''
                except:
                    pass
                
                return DirectoryScanResult(
                    url=url,
                    path='/' + path.lstrip('/'),
                    status_code=resp.status_code,
                    content_length=len(resp.content),
                    content_type=resp.headers.get('Content-Type', ''),
                    response_time=round(response_time, 3),
                    response_headers=dict(resp.headers),
                    response_body=body
                )
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_path, ep): ep for ep in endpoints}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    
    return results


def fetch_responses_for_paths(discovered_paths: List[DirectoryScanResult]) -> List[DirectoryScanResult]:
    """
    Fetch HTTP responses for all discovered paths.
    Uses multithreading for parallel requests.
    """
    import requests
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import urllib3
    import time
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Filter paths that don't have response data yet
    paths_to_fetch = [p for p in discovered_paths 
                      if not p.get('response_headers') or not p.get('response_body')]
    
    if not paths_to_fetch:
        return discovered_paths
    
    def fetch_response(result: DirectoryScanResult) -> DirectoryScanResult:
        full_url = result['url'].rstrip('/') + result['path']
        try:
            start_time = time.time()
            resp = requests.get(
                full_url,
                timeout=10,
                verify=False,
                allow_redirects=False,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            response_time = time.time() - start_time
            
            # Get response body (truncate to 50KB)
            body = ''
            try:
                body = resp.text[:51200] if resp.text else ''
            except:
                pass
            
            # Update result with response data
            result['content_type'] = resp.headers.get('Content-Type', '')
            result['response_time'] = round(response_time, 3)
            result['response_headers'] = dict(resp.headers)
            result['response_body'] = body
            result['content_length'] = len(resp.content)
            
        except Exception as e:
            result['response_headers'] = {'error': str(e)}
            result['response_body'] = ''
            result['content_type'] = ''
            result['response_time'] = 0
        
        return result
    
    # Fetch responses in parallel
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(fetch_response, p): p for p in paths_to_fetch}
        for future in as_completed(futures):
            pass  # Results are updated in-place
    
    return discovered_paths



def run(state: ScanState) -> dict:
    """
    Directory Scanner Node - Entry point
    
    Uses local dirsearch (tools/repos/dirsearch) with default wordlist.
    Also checks custom endpoints from data/endpoints.txt.
    """
    web_servers = state.get('web_servers', [])
    
    logs = []
    errors = []
    discovered_paths: List[DirectoryScanResult] = []
    
    logs.append(f"[DirectoryScanner] Scanning {len(web_servers)} web servers")
    
    if not web_servers:
        logs.append("[DirectoryScanner] No web servers to scan")
        return {
            'discovered_paths': [],
            'errors': errors,
            'logs': logs
        }
    
    # Load custom endpoints
    custom_endpoints = load_custom_endpoints()
    logs.append(f"[DirectoryScanner] Loaded {len(custom_endpoints)} custom endpoints")
    
    # Check if dirsearch is installed
    dirsearch_available = config.DIRSEARCH_SCRIPT.exists()
    
    if dirsearch_available:
        logs.append(f"[DirectoryScanner] Using local dirsearch: {config.DIRSEARCH_SCRIPT}")
    else:
        logs.append("[DirectoryScanner] dirsearch not found. Run: ./tools/install_tools.sh")
        logs.append("[DirectoryScanner] Using simple HTTP check with custom endpoints only")
    
    for i, url in enumerate(web_servers):
        logs.append(f"[DirectoryScanner] ({i+1}/{len(web_servers)}) Scanning: {url}")
        url_results = []
        
        try:
            if dirsearch_available:
                # Run dirsearch with default wordlist
                logs.append(f"[DirectoryScanner]   -> Running dirsearch...")
                dirsearch_results = run_dirsearch(url)
                url_results.extend(dirsearch_results)
                logs.append(f"[DirectoryScanner]   -> dirsearch found {len(dirsearch_results)} paths")
            
            # Also check custom endpoints
            if custom_endpoints:
                logs.append(f"[DirectoryScanner]   -> Checking custom endpoints...")
                custom_results = simple_dir_check(url, custom_endpoints)
                
                # Deduplicate
                existing_paths = {r['path'] for r in url_results}
                new_custom = 0
                for r in custom_results:
                    if r['path'] not in existing_paths:
                        url_results.append(r)
                        existing_paths.add(r['path'])
                        new_custom += 1
                
                logs.append(f"[DirectoryScanner]   -> Custom: {new_custom} new paths")
            
            discovered_paths.extend(url_results)
            logs.append(f"[DirectoryScanner] Total: {len(url_results)} paths on {url}")
            
        except FileNotFoundError as e:
            errors.append(f"[DirectoryScanner] {str(e)}")
            # Fallback to custom endpoints only
            if custom_endpoints:
                url_results = simple_dir_check(url, custom_endpoints)
                discovered_paths.extend(url_results)
                logs.append(f"[DirectoryScanner] Fallback: {len(url_results)} paths")
        except Exception as e:
            errors.append(f"[DirectoryScanner] Error scanning {url}: {str(e)}")
    
    logs.append(f"[DirectoryScanner] Total discovered paths: {len(discovered_paths)}")
    
    # Fetch HTTP responses for paths that don't have them (dirsearch results)
    if discovered_paths:
        # Initialize missing fields for dirsearch results
        for path in discovered_paths:
            if 'response_headers' not in path:
                path['response_headers'] = None
            if 'response_body' not in path:
                path['response_body'] = None
            if 'content_type' not in path:
                path['content_type'] = None
            if 'response_time' not in path:
                path['response_time'] = None
        
        logs.append("[DirectoryScanner] Fetching HTTP responses for discovered paths...")
        discovered_paths = fetch_responses_for_paths(discovered_paths)
        logs.append("[DirectoryScanner] Response fetching complete")
    
    return {
        'discovered_paths': discovered_paths,
        'errors': errors,
        'logs': logs
    }
