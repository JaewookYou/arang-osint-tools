"""
Red Iris Info Gather - Nuclei Scanner Node

Performs vulnerability scanning using Nuclei.
Matches discovered paths against template patterns and runs relevant templates.
"""
import subprocess
import json
import os
import re
import tempfile
from typing import List, Dict, Set
from pathlib import Path

from state import ScanState, NucleiResult, DirectoryScanResult
import config


def load_template_patterns() -> Dict[str, List[str]]:
    """
    Load nuclei templates and extract their target patterns.
    Returns: {template_path: [patterns]}
    """
    patterns = {}
    templates_dir = config.NUCLEI_TEMPLATES_DIR
    
    if not templates_dir.exists():
        return patterns
    
    for template_file in templates_dir.glob('**/*.yaml'):
        try:
            with open(template_file, 'r') as f:
                content = f.read()
            
            # Extract paths from template (look for path: or endpoints in requests)
            template_patterns = []
            
            # Match path patterns in requests section
            path_matches = re.findall(r'path:\s*\n\s*-\s*["\']?([^"\'{\n]+)', content)
            template_patterns.extend(path_matches)
            
            # Match raw paths
            raw_matches = re.findall(r'GET\s+(/[^\s]+)', content)
            template_patterns.extend(raw_matches)
            
            # Clean patterns (remove template variables)
            cleaned = []
            for p in template_patterns:
                p = re.sub(r'\{\{.*?\}\}', '', p)
                p = p.strip()
                if p:
                    cleaned.append(p)
            
            if cleaned:
                patterns[str(template_file)] = cleaned
                
        except Exception:
            pass
    
    return patterns


def match_templates_to_paths(
    discovered_paths: List[DirectoryScanResult],
    template_patterns: Dict[str, List[str]]
) -> Dict[str, Set[str]]:
    """
    Match discovered paths to relevant templates.
    Returns: {template_path: set of target URLs}
    """
    matches: Dict[str, Set[str]] = {}
    
    for result in discovered_paths:
        discovered = result['path'].lower().strip('/')
        base_url = result['url']
        
        for template_path, patterns in template_patterns.items():
            for pattern in patterns:
                pattern_clean = pattern.lower().strip('/')
                
                # Check if paths match
                if pattern_clean in discovered or discovered in pattern_clean:
                    if template_path not in matches:
                        matches[template_path] = set()
                    
                    # Construct target URL
                    target = f"{base_url.rstrip('/')}/{result['path'].lstrip('/')}"
                    matches[template_path].add(target)
    
    return matches


def run_nuclei(template: str, targets: List[str]) -> List[NucleiResult]:
    """Run nuclei with a specific template against targets"""
    results = []
    
    try:
        # Create temp file with targets
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            target_file = f.name
        
        # Run nuclei
        cmd = [
            config.NUCLEI_PATH,
            '-t', template,
            '-l', target_file,
            '-json',
            '-silent'
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        # Parse JSON output
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    results.append(NucleiResult(
                        template_id=data.get('template-id', ''),
                        template_name=data.get('info', {}).get('name', ''),
                        severity=data.get('info', {}).get('severity', 'unknown'),
                        matched_url=data.get('matched-at', data.get('host', '')),
                        matched_at=data.get('matched-at', ''),
                        extracted_results=data.get('extracted-results', [])
                    ))
                except json.JSONDecodeError:
                    pass
        
        # Cleanup
        os.unlink(target_file)
        
    except FileNotFoundError:
        raise
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    
    return results


def run_nuclei_on_all(targets: List[str], templates_dir: Path) -> List[NucleiResult]:
    """Run all nuclei templates against all targets (fallback)"""
    results = []
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            target_file = f.name
        
        cmd = [
            config.NUCLEI_PATH,
            '-t', str(templates_dir),
            '-l', target_file,
            '-json',
            '-silent'
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )
        
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    results.append(NucleiResult(
                        template_id=data.get('template-id', ''),
                        template_name=data.get('info', {}).get('name', ''),
                        severity=data.get('info', {}).get('severity', 'unknown'),
                        matched_url=data.get('matched-at', data.get('host', '')),
                        matched_at=data.get('matched-at', ''),
                        extracted_results=data.get('extracted-results', [])
                    ))
                except json.JSONDecodeError:
                    pass
        
        os.unlink(target_file)
        
    except:
        pass
    
    return results


def run(state: ScanState) -> dict:
    """
    Nuclei Scanner Node - Entry point
    
    Matches discovered paths to nuclei templates and runs vulnerability scans.
    """
    discovered_paths = state.get('discovered_paths', [])
    web_servers = state.get('web_servers', [])
    
    logs = []
    errors = []
    vulnerabilities: List[NucleiResult] = []
    
    logs.append(f"[NucleiScanner] Starting nuclei scan with {len(discovered_paths)} discovered paths")
    
    # Check if nuclei is available
    try:
        subprocess.run([config.NUCLEI_PATH, '-version'], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logs.append("[NucleiScanner] Nuclei not found, skipping vulnerability scan")
        return {
            'vulnerabilities': [],
            'errors': errors,
            'logs': logs
        }
    
    # Check if we have custom templates
    templates_dir = config.NUCLEI_TEMPLATES_DIR
    if not templates_dir.exists() or not list(templates_dir.glob('*.yaml')):
        logs.append("[NucleiScanner] No custom nuclei templates found")
        
        # If we have web servers, run with nuclei's default templates
        if web_servers:
            logs.append("[NucleiScanner] Running nuclei with default templates on web servers")
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    f.write('\n'.join(web_servers))
                    target_file = f.name
                
                result = subprocess.run(
                    [config.NUCLEI_PATH, '-l', target_file, '-json', '-silent', '-severity', 'medium,high,critical'],
                    capture_output=True,
                    text=True,
                    timeout=600
                )
                
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            data = json.loads(line)
                            vulnerabilities.append(NucleiResult(
                                template_id=data.get('template-id', ''),
                                template_name=data.get('info', {}).get('name', ''),
                                severity=data.get('info', {}).get('severity', 'unknown'),
                                matched_url=data.get('matched-at', data.get('host', '')),
                                matched_at=data.get('matched-at', ''),
                                extracted_results=data.get('extracted-results', [])
                            ))
                        except json.JSONDecodeError:
                            pass
                
                os.unlink(target_file)
                logs.append(f"[NucleiScanner] Found {len(vulnerabilities)} vulnerabilities")
                
            except Exception as e:
                errors.append(f"[NucleiScanner] Error running default templates: {str(e)}")
        
        return {
            'vulnerabilities': vulnerabilities,
            'errors': errors,
            'logs': logs
        }
    
    # Load template patterns
    template_patterns = load_template_patterns()
    logs.append(f"[NucleiScanner] Loaded {len(template_patterns)} templates with patterns")
    
    # Match templates to discovered paths
    matches = match_templates_to_paths(discovered_paths, template_patterns)
    logs.append(f"[NucleiScanner] {len(matches)} templates matched to discovered paths")
    
    # Run matched templates
    for template_path, targets in matches.items():
        if targets:
            logs.append(f"[NucleiScanner] Running {Path(template_path).name} against {len(targets)} targets")
            try:
                results = run_nuclei(template_path, list(targets))
                vulnerabilities.extend(results)
                if results:
                    logs.append(f"[NucleiScanner] Found {len(results)} matches with {Path(template_path).name}")
            except Exception as e:
                errors.append(f"[NucleiScanner] Error with {template_path}: {str(e)}")
    
    # Also run all custom templates against web servers
    if web_servers:
        logs.append("[NucleiScanner] Running all custom templates against web servers")
        try:
            results = run_nuclei_on_all(web_servers, templates_dir)
            vulnerabilities.extend(results)
        except Exception as e:
            errors.append(f"[NucleiScanner] Error running all templates: {str(e)}")
    
    logs.append(f"[NucleiScanner] Total vulnerabilities found: {len(vulnerabilities)}")
    
    return {
        'vulnerabilities': vulnerabilities,
        'errors': errors,
        'logs': logs
    }
