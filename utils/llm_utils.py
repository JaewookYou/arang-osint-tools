"""
Red Iris Info Gather - LLM Utility Module

Multi-provider LLM support for enhanced CVE analysis:
- Google Gemini 3 Pro
- Anthropic Opus 4.5
- OpenAI GPT-5.2 Pro

Provides:
- CVE severity prioritization
- Exploit likelihood assessment
- Mitigation recommendations
- Attack vector analysis
"""
import os
import json
import requests
from typing import Optional, Dict, Any, List

import config


class LLMProvider:
    """Base class for LLM providers"""
    
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model
    
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        raise NotImplementedError


class GeminiProvider(LLMProvider):
    """Google Gemini API provider"""
    
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        
        headers = {
            "Content-Type": "application/json",
        }
        
        contents = []
        if system_prompt:
            contents.append({
                "role": "user",
                "parts": [{"text": f"System: {system_prompt}"}]
            })
            contents.append({
                "role": "model", 
                "parts": [{"text": "Understood. I will follow these instructions."}]
            })
        
        contents.append({
            "role": "user",
            "parts": [{"text": prompt}]
        })
        
        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 2048,
            }
        }
        
        try:
            response = requests.post(
                f"{url}?key={self.api_key}",
                headers=headers,
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                data = response.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
            else:
                return f"Error: {response.status_code}"
                
        except Exception as e:
            return f"Error: {str(e)}"


class AnthropicProvider(LLMProvider):
    """Anthropic Claude/Opus API provider"""
    
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        url = "https://api.anthropic.com/v1/messages"
        
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2024-01-01"
        }
        
        payload = {
            "model": self.model,
            "max_tokens": 2048,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                return data["content"][0]["text"]
            else:
                return f"Error: {response.status_code}"
                
        except Exception as e:
            return f"Error: {str(e)}"


class OpenAIProvider(LLMProvider):
    """OpenAI GPT API provider"""
    
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        url = "https://api.openai.com/v1/chat/completions"
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": 2048,
            "temperature": 0.3
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"]
            else:
                return f"Error: {response.status_code}"
                
        except Exception as e:
            return f"Error: {str(e)}"


# Model name mappings
# User-friendly name -> (provider, actual_api_model_name)
MODEL_MAPPINGS = {
    # Gemini (Google AI)
    "gemini-3.0-pro": ("gemini", "gemini-3-pro-preview"),
    "gemini-2.5-flash": ("gemini", "gemini-2.5-flash-preview-05-20"),
    "gemini-2.0-flash": ("gemini", "gemini-2.0-flash"),
    "gemini-1.5-pro": ("gemini", "gemini-1.5-pro"),
    "gemini-1.5-flash": ("gemini", "gemini-1.5-flash"),
    # Anthropic Claude
    "claude-opus-4": ("anthropic", "claude-opus-4-20250514"),
    "claude-sonnet-4": ("anthropic", "claude-sonnet-4-20250514"),
    "claude-3.5-sonnet": ("anthropic", "claude-3-5-sonnet-20241022"),
    "claude-3-opus": ("anthropic", "claude-3-opus-20240229"),
    # OpenAI GPT
    "gpt-4.1": ("openai", "gpt-4.1"),
    "gpt-4o": ("openai", "gpt-4o"),
    "gpt-4-turbo": ("openai", "gpt-4-turbo"),
    "gpt-4": ("openai", "gpt-4"),
    "o3": ("openai", "o3"),
    "o4-mini": ("openai", "o4-mini"),
}


def get_llm_provider() -> Optional[LLMProvider]:
    """Get LLM provider based on configuration"""
    
    # Check if LLM is enabled
    llm_mode = os.environ.get("LLM_MODE", "off").lower()
    if llm_mode != "on":
        return None
    
    api_key = os.environ.get("LLM_API_KEY", "")
    model = os.environ.get("LLM_MODEL", "gemini-3-pro")
    
    if not api_key:
        return None
    
    # Get provider and actual model name
    if model in MODEL_MAPPINGS:
        provider_type, actual_model = MODEL_MAPPINGS[model]
    else:
        # Default to Gemini
        provider_type = "gemini"
        actual_model = model
    
    # Create provider instance
    if provider_type == "gemini":
        return GeminiProvider(api_key, actual_model)
    elif provider_type == "anthropic":
        return AnthropicProvider(api_key, actual_model)
    elif provider_type == "openai":
        return OpenAIProvider(api_key, actual_model)
    
    return None


# ============================================
# CVE Analysis Prompts
# ============================================
CVE_ANALYSIS_SYSTEM_PROMPT = """You are a cybersecurity expert specializing in vulnerability assessment and penetration testing.
Your task is to analyze CVE data and provide actionable intelligence for security assessments.
Be concise, technical, and focus on practical exploitation potential.
Always respond in valid JSON format."""


def analyze_cves_with_llm(cves: List[Dict], tech_stack: str) -> Dict[str, Any]:
    """
    Use LLM to analyze CVEs and provide prioritized recommendations.
    
    Returns:
        - prioritized_cves: CVEs sorted by actual exploitability
        - exploit_suggestions: Potential attack vectors
        - mitigation_summary: Quick fix recommendations
    """
    provider = get_llm_provider()
    
    if not provider or not cves:
        return {}
    
    # Prepare CVE summary
    cve_list = []
    for cve in cves[:20]:  # Limit to top 20
        cve_list.append({
            "id": cve.get("cve_id"),
            "cvss": cve.get("cvss_score"),
            "severity": cve.get("severity"),
            "description": cve.get("description", "")[:200]
        })
    
    prompt = f"""Analyze these CVEs for {tech_stack} and provide:

1. **Priority Ranking**: Rank top 5 CVEs by real-world exploitability (not just CVSS)
2. **Exploit Potential**: For each top CVE, assess if public exploits exist
3. **Attack Vectors**: Suggest practical attack approaches
4. **Quick Wins**: Immediate mitigations

CVE Data:
{json.dumps(cve_list, indent=2)}

Respond in JSON format:
{{
    "priority_cves": [
        {{"id": "CVE-XXXX", "reason": "...", "exploit_available": true/false}}
    ],
    "attack_vectors": ["..."],
    "mitigations": ["..."],
    "risk_summary": "..."
}}"""

    try:
        response = provider.generate(prompt, CVE_ANALYSIS_SYSTEM_PROMPT)
        
        # Parse JSON response
        # Find JSON in response
        start = response.find('{')
        end = response.rfind('}') + 1
        if start >= 0 and end > start:
            json_str = response[start:end]
            return json.loads(json_str)
    except Exception as e:
        pass
    
    return {}


def generate_exploit_suggestions(cve: Dict, target_url: str) -> str:
    """Generate detailed exploit suggestions for a specific CVE"""
    provider = get_llm_provider()
    
    if not provider:
        return ""
    
    prompt = f"""For CVE {cve.get('cve_id')} affecting {cve.get('product')} {cve.get('version', '')}:

Description: {cve.get('description', '')}
Target: {target_url}

Provide:
1. Step-by-step exploitation approach
2. Required tools/scripts
3. Proof-of-concept outline
4. Detection indicators

Be specific and technical. This is for authorized penetration testing only."""

    try:
        return provider.generate(prompt, CVE_ANALYSIS_SYSTEM_PROMPT)
    except:
        return ""


def summarize_security_posture(tech_results: List[Dict], cve_results: List[Dict]) -> str:
    """Generate executive summary of security findings"""
    provider = get_llm_provider()
    
    if not provider:
        return ""
    
    # Summarize tech stack
    techs = []
    for result in tech_results:
        for tech in result.get('technologies', []):
            techs.append(f"{tech.get('name')} {tech.get('version', '')}")
    
    # Count CVEs by severity
    severity_counts = {}
    for cve in cve_results:
        sev = cve.get('severity', 'unknown')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    prompt = f"""Generate a concise security assessment summary (max 300 words):

Technology Stack:
{', '.join(techs[:15])}

Vulnerability Summary:
- Critical: {severity_counts.get('critical', 0)}
- High: {severity_counts.get('high', 0)}
- Medium: {severity_counts.get('medium', 0)}
- Low: {severity_counts.get('low', 0)}
- Total CVEs: {len(cve_results)}

Provide:
1. Overall risk rating (Critical/High/Medium/Low)
2. Top 3 immediate concerns
3. Recommended actions priority"""

    try:
        return provider.generate(prompt, CVE_ANALYSIS_SYSTEM_PROMPT)
    except:
        return ""
def summarize_cves_korean(cves: List[Dict]) -> List[Dict]:
    """
    Generate Korean summaries for CVEs using LLM.
    Returns CVEs with added 'korean_summary' field.
    """
    provider = get_llm_provider()
    
    if not provider or not cves:
        return cves
    
    # Prepare CVE data for batch processing
    cve_data = []
    for cve in cves[:15]:  # Limit to 15 for token efficiency
        cve_data.append({
            "id": cve.get("cve_id"),
            "desc": cve.get("description", "")[:300],
            "product": cve.get("product", ""),
            "severity": cve.get("severity", "")
        })
    
    prompt = f"""다음 CVE 목록을 분석하고 각각에 대해 한국어로 간단한 요약을 작성해주세요.

각 CVE에 대해:
1. 취약점 유형 (예: RCE, SSRF, XSS 등)
2. 공격자가 할 수 있는 것 (한 문장)
3. 영향받는 구성요소

CVE 데이터:
{json.dumps(cve_data, ensure_ascii=False, indent=2)}

JSON 형식으로 응답:
{{
    "summaries": [
        {{
            "id": "CVE-XXXX",
            "type": "취약점 유형",
            "impact": "공격자가 할 수 있는 것",
            "component": "영향받는 구성요소",
            "summary_ko": "전체 한국어 요약 (2-3문장)"
        }}
    ]
}}"""

    try:
        response = provider.generate(prompt, "보안 전문가로서 CVE를 분석합니다. JSON으로만 응답하세요.")
        
        # Parse JSON response
        start = response.find('{')
        end = response.rfind('}') + 1
        if start >= 0 and end > start:
            result = json.loads(response[start:end])
            summaries = {s['id']: s for s in result.get('summaries', [])}
            
            # Add Korean summaries to CVEs
            for cve in cves:
                cve_id = cve.get('cve_id')
                if cve_id in summaries:
                    s = summaries[cve_id]
                    cve['korean_summary'] = s.get('summary_ko', '')
                    cve['vuln_type'] = s.get('type', '')
                    cve['impact'] = s.get('impact', '')
                    cve['component'] = s.get('component', '')
    except Exception as e:
        pass
    
    return cves


def is_llm_enabled() -> bool:
    """Check if LLM mode is enabled"""
    return os.environ.get("LLM_MODE", "off").lower() == "on" and os.environ.get("LLM_API_KEY", "")

