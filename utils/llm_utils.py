"""
Red Iris Info Gather - LLM Utility Module

Multi-provider LLM support for enhanced CVE analysis:
- Google Gemini
- Anthropic Claude
- OpenAI GPT

Provides:
- CVE severity prioritization
- Detailed Korean CVE summaries
- Attack vector analysis
- Request/Response logging
"""
import os
import json
import requests
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

import config

# LLM Log directory
LLM_LOG_DIR = config.OUTPUT_DIR / "llm_logs"


def log_llm_request(provider: str, model: str, prompt: str, system_prompt: str, response: str):
    """Log LLM request/response for debugging"""
    try:
        LLM_LOG_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = LLM_LOG_DIR / f"llm_{timestamp}.json"
        
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "provider": provider,
            "model": model,
            "system_prompt": system_prompt,
            "prompt": prompt,
            "response": response,
        }
        
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, ensure_ascii=False, indent=2)
    except:
        pass  # Don't fail on logging errors


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
                "maxOutputTokens": 4096,
            }
        }
        
        response_text = ""
        try:
            response = requests.post(
                f"{url}?key={self.api_key}",
                headers=headers,
                json=payload,
                timeout=120
            )
            
            if response.status_code == 200:
                data = response.json()
                response_text = data["candidates"][0]["content"]["parts"][0]["text"]
            else:
                response_text = f"Error: {response.status_code} - {response.text[:200]}"
                
        except Exception as e:
            response_text = f"Error: {str(e)}"
        
        # Log request/response
        log_llm_request("gemini", self.model, prompt, system_prompt, response_text)
        return response_text


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
            "max_tokens": 4096,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        response_text = ""
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=120)
            
            if response.status_code == 200:
                data = response.json()
                response_text = data["content"][0]["text"]
            else:
                response_text = f"Error: {response.status_code} - {response.text[:200]}"
                
        except Exception as e:
            response_text = f"Error: {str(e)}"
        
        log_llm_request("anthropic", self.model, prompt, system_prompt, response_text)
        return response_text


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
            "max_tokens": 4096,
            "temperature": 0.3
        }
        
        response_text = ""
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=120)
            
            if response.status_code == 200:
                data = response.json()
                response_text = data["choices"][0]["message"]["content"]
            else:
                response_text = f"Error: {response.status_code} - {response.text[:200]}"
        except Exception as e:
            response_text = f"Error: {str(e)}"
        
        log_llm_request("openai", self.model, prompt, system_prompt, response_text)
        return response_text
# Model name mappings
# User-friendly name -> (provider, actual_api_model_name)
MODEL_MAPPINGS = {
    # Gemini (Google AI)
    "gemini-3-pro": ("gemini", "gemini-3-pro-preview"),
    "gemini-3-flash": ("gemini", "gemini-3-flash-preview"),
    "gemini-2.5-flash": ("gemini", "gemini-2.5-flash"),
    "gemini-2.5-pro": ("gemini", "gemini-2.5-pro"),
    # Anthropic Claude
    "claude-opus-4": ("anthropic", "claude-opus-4-5-20251101"),
    "claude-sonnet-4": ("anthropic", "claude-sonnet-4-5-20250929"),
    # OpenAI GPT
    "gpt-5.2-pro": ("openai", "gpt-5.2-pro"),
    "gpt-5.2": ("openai", "gpt-5.2"),
    "gpt-5-nano": ("openai", "gpt-5-nano"),
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
    Generate detailed Korean summaries for ALL CVEs using LLM.
    Focus: Attack perspective only (no mitigations).
    Includes: exploit links when available.
    """
    provider = get_llm_provider()
    
    if not provider or not cves:
        return cves
    
    # Process ALL CVEs (in batches if needed)
    cve_data = []
    for cve in cves:  # All CVEs
        cve_data.append({
            "id": cve.get("cve_id"),
            "desc": cve.get("description", ""),
            "product": cve.get("product", ""),
            "version": cve.get("version", ""),
            "severity": cve.get("severity", "")
        })
    
    prompt = f"""당신은 한국인 모의해킹 전문가입니다. 아래 CVE 목록을 분석하여 **모든 응답을 반드시 한국어로** 작성하세요.

## 분석할 CVE 목록:
{json.dumps(cve_data, ensure_ascii=False, indent=2)}

## 각 CVE에 대해 다음 정보를 한국어로 작성:

1. **vuln_type**: 취약점 유형 (예: 원격 코드 실행, 경로 탐색, SSRF, DoS)
2. **affected_versions**: 취약한 버전 범위 (예: "2.4.49 이상 2.4.51 미만")
3. **conditions**: 공격 성공을 위한 전제 조건 (예: "mod_cgi 활성화 필요", "인증 불필요")
4. **attack_method**: 구체적인 공격 방법 (1-2문장)
5. **impact**: 공격 성공 시 결과 (예: "웹 서버 쉘 획득", "민감 파일 유출")
6. **exploit_url**: 공개된 익스플로잇 코드 URL (있으면 GitHub/exploit-db 링크, 없으면 빈 문자열)
7. **summary_ko**: 전체 요약 (3-4문장, 공격자 관점에서 상세히)

## 중요 지침:
- 대응방안/패치 정보는 작성하지 마세요 (공격 관점만)
- 모든 텍스트는 반드시 한국어로 작성하세요
- exploit_url은 실제 존재하는 URL만 작성하세요 (확실하지 않으면 빈 문자열)

## JSON 형식으로만 응답:
{{
    "summaries": [
        {{
            "id": "CVE-XXXX-XXXXX",
            "vuln_type": "원격 코드 실행",
            "affected_versions": "2.4.49 ~ 2.4.51",
            "conditions": "mod_cgi 활성화, CGI 스크립트 실행 가능",
            "attack_method": "경로 탐색 문자(%2e%2e/)를 포함한 URL 요청으로 /etc/passwd 접근",
            "impact": "웹 서버 루트 권한으로 쉘 획득 가능",
            "exploit_url": "https://github.com/...",
            "summary_ko": "Apache HTTP Server의 경로 정규화 취약점입니다..."
        }}
    ]
}}"""

    system_prompt = """당신은 한국인 보안 전문가입니다. 
모든 응답은 반드시 한국어로 작성해야 합니다. 영어로 작성하면 안 됩니다.
JSON 형식으로만 응답하세요."""

    try:
        response = provider.generate(prompt, system_prompt)
        
        # Parse JSON response
        start = response.find('{')
        end = response.rfind('}') + 1
        if start >= 0 and end > start:
            result = json.loads(response[start:end])
            summaries = {s['id']: s for s in result.get('summaries', [])}
            
            # Add Korean summaries to ALL CVEs
            for cve in cves:
                cve_id = cve.get('cve_id')
                if cve_id in summaries:
                    s = summaries[cve_id]
                    cve['korean_summary'] = s.get('summary_ko', '')
                    cve['vuln_type'] = s.get('vuln_type', '')
                    cve['affected_versions'] = s.get('affected_versions', '')
                    cve['conditions'] = s.get('conditions', '')
                    cve['attack_method'] = s.get('attack_method', '')
                    cve['impact'] = s.get('impact', '')
                    cve['exploit_url'] = s.get('exploit_url', '')
    except Exception as e:
        pass
    
    return cves


def search_exploit_db(cve_id: str) -> str:
    """Search for exploit links for a CVE"""
    try:
        # Try exploit-db API
        url = f"https://www.exploit-db.com/search?cve={cve_id.replace('CVE-', '')}"
        return url
    except:
        return ""


def is_llm_enabled() -> bool:
    """Check if LLM mode is enabled"""
    return os.environ.get("LLM_MODE", "off").lower() == "on" and os.environ.get("LLM_API_KEY", "")


