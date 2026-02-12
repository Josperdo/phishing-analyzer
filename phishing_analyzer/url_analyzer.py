# URL analysis module for detecting suspicious links

import re
import requests
import time
from urllib.parse import urlparse
from typing import Dict, List, Optional
from dataclasses import dataclass

from .config import Config, SUSPICIOUS_INDICATORS


@dataclass
class URLAnalysis:
    # Results of analyzing a single URL
    url: str
    is_suspicious: bool
    suspicion_score: int
    reasons: List[str]
    virustotal_result: Optional[Dict] = None


class URLAnalyzer:
    # Analyzes URLs for phishing indicators

    def __init__(self):
        self.vt_enabled = Config.is_virustotal_enabled()
        self.cache = {}  # Cache for previous lookups

    def analyze_url(self, url: str) -> URLAnalysis:
        # Analyze a single URL for suspicious patterns
        score , reasons = self._check_suspicious_patterns(url)
        
        # Check if VirusTotal is enabled
        vt_result = self._check_virustotal(url)
        if vt_result and vt_result["malicious"] > 0:
            score += 5
            reasons.append(f"VirusTotal: {vt_result['malicious']} engines flagged as malicious")
        
        return URLAnalysis(
            url=url,
            is_suspicious=score >= Config.MIN_SUSPICIOUS_SCORE,
            suspicion_score=score,
            reasons=reasons,
            virustotal_result=vt_result
        )

    def _check_suspicious_patterns(self, url: str) -> tuple[int, List[str]]:
        # Check URL against known suspicious patterns.
        score = 0
        reasons = []
        parsed = urlparse(url)

        # Suspicious TLDs check
        for tld in SUSPICIOUS_INDICATORS["suspicious_tlds"]:
            if parsed.netloc.endswith(tld):
                score += 2
                reasons.append(f"Suspicious TLD: {tld}")
                break

        # IP address check
        if re.match(r'^\d+\.\d+\.\d+\.\d+', parsed.netloc):
            score += 3
            reasons.append(f"IP address used instead of domain: {parsed.netloc}")

        # Suspicious keywords in domain
        suspicious_keywords = SUSPICIOUS_INDICATORS["suspicious_domain_keywords"]
        for keyword in suspicious_keywords:
            if keyword in parsed.netloc.lower():
                score += 1
                reasons.append(f"Suspicious keyword in domain: {keyword}")

        # Http vs Https check
        if parsed.scheme == "http":
            score += 1
            reasons.append("Uses Http instead of Https")

        return score, reasons

    def _check_virustotal(self, url: str) -> Optional[Dict]:
        # Check URL against VirusTotal API
        if not self.vt_enabled:
            return None
        
        # Check cache first to avoid duplicate API calls
        if url in self.cache:
            return self.cache[url]
        
        headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
        
        try:
            # Submit URL for analysis
            response = requests.post(
                Config.VIRUSTOTAL_URL,
                headers=headers,
                data={"url": url},
            )
            response.raise_for_status()
            analysis_id = response.json()["data"]["id"]
            
            # Rate limit handling (Free tier allows 4 requests/minute)
            time.sleep(15)
            
            # Get analysis results
            result = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
            )
            result.raise_for_status()
            stats = result.json()["data"]["attributes"]["stats"]
            
            vt_result = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
            
            # Cache the result
            self.cache[url] = vt_result
            return vt_result
    
        except requests.RequestException as e:
            print(f"VirusTotal API error: {e}")
            return None
    

    def analyze_multiple(self, urls: List[str]) -> List[URLAnalysis]:
        # Analyze multiple URLs
        return [self.analyze_url(url) for url in urls]


if __name__ == "__main__":
    analyzer = URLAnalyzer()

    test_urls = [
        "https://google.com",
        "http://192.168.1.1/login",
        "https://paypal-verify.tk/account",
        "https://bit.ly/abc123",
    ]

    for url in test_urls:
        result = analyzer.analyze_url(url)
        print(f"\n{url}")
        print(f"  Suspicious: {result.is_suspicious}")
        print(f"  Score: {result.suspicion_score}")
        print(f"  Reasons: {result.reasons}")
