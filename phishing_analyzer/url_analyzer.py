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
        return URLAnalysis(
            url=url,
            is_suspicious=score >= Config.MIN_SUSPICIOUS_SCORE,
            suspicion_score=score,
            reasons=reasons
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
        pass

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
