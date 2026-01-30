"""
URL analysis module for detecting suspicious links.
"""

import re
import requests
import time
from urllib.parse import urlparse
from typing import Dict, List, Optional
from dataclasses import dataclass

from .config import Config, SUSPICIOUS_INDICATORS


@dataclass
class URLAnalysis:
    """Results of analyzing a single URL."""
    url: str
    is_suspicious: bool
    suspicion_score: int
    reasons: List[str]
    virustotal_result: Optional[Dict] = None


class URLAnalyzer:
    """Analyzes URLs for phishing indicators."""

    def __init__(self):
        self.vt_enabled = Config.is_virustotal_enabled()
        # TODO: Add a cache dictionary to store previous lookups
        # This prevents hammering the API with duplicate URLs

    def analyze_url(self, url: str) -> URLAnalysis:
        """
        Analyze a single URL for suspicious patterns.

        Args:
            url: The URL to analyze

        Returns:
            URLAnalysis object with results

        TODO: Implement this method
        WORKFLOW:
        1. Run pattern-based checks (implemented below)
        2. Calculate suspicion score
        3. If VirusTotal is enabled and score is high, check API
        4. Return URLAnalysis object

        HINT: Start simple - just use pattern checks first!
        """
        raise NotImplementedError("TODO: Implement analyze_url() method")

    def _check_suspicious_patterns(self, url: str) -> tuple[int, List[str]]:
        """
        Check URL against known suspicious patterns.

        Args:
            url: The URL to check

        Returns:
            Tuple of (score, reasons) where score is suspicion level

        TODO: Implement this method
        SUSPICIOUS PATTERNS TO CHECK:
        1. Suspicious TLDs (.tk, .ml, etc.) - +2 points
        2. IP address instead of domain - +3 points
        3. Suspicious keywords in domain (verify, secure, account) - +1 point each
        4. Excessive subdomains (more than 3) - +2 points
        5. URL shorteners (bit.ly, tinyurl.com) - +1 point
        6. Mismatched protocols (http instead of https for known sites) - +2 points

        HINTS:
        - Use urlparse() to break down the URL
        - Check netloc (domain) for IP addresses: re.match(r'^\d+\.\d+\.\d+\.\d+$')
        - Use SUSPICIOUS_INDICATORS from config
        - Count subdomains by splitting netloc on '.'

        LEARNING: What makes these patterns suspicious?
        Research real phishing examples!
        """
        raise NotImplementedError("TODO: Implement _check_suspicious_patterns() method")

    def _check_virustotal(self, url: str) -> Optional[Dict]:
        """
        Check URL against VirusTotal API.

        Args:
            url: The URL to check

        Returns:
            Dictionary with VT results or None if error/disabled

        TODO: Implement this LATER (after pattern matching works)

        WHEN YOU'RE READY:
        1. Get API key from Config.VIRUSTOTAL_API_KEY
        2. Encode URL (base64 URL-safe, no padding)
        3. Make GET request to /api/v3/urls/{encoded_url}
        4. Handle rate limiting (4 requests/min for free tier)
        5. Parse response for malicious/suspicious counts

        API DOCS: https://developers.virustotal.com/reference/url-info

        HINTS:
        - Use base64.urlsafe_b64encode() but remove '=' padding
        - Add header: {'x-apikey': api_key}
        - Check response['data']['attributes']['last_analysis_stats']
        - Handle HTTPError exceptions gracefully

        CHECKPOINT: How will you handle rate limiting?
        Consider: time.sleep(), request queuing, or caching results
        """
        if not self.vt_enabled:
            return None

        # TODO: Implement VirusTotal API integration
        raise NotImplementedError("TODO: Implement VirusTotal integration")

    def analyze_multiple(self, urls: List[str]) -> List[URLAnalysis]:
        """
        Analyze multiple URLs.

        Args:
            urls: List of URLs to analyze

        Returns:
            List of URLAnalysis results

        TODO: Implement this method
        HINTS:
        - Loop through URLs and call analyze_url() for each
        - Consider adding progress indication for long lists
        - If using VirusTotal, respect rate limits!

        ENHANCEMENT IDEA:
        Could you batch process URLs more efficiently?
        What if you prioritized high-suspicion URLs for API checks?
        """
        raise NotImplementedError("TODO: Implement analyze_multiple() method")


# TESTING YOUR CODE:
# Test suspicious pattern detection first:
#
# if __name__ == "__main__":
#     analyzer = URLAnalyzer()
#
#     test_urls = [
#         "https://google.com",  # Should be clean
#         "http://192.168.1.1/login",  # IP address - suspicious
#         "https://paypal-verify.tk/account",  # Suspicious TLD + keyword
#         "https://bit.ly/abc123",  # URL shortener
#     ]
#
#     for url in test_urls:
#         result = analyzer.analyze_url(url)
#         print(f"\n{url}")
#         print(f"  Suspicious: {result.is_suspicious}")
#         print(f"  Score: {result.suspicion_score}")
#         print(f"  Reasons: {result.reasons}")
