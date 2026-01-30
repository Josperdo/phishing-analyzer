"""
Report generation module for formatting analysis results.
"""

import json
from datetime import datetime
from typing import List
from .email_parser import EmailData
from .url_analyzer import URLAnalysis


class ReportGenerator:
    """Generates formatted reports from analysis results."""

    def __init__(self, email_data: EmailData, url_analyses: List[URLAnalysis]):
        """
        Initialize report generator.

        Args:
            email_data: Parsed email information
            url_analyses: List of URL analysis results
        """
        self.email_data = email_data
        self.url_analyses = url_analyses
        self.timestamp = datetime.now().isoformat()

    def generate_text_report(self) -> str:
        """
        Generate a human-readable text report.

        Returns:
            Formatted text report as string

        TODO: Implement this method

        SUGGESTED STRUCTURE:
        ======================================
        PHISHING EMAIL ANALYSIS REPORT
        Generated: [timestamp]
        ======================================

        EMAIL SUMMARY:
        From: [sender]
        To: [recipient]
        Subject: [subject]
        Date: [date]

        ATTACHMENTS: [count]
        - [filename] ([type], [size] bytes)

        URL ANALYSIS:
        Total URLs found: [count]
        Suspicious URLs: [count]

        SUSPICIOUS URLS DETECTED:
        [URL]
          Suspicion Score: [score]/10
          Reasons:
            - [reason 1]
            - [reason 2]
          VirusTotal: [if available]

        OVERALL RISK ASSESSMENT: [HIGH/MEDIUM/LOW]
        Recommendation: [Action to take]

        ======================================

        HINTS:
        - Use f-strings for clean formatting
        - Add colors/formatting if you want (termcolor library)
        - Calculate overall risk based on URL scores and attachments
        """
        raise NotImplementedError("TODO: Implement generate_text_report() method")

    def generate_json_report(self) -> str:
        """
        Generate a JSON report for machine processing.

        Returns:
            JSON string

        TODO: Implement this method

        SUGGESTED STRUCTURE:
        {
            "timestamp": "...",
            "email": {
                "subject": "...",
                "sender": "...",
                "recipient": "...",
                "date": "...",
                "attachment_count": 0,
                "attachments": [...]
            },
            "url_analysis": {
                "total_urls": 5,
                "suspicious_urls": 2,
                "results": [
                    {
                        "url": "...",
                        "is_suspicious": true,
                        "score": 5,
                        "reasons": [...],
                        "virustotal": {...}
                    }
                ]
            },
            "risk_level": "HIGH",
            "recommendations": [...]
        }

        HINTS:
        - Build a nested dictionary structure
        - Use json.dumps(data, indent=2) for pretty printing
        - Consider making EmailData and URLAnalysis JSON-serializable
          (add a to_dict() method or use dataclasses.asdict())
        """
        raise NotImplementedError("TODO: Implement generate_json_report() method")

    def _calculate_risk_level(self) -> str:
        """
        Calculate overall risk level based on all indicators.

        Returns:
            Risk level: "HIGH", "MEDIUM", or "LOW"

        TODO: Implement this method

        SUGGESTED CRITERIA:
        HIGH: Any URL with score >= 5, or 3+ suspicious URLs
        MEDIUM: Any URL with score >= 3, or suspicious attachments
        LOW: All URLs clean, no suspicious patterns

        ENHANCEMENT: Factor in more indicators:
        - Urgent language in subject/body
        - Mismatched sender/reply-to
        - Failed DKIM/SPF (if you add that to parser)
        - Suspicious attachment types
        """
        raise NotImplementedError("TODO: Implement _calculate_risk_level() method")

    def _generate_recommendations(self) -> List[str]:
        """
        Generate actionable recommendations based on analysis.

        Returns:
            List of recommendation strings

        TODO: Implement this method

        EXAMPLES:
        - "Do not click any links in this email"
        - "Delete this email immediately"
        - "Forward to security@company.com for investigation"
        - "Verify sender identity through alternate communication channel"
        - "Email appears legitimate but verify sender before taking action"

        HINT: Base recommendations on risk level and specific findings
        """
        raise NotImplementedError("TODO: Implement _generate_recommendations() method")

    def save_report(self, output_path: str, format: str = "text"):
        """
        Save report to file.

        Args:
            output_path: Where to save the report
            format: "text" or "json"

        TODO: Implement this method
        HINT: Call appropriate generate method, then write to file
        """
        raise NotImplementedError("TODO: Implement save_report() method")


# TESTING YOUR CODE:
# After implementing email_parser and url_analyzer:
#
# if __name__ == "__main__":
#     from email_parser import EmailParser
#     from url_analyzer import URLAnalyzer
#
#     parser = EmailParser("tests/sample_emails/test_email.eml")
#     email_data = parser.parse()
#
#     analyzer = URLAnalyzer()
#     url_results = analyzer.analyze_multiple(email_data.urls)
#
#     reporter = ReportGenerator(email_data, url_results)
#     print(reporter.generate_text_report())
