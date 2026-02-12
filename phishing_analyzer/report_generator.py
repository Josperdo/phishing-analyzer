# Report generation module for formatting analysis results

import json
from datetime import datetime
from typing import List
from .email_parser import EmailData
from .url_analyzer import URLAnalysis
from dataclasses import asdict


class ReportGenerator:
    # Generates formatted reports from analysis results

    def __init__(self, email_data: EmailData, url_analyses: List[URLAnalysis]):
        self.email_data = email_data
        self.url_analyses = url_analyses
        self.timestamp = datetime.now().isoformat()

    def generate_text_report(self) -> str:
        risk_level = self._calculate_risk_level()
        
        # Generate a human-readable text report
        report = ""
        report += "=" * 50 + "\n"
        report += " PHISHING EMAIL ANALYSIS REPORT\n"
        report += f"Generated: {self.timestamp}\n"
        report += "=" * 50 + "\n\n"
        
        # email summary
        report += "EMAIL SUMMARY:\n"
        report += f"From: {self.email_data.sender}\n"
        report += f"To: {self.email_data.recipient}\n"
        report += f"Subject: {self.email_data.subject}\n"
        report += f"Date: {self.email_data.date}\n"
        report += f"Reply-To: {self.email_data.reply_to}\n"
        
        if self.email_data.reply_to_mismatch:
            report += "WARNING: Reply-To mismatch detected!\n"
        
        # URL analysis
        report += f"URLs Found: {len(self.url_analyses)}\n"
        for analysis in self.url_analyses:
            status = "SUSPICIOUS" if analysis.is_suspicious else "CLEAN"    
            report += f"[{status}] {analysis.url} (Score: {analysis.suspicion_score})\n"
            for reason in analysis.reasons:
                report += f"  - {reason}\n"
                
        # Risk level
        report += f"\nOVERALL RISK: {risk_level}\n"
        report += "=" * 50 + "\n"
        
        return report

    def generate_json_report(self) -> str:
        # Generate a JSON report for machine processing
        risk_level = self._calculate_risk_level()
    
        report = {
            "timestamp": self.timestamp,
            "email": {
                "subject": self.email_data.subject,
                "sender": self.email_data.sender,
                "recipient": self.email_data.recipient,
                "date": self.email_data.date,
                "attachments": self.email_data.attachments,
                "reply_to": self.email_data.reply_to,
                "reply_to_mismatch": self.email_data.reply_to_mismatch,
            },
            "url_analyses": {
                "total_urls": len(self.url_analyses),
                "results": [asdict(a) for a in self.url_analyses],
            },
            "risk_level": risk_level,
        }
    
        return json.dumps(report, indent=2)

    def _calculate_risk_level(self) -> str:
        # Calculate overall risk level based on all indicators. Returns: "HIGH", "MEDIUM", or "LOW"
        max_score = 0
        suspicious_count = 0
        
        for analysis in self.url_analyses:
            if analysis.suspicion_score > max_score:
                max_score = analysis.suspicion_score
            if analysis.is_suspicious:
                suspicious_count += 1
        
        if max_score >= 5 or suspicious_count > 3:
            return "HIGH"
        elif max_score >= 3 or suspicious_count > 1:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_recommendations(self) -> List[str]:
        # Generate actionable recommendations based on analysis
        pass

    def save_report(self, output_path: str, format: str = "text"):
        # Save report to file
        pass