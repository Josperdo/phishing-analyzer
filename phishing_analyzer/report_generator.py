# Report generation module for formatting analysis results

import json
from datetime import datetime
from typing import List
from .email_parser import EmailData
from .url_analyzer import URLAnalysis
from dataclasses import asdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich import box

console = Console()


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

    def print_rich_report(self) -> None:
        risk_level = self._calculate_risk_level()

        # Header
        header = Text(justify="center")
        header.append("PHISHING EMAIL ANALYSIS REPORT\n", style="bold white")
        header.append(f"Generated: {self.timestamp}", style="dim")
        console.print(Panel(header, border_style="cyan"))
        console.print()

        # Email headers table
        console.print(Rule("[bold cyan]EMAIL HEADERS[/bold cyan]", style="cyan"))
        header_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        header_table.add_column(style="bold dim", no_wrap=True)
        header_table.add_column()
        header_table.add_row("From", self.email_data.sender)
        header_table.add_row("To", self.email_data.recipient)
        header_table.add_row("Subject", self.email_data.subject)
        header_table.add_row("Date", self.email_data.date)
        if self.email_data.reply_to:
            header_table.add_row("Reply-To", self.email_data.reply_to)
        console.print(header_table)

        if self.email_data.reply_to_mismatch:
            console.print("[bold red]  ⚠  Reply-To mismatch detected — possible sender spoofing[/bold red]")
        console.print()

        # Attachments
        if self.email_data.attachments:
            console.print(Rule("[bold cyan]ATTACHMENTS[/bold cyan]", style="cyan"))
            att_table = Table(box=box.SIMPLE_HEAD, padding=(0, 1))
            att_table.add_column("Filename", style="yellow")
            att_table.add_column("Type", style="dim")
            att_table.add_column("Size", justify="right", style="dim")
            for att in self.email_data.attachments:
                att_table.add_row(att["filename"], att["content_type"], f"{att['size']} bytes")
            console.print(att_table)
            console.print()

        # URL analysis
        console.print(Rule(f"[bold cyan]URL ANALYSIS[/bold cyan]  [dim]({len(self.url_analyses)} found)[/dim]", style="cyan"))

        if self.url_analyses:
            url_table = Table(box=box.SIMPLE_HEAD, padding=(0, 1), show_lines=False)
            url_table.add_column("URL", no_wrap=False)
            url_table.add_column("Score", justify="center", width=7)
            url_table.add_column("Status", justify="center", width=12)

            for analysis in self.url_analyses:
                if analysis.is_suspicious:
                    status = Text("SUSPICIOUS", style="bold red")
                    score = Text(str(analysis.suspicion_score), style="bold red")
                else:
                    status = Text("CLEAN", style="bold green")
                    score = Text(str(analysis.suspicion_score), style="green")
                url_table.add_row(analysis.url, score, status)

            console.print(url_table)

            for analysis in self.url_analyses:
                if analysis.reasons:
                    console.print(f"  [dim]{analysis.url}[/dim]")
                    for reason in analysis.reasons:
                        console.print(f"    [yellow]•[/yellow] {reason}")
                    if analysis.virustotal_result:
                        vt = analysis.virustotal_result
                        console.print(
                            f"    [dim]VT: {vt['malicious']} malicious / "
                            f"{vt['suspicious']} suspicious / "
                            f"{vt['harmless']} harmless[/dim]"
                        )
                    console.print()
        else:
            console.print("  [dim]No URLs found.[/dim]")
            console.print()

        # Overall risk panel
        risk_colors = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        risk_color = risk_colors.get(risk_level, "white")
        risk_text = Text(f"OVERALL RISK: {risk_level}", style=f"bold {risk_color}", justify="center")
        console.print(Panel(risk_text, border_style=risk_color))

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