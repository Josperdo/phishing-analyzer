# Main CLI entry point for the Phishing Email Analyzer

import argparse
import sys
from pathlib import Path

from phishing_analyzer.email_parser import EmailParser
from phishing_analyzer.url_analyzer import URLAnalyzer
from phishing_analyzer.report_generator import ReportGenerator

def main():
    parser = argparse.ArgumentParser(
        description="Analyze emails for phishing indicators",
    )
    parser.add_argument("email_file", help="Path to .eml file to analyze")
    args = parser.parse_args()
    
    # 1. Parse email(s)
    email_parser = EmailParser(args.email_file)
    email_data = email_parser.parse()
    
    # 2. Analyze URL(s)
    url_analyzer = URLAnalyzer()
    url_results = url_analyzer.analyze_multiple(email_data.urls)
    
    # 3. Generate report
    reporter = ReportGenerator(email_data, url_results)
    print(reporter.generate_text_report())

# Run the main function when executed as a script
if __name__ == "__main__":
    main()
