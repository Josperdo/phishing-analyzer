"""
Main CLI entry point for the Phishing Email Analyzer.

This ties everything together and provides a command-line interface.
"""

import argparse
import sys
from pathlib import Path

from phishing_analyzer.email_parser import EmailParser
from phishing_analyzer.url_analyzer import URLAnalyzer
from phishing_analyzer.report_generator import ReportGenerator


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description="Analyze emails for phishing indicators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s suspicious_email.eml
  %(prog)s email.eml --format json --output report.json
  %(prog)s email.eml --verbose
        """,
    )

    parser.add_argument("email_file", help="Path to .eml file to analyze")

    # TODO: Add arguments: --format, --output, --verbose, --no-api

    args = parser.parse_args()

    # TODO: Implement analysis logic
    print("TODO: Implement main() function")
    print(f"Would analyze: {args.email_file}")


if __name__ == "__main__":
    main()
