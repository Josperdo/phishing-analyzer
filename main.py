# Main CLI entry point for Reelphish

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.rule import Rule

from phishing_analyzer.email_parser import EmailParser
from phishing_analyzer.url_analyzer import URLAnalyzer
from phishing_analyzer.report_generator import ReportGenerator

console = Console()

def main():
    parser = argparse.ArgumentParser(
        description="Analyze emails for phishing indicators",
    )
    parser.add_argument("email_file", nargs="?", help="Path to .eml file to analyze")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format for the report")
    parser.add_argument("--directory", help="Analyze all .eml files in the specified directory")
    args = parser.parse_args()
    
    # Batch mode: scan all .eml files in a directory
    if args.directory:
        eml_files = list(Path(args.directory).glob("*.eml"))
        for eml_file in eml_files:
            if args.format != "json":
                console.print(Rule(f"[bold dim]{eml_file.name}[/bold dim]", style="dim"))
            email_parser = EmailParser(str(eml_file))
            email_data = email_parser.parse()
            url_analyzer = URLAnalyzer()
            url_results = url_analyzer.analyze_multiple(email_data.urls)
            reporter = ReportGenerator(email_data, url_results)
            if args.format == "json":
                print(reporter.generate_json_report())
            else:
                reporter.print_rich_report()
    # Single file mode
    else:
        email_parser = EmailParser(args.email_file)
        email_data = email_parser.parse()
        url_analyzer = URLAnalyzer()
        url_results = url_analyzer.analyze_multiple(email_data.urls)
        reporter = ReportGenerator(email_data, url_results)
        if args.format == "json":
            print(reporter.generate_json_report())
        else:
            reporter.print_rich_report()
    

# Run the main function when executed as a script
if __name__ == "__main__":
    main()
