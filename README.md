# Phishing Email Analyzer

A command-line tool that parses `.eml` email files and analyzes them for phishing indicators. Extracts headers, body content, URLs, and attachment metadata, then scores each URL against known suspicious patterns to produce a risk assessment report.

Built with Python's standard `email` library for parsing and custom pattern-matching logic for detection.

## Features

- **Email Parsing** - Extracts headers, body (plain text + HTML), URLs, and attachment metadata from `.eml` files with charset-aware decoding and input validation
- **URL Pattern Detection** - Scores URLs against suspicious TLDs, IP-based domains, phishing keywords, and protocol checks
- **Risk Assessment** - Calculates overall risk level (HIGH/MEDIUM/LOW) based on cumulative URL analysis
- **Report Generation** - Outputs formatted analysis reports to the terminal

## Sample Output

```
==================================================
 PHISHING EMAIL ANALYSIS REPORT
Generated: 2026-02-09T20:54:05.097247
==================================================

EMAIL SUMMARY:
From: PayPal Security <no-reply@paypal-verify.tk>
To: victim@example.com
Subject: URGENT: Verify Your Account Now!
Date: Fri, 30 Jan 2026 10:30:00 +0000
URLs Found: 1
[SUSPICIOUS] http://192.168.1.100/paypal/verify?id=12345 (Score: 4)
  - IP address used instead of domain: 192.168.1.100
  - Uses Http instead of Https

OVERALL RISK: MEDIUM
==================================================
```

## Setup

```bash
python -m venv venv

# Linux/Mac:
source venv/bin/activate

# Windows:
venv\Scripts\activate

pip install -r requirements.txt
```

Copy `.env.example` to `.env` and add API keys if needed.

## Usage

```bash
python main.py <email_file.eml>
```

Example:
```bash
python main.py tests/sample_emails/sample_phishing.eml
```

## Project Structure

```
phishing_analyzer/
├── email_parser.py      # Parses .eml files, extracts headers/body/URLs/attachments
├── url_analyzer.py      # Scores URLs against suspicious patterns
├── report_generator.py  # Formats analysis into readable reports
└── config.py            # Suspicious indicators and thresholds
```

## Testing

```bash
pytest tests/ -v
```

## Security Considerations

- Email files are parsed as untrusted input with error handling and charset detection
- Attachments are metadata-only (not saved or executed)
- URL analysis is passive (no outbound requests unless VirusTotal is configured)

## Roadmap

- [x] Email parser implementation
- [x] URL pattern detection
- [x] Report generation
- [x] CLI integration
- [ ] VirusTotal API integration
- [ ] Batch folder scanning
- [x] JSON report export
- [ ] Sender domain/Reply-To mismatch detection
