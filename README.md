# Phishing Email Analyzer

A command-line tool that parses `.eml` email files and analyzes them for phishing indicators. Extracts headers, body content, URLs, and attachment metadata, then scores each URL against known suspicious patterns and VirusTotal's threat intelligence to produce a risk assessment report.

Built with Python's standard `email` library for parsing, custom pattern-matching logic for detection, and VirusTotal API integration for URL reputation checks.

## Features

- **Email Parsing** - Extracts headers, body (plain text + HTML), URLs, and attachment metadata from `.eml` files with charset-aware decoding and input validation
- **URL Pattern Detection** - Scores URLs against suspicious TLDs, IP-based domains, phishing keywords, and protocol checks
- **VirusTotal Integration** - Checks URLs against 70+ security engines for real-time threat intelligence (optional, requires free API key)
- **Reply-To Mismatch Detection** - Flags sender spoofing when the Reply-To domain doesn't match the From domain
- **Batch Scanning** - Analyze all `.eml` files in a directory with a single command
- **Risk Assessment** - Calculates overall risk level (HIGH/MEDIUM/LOW) based on cumulative URL analysis
- **Report Generation** - Outputs formatted reports in text or JSON format

## Sample Output

**Text Report:**
```
==================================================
 PHISHING EMAIL ANALYSIS REPORT
Generated: 2026-02-11T19:30:23.462807
==================================================

EMAIL SUMMARY:
From: PayPal Security <no-reply@paypal-verify.tk>
To: victim@example.com
Subject: URGENT: Verify Your Account Now!
Date: Fri, 30 Jan 2026 10:30:00 +0000
Reply-To:
URLs Found: 1
[SUSPICIOUS] http://192.168.1.100/paypal/verify?id=12345 (Score: 4)
  - IP address used instead of domain: 192.168.1.100
  - Uses Http instead of Https

OVERALL RISK: MEDIUM
==================================================
```

**JSON Report** (`--format json`):
```json
{
  "timestamp": "2026-02-11T19:35:08.967382",
  "email": {
    "subject": "URGENT: Verify Your Account Now!",
    "sender": "PayPal Security <no-reply@paypal-verify.tk>",
    "recipient": "victim@example.com",
    "reply_to": "",
    "reply_to_mismatch": false
  },
  "url_analyses": {
    "total_urls": 1,
    "results": [
      {
        "url": "http://192.168.1.100/paypal/verify?id=12345",
        "is_suspicious": true,
        "suspicion_score": 4,
        "virustotal_result": { "malicious": 0, "suspicious": 0, "harmless": 63, "undetected": 31 }
      }
    ]
  },
  "risk_level": "MEDIUM"
}
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

**Single file analysis:**
```bash
python main.py tests/sample_emails/sample_phishing.eml
```

**Batch scan a directory:**
```bash
python main.py --directory tests/sample_emails/
```

**JSON output:**
```bash
python main.py tests/sample_emails/sample_phishing.eml --format json
```

**VirusTotal integration (optional):**
```bash
# Copy .env.example to .env and add your API key
cp .env.example .env
# Then run as normal - VT checks are automatic when key is present
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
- API keys are stored in `.env` (excluded from version control via `.gitignore`)
- VirusTotal free tier rate limiting enforced (4 requests/minute)

## Roadmap

- [x] Email parser implementation
- [x] URL pattern detection
- [x] Report generation
- [x] CLI integration
- [x] VirusTotal API integration
- [x] Batch folder scanning
- [x] JSON report export
- [x] Sender domain/Reply-To mismatch detection
