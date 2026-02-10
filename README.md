# Phishing Email Analyzer

Email analysis tool for extracting and analyzing indicators of compromise from .eml files.

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

## Structure

```
phishing_analyzer/
├── email_parser.py      # Email parsing
├── url_analyzer.py      # URL pattern detection
├── report_generator.py  # Report generation
└── config.py            # Config and suspicious indicators
```

## Testing

```bash
pytest tests/ -v
```

## TODO

- [x] Email parser implementation
- [x] URL pattern detection
- [x] Report generation
- [x] CLI integration
- [ ] VirusTotal API integration
