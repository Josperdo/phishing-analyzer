# Phishing Email Analyzer

WIP - Email analysis tool for extracting and analyzing indicators of compromise from email files.

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

**Parse a single email (currently working):**
```bash
python -m phishing_analyzer.email_parser
```

**CLI tool (coming soon):**
```bash
python main.py <email_file.eml>
```

## Structure

```
phishing_analyzer/
├── email_parser.py      # Email parsing (implemented)
├── url_analyzer.py      # URL analysis (stub)
├── report_generator.py  # Report generation (stub)
└── config.py            # Config
```

## Testing

```bash
pytest tests/ -v
```

## TODO

- [x] Email parser implementation
- [ ] URL pattern detection
- [ ] Report generation
- [ ] CLI integration
- [ ] VirusTotal API integration
