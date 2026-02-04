# Phishing Email Analyzer

WIP - Email analysis tool for extracting and analyzing indicators of compromise from email files.

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and add API keys if needed.

## Usage

```bash
python main.py <email_file.eml>
```

## Structure

```
phishing_analyzer/
├── email_parser.py      # Email parsing
├── url_analyzer.py      # URL analysis
├── report_generator.py  # Report generation
└── config.py           # Config
```

## Testing

```bash
pytest tests/
```

## TODO

- [x] Email parser implementation
- [ ] URL pattern detection
- [ ] Report generation
- [ ] CLI integration
- [ ] VirusTotal API integration
