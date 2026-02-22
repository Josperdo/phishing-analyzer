# Reelphish

Phishing is the dominant initial access vector across ransomware, business email compromise, and credential-harvesting campaigns. When a suspicious `.eml` file lands in a SOC ticket — from a user report, an email gateway alert, or an IR artifact dump — triage is often manual: copying headers into a text editor, inspecting URLs one at a time, and cross-referencing threat intel by hand.

Reelphish automates that triage. It parses `.eml` files, extracts every observable indicator, scores URLs against a weighted ruleset, and optionally enriches results through VirusTotal — producing a structured risk report in seconds.

---

## How It Works

Analysis runs in three sequential stages:

**1. Parse** — The `.eml` file is ingested via Python's `email.parser.BytesParser`, which handles MIME multipart structures (`text/plain`, `text/html`, `multipart/mixed`). Headers are extracted by field. URLs are pulled from both the plain text and HTML body parts using regex, deduplicated, and passed downstream. Attachment metadata (filename, MIME type, byte size) is captured without writing content to disk.

**2. Score** — Each URL is evaluated against a pattern ruleset. Scoring is additive: signals stack rather than override. A single `.tk` domain hosting a `login` keyword over HTTP accumulates enough signal to flag without any external threat intel.

**3. Enrich** *(optional)* — When a VirusTotal API key is present, URLs are submitted to the VT v3 API. Engine verdict counts (malicious / suspicious / harmless / undetected) are appended to the per-URL result. Rate limiting for the free tier is enforced internally.

---

## IOC Extraction

### Header Signals

| Field | What's Checked |
|-------|----------------|
| `From` | Sender address extracted; domain isolated for mismatch comparison |
| `Reply-To` | Domain compared against `From` — divergence flags sender spoofing |
| `Subject` | Captured for report context |

**Reply-To mismatch** is one of the more reliable spoofing tells. An attacker sending from a lookalike domain often needs replies routed to infrastructure they actually control — and that divergence surfaces in the headers. The tool compares the domain portion of `From` against `Reply-To` and emits a warning when they differ.

### URL Scoring

Each URL is scored independently. The final score determines whether the URL is flagged and contributes to the overall risk level.

| Signal | Score | Rationale |
|--------|-------|-----------|
| Suspicious TLD (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`) | +2 | Free registrar TLDs disproportionately used for throwaway phishing infrastructure |
| IP address as host | +3 | Legitimate services don't use raw IPs; common in kit-based phishing with no domain attribution |
| Phishing keyword in domain (`verify`, `secure`, `login`, `account`, `confirm`, etc.) | +1 each | Attackers name domains to impersonate legitimacy; keywords accumulate |
| HTTP instead of HTTPS | +1 | Absence of TLS on a credential-harvesting page is a signal in context |
| VirusTotal malicious detection | +5 | Hard confirmation from 70+ engine consensus |

**Threshold:** Score ≥ 3 → `SUSPICIOUS`

**Risk rollup:**

| Level | Condition |
|-------|-----------|
| `HIGH` | Max URL score ≥ 5, or more than 3 suspicious URLs |
| `MEDIUM` | Max URL score ≥ 3, or more than 1 suspicious URL |
| `LOW` | Below threshold |

### Attachments

Filename, MIME type, and byte size are extracted and surfaced in the report. No content is saved to disk or parsed beyond MIME metadata.

---

## Detection in Action

**Scenario:** Microsoft account security alert impersonation — multipart HTML email with a spoofed sender domain and a `.tk`-hosted payload embedded in both the plain text and HTML parts.

**The email:**

```
From: Microsoft Support <security@microsoft-account-verify.xyz>
To: user@example.com
Subject: Action Required: Unusual Sign-In Activity
Date: Tue, 04 Feb 2026 14:22:00 +0000
```

The HTML part renders a convincing branded notification — Microsoft logo, a sign-in alert table, and a styled "Secure My Account" CTA button. The sender domain (`microsoft-account-verify.xyz`) passes a casual visual scan. Every URL in the email, including the logo image request, resolves to the same attacker-controlled host.

**Text report:**

```
==================================================
 PHISHING EMAIL ANALYSIS REPORT
Generated: 2026-02-22T09:14:37.882041
==================================================

EMAIL SUMMARY:
From: Microsoft Support <security@microsoft-account-verify.xyz>
To: user@example.com
Subject: Action Required: Unusual Sign-In Activity
Date: Tue, 04 Feb 2026 14:22:00 +0000
Reply-To:
URLs Found: 2
[SUSPICIOUS] http://microsoft-secure-login.tk/verify (Score: 5)
  - Suspicious TLD: .tk
  - Suspicious keyword in domain: secure
  - Suspicious keyword in domain: login
  - Uses Http instead of Https
[SUSPICIOUS] http://microsoft-secure-login.tk/logo.png (Score: 5)
  - Suspicious TLD: .tk
  - Suspicious keyword in domain: secure
  - Suspicious keyword in domain: login
  - Uses Http instead of Https

OVERALL RISK: HIGH
==================================================
```

Both URLs hit the same infrastructure. The logo request is worth noting — attackers frequently use tracking pixels and remote image loads on their phishing domains, meaning any email open sends a beacon and confirms the address is live.

**JSON report** (`--format json`):

```json
{
  "timestamp": "2026-02-22T09:14:37.882041",
  "email": {
    "subject": "Action Required: Unusual Sign-In Activity",
    "sender": "Microsoft Support <security@microsoft-account-verify.xyz>",
    "recipient": "user@example.com",
    "date": "Tue, 04 Feb 2026 14:22:00 +0000",
    "attachments": [],
    "reply_to": "",
    "reply_to_mismatch": false
  },
  "url_analyses": {
    "total_urls": 2,
    "results": [
      {
        "url": "http://microsoft-secure-login.tk/verify",
        "is_suspicious": true,
        "suspicion_score": 5,
        "reasons": [
          "Suspicious TLD: .tk",
          "Suspicious keyword in domain: secure",
          "Suspicious keyword in domain: login",
          "Uses Http instead of Https"
        ],
        "virustotal_result": null
      },
      {
        "url": "http://microsoft-secure-login.tk/logo.png",
        "is_suspicious": true,
        "suspicion_score": 5,
        "reasons": [
          "Suspicious TLD: .tk",
          "Suspicious keyword in domain: secure",
          "Suspicious keyword in domain: login",
          "Uses Http instead of Https"
        ],
        "virustotal_result": null
      }
    ]
  },
  "risk_level": "HIGH"
}
```

JSON output is suitable for piping into a SIEM, case management system, or enrichment pipeline.

### Reply-To Spoofing Detection

A separate detection path covers sender spoofing via header manipulation. When `From` and `Reply-To` resolve to different domains, the report flags it:

```
From: Amazon Support <support@amazon.com>
Reply-To: refund-claims@amaz0n-support.ru
```

```
WARNING: Reply-To mismatch detected!
```

This pattern appears in BEC and refund scams where the attacker impersonates a trusted brand in the `From` field but needs victim replies to reach infrastructure they control. The `From` domain passes a visual check; the `Reply-To` exposes the operation.

---

## Setup

**Requirements:** Python 3.10+

```bash
git clone https://github.com/xsubv/reelphish.git
cd reelphish

python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

pip install -r requirements.txt
```

**VirusTotal integration (optional):**

```bash
cp .env.example .env
# Edit .env: VIRUSTOTAL_API_KEY=your_key_here
```

Free API keys at [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey). The free tier supports 4 requests/minute — rate limiting is handled automatically via a 15-second inter-request delay.

---

## Usage

```bash
# Analyze a single email
python main.py suspicious.eml

# JSON output for downstream processing
python main.py suspicious.eml --format json

# Batch scan a directory
python main.py --directory /path/to/eml/exports/
```

---

## Architecture

```
phishing_analyzer/
├── email_parser.py      # MIME parsing, header/URL/attachment extraction
├── url_analyzer.py      # Pattern scoring and VirusTotal enrichment
├── report_generator.py  # Text and JSON report formatting, risk rollup
└── config.py            # Suspicious indicator lists and score thresholds
```

---

## Security Design

- **Passive analysis** — URLs are scored by inspection, not visited. No outbound requests are made unless VirusTotal is explicitly configured via environment variable.
- **No attachment execution** — Content is not extracted, saved, or parsed beyond MIME metadata (filename, content type, size).
- **Untrusted input handling** — Email files are parsed via `BytesParser` with charset fallback and error handling for malformed or encoding-broken content.
- **Credential isolation** — API keys are loaded from `.env` via `python-dotenv`; the file is excluded from version control.

---

## Testing

```bash
pytest tests/ -v
```

The test suite covers nine `.eml` scenarios: classic phishing, HTML-based phishing, spear phishing with Reply-To mismatch, attachment-based phishing, and legitimate baselines for false-positive validation. CI runs on Python 3.10, 3.11, and 3.12 via GitHub Actions.
