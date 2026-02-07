# Email parsing module for extracting components from .eml files

import email
import logging
from email import policy
from email.parser import BytesParser
import re
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class EmailData:
    subject: str
    sender: str
    recipient: str
    date: str
    body_text: str
    body_html: Optional[str]
    headers: Dict[str, str]
    urls: List[str]
    attachments: List[Dict[str, str]]


class EmailParser:
    # Parses .eml files and extracts relevant information

    def __init__(self, eml_path: str):
        self.eml_path = Path(eml_path)
        self.message = None

        # Validate input before we even try to parse
        if not self.eml_path.exists():
            raise FileNotFoundError(f"Email file not found: {self.eml_path}")
        if self.eml_path.suffix.lower() != '.eml':
            raise ValueError(f"Expected .eml file, got: {self.eml_path.suffix}")

    def parse(self) -> EmailData:
        # Parse the email file and extract all relevant data
        try:
            with open(self.eml_path, 'rb') as f:
                self.message = BytesParser(policy=policy.default).parse(f)
        except Exception as e:
            logger.error(f"Failed to parse email file: {e}")
            raise

        headers = self._extract_headers()
        body_text, body_html = self._extract_body()
        urls = self._extract_urls(body_text, body_html)
        attachments = self._extract_attachments()

        return EmailData(
            subject=headers['subject'],
            sender=headers['from'],
            recipient=headers['to'],
            date=headers['date'],
            body_text=body_text or "",
            body_html=body_html,
            headers=headers,
            urls=urls,
            attachments=attachments
        )

    def _extract_headers(self) -> Dict[str, str]:
        # Extract important email headers, default to empty string if missing
        return {
            'subject': self.message['Subject'] or "",
            'from': self.message['From'] or "",
            'to': self.message['To'] or "",
            'date': self.message['Date'] or "",
        }

    def _extract_body(self) -> tuple[str, Optional[str]]:
        # Extract plain text and HTML body content
        body_text = None
        body_html = None

        for part in self.message.walk():
            content_type = part.get_content_type()

            if content_type not in ("text/plain", "text/html"):
                continue

            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            # Use the charset from the email header, fall back to utf-8
            charset = part.get_content_charset() or 'utf-8'
            try:
                decoded = payload.decode(charset)
            except (UnicodeDecodeError, LookupError):
                logger.warning(f"Failed to decode {content_type} with charset {charset}, trying utf-8")
                decoded = payload.decode('utf-8', errors='replace')

            if content_type == "text/plain":
                body_text = decoded
            elif content_type == "text/html":
                body_html = decoded

        return body_text, body_html

    def _extract_urls(self, text: str, html: Optional[str]) -> List[str]:
        # Extract all URLs from email body (both text and HTML)
        pattern = r'https?://[^\s<>"\')]+'
        urls = []
        if text:
            urls.extend(re.findall(pattern, text))
        if html:
            urls.extend(re.findall(pattern, html))
        return list(set(urls))  # Remove duplicates

    def _extract_attachments(self) -> List[Dict[str, str]]:
        # Extract attachment metadata (filename, content_type, size)
        # Don't save attachments - just collect info about them
        attachments = []
        for part in self.message.walk():
            if part.get_content_disposition() == 'attachment':
                payload = part.get_payload(decode=True)
                attachments.append({
                    'filename': part.get_filename() or "unknown",
                    'content_type': part.get_content_type(),
                    'size': len(payload) if payload else 0,
                })
        return attachments


if __name__ == "__main__":
    parser = EmailParser("tests/sample_emails/sample_phishing.eml")
    result = parser.parse()
    print(f"Subject: {result.subject}")
    print(f"From: {result.sender}")
    print(f"URLs found: {result.urls}")
    print(f"Attachments: {len(result.attachments)}")
