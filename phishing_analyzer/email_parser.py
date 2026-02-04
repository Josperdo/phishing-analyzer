# Email parsing module for extracting components from .eml files

import email
from email import policy
from email.parser import BytesParser
import re
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass


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

    def parse(self) -> EmailData:
        # Parse the email file and extract all relevant data
        with open(self.eml_path, 'rb') as f:
            self.message = BytesParser(policy=policy.default).parse(f)

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
        # Extract important email headers
        return {
            'subject': self.message['Subject'],
            'from': self.message['From'],
            'to': self.message['To'],
            'date': self.message['Date'],
        }
        

    def _extract_body(self) -> tuple[str, Optional[str]]:
        # Extract plain text and HTML body content
        body_text = None
        body_html = None
        
        for part in self.message.walk():
            content_type = part.get_content_type()
            
            if content_type == "text/plain":
                body_text = part.get_payload(decode=True).decode('utf-8')
            elif content_type == "text/html":
                body_html = part.get_payload(decode=True).decode('utf-8')
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
        attachments = []
        # Extract attachment metadata (filename, content_type, size)
        # Don't save attachments - just collect info about them
        for part in self.message.walk():
            if part.get_content_disposition() == 'attachment':
                attachments.append({
                'filename': part.get_filename(),
                'content_type': part.get_content_type(),
                'size': len(part.get_payload(decode=True)),
            })
        return attachments


if __name__ == "__main__":
    parser = EmailParser("tests/sample_emails/sample_phishing.eml")
    result = parser.parse()
    print(f"Subject: {result.subject}")
    print(f"From: {result.sender}")
    print(f"URLs found: {result.urls}")
    print(f"Attachments: {len(result.attachments)}")
