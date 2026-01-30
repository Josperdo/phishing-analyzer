"""
Email parser module for extracting data from .eml files.
"""

import email
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class EmailData:
    """
    Data structure to hold parsed email information.

    Using a dataclass makes it easy to access email components
    and pass them between functions.
    """

    subject: str
    sender: str
    recipient: str
    date: str
    body_text: str
    body_html: Optional[str]
    headers: Dict[str, str]
    urls: List[str]
    attachments: List[Dict[str, str]]

    # TODO: Consider adding these fields as you enhance the parser:
    # - reply_to (often different from sender in phishing)
    # - received_headers (shows the email's path)
    # - authentication_results (SPF, DKIM, DMARC)


class EmailParser:
    """Parses .eml files and extracts relevant information."""

    def __init__(self, eml_path: str):
        """
        Initialize the parser with a path to an .eml file.

        Args:
            eml_path: Path to the .eml file
        """
        self.eml_path = Path(eml_path)
        self.message = None

    def parse(self) -> EmailData:
        """
        Parse the email file and extract all relevant data.

        Returns:
            EmailData object containing parsed information

        TODO: Implement this method
        HINTS:
        1. Read the .eml file in binary mode ('rb')
        2. Use BytesParser with policy.default to parse it
        3. Call the helper methods below to extract each component
        4. Return an EmailData object with all the information

        CHECKPOINT: After implementing, ask yourself:
        - What happens if the file doesn't exist?
        - What if it's not a valid .eml file?
        - Should you add error handling?
        """
        raise NotImplementedError("TODO: Implement parse() method")

    def _extract_headers(self) -> Dict[str, str]:
        """
        Extract important email headers.

        Returns:
            Dictionary of header name -> value

        TODO: Implement this method
        HINTS:
        - Use self.message.items() to get all headers
        - Focus on: From, To, Subject, Date, Return-Path, Received
        - Consider storing Reply-To if present (common in phishing!)

        LEARNING: Why are 'Received' headers important for phishing analysis?
        """
        raise NotImplementedError("TODO: Implement _extract_headers() method")

    def _extract_body(self) -> tuple[str, Optional[str]]:
        """
        Extract both plain text and HTML body content.

        Returns:
            Tuple of (text_body, html_body)

        TODO: Implement this method
        HINTS:
        - Emails can be multipart (multiple parts: text, html, attachments)
        - Use message.walk() to iterate through parts
        - Check part.get_content_type() for 'text/plain' and 'text/html'
        - Use part.get_payload(decode=True) to get the content
        - Handle encoding (usually utf-8, but might be others)

        CHALLENGE: What if the email has multiple text/plain parts?
        """
        raise NotImplementedError("TODO: Implement _extract_body() method")

    def _extract_urls(self, text: str, html: Optional[str]) -> List[str]:
        """
        Extract all URLs from email body.

        Args:
            text: Plain text body
            html: HTML body (if present)

        Returns:
            List of unique URLs found

        TODO: Implement this method
        HINTS:
        - Use regex to find URLs: r'https?://[^\s<>"{}|\\^`\[\]]+'
        - Extract from both text and HTML bodies
        - For HTML, you might also parse <a href="..."> tags
        - Remove duplicates (use a set, then convert to list)

        LEARNING OPPORTUNITY:
        - What's the difference between display text and actual link in HTML?
        - How do phishers hide malicious URLs? (e.g., google.com@evil.com)
        """
        raise NotImplementedError("TODO: Implement _extract_urls() method")

    def _extract_attachments(self) -> List[Dict[str, str]]:
        """
        Extract attachment information (without saving files yet).

        Returns:
            List of dicts with keys: filename, content_type, size

        TODO: Implement this method
        HINTS:
        - Iterate through message parts with message.walk()
        - Check if part.get_content_disposition() == 'attachment'
        - Get filename: part.get_filename()
        - Get content type: part.get_content_type()
        - Get size: len(part.get_payload(decode=True))

        SECURITY NOTE: Don't automatically save attachments - they could be malicious!
        For now, just collect metadata.

        CHALLENGE: Some malicious emails hide executables as other file types.
        How would you detect a .exe renamed to .pdf?
        """
        raise NotImplementedError("TODO: Implement _extract_attachments() method")


# TESTING YOUR CODE:
# Once you implement the methods above, test with:
#
# if __name__ == "__main__":
#     parser = EmailParser("tests/sample_emails/test_email.eml")
#     data = parser.parse()
#     print(f"Subject: {data.subject}")
#     print(f"From: {data.sender}")
#     print(f"URLs found: {data.urls}")
#     print(f"Attachments: {len(data.attachments)}")
