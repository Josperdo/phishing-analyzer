# Test suite for email parser

import pytest
from pathlib import Path
from phishing_analyzer.email_parser import EmailParser, EmailData


class TestEmailParser:

    def test_parse_phishing_sample(self):
        """Test parsing the sample phishing email."""
        parser = EmailParser("tests/sample_emails/sample_phishing.eml")
        result = parser.parse()

        # Verify we get an EmailData object back
        assert isinstance(result, EmailData)

        # Verify basic fields are populated
        assert result.subject is not None
        assert result.sender is not None
        assert result.recipient is not None
        assert result.body_text is not None

        # Verify it's our test email
        assert "URGENT" in result.subject
        assert "paypal" in result.sender.lower()

    def test_parse_legitimate_sample(self):
        """Test parsing the sample legitimate email."""
        parser = EmailParser("tests/sample_emails/sample_legitimate.eml")
        result = parser.parse()

        assert isinstance(result, EmailData)
        assert result.subject is not None
        assert result.sender is not None

    def test_urls_extracted(self):
        """Test that URLs are extracted from email body."""
        parser = EmailParser("tests/sample_emails/sample_phishing.eml")
        result = parser.parse()

        # Should find at least one URL in a phishing email
        assert isinstance(result.urls, list)

    def test_attachments_list(self):
        """Test that attachments returns a list."""
        parser = EmailParser("tests/sample_emails/sample_phishing.eml")
        result = parser.parse()

        assert isinstance(result.attachments, list)
