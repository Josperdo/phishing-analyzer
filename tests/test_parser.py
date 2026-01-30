"""
Test suite for email parser.

TODO: Write tests as you implement features!

TESTING APPROACH:
1. Start with simple tests for individual methods
2. Add edge cases (empty emails, malformed data, etc.)
3. Test with real phishing examples (safely!)

PRO TIP: Write tests BEFORE implementing features (TDD)
This helps you think through the API design.
"""

import pytest
from pathlib import Path
from phishing_analyzer.email_parser import EmailParser, EmailData


class TestEmailParser:
    """Test suite for EmailParser class."""

    def test_parse_simple_email(self):
        """
        Test parsing a basic email.

        TODO: Implement this test
        STEPS:
        1. Create a simple .eml test file (or use fixture)
        2. Parse it
        3. Assert expected values (subject, sender, etc.)
        """
        pytest.skip("TODO: Implement test_parse_simple_email")

    def test_extract_urls_from_text(self):
        """
        Test URL extraction from plain text.

        TODO: Implement this test
        TEST CASES:
        - Single URL
        - Multiple URLs
        - No URLs
        - URLs with query parameters
        """
        pytest.skip("TODO: Implement test_extract_urls_from_text")

    def test_extract_urls_from_html(self):
        """Test URL extraction from HTML body."""
        pytest.skip("TODO: Implement test_extract_urls_from_html")

    def test_parse_multipart_email(self):
        """Test parsing email with attachments."""
        pytest.skip("TODO: Implement test_parse_multipart_email")

    def test_invalid_email_file(self):
        """Test handling of invalid .eml files."""
        pytest.skip("TODO: Implement test_invalid_email_file")


# TODO: Add more test classes:
# - TestURLAnalyzer
# - TestReportGenerator
# - Integration tests that tie everything together

# RUNNING TESTS:
# pytest tests/
# pytest tests/ -v              # Verbose output
# pytest tests/ --cov           # With coverage report
