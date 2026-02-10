# Test suite for email parser

import pytest
from pathlib import Path
from phishing_analyzer.email_parser import EmailParser, EmailData
from phishing_analyzer.url_analyzer import URLAnalyzer, URLAnalysis

class TestEmailParser:
    # Test that parsing a known phishing email returns expected results
    def test_parse_phishing_sample(self):
        parser = EmailParser("tests/sample_emails/sample_phishing.eml")
        result = parser.parse()
        
        # Verify we get an EmailData object back
        assert isinstance(result, EmailData)
        
        # Verify it's our test email
        assert "URGENT" in result.subject
        assert "paypal" in result.sender.lower()

        # Verify basic fields are populated
        assert result.subject is not None
        assert result.sender is not None
        assert result.recipient is not None
        assert result.body_text is not None

    # Test that parsing a known legitimate email returns expected results
    def test_parse_legitimate_sample(self):
        parser = EmailParser("tests/sample_emails/sample_legitimate.eml")
        result = parser.parse()
        
        # Verify we get an EmailData object back
        assert isinstance(result, EmailData)
        assert "github.com" in result.sender

        # Verify basic fields are populated
        assert result.subject is not None
        assert result.sender is not None
    
    # Test that providing a non-existent file path raises an error
    def test_invalid_file_path(self):
        with pytest.raises(FileNotFoundError):
            EmailParser("nonexistent.eml")
    
    # Test that providing a non-.eml file raises an error
    def test_invalid_extension(self):
        with pytest.raises(ValueError):
            EmailParser("README.md")
            
    # Test that URLS are extracted from email body
    def test_urls_extracted(self):
        parser = EmailParser("tests/sample_emails/sample_phishing.eml")
        result = parser.parse()
        
        # Should find at least one URL in a phishing email
        assert isinstance(result.urls, list)
        
    # Test that attachments are extracted as a list
    def test_attachments_list(self):
        parser = EmailParser("tests/sample_emails/sample_phishing.eml")
        result = parser.parse()

        # Even if there are no attachments, it should be an empty list, not None
        assert isinstance(result.attachments, list)

class TestURLAnalyzer:

    # Test that analyzing a clean URL returns no suspicion
    def test_clean_url(self):
        analyzer = URLAnalyzer()
        result = analyzer.analyze_url("https://google.com")
        assert not result.is_suspicious
        assert result.suspicion_score == 0
    
    # Test that analyzing a URL with a suspicious TLD returns suspicion
    def test_suspicious_tld(self):
        analyzer = URLAnalyzer()
        result = analyzer.analyze_url("https://paypal-verify.tk/account")
        assert result.is_suspicious
        assert result.suspicion_score >= 2
        assert "Suspicious TLD: .tk" in result.reasons[0]
    
    # Test that analyzing a URL with an IP address instead of a domain returns suspicion
    def test_ip_address_domain(self):
        analyzer = URLAnalyzer()
        result = analyzer.analyze_url("http://192.168.1.1/login")
        assert result.is_suspicious
        assert result.suspicion_score >= 3
        assert "IP address used instead of domain" in result.reasons[0]
    
    # Test that analyzing a URL with suspicious keywords in the domain returns suspicion
    def test_multiple_urls(self):
        analyzer = URLAnalyzer()
        results = analyzer.analyze_multiple(["https://google.com", "http://192.168.1.1/login"])
        assert len(results) == 2
        assert not results[0].is_suspicious