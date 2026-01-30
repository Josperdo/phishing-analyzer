"""
Configuration management for the phishing analyzer.
Handles API keys, settings, and constants.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Application configuration."""

    # VirusTotal API Configuration
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

    # Suspicious pattern thresholds
    MIN_SUSPICIOUS_SCORE = 3  # Score needed to flag an email

    # TODO: Add more configuration as needed
    # Examples: timeout values, max attachment size, output formats, etc.

    @staticmethod
    def is_virustotal_enabled():
        """Check if VirusTotal API is configured."""
        return bool(Config.VIRUSTOTAL_API_KEY)


# Suspicious patterns to detect (before API calls)
SUSPICIOUS_INDICATORS = {
    "urgent_words": [
        "urgent", "immediate action", "verify your account",
        "suspended", "unusual activity", "confirm your identity",
        "limited time", "act now", "click here immediately"
    ],
    "suspicious_senders": [
        # Common spoofed domains - add more as you learn about phishing patterns
        "paypal-secure", "amazon-verify", "bank-alert"
    ],
    "suspicious_tlds": [
        ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs often used in phishing
        ".xyz", ".top"
    ],
    # TODO: Add more indicator categories:
    # - Mismatched display names vs email addresses
    # - Known malicious attachment types
    # - Suspicious URL patterns (IP addresses, misspellings, etc.)
}
