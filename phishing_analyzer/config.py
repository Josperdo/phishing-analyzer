# Configuration management for the phishing analyzer

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


class Config:
    #Application configuration

    # VirusTotal API
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

    # Thresholds
    MIN_SUSPICIOUS_SCORE = 3

    @staticmethod
    def is_virustotal_enabled():
        # Check if VirusTotal API is configured
        return bool(Config.VIRUSTOTAL_API_KEY)


# Suspicious patterns to detect
SUSPICIOUS_INDICATORS = {
    "urgent_words": [
        "urgent",
        "immediate action",
        "verify your account",
        "suspended",
        "unusual activity",
        "confirm your identity",
        "limited time",
        "act now",
        "click here immediately",
    ],
    "suspicious_domain_keywords": [
    "verify", "secure", "login", "account", "update",
    "confirm", "suspend", "alert", "bank", "paypal",
    ],
    "suspicious_senders": [
        "paypal-secure",
        "amazon-verify",
        "bank-alert",
    ],
    "suspicious_tlds": [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".xyz",
        ".top",
    ],
}
