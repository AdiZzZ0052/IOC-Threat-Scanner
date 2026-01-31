# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2025-01-31

### Added
- Input sanitization for all IOC inputs
- HTML escaping for XSS prevention
- URL encoding for API request parameters
- Enhanced error messages without sensitive data exposure

### Security
- Implemented `sanitize_ioc()` function to validate all inputs
- Added `escape_html()` function to prevent XSS attacks
- All API requests now use HTTPS with certificate verification
- Improved input length validation (max 256 characters)
- Dangerous character filtering for injection prevention

### Changed
- Improved error handling to avoid exposing internal details
- Enhanced configuration file security with restricted permissions

## [1.0.0] - 2025-01-01

### Added
- Initial release of IOC Threat Scanner
- Single IOC scanning capability
- Bulk scanning with progress tracking
- Email header analysis
- AI-powered phishing detection (Bytez integration)
- Analyst helper tools:
  - Defang/Refang URLs
  - Base64 encode/decode
  - URL decode
  - IP extraction
  - Port lookup
- Password protection with SHA-256 hashing
- Brute-force protection (10 attempts, 30-min lockout)
- Scan history tracking
- Copy output functionality
- Font size adjustment

### Integrations
- VirusTotal API
- AbuseIPDB API
- AlienVault OTX API
- Hybrid Analysis API
- URLScan.io API
- ThreatYeti (link-based)
- WHOIS lookup
- GeoIP lookup (ip-api.com)
- Bytez AI (Mistral-7B)

### Security
- Password-protected application access
- Secure API key storage
- Configuration file with restricted permissions
- Account lockout mechanism

---

## Versioning

This project uses [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for new functionality in a backward-compatible manner
- **PATCH** version for backward-compatible bug fixes

## Unreleased

### Planned Features
- [ ] Export scan results to PDF/CSV
- [ ] Multiple user profiles
- [ ] Custom threat intelligence feeds
- [ ] Automated scheduled scans
- [ ] Integration with SIEM platforms
