# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Features

IOC Threat Scanner implements multiple security measures to protect users:

### Authentication & Access Control
- **Password Protection**: Application access requires password authentication
- **SHA-256 Hashing**: Passwords are stored as secure hashes, never in plaintext
- **Brute-Force Protection**: Account lockout after 10 failed attempts (30-minute cooldown)
- **No Password Recovery**: By design, to prevent unauthorized access

### Input Validation & Sanitization
- **IOC Sanitization**: All user inputs are validated and sanitized
- **Length Limits**: Input length restrictions prevent buffer-based attacks
- **Character Filtering**: Dangerous characters are stripped to prevent injection
- **Type Validation**: IOC types are verified before processing

### Output Security
- **HTML Escaping**: All output is HTML-escaped to prevent XSS attacks
- **URL Encoding**: IOCs are URL-encoded before API requests
- **Safe Link Handling**: External links are opened securely via system browser

### API Security
- **HTTPS Only**: All API communications use TLS encryption
- **Certificate Verification**: SSL certificates are verified on all requests
- **Secure Storage**: API keys are stored in a protected configuration file
- **File Permissions**: Config file is created with restricted permissions (0600 on Unix)

### Network Security
- **Request Timeouts**: All API requests have timeout limits
- **Rate Limiting Awareness**: Built-in handling for API rate limits
- **No Credential Logging**: Sensitive data is never logged or displayed

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**DO NOT** report security vulnerabilities through public GitHub issues.

Instead, please:

1. **GitHub Security Advisory** (Preferred)
   - Go to the repository's Security tab
   - Click "Report a vulnerability"
   - Fill out the security advisory form

2. **Email** (Alternative)
   - Contact the maintainer directly via LinkedIn
   - LinkedIn: [Adi Cohen](https://www.linkedin.com/in/adi-cohen-ac/)

### What to Include

Please include as much of the following information as possible:

- Type of vulnerability (e.g., XSS, injection, authentication bypass)
- Full paths of affected source files
- Step-by-step instructions to reproduce
- Proof-of-concept or exploit code (if possible)
- Impact assessment and potential attack scenarios

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Disclosure Policy

- We follow responsible disclosure practices
- We will credit researchers who report valid vulnerabilities
- Please allow us reasonable time to fix issues before public disclosure
- We will not pursue legal action against researchers who follow this policy

## Security Best Practices for Users

### Protecting Your Installation

1. **Strong Password**
   - Use a unique, strong password (12+ characters)
   - Include uppercase, lowercase, numbers, and symbols
   - Never reuse passwords from other services

2. **API Key Security**
   - Obtain your own API keys from official sources
   - Never share your API keys
   - Rotate keys periodically
   - Use keys with minimal required permissions

3. **Configuration File**
   - Location: `~/ioc_scanner_config.json`
   - Never share this file (contains API keys)
   - Back up securely (encrypted storage)
   - On Unix systems, verify permissions: `chmod 600 ~/ioc_scanner_config.json`

4. **Network Security**
   - Use on trusted networks
   - Consider VPN for sensitive investigations
   - Be aware that IOC lookups may be logged by API providers

### Operational Security (OPSEC)

When using this tool for investigations:

- **Data Sensitivity**: Don't analyze internal/sensitive IOCs on public APIs
- **Attribution Concerns**: API providers may log your queries
- **AI Analysis**: Don't submit PII or classified data to AI features
- **Export Handling**: Treat scan reports as sensitive documents

## Known Limitations

### By Design
- No password recovery mechanism (security feature)
- Configuration stored in user home directory
- API keys stored locally (not in cloud)

### Current Limitations
- Single-user application (no multi-user support)
- Local authentication only (no SSO/OAuth)
- No audit logging of user actions

## Security Hardening Checklist

For users in high-security environments:

- [ ] Use dedicated analysis machine
- [ ] Enable full-disk encryption
- [ ] Use application in air-gapped environment if needed
- [ ] Implement network monitoring
- [ ] Regularly rotate API keys
- [ ] Review configuration file permissions
- [ ] Keep Python and dependencies updated
- [ ] Use latest version of IOC Threat Scanner

## Changelog

### Security Updates

| Version | Date | Description |
|---------|------|-------------|
| 1.0.1 | 2025 | Added XSS prevention, input sanitization |
| 1.0.0 | 2025 | Initial release with password protection |

---

Thank you for helping keep IOC Threat Scanner secure!

— **Adi Cohen** ([@AdiZzZ0052](https://github.com/AdiZzZ0052))
