# IOC Threat Scanner

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Hardened-brightgreen.svg)](#security-features)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#installation)

A professional-grade **Indicator of Compromise (IOC) Threat Intelligence Platform** built with Python and PyQt6. This tool enables security analysts to quickly investigate suspicious IPs, domains, and file hashes across multiple threat intelligence sources.

![IOC Scanner](https://img.shields.io/badge/Status-Production%20Ready-success)

## Author

**Adi Cohen**
- GitHub: [@AdiZzZ0052](https://github.com/AdiZzZ0052)
- LinkedIn: [Adi Cohen](https://www.linkedin.com/in/adi-cohen-ac/)

---

## Features

### Core Scanning Capabilities
- **Single IOC Scanner** - Investigate individual IPs, domains, or file hashes
- **Bulk Scanner** - Process multiple IOCs simultaneously with progress tracking
- **Email Analysis** - Parse email headers and detect phishing attempts
- **Analyst Helper Tools** - Essential utilities for SOC analysts

### Integrated Threat Intelligence Sources
| Source | Type | Description |
|--------|------|-------------|
| VirusTotal | API | Multi-AV scan results and detection details |
| AbuseIPDB | API | IP reputation and abuse reports |
| AlienVault OTX | API | Threat pulses and community intelligence |
| Hybrid Analysis | API | Sandbox analysis results |
| URLScan.io | API | Website scanning and screenshots |
| ThreatYeti | Link | Additional threat context |
| WHOIS | Lookup | Domain registration details |
| GeoIP | Lookup | IP geolocation and ISP info |

### AI-Powered Analysis
- Integrated **Bytez AI** (Mistral-7B) for intelligent threat summarization
- Automated phishing email analysis with verdict scoring
- Context-aware threat assessment

### Security Features
- **Password Protection** - SHA-256 hashed application password
- **Brute-Force Protection** - Account lockout after 10 failed attempts (30-min cooldown)
- **Input Sanitization** - Protection against injection attacks
- **XSS Prevention** - HTML output escaping
- **Secure Configuration** - Protected API key storage with restricted file permissions

---

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/AdiZzZ0052/IOC-Threat-Scanner.git
cd IOC-Threat-Scanner
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the application**
```bash
python ioc_scanner.py
```

### First-Time Setup
On first launch, you'll be prompted to create a master password to protect your API keys and configuration.

> **Important:** Remember this password! There is no recovery option.

---

## Configuration

### API Keys Setup

1. Launch the application and authenticate
2. Click **Settings** (gear icon)
3. Enter your API keys for the services you want to use:

| Service | Get API Key |
|---------|-------------|
| VirusTotal | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |
| AlienVault OTX | [otx.alienvault.com/api](https://otx.alienvault.com/api) |
| Hybrid Analysis | [hybrid-analysis.com/apikeys](https://www.hybrid-analysis.com/apikeys/info) |
| URLScan.io | [urlscan.io/user/profile](https://urlscan.io/user/profile) |
| Bytez AI | [bytez.com](https://bytez.com) |

### Configuration File Location
- **Windows:** `C:\Users\<username>\ioc_scanner_config.json`
- **Linux/macOS:** `~/ioc_scanner_config.json`

---

## Usage

### Single IOC Scan
1. Navigate to the **Single Scanner** tab
2. Enter an IOC (IP address, domain, or file hash)
3. Click **Scan** or press Enter
4. View results with clickable links to detailed reports

### Bulk Scanning
1. Navigate to the **Bulk Scanner** tab
2. Enter multiple IOCs (one per line or comma-separated)
3. Click **Run Batch**
4. Monitor progress and view consolidated results

### Email Analysis
1. Navigate to the **Email Analysis** tab
2. Paste the raw email content (including headers)
3. Click **Analyze Headers** for technical analysis
4. Click **AI Phish Check** for AI-powered phishing detection

### Analyst Helper Tools
- **Defang/Refang** - Convert URLs for safe sharing
- **Base64 Encode/Decode** - Handle encoded content
- **URL Decode** - Decode URL-encoded strings
- **Extract IPs** - Pull all IP addresses from text
- **Port Lookup** - Identify common port services

---

## Supported IOC Types

| Type | Example | Detection |
|------|---------|-----------|
| IPv4 | `192.168.1.1` | Automatic |
| IPv6 | `2001:0db8::1` | Automatic |
| Domain | `example.com` | Automatic |
| MD5 Hash | `d41d8cd98f00b204e9800998ecf8427e` | 32 chars |
| SHA1 Hash | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | 40 chars |
| SHA256 Hash | `e3b0c44298fc1c149afbf4c8996fb924...` | 64 chars |

---

## Screenshots
<img width="1196" height="853" alt="image" src="https://github.com/user-attachments/assets/9bc601bc-6931-49c5-9ddb-90f89b88c377" />

<img width="1191" height="856" alt="image" src="https://github.com/user-attachments/assets/0f6f736b-956f-4d25-bd9d-796469ca97e1" />



### Main Scanner Interface
```
┌─────────────────────────────────────────────────────────┐
│  Threat Intelligence Platform                    [⚙️]   │
├─────────────────────────────────────────────────────────┤
│  [Single Scanner] [Bulk Scanner] [Helper] [Email]       │
├─────────────────────────────────────────────────────────┤
│  Enter IOC: [________________________] [🔍 Scan]        │
├─────────────────────────────────────────────────────────┤
│  Results:                                               │
│  VirusTotal: 5/72 detections | [Scan link]             │
│  AbuseIPDB: 87/100 confidence | [Scan link]            │
│  OTX: Found in 3 pulses | [Scan link]                  │
│                                                         │
│  AI Analysis: This IP is associated with a known       │
│  botnet command and control server...                   │
└─────────────────────────────────────────────────────────┘
```

---

## Security Considerations

### For Users
- Never share your configuration file (contains API keys)
- Use a strong, unique password for the application
- Keep API keys confidential and rotate them periodically
- Review scan results before acting on them

### For Developers
- Input sanitization prevents command/SQL injection
- HTML escaping prevents XSS attacks
- API requests use HTTPS with certificate verification
- Sensitive data is never logged or displayed in plain text

---

## Troubleshooting

### Common Issues

**"API Key Missing" errors**
- Open Settings and verify your API keys are entered correctly
- Some services require account verification before API access

**"Account Locked" message**
- Wait 30 minutes for the lockout to expire
- Contact the repository maintainer if you've forgotten your password

**Dependencies not installing**
```bash
# Try upgrading pip first
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**PyQt6 issues on Linux**
```bash
# Install system dependencies
sudo apt-get install python3-pyqt6 libxcb-xinerama0
```

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
git clone https://github.com/AdiZzZ0052/IOC-Threat-Scanner.git
cd IOC-Threat-Scanner
pip install -r requirements-dev.txt
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [VirusTotal](https://www.virustotal.com) for their comprehensive malware database
- [AbuseIPDB](https://www.abuseipdb.com) for IP reputation data
- [AlienVault OTX](https://otx.alienvault.com) for open threat exchange
- [Bytez](https://bytez.com) for AI model hosting

---

## Disclaimer

This tool is intended for legitimate security research and defensive purposes only. Users are responsible for ensuring their use complies with applicable laws and terms of service of integrated APIs. The author assumes no liability for misuse of this software.

---

<p align="center">
  Made with ❤️ for the cybersecurity community
  <br>
  <a href="https://github.com/AdiZzZ0052">@AdiZzZ0052</a>
</p>
