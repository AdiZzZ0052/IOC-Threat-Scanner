"""
IOC Threat Scanner - Professional Threat Intelligence Platform
Author: Adi Cohen
License: MIT
Version: 1.0.7
Repository: https://github.com/AdiZzZ0052/IOC-Threat-Scanner
"""

__version__ = "1.0.7"
__author__ = "Adi Cohen"
__license__ = "MIT"

import sys
import os
import multiprocessing

# ===================== CRITICAL: FREEZE SUPPORT FOR EXE =====================
# This MUST be at the very top, before any other code runs
# Prevents infinite process spawning when running as frozen EXE
if __name__ == "__main__":
    multiprocessing.freeze_support()

# Check if we're running as a frozen executable (PyInstaller)
IS_FROZEN = getattr(sys, 'frozen', False)

import subprocess
import json
import re
import base64
import urllib.parse
import ipaddress
import webbrowser
import email
from datetime import datetime, timedelta
import concurrent.futures
import hashlib
import html as html_lib  # For HTML escaping

# ===================== AUTO-INSTALLER =====================
# Only run auto-installer when NOT frozen (not running as EXE)
def install_dependencies():
    if IS_FROZEN:
        return

    requirements = ["PyQt6", "requests", "bytez"]
    for package in requirements:
        try:
            module_name = package.replace("-", "_")
            __import__(module_name)
        except ImportError:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            except: pass

install_dependencies()

try:
    from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                                QHBoxLayout, QLabel, QLineEdit, QTextEdit, QTextBrowser, QPushButton,
                                QTabWidget, QProgressBar, QFrame, QMessageBox, QFileDialog,
                                QScrollArea, QSizePolicy, QSplitter, QDialog, QFormLayout, QComboBox)
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer, QRectF, QMimeData
    from PyQt6.QtGui import (QColor, QFont, QIcon, QPalette, QBrush, QLinearGradient,
                             QTextCursor, QPainter, QPainterPath, QPen, QGuiApplication)
    import requests
except ImportError:
    sys.exit(1)

# === LOGIC IMPORTS ===
try:
    from bytez import Bytez
    BYTEZ_AVAILABLE = True
except ImportError:
    BYTEZ_AVAILABLE = False

# ===================== SECURITY FUNCTIONS =====================
def sanitize_ioc(ioc):
    """
    SECURITY: Validate and sanitize IOC input to prevent injection attacks
    Returns: Clean IOC or None if invalid
    """
    if not ioc:
        return None

    # Convert to string and strip whitespace
    ioc = str(ioc).strip()

    if not ioc:
        return None

    # Length validation (reasonable limit)
    if len(ioc) > 256:
        return None

    # Remove dangerous characters that could be used for injection
    dangerous_chars = [
        '\n', '\r', '\0',  # Newlines and null bytes
        '<', '>', '"', "'",  # HTML/XML special chars
        '\\', ';', '&', '|',  # Shell metacharacters
        '`', '$', '(', ')',  # Command substitution
        '{', '}', '[', ']'   # Additional risky chars
    ]

    for char in dangerous_chars:
        if char in ioc:
            return None

    return ioc

def escape_html(text):
    """
    SECURITY: Escape HTML to prevent XSS attacks
    Returns: HTML-safe string
    """
    if not text:
        return ""
    return html_lib.escape(str(text))

# ===================== CONFIGURATION =====================
CONFIG_FILE = os.path.join(os.path.expanduser("~"), "ioc_scanner_config.json")

DEFAULT_CONFIG = {
    "VT_API_KEY": "",
    "ABUSEIPDB_API_KEY": "",
    "URLSCAN_API_KEY": "",
    "HYBRID_API_KEY": "",
    "BYTEZ_API_KEY": "",
    "OTX_API_KEY": "",
    "APP_PASSWORD_HASH": "",
    "FAILED_ATTEMPTS": 0,
    "LOCKOUT_UNTIL": ""
}

CONFIG = DEFAULT_CONFIG.copy()

# ===================== PASSWORD FUNCTIONS =====================
def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    return hash_password(password) == stored_hash

def is_locked_out():
    """Check if account is currently locked out"""
    lockout_str = CONFIG.get("LOCKOUT_UNTIL", "")
    if not lockout_str:
        return False, 0

    try:
        lockout_time = datetime.fromisoformat(lockout_str)
        now = datetime.now()

        if now < lockout_time:
            remaining = (lockout_time - now).total_seconds()
            return True, int(remaining)
        else:
            CONFIG["FAILED_ATTEMPTS"] = 0
            CONFIG["LOCKOUT_UNTIL"] = ""
            save_config_file()
            return False, 0
    except:
        CONFIG["FAILED_ATTEMPTS"] = 0
        CONFIG["LOCKOUT_UNTIL"] = ""
        save_config_file()
        return False, 0

def record_failed_attempt():
    """Record a failed login attempt and apply lockout if needed"""
    CONFIG["FAILED_ATTEMPTS"] = CONFIG.get("FAILED_ATTEMPTS", 0) + 1

    if CONFIG["FAILED_ATTEMPTS"] >= 10:
        lockout_time = datetime.now() + timedelta(minutes=30)
        CONFIG["LOCKOUT_UNTIL"] = lockout_time.isoformat()
        CONFIG["FAILED_ATTEMPTS"] = 0

    save_config_file()
    return CONFIG.get("FAILED_ATTEMPTS", 0)

def reset_failed_attempts():
    """Reset failed attempts counter on successful login"""
    CONFIG["FAILED_ATTEMPTS"] = 0
    CONFIG["LOCKOUT_UNTIL"] = ""
    save_config_file()

# ===================== FILE OPERATIONS =====================
def load_config():
    """Load configuration with error handling"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                saved = json.load(f)
                for k, v in saved.items():
                    if k in CONFIG:
                        CONFIG[k] = v
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
            pass

def save_config_file():
    """Save configuration with improved error handling"""
    try:
        config_dir = os.path.dirname(CONFIG_FILE)
        if config_dir and not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)

        with open(CONFIG_FILE, 'w') as f:
            json.dump(CONFIG, f, indent=4)

        try:
            if os.name != 'nt':
                os.chmod(CONFIG_FILE, 0o600)
        except:
            pass

        return True

    except PermissionError as e:
        print(f"Permission Error: {e}")
        print(f"Config file location: {CONFIG_FILE}")
        return False

    except Exception as e:
        print(f"Error saving config: {e}")
        print(f"Config file location: {CONFIG_FILE}")
        return False

load_config()

# ===================== DATA DICTIONARIES =====================
PORT_DATA = {
    "20": "FTP Data", "21": "FTP Control", "22": "SSH", "23": "Telnet", "25": "SMTP",
    "53": "DNS", "80": "HTTP", "443": "HTTPS", "445": "SMB", "3389": "RDP",
    "8080": "HTTP Proxy", "8443": "HTTPS Alt"
}

ABUSEIPDB_CATEGORIES = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing",
    8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted"
}

# ===================== AI ENGINE =====================
class LocalAIAnalyst:
    def __init__(self):
        self.client = None
        self.reload()

    def reload(self):
        if CONFIG.get("BYTEZ_API_KEY") and BYTEZ_AVAILABLE:
            try:
                self.client = Bytez(CONFIG.get("BYTEZ_API_KEY"))
            except:
                self.client = None

    def summarize(self, text, ioc):
        if not self.client:
            return "AI Config Missing."

        # SECURITY: Sanitize IOC to prevent prompt injection
        safe_ioc = sanitize_ioc(ioc)
        if not safe_ioc:
            return "Invalid IOC format"

        # SECURITY: Limit text size
        safe_text = str(text)[:3000]

        try:
            model = self.client.model("mistralai/Mistral-7B-Instruct-v0.3")
            prompt = f"""[INST] Analyze this IOC: {safe_ioc}
Context: {safe_text}
Task: Write ONE professional sentence describing what this IP/Domain IS and its Function.
Do NOT use flowery language. Be direct.
[/INST]"""
            resp = model.run(prompt, params={"max_new_tokens": 80})
            out = str(resp)
            if hasattr(resp, 'output') and resp.output:
                out = resp.output
            if "Rate limited" in out:
                return "AI Busy."
            if "[/INST]" in out:
                out = out.split('[/INST]')[-1]
            return f"AI Analysis: {out.strip()}"
        except Exception as e:
            return "AI Error occurred"

    def phish(self, text):
        if not self.client:
            return "AI Config Missing."

        # SECURITY: Limit input size
        safe_text = str(text)[:2000]

        try:
            model = self.client.model("mistralai/Mistral-7B-Instruct-v0.3")
            resp = model.run(f"[INST] Phishing Analysis. Verdict & Score.\n{safe_text}\n[/INST]", params={"max_new_tokens": 300})
            out = str(resp)
            if hasattr(resp, 'output') and resp.output:
                out = resp.output
            return out.split('[/INST]')[-1].strip()
        except Exception as e:
            return "AI Error occurred"

# ===================== UTILS =====================
def detect_type(ioc):
    if not ioc: return "unknown"
    ioc = ioc.strip()
    try:
        ip = ipaddress.ip_address(ioc)
        return 'ipv4' if ip.version == 4 else 'ipv6'
    except ValueError:
        pass
    if len(ioc) in [32, 40, 64] and not "." in ioc: return "hash"
    if "." in ioc: return "domain"
    return "unknown"

# ===================== API QUERIES (SECURED) =====================
def q_vt(ioc):
    if not CONFIG["VT_API_KEY"]:
        return "VirusTotal: Key Missing", "", {}

    # SECURITY: Sanitize input
    safe_ioc = sanitize_ioc(ioc)
    if not safe_ioc:
        return "VirusTotal: Invalid IOC format", "", {}

    # SECURITY: URL encode to prevent injection
    encoded_ioc = urllib.parse.quote(safe_ioc)
    link = f"https://www.virustotal.com/gui/search/{encoded_ioc}"

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/search?query={encoded_ioc}",
            headers={"x-apikey": CONFIG["VT_API_KEY"]},
            timeout=5,
            verify=True
        )
        if r.status_code == 200:
            d = r.json().get('data', [{}])[0].get('attributes', {})
            stats = d.get('last_analysis_stats', {})
            score = f"{stats.get('malicious', 0)}/{sum(stats.values())}"
            dets = {}
            for k,v in d.get('last_analysis_results', {}).items():
                if v['category'] == 'malicious':
                    # SECURITY: Escape HTML output
                    dets[escape_html(k)] = escape_html(v['result'])

            return f'VirusTotal: Scan Score {escape_html(score)} | <a href="{link}" style="color:#667eea; text-decoration:none;">Scan link</a>', f"VirusTotal Score: {score}", {'detections': dets}
    except:
        pass

    return f'VirusTotal: N/A | <a href="{link}" style="color:#667eea; text-decoration:none;">Scan link</a>', "VirusTotal: N/A", {}

def q_abuse(ioc):
    if not CONFIG["ABUSEIPDB_API_KEY"]:
        return "AbuseIPDB: Key Missing", "", {}

    # SECURITY: Sanitize input
    safe_ioc = sanitize_ioc(ioc)
    if not safe_ioc:
        return "AbuseIPDB: Invalid IP format", "", {}

    # Additional validation: Must be valid IP
    try:
        ipaddress.ip_address(safe_ioc)
    except:
        return "AbuseIPDB: Invalid IP address", "", {}

    encoded_ioc = urllib.parse.quote(safe_ioc)
    link = f"https://www.abuseipdb.com/check/{encoded_ioc}"

    try:
        r = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={encoded_ioc}&maxAgeInDays=90&verbose=",
            headers={'Key': CONFIG["ABUSEIPDB_API_KEY"]},
            timeout=5,
            verify=True
        )
        if r.status_code == 200:
            d = r.json()['data']
            cats = set()
            for rep in d.get('reports', []):
                for c in rep.get('categories', []):
                    if c in ABUSEIPDB_CATEGORIES:
                        cats.add(ABUSEIPDB_CATEGORIES[c])

            details = {
                'score': d['abuseConfidenceScore'],
                'reports': d['totalReports'],
                'last': escape_html(str(d['lastReportedAt'])),
                'cats': [escape_html(c) for c in list(cats)[:5]]
            }

            score = escape_html(str(d["abuseConfidenceScore"]))
            return f'AbuseIPDB: Scan Score {score}/100 | <a href="{link}" style="color:#667eea; text-decoration:none;">Scan link</a>', f"AbuseIPDB Score: {d['abuseConfidenceScore']}", details
    except:
        pass

    return f'AbuseIPDB: N/A | <a href="{link}" style="color:#667eea; text-decoration:none;">Scan link</a>', "AbuseIPDB: N/A", {}

def q_otx(ioc):
    if not CONFIG["OTX_API_KEY"]:
        return "OTX: Key Missing", "", {}

    # SECURITY: Sanitize input
    safe_ioc = sanitize_ioc(ioc)
    if not safe_ioc:
        return "OTX: Invalid IOC format", "", {}

    t = detect_type(safe_ioc)
    if t == "ipv4":
        ep = f"IPv4/{safe_ioc}/general"; url_type = "ip"
    elif t == "ipv6":
        ep = f"IPv6/{safe_ioc}/general"; url_type = "ip"
    elif t == "hash":
        ep = f"file/{safe_ioc}/general"; url_type = "file"
    else:
        ep = f"domain/{safe_ioc}/general"; url_type = "domain"

    encoded_ioc = urllib.parse.quote(safe_ioc)
    link = f"https://otx.alienvault.com/indicator/{url_type}/{encoded_ioc}"

    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{ep}",
            headers={'X-OTX-API-KEY': CONFIG["OTX_API_KEY"]},
            timeout=5,
            verify=True
        )
        if r.status_code == 200:
            d = r.json()
            pulses = d.get('pulse_info', {}).get('pulses', [])
            count = d.get('pulse_info', {}).get('count', 0)
            txt = "Found in 0 pulses" if count == 0 else f"Found in {count} pulses"
            return f'AlienVault OTX: {escape_html(txt)} | <a href="{link}" style="color:#667eea; text-decoration:none;">Scan link</a>', f"OTX: {count} pulses", {'pulses': pulses}
    except:
        pass

    return f'AlienVault OTX: N/A | <a href="{link}" style="color:#667eea; text-decoration:none;">Scan link</a>', "OTX: N/A", {}

def q_yeti(ioc):
    safe_ioc = sanitize_ioc(ioc)
    if not safe_ioc:
        return "ThreatYeti: Invalid IOC", "", {}
    encoded_ioc = urllib.parse.quote(safe_ioc)
    link = f"https://threatyeti.com/search?q={encoded_ioc}"
    return f'ThreatYeti: <a href="{link}" style="color:#667eea; text-decoration:none;">Scan link</a>', "", {}

def q_hybrid(ioc):
    if not CONFIG.get("HYBRID_API_KEY"):
        return "", "", {}

    safe_ioc = sanitize_ioc(ioc)
    if not safe_ioc:
        return "", "", {}

    headers = {'User-Agent': 'Falcon Sandbox', 'api-key': CONFIG["HYBRID_API_KEY"]}
    encoded_ioc = urllib.parse.quote(safe_ioc)
    link = f"https://www.hybrid-analysis.com/search?query={encoded_ioc}"

    try:
        r = requests.get(
            f"https://www.hybrid-analysis.com/api/v2/quick-scan/{safe_ioc}",
            headers=headers,
            timeout=8,
            verify=True
        )
        if r.status_code == 200:
            d = r.json()
            if d.get('finished'):
                link = f"https://www.hybrid-analysis.com/sample/{encoded_ioc}"
                score = escape_html(str(d.get('threat_score')))
                return f'Hybrid Analysis: Threat Score {score}/100 | <a href="{link}" style="color:#667eea; text-decoration:none;">Scan link</a>', f"Hybrid Score: {d.get('threat_score')}", {}
    except:
        pass

    return f'Hybrid Analysis: N/A | <a href="{link}" style="color:#667eea; text-decoration:none;">Scan link</a>', "", {}

def q_urlscan(ioc):
    if not CONFIG.get("URLSCAN_API_KEY"):
        return "", "", {}

    safe_ioc = sanitize_ioc(ioc)
    if not safe_ioc:
        return "", "", {}

    encoded_ioc = urllib.parse.quote(safe_ioc)
    link = f"https://urlscan.io/search#{encoded_ioc}"
    return f'URLScan.io: <a href="{link}" style="color:#667eea; text-decoration:none;">Scan link</a>', "", {}

def q_whois(ioc):
    safe_ioc = sanitize_ioc(ioc)
    if not safe_ioc:
        return "", "", {}

    encoded_ioc = urllib.parse.quote(safe_ioc)
    link = f"https://who.is/whois/{encoded_ioc}"
    return f'WHOIS Record: <a href="{link}" style="color:#667eea; text-decoration:none;">Scan link</a>', "", {}

def q_geo(ioc):
    """
    SECURITY FIX: Uses passive DNS for domains to avoid direct connections
    Output format is identical to previous version
    """
    safe_ioc = sanitize_ioc(ioc)
    if not safe_ioc:
        return "", ""

    t = detect_type(safe_ioc)
    target = None

    # For domains: Get IP from VirusTotal passive DNS (NO direct DNS lookup!)
    if t == 'domain':
        if CONFIG.get("VT_API_KEY"):
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{safe_ioc}",
                    headers={"x-apikey": CONFIG["VT_API_KEY"]},
                    timeout=5,
                    verify=True
                )
                if r.status_code == 200:
                    d = r.json()
                    last_dns = d.get('data', {}).get('attributes', {}).get('last_dns_records', [])
                    for record in last_dns:
                        if record.get('type') == 'A':
                            target = record.get('value')
                            break
            except:
                pass

    # For IPs: Use directly (no DNS lookup needed)
    elif t in ['ipv4', 'ipv6']:
        target = safe_ioc

    # If no target resolved, return empty (same as before)
    if not target:
        return "", ""

    # Query geo API
    try:
        r = requests.get(
            f"https://ip-api.com/json/{target}?fields=status,country,city,isp,org,as",
            timeout=3
        )
        if r.status_code == 200:
            d = r.json()
            html = [
                "<br><b>IP Address Information:</b>",
                f"IP Address: {escape_html(target)}",
                f"Country: {escape_html(str(d.get('country','N/A')))}",
                f"City: {escape_html(str(d.get('city','N/A')))}",
                f"ISP: {escape_html(str(d.get('isp','N/A')))}",
                f"Organization: {escape_html(str(d.get('org','N/A')))}",
                f"Network Name: {escape_html(str(d.get('as','N/A')))}"
            ]
            raw = f"Location: {d.get('country','N/A')}, ISP: {d.get('isp','N/A')}, Org: {d.get('org','N/A')}"
            return "<br>".join(html), raw
    except:
        pass

    return "", ""

def build_report(results, details):
    html = "<br>".join(results)
    sep = "=" * 60

    if 'virustotal' in details and details['virustotal'].get('detections'):
        html += f"<br><br>{sep}<br><b>VIRUSTOTAL DETECTION DETAILS</b><br>{sep}<br><br>Antivirus Detections:"
        for k,v in list(details['virustotal']['detections'].items())[:5]:
            html += f"<br> • {k}: {v}"

    if 'abuseipdb' in details:
        ab = details['abuseipdb']
        if ab.get('reports', 0) > 0 or ab.get('score', 0) > 0:
            html += f"<br><br>{sep}<br><b>ABUSEIPDB REPORT DETAILS</b><br>{sep}"
            html += f"<br>Total Reports: {escape_html(str(ab['reports']))}"
            html += f"<br>Last Reported: {ab['last']}"
            if ab.get('cats'):
                html += f"<br><br>Report Categories:"
                for c in ab['cats']:
                    html += f"<br> • {c}"

    if 'otx' in details and details['otx'].get('pulses'):
        html += f"<br><br>{sep}<br><b>ALIENVAULT OTX THREAT INTELLIGENCE</b><br>{sep}"
        html += f"<br><br>Threat Pulses ({len(details['otx']['pulses'])} shown):"
        for p in details['otx']['pulses'][:10]:
            # SECURITY: Escape all pulse data
            html += f"<br><br> 📋 {escape_html(str(p.get('name', '')))}"
            html += f"<br>     Author: {escape_html(str(p.get('author_name','Unknown')))}"
            html += f"<br>     Created: {escape_html(str(p.get('created','Unknown')))}"
            if p.get('tags'):
                tags = ', '.join([escape_html(str(t)) for t in p['tags']])
                html += f"<br>     Tags: {tags}"

    return html

# ===================== SCAN REPORT GENERATOR =====================
def generate_scan_report(ioc):
    if not ioc:
        return "Error: No IOC", ""

    # SECURITY: Validate IOC before processing
    safe_ioc = sanitize_ioc(ioc)
    if not safe_ioc:
        return "Error: Invalid IOC format. Please enter a valid IP, domain, or hash.", ""

    t = detect_type(safe_ioc)

    res_html = []
    ai_context_list = []
    det_map = {}

    with concurrent.futures.ThreadPoolExecutor() as ex:
        f_vt = ex.submit(q_vt, safe_ioc)
        f_otx = ex.submit(q_otx, safe_ioc)

        f_yeti = None
        if t != "hash":
            f_yeti = ex.submit(q_yeti, safe_ioc)

        f_hybrid = None
        if t == "hash":
            f_hybrid = ex.submit(q_hybrid, safe_ioc)

        f_whois = None
        f_urlscan = None
        if t == "domain":
            f_whois = ex.submit(q_whois, safe_ioc)
            f_urlscan = ex.submit(q_urlscan, safe_ioc)

        f_ab = None
        f_geo = None
        if t == "ipv4" or t == "ipv6" or t == "domain":
            if t != "domain":
                f_ab = ex.submit(q_abuse, safe_ioc)
            f_geo = ex.submit(q_geo, safe_ioc)

        vt_h, vt_raw, vt_d = f_vt.result()
        res_html.append(vt_h)
        if vt_raw: ai_context_list.append(vt_raw)
        if vt_d: det_map['virustotal'] = vt_d

        if f_ab:
            ab_h, ab_raw, ab_d = f_ab.result()
            res_html.append(ab_h)
            if ab_raw: ai_context_list.append(ab_raw)
            if ab_d: det_map['abuseipdb'] = ab_d

        otx_h, otx_raw, otx_d = f_otx.result()
        res_html.append(otx_h)
        if otx_raw: ai_context_list.append(otx_raw)
        if otx_d: det_map['otx'] = otx_d

        if f_hybrid:
            hy_h, hy_raw, _ = f_hybrid.result()
            if hy_h:
                res_html.append(hy_h)
            if hy_raw:
                ai_context_list.append(hy_raw)

        if f_yeti:
            yeti_result = f_yeti.result()
            if yeti_result and yeti_result[0]:
                res_html.append(yeti_result[0])

        if f_urlscan:
            urlscan_result = f_urlscan.result()
            if urlscan_result and urlscan_result[0]:
                res_html.append(urlscan_result[0])

        if f_whois:
            whois_result = f_whois.result()
            if whois_result and whois_result[0]:
                res_html.append("<br>" + whois_result[0])

        if f_geo:
            geo_h, geo_raw = f_geo.result()
            if geo_h:
                res_html.append(geo_h)
            if geo_raw:
                ai_context_list.append(geo_raw)

    full_html = build_report(res_html, det_map)
    ai_text = " | ".join(ai_context_list)
    return full_html, ai_text

# ===================== WORKERS =====================
class ScanWorker(QThread):
    fast_sig = pyqtSignal(str)
    slow_sig = pyqtSignal(str)

    def __init__(self, ioc, ai):
        super().__init__()
        self.ioc = ioc
        self.ai = ai

    def run(self):
        try:
            html_report, raw_text_for_ai = generate_scan_report(self.ioc)
            self.fast_sig.emit(html_report)

            ai_res = self.ai.summarize(raw_text_for_ai, self.ioc)
            sep = "=" * 60
            # SECURITY: Escape AI output
            ai_html = f'<br><br>{sep}<br><span style="font-family:Segoe UI; font-size:14px;">{escape_html(ai_res)}</span><br>{sep}'
            self.slow_sig.emit(ai_html)

        except Exception as e:
            self.fast_sig.emit("Scan error occurred. Please check your input.")

class BulkScanWorker(QThread):
    update = pyqtSignal(str)
    progress = pyqtSignal(int)
    finished = pyqtSignal()

    def __init__(self, iocs):
        super().__init__()
        self.iocs = iocs
        self.running = True

    def run(self):
        total = len(self.iocs)
        for i, ioc in enumerate(self.iocs):
            if not self.running:
                break
            try:
                html_report, _ = generate_scan_report(ioc)
                # SECURITY: Escape IOC in header
                formatted = f"<br><hr><br><b>=== RESULTS FOR: {escape_html(ioc)} ===</b><br>{html_report}"
                self.update.emit(formatted)
                self.progress.emit(int(((i + 1) / total) * 100))
            except Exception as e:
                self.update.emit(f"<br>Error scanning {escape_html(ioc)}: Scan failed")

        self.finished.emit()

    def stop(self):
        self.running = False

class PhishWorker(QThread):
    done = pyqtSignal(str)
    def __init__(self, txt, ai):
        super().__init__()
        self.txt = txt
        self.ai = ai
    def run(self):
        if not self.ai:
            self.done.emit("AI is not configured. Please add a Bytez API key in Settings.")
            return
        try:
            res = self.ai.phish(self.txt)
            self.done.emit(f"=== AI PHISHING VERDICT ===\n\n{res}")
        except Exception as e:
            self.done.emit(f"AI analysis failed: {str(e)}")

# ===================== PASSWORD DIALOG =====================
class PasswordDialog(QDialog):
    def __init__(self, parent=None, is_first_time=False):
        super().__init__(parent)
        self.setWindowTitle("Security Setup" if is_first_time else "Authentication Required")
        self.setModal(True)
        self.resize(450, 280)
        self.is_first_time = is_first_time
        self.password_hash = None

        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint)

        self.setStyleSheet("""
            QDialog { background-color: #121218; color: white; }
            QLabel { color: #e9d5ff; font-size: 14px; }
            QLabel#Title { font-size: 18px; font-weight: bold; color: #667eea; margin-bottom: 10px; }
            QLabel#Warning { color: #ff6b6b; background-color: rgba(255, 107, 107, 0.1); padding: 10px; border-radius: 5px; border: 1px solid #ff6b6b; }
            QLabel#Attempts { color: #ffa500; background-color: rgba(255, 165, 0, 0.1); padding: 8px; border-radius: 5px; border: 1px solid #ffa500; }
            QLineEdit { background-color: #0f0f1f; border: 2px solid #4d5d96; border-radius: 5px; color: white; padding: 10px; font-size: 14px; }
            QLineEdit:focus { border: 2px solid #667eea; }
            QPushButton { background-color: #667eea; color: white; border-radius: 5px; padding: 12px; font-weight: bold; font-size: 14px; }
            QPushButton:hover { background-color: #5649c0; }
            QPushButton:pressed { background-color: #4538a0; }
            QPushButton#ExitBtn { background-color: #2d3555; border: 1px solid #4d5d96; }
            QPushButton#ExitBtn:hover { background-color: #3d4565; }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        if not is_first_time:
            locked, remaining = is_locked_out()
            if locked:
                self.show_lockout_screen(layout, remaining)
                return

        if is_first_time:
            title = QLabel("🔒 Welcome to IOC Scanner")
            title.setObjectName("Title")
            layout.addWidget(title)

            info = QLabel("Please create a password to protect your API keys and configuration.")
            info.setWordWrap(True)
            layout.addWidget(info)

            warning = QLabel("⚠️ Important: Remember this password! There is no recovery option.")
            warning.setObjectName("Warning")
            warning.setWordWrap(True)
            layout.addWidget(warning)

            layout.addWidget(QLabel("New Password (minimum 8 characters):"))
            self.pass_input = QLineEdit()
            self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.pass_input.setPlaceholderText("Enter strong password...")
            layout.addWidget(self.pass_input)

            layout.addWidget(QLabel("Confirm Password:"))
            self.pass_confirm = QLineEdit()
            self.pass_confirm.setEchoMode(QLineEdit.EchoMode.Password)
            self.pass_confirm.setPlaceholderText("Re-enter password...")
            self.pass_confirm.returnPressed.connect(self.verify)
            layout.addWidget(self.pass_confirm)

        else:
            title = QLabel("🔒 IOC Scanner - Authentication")
            title.setObjectName("Title")
            layout.addWidget(title)

            info = QLabel("Enter your password to access the application.")
            layout.addWidget(info)

            failed_attempts = CONFIG.get("FAILED_ATTEMPTS", 0)
            if failed_attempts > 0:
                remaining_attempts = 10 - failed_attempts
                attempt_warning = QLabel(
                    f"⚠️ Warning: {failed_attempts} failed attempt(s).\n"
                    f"{remaining_attempts} attempts remaining before 30-minute lockout."
                )
                attempt_warning.setObjectName("Attempts")
                attempt_warning.setWordWrap(True)
                layout.addWidget(attempt_warning)

            layout.addWidget(QLabel("Password:"))
            self.pass_input = QLineEdit()
            self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.pass_input.setPlaceholderText("Enter password...")
            self.pass_input.returnPressed.connect(self.verify)
            layout.addWidget(self.pass_input)

        btn_text = "Create Password & Continue" if is_first_time else "Unlock"
        btn = QPushButton(btn_text)
        btn.clicked.connect(self.verify)
        layout.addWidget(btn)

        if not is_first_time:
            exit_btn = QPushButton("Exit Application")
            exit_btn.setObjectName("ExitBtn")
            exit_btn.clicked.connect(self.reject_and_exit)
            layout.addWidget(exit_btn)

        layout.addStretch()

    def show_lockout_screen(self, layout, remaining_seconds):
        title = QLabel("🔒 Account Locked")
        title.setObjectName("Title")
        layout.addWidget(title)

        minutes = remaining_seconds // 60
        seconds = remaining_seconds % 60

        lockout_msg = QLabel(
            f"⛔ Too many failed login attempts.\n\n"
            f"Your account is locked for:\n"
            f"{minutes} minutes and {seconds} seconds\n\n"
            f"Please try again later."
        )
        lockout_msg.setObjectName("Warning")
        lockout_msg.setWordWrap(True)
        lockout_msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lockout_msg)

        self.lockout_timer = QTimer(self)
        self.lockout_timer.timeout.connect(lambda: self.update_lockout_display(lockout_msg))
        self.lockout_timer.start(1000)

        exit_btn = QPushButton("Exit Application")
        exit_btn.setObjectName("ExitBtn")
        exit_btn.clicked.connect(self.reject_and_exit)
        layout.addWidget(exit_btn)

        layout.addStretch()

    def update_lockout_display(self, label):
        locked, remaining = is_locked_out()

        if not locked:
            self.lockout_timer.stop()
            self.accept()
            return

        minutes = remaining // 60
        seconds = remaining % 60

        label.setText(
            f"⛔ Too many failed login attempts.\n\n"
            f"Your account is locked for:\n"
            f"{minutes} minutes and {seconds} seconds\n\n"
            f"Please try again later."
        )

    def verify(self):
        if self.is_first_time:
            pass1 = self.pass_input.text()
            pass2 = self.pass_confirm.text()

            if len(pass1) < 8:
                QMessageBox.warning(
                    self,
                    "Weak Password",
                    "Password must be at least 8 characters long.\n\n"
                    "Consider using:\n"
                    "• Mix of uppercase and lowercase\n"
                    "• Numbers and special characters\n"
                    "• Avoid common words"
                )
                return

            if pass1 != pass2:
                QMessageBox.warning(self, "Password Mismatch", "Passwords don't match. Please try again.")
                self.pass_confirm.clear()
                return

            self.password_hash = hash_password(pass1)
            CONFIG["APP_PASSWORD_HASH"] = self.password_hash
            CONFIG["FAILED_ATTEMPTS"] = 0
            CONFIG["LOCKOUT_UNTIL"] = ""

            if save_config_file():
                QMessageBox.information(
                    self,
                    "Success",
                    f"✓ Password created successfully!\n\n"
                    f"Your configuration file is now protected.\n\n"
                    f"Config location:\n{CONFIG_FILE}\n\n"
                    f"⚠️ After 10 failed attempts, the app locks for 30 minutes."
                )
                self.accept()
            else:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"❌ Failed to save password!\n\n"
                    f"Please check:\n"
                    f"1. You have write permission to:\n   {CONFIG_FILE}\n\n"
                    f"2. The folder exists and is accessible\n\n"
                    f"3. No antivirus is blocking the file\n\n"
                    f"Try running the app as administrator."
                )
        else:
            entered_password = self.pass_input.text()
            stored_hash = CONFIG.get("APP_PASSWORD_HASH", "")

            if verify_password(entered_password, stored_hash):
                reset_failed_attempts()
                self.accept()
            else:
                failed_count = record_failed_attempt()
                remaining = 10 - failed_count

                if remaining <= 0:
                    QMessageBox.critical(
                        self,
                        "Account Locked",
                        "⛔ Too many failed attempts!\n\n"
                        "Your account is now locked for 30 minutes.\n\n"
                        "The application will now close."
                    )
                    self.reject_and_exit()
                else:
                    QMessageBox.warning(
                        self,
                        "Authentication Failed",
                        f"❌ Incorrect password!\n\n"
                        f"Remaining attempts: {remaining}/10\n\n"
                        f"After 10 failed attempts, the app will\n"
                        f"lock for 30 minutes."
                    )
                    self.pass_input.clear()
                    self.pass_input.setFocus()

    def reject_and_exit(self):
        self.reject()
        sys.exit(0)

# ===================== UI & DIALOGS =====================
class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("API Settings")
        self.resize(600, 450)
        self.setStyleSheet("""
            QDialog { background-color: #121218; color: white; }
            QLabel { color: #a0aaec; font-size: 14px; font-weight: bold; }
            QLineEdit { background-color: #0f0f1f; border: 1px solid #4d5d96; border-radius: 5px; color: white; padding: 5px; font-family: Consolas; }
            QPushButton { background-color: #667eea; color: white; border-radius: 5px; padding: 8px; font-weight: bold; }
            QPushButton:hover { background-color: #5649c0; }
        """)
        layout = QVBoxLayout(self)

        warning = QLabel("🔒 SECURITY: Your API keys are protected by your password.")
        warning.setStyleSheet("color: #4CAF50; margin-bottom: 10px; padding: 10px; background-color: rgba(76,175,80,0.1); border-radius: 5px;")
        layout.addWidget(warning)

        info = QLabel(f"Config file location:\n{CONFIG_FILE}")
        info.setStyleSheet("color: #888; margin-bottom: 10px; font-size: 11px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        form = QFormLayout()
        self.inputs = {}

        excluded_keys = ["APP_PASSWORD_HASH", "FAILED_ATTEMPTS", "LOCKOUT_UNTIL"]
        for key in DEFAULT_CONFIG.keys():
            if key in excluded_keys:
                continue

            lbl = key.replace("_API_KEY", "").replace("_", " ")
            inp = QLineEdit(CONFIG[key])
            inp.setEchoMode(QLineEdit.EchoMode.Password)
            self.inputs[key] = inp
            form.addRow(lbl + ":", inp)

        layout.addLayout(form)
        btn = QPushButton("Save & Close")
        btn.clicked.connect(self.save)
        layout.addWidget(btn)

    def save(self):
        for k, i in self.inputs.items():
            val = i.text().strip()
            if val:
                CONFIG[k] = val
        save_config_file()
        self.accept()

GLASS_CSS_TEMPLATE = """
QMainWindow {{ background-color: #121218; }}
QWidget {{ color: #e9d5ff; font-family: 'Segoe UI'; font-size: {size}px; }}
QFrame#Glass {{ background-color: rgba(30, 30, 50, 255); border: 1px solid #667eea; border-radius: 12px; }}
QLabel#Head {{ color: #fff; font-weight: bold; font-size: {head_size}px; border-bottom: 2px solid #667eea; padding-bottom: 5px; }}
QLineEdit, QTextEdit, QTextBrowser {{ background-color: #0f0f1f; border: 1px solid #4d5d96; border-radius: 8px; color: white; padding: 8px; font-family: Consolas; }}
QLineEdit:focus, QTextEdit:focus, QTextBrowser:focus {{ border: 2px solid #667eea; }}
QComboBox {{ background-color: #0f0f1f; color: white; border: 1px solid #4d5d96; padding: 5px; }}
QPushButton {{ background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:1, stop:0 #667eea, stop:1 #764ba2); border:none; border-radius:8px; color:white; font-weight:bold; padding:10px; }}
QPushButton:hover {{ background-color: #5649c0; }}
QPushButton#Sec {{ background-color: #2d3555; border: 1px solid #4d5d96; }}
QPushButton#Success {{ background-color: #4CAF50; border: 1px solid #4CAF50; }}
"""

# ===================== MAIN APP =====================
class IOCScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        if not CONFIG.get("APP_PASSWORD_HASH"):
            dialog = PasswordDialog(self, is_first_time=True)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                sys.exit(0)
        else:
            locked, remaining = is_locked_out()
            if locked:
                dialog = PasswordDialog(self, is_first_time=False)
                dialog.exec()
                sys.exit(0)

            dialog = PasswordDialog(self, is_first_time=False)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                sys.exit(0)

        self.setWindowTitle(f"IOC-Threat-Scanner-v{__version__} - Professional (Secured)")
        self.resize(1200, 850)
        self.central = QWidget()
        self.setCentralWidget(self.central)
        self.current_font_size = 14
        self.update_style()
        self.layout = QVBoxLayout(self.central)
        self.layout.setSpacing(15)

        self.scan_history = []

        h_layout = QHBoxLayout()
        title = QLabel("Threat Intelligence Platform 🔒")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        h_layout.addWidget(title)
        h_layout.addStretch()
        sett_btn = QPushButton("⚙️ Settings")
        sett_btn.setObjectName("Sec")
        sett_btn.clicked.connect(self.open_settings)
        h_layout.addWidget(sett_btn)
        self.layout.addLayout(h_layout)

        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)
        self.ai = LocalAIAnalyst()
        self.warn_shown = False
        self.tabs.currentChanged.connect(self.tab_change)

        self.init_scanner()
        self.init_bulk()
        self.init_helper()
        self.init_email()

        self.footer = QHBoxLayout()
        self.status = QLabel("System Ready 🔒 Secured")
        self.status.setStyleSheet("color: #4CAF50; padding: 5px; font-weight: bold;")
        self.footer.addWidget(self.status)
        self.footer.addStretch()

        btn_out = QPushButton("[-]")
        btn_out.setFixedSize(40, 30)
        btn_out.setObjectName("Sec")
        btn_out.clicked.connect(lambda: self.change_font(-2))
        self.footer.addWidget(btn_out)

        btn_in = QPushButton("[+]")
        btn_in.setFixedSize(40, 30)
        btn_in.setObjectName("Sec")
        btn_in.clicked.connect(lambda: self.change_font(2))
        self.footer.addWidget(btn_in)

        self.layout.addLayout(self.footer)

    def update_style(self):
        self.setStyleSheet(GLASS_CSS_TEMPLATE.format(size=self.current_font_size, head_size=self.current_font_size+2))

    def change_font(self, delta):
        self.current_font_size = max(10, min(30, self.current_font_size + delta))
        self.update_style()
        self.status.setText(f"Font Size: {self.current_font_size}px")

    def open_settings(self):
        d = SettingsDialog(self)
        if d.exec():
            self.ai.reload()
            self.status.setText("Settings Updated ✓")

    def tab_change(self, idx):
        if idx == 3 and not self.warn_shown:
            QMessageBox.warning(self, "OPSEC Warning", "⚠️ Do not upload PII or sensitive internal data to the AI.")
            self.warn_shown = True

    # --- TAB 1: SCANNER ---
    def init_scanner(self):
        tab = QWidget(); lay = QVBoxLayout(tab)

        f1 = QFrame(); f1.setObjectName("Glass"); l1 = QVBoxLayout(f1)

        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("Enter IOC", objectName="Head"))
        top_row.addStretch()
        top_row.addWidget(QLabel("Recent:"))
        self.history_combo = QComboBox()
        self.history_combo.setFixedWidth(200)
        self.history_combo.currentTextChanged.connect(self.load_from_history)
        top_row.addWidget(self.history_combo)
        l1.addLayout(top_row)

        self.inp = QLineEdit(); self.inp.setPlaceholderText("IP, Domain, Hash..."); self.inp.returnPressed.connect(self.scan)
        l1.addWidget(self.inp)

        hb = QHBoxLayout()
        b_scan = QPushButton("🔍 Scan"); b_scan.clicked.connect(self.scan)
        b_clr = QPushButton("Clear"); b_clr.setObjectName("Sec"); b_clr.clicked.connect(self.inp.clear)
        hb.addWidget(b_scan); hb.addWidget(b_clr)
        l1.addLayout(hb)
        lay.addWidget(f1)

        f2 = QFrame(); f2.setObjectName("Glass"); l2 = QVBoxLayout(f2)
        hh = QHBoxLayout(); hh.addWidget(QLabel("Results", objectName="Head"))
        self.prog = QProgressBar(); self.prog.setRange(0,0); self.prog.setVisible(False); self.prog.setFixedWidth(150)
        hh.addWidget(self.prog); l2.addLayout(hh)

        self.out = QTextBrowser()
        self.out.setOpenExternalLinks(True)
        self.out.setOpenLinks(False)
        self.out.anchorClicked.connect(lambda u: webbrowser.open(u.toString()))
        l2.addWidget(self.out)

        self.cp_btn = QPushButton("📋 Copy Output"); self.cp_btn.setObjectName("Sec")
        self.cp_btn.clicked.connect(self.copy_effect)
        l2.addWidget(self.cp_btn)

        lay.addWidget(f2)
        self.tabs.addTab(tab, "Single Scanner")

    def copy_effect(self):
        mime = QMimeData()
        mime.setHtml(self.out.toHtml())
        mime.setText(self.out.toPlainText())
        QGuiApplication.clipboard().setMimeData(mime)

        self.cp_btn.setText("Copied! ✓")
        self.cp_btn.setObjectName("Success")
        self.cp_btn.setStyleSheet("background-color: #4CAF50; border: 1px solid #4CAF50;")
        QTimer.singleShot(2000, self.reset_copy)

    def reset_copy(self):
        self.cp_btn.setText("📋 Copy Output")
        self.cp_btn.setObjectName("Sec")
        self.cp_btn.setStyleSheet("")

    def load_from_history(self, text):
        if text: self.inp.setText(text)

    def update_history(self, ioc):
        if ioc not in self.scan_history:
            self.scan_history.insert(0, ioc)
            self.history_combo.clear()
            self.history_combo.addItems(self.scan_history[:10])

    def scan(self):
        ioc = self.inp.text().strip();
        if not ioc: return

        self.update_history(ioc)
        self.inp.clear()
        self.out.clear(); self.prog.setVisible(True); self.status.setText(f"Scanning...")

        self.worker = ScanWorker(ioc, self.ai)
        self.worker.fast_sig.connect(self.show_fast)
        self.worker.slow_sig.connect(self.show_slow)
        self.worker.start()

    def show_fast(self, html):
        self.prog.setVisible(False)
        wrapper = f'<div style="font-family: Segoe UI; font-size: {self.current_font_size}px; color: #e9d5ff;">{html}</div>'
        self.out.setHtml(wrapper)
        self.status.setText("Scan Done. AI Analyzing...")

    def show_slow(self, txt):
        cursor = self.out.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.out.setTextCursor(cursor)
        self.out.insertHtml(txt)
        self.status.setText("AI Complete.")

    # --- TAB 2: BULK ---
    def init_bulk(self):
        tab = QWidget(); lay = QVBoxLayout(tab)
        p = self.create_panel(lay)
        p.addWidget(QLabel("Bulk Inputs"))
        self.bulk_in = QTextEdit(); self.bulk_in.setFixedHeight(100)
        p.addWidget(self.bulk_in)
        h = QHBoxLayout()
        b_run = QPushButton("▶ Run Batch"); b_run.clicked.connect(self.run_bulk)
        h.addWidget(b_run)
        b_stop = QPushButton("⏹ Stop"); b_stop.setObjectName("DangerBtn"); b_stop.clicked.connect(self.stop_bulk)
        h.addWidget(b_stop)
        p.addLayout(h)
        self.b_prog = QProgressBar(); p.addWidget(self.b_prog)
        self.b_out = QTextBrowser(); self.b_out.setOpenExternalLinks(True)
        self.b_out.setOpenLinks(False)
        self.b_out.anchorClicked.connect(lambda u: webbrowser.open(u.toString()))
        p.addWidget(self.b_out)
        self.tabs.addTab(tab, "Bulk Scanner")

    def run_bulk(self):
        raw = self.bulk_in.toPlainText(); iocs = [x.strip() for x in raw.replace('\n', ',').split(',') if x.strip()]
        if not iocs: return
        self.b_out.clear(); self.b_prog.setValue(0)
        self.bw = BulkScanWorker(iocs); self.bw.update.connect(self.b_out.append); self.bw.progress.connect(self.b_prog.setValue)
        self.bw.finished.connect(lambda: self.status.setText("Batch Done")); self.bw.start()

    def stop_bulk(self):
        if hasattr(self, 'bw'): self.bw.stop()

    # --- TAB 3: HELPER ---
    def init_helper(self):
        tab = QWidget(); lay = QVBoxLayout(tab)
        p = self.create_panel(lay)
        p.addWidget(QLabel("Cyber Tools", objectName="Head"))
        self.h_in = QTextEdit(); self.h_in.setPlaceholderText("Input..."); self.h_in.setFixedHeight(80)
        p.addWidget(self.h_in)
        h1 = QHBoxLayout()
        for t, f in [("Defang", self.do_defang), ("Refang", self.do_refang), ("Extract IPs", self.do_extract)]:
            b = QPushButton(t); b.setObjectName("Sec"); b.clicked.connect(f); h1.addWidget(b)
        p.addLayout(h1)
        h2 = QHBoxLayout()
        for t, f in [("B64 Decode", self.do_b64d), ("B64 Encode", self.do_b64e), ("URL Decode", self.do_urld)]:
            b = QPushButton(t); b.setObjectName("Sec"); b.clicked.connect(f); h2.addWidget(b)
        p.addLayout(h2)
        h3 = QHBoxLayout()
        self.p_btn = QPushButton("Lookup Port"); self.p_btn.clicked.connect(self.do_port)
        h3.addWidget(self.p_btn)
        p.addLayout(h3)
        self.h_out = QTextEdit(); self.h_out.setReadOnly(True)
        p.addWidget(self.h_out)
        self.tabs.addTab(tab, "Analyst Helper")

    # --- TAB 4: EMAIL ---
    def init_email(self):
        tab = QWidget(); lay = QHBoxLayout(tab)
        f1 = self.create_panel(lay); f1.addWidget(QLabel("Raw Email", objectName="Head"))
        self.e_in = QTextEdit(); f1.addWidget(self.e_in)
        b1 = QPushButton("Analyze Headers"); b1.clicked.connect(self.do_head); f1.addWidget(b1)
        b2 = QPushButton("AI Phish Check"); b2.clicked.connect(self.do_phish); f1.addWidget(b2)
        f2 = self.create_panel(lay); f2.addWidget(QLabel("Report", objectName="Head"))
        self.e_out = QTextBrowser(); f2.addWidget(self.e_out)
        self.tabs.addTab(tab, "Email Analysis")

    def create_panel(self, layout):
        f = QFrame(); f.setObjectName("Glass"); l = QVBoxLayout(f)
        l.setContentsMargins(15,15,15,15); layout.addWidget(f); return l

    # LOGIC
    def do_defang(self): self.h_out.setText(self.h_in.toPlainText().replace(".", "[.]").replace("http", "hxxp"))
    def do_refang(self): self.h_out.setText(self.h_in.toPlainText().replace("[.]", ".").replace("hxxp", "http"))
    def do_b64d(self):
        try: self.h_out.setText(base64.b64decode(self.h_in.toPlainText()).decode('utf-8'))
        except: self.h_out.setText("Invalid Base64")
    def do_b64e(self): self.h_out.setText(base64.b64encode(self.h_in.toPlainText().encode('utf-8')).decode('utf-8'))
    def do_urld(self): self.h_out.setText(urllib.parse.unquote(self.h_in.toPlainText()))
    def do_extract(self):
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', self.h_in.toPlainText())
        self.h_out.setText("\n".join(list(set(ips))) if ips else "No IPs")
    def do_port(self):
        p = self.h_in.toPlainText().strip()
        self.h_out.setText(f"Port {p}: {PORT_DATA.get(p, 'Unknown')}")
    def do_head(self):
        try:
            msg = email.parser.Parser().parsestr(self.e_in.toPlainText())
            res = f"Subject: {msg.get('subject')}\nFrom: {msg.get('from')}\nTo: {msg.get('to')}\n\n"
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', self.e_in.toPlainText())
            res += f"IPs Found: {list(set(ips))}"
            self.e_out.setText(res)
        except Exception as e: self.e_out.setText("Error parsing email headers")
    def do_phish(self):
        self.e_out.setText("AI Analyzing..."); self.pw = PhishWorker(self.e_in.toPlainText(), self.ai)
        self.pw.done.connect(self.e_out.setText); self.pw.start()


def main():
    """Main entry point for the application."""
    multiprocessing.freeze_support()

    app = QApplication(sys.argv)
    window = IOCScannerApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
