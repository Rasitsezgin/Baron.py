# KULLANIMI python baron1.py -u http://10.0.2.15 -o json


import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import argparse
import datetime
import json
import os

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
        
        # Kullanıcı ajanı ayarı (isteğe bağlı)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VulnerabilityScanner/1.0'
        })
    
    def scan_sql_injection(self):
        """Temel SQL enjeksiyon zafiyetlerini tarar"""
        test_urls = [
            f"{self.target_url}?id=1'",
            f"{self.target_url}?id=1 AND 1=1",
            f"{self.target_url}?id=1 AND 1=2"
        ]
        
        for url in test_urls:
            try:
                response = self.session.get(url, timeout=10)
                if any(error in response.text.lower() for error in ['sql syntax', 'mysql', 'ora-', 'syntax error']):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'url': url,
                        'severity': 'High',
                        'description': 'SQL enjeksiyon zafiyeti tespit edildi',
                        'timestamp': datetime.datetime.now().isoformat()
                    })
            except Exception as e:
                print(f"SQL test hatası: {e}")
    
    def scan_xss(self):
        """Temel XSS zafiyetlerini tarar"""
        test_payload = "<script>alert('XSS')</script>"
        test_urls = [
            f"{self.target_url}?search={test_payload}",
            f"{self.target_url}?q={test_payload}"
        ]
        
        for url in test_urls:
            try:
                response = self.session.get(url, timeout=10)
                if test_payload in response.text:
                    self.vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'url': url,
                        'severity': 'Medium',
                        'description': 'XSS zafiyeti tespit edildi',
                        'timestamp': datetime.datetime.now().isoformat()
                    })
            except Exception as e:
                print(f"XSS test hatası: {e}")
    
    def scan_sensitive_files(self):
        """Hassas dosyaların varlığını kontrol eder"""
        common_files = [
            'robots.txt',
            '.git/config',
            '.env',
            'wp-config.php',
            'config.php'
        ]
        
        for file in common_files:
            url = urljoin(self.target_url, file)
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'Sensitive File Exposure',
                        'url': url,
                        'severity': 'Low',
                        'description': f'Hassas dosya erişilebilir: {file}',
                        'timestamp': datetime.datetime.now().isoformat()
                    })
            except Exception as e:
                print(f"Dosya tarama hatası: {e}")
    
    def scan_headers(self):
        """Güvenlikle ilgili HTTP başlıklarını kontrol eder"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-XSS-Protection': '1; mode=block',
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY or SAMEORIGIN',
                'Content-Security-Policy': 'varlık kontrolü',
                'Strict-Transport-Security': 'varlık kontrolü'
            }
            
            missing_headers = []
            for header, value in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self.vulnerabilities.append({
                    'type': 'Missing Security Headers',
                    'url': self.target_url,
                    'severity': 'Low',
                    'description': f'Eksik güvenlik başlıkları: {", ".join(missing_headers)}',
                    'timestamp': datetime.datetime.now().isoformat()
                })
                
        except Exception as e:
            print(f"Başlık tarama hatası: {e}")
    
    def scan_forms(self):
        """Formlardaki güvenlik açıklarını tarar"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                # CSRF token kontrolü
                if not form.find('input', {'name': 'csrf_token'}) and not form.find('input', {'name': '_token'}):
                    self.vulnerabilities.append({
                        'type': 'Potential CSRF Vulnerability',
                        'url': self.target_url,
                        'severity': 'Medium',
                        'description': 'Formda CSRF koruması eksik',
                        'form_action': form.get('action', 'N/A'),
                        'timestamp': datetime.datetime.now().isoformat()
                    })
                
                # HTTP method kontrolü
                method = form.get('method', 'get').lower()
                if method == 'get' and ('password' in str(form).lower() or 'login' in str(form).lower()):
                    self.vulnerabilities.append({
                        'type': 'Form Security Issue',
                        'url': self.target_url,
                        'severity': 'Low',
                        'description': 'Hassas veri GET metodu ile gönderiliyor',
                        'form_action': form.get('action', 'N/A'),
                        'timestamp': datetime.datetime.now().isoformat()
                    })
                    
        except Exception as e:
            print(f"Form tarama hatası: {e}")
    
    def run_scan(self):
        """Tüm taramaları çalıştırır"""
        print(f"[*] {self.target_url} için tarama başlatılıyor...")
        
        self.scan_sql_injection()
        self.scan_xss()
        self.scan_sensitive_files()
        self.scan_headers()
        self.scan_forms()
        
        print(f"[*] Tarama tamamlandı. {len(self.vulnerabilities)} zafiyet bulundu.")
        return self.vulnerabilities
    
    def generate_report(self, output_format='json'):
        """Tarama sonuçlarını raporlar"""
        if not self.vulnerabilities:
            print("Hiç zafiyet bulunamadı.")
            return
        
        report = {
            'target': self.target_url,
            'date': datetime.datetime.now().isoformat(),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total': len(self.vulnerabilities),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'High'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'Medium'),
                'low': sum(1 for v in self.vulnerabilities if v['severity'] == 'Low')
            }
        }
        
        if output_format == 'json':
            filename = f"vulnerability_report_{self.target_url.replace('://', '_').replace('/', '_')}.json"
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            print(f"[+] Rapor oluşturuldu: {filename}")
        else:
            print("\n=== Zafiyet Raporu ===")
            print(f"Hedef: {self.target_url}")
            print(f"Tarih: {report['date']}")
            print(f"\nToplam Zafiyet: {report['summary']['total']}")
            print(f"Yüksek Önem: {report['summary']['high']}")
            print(f"Orta Önem: {report['summary']['medium']}")
            print(f"Düşük Önem: {report['summary']['low']}")
            
            print("\nDetaylar:")
            for vuln in report['vulnerabilities']:
                print(f"\n[{vuln['severity']}] {vuln['type']}")
                print(f"URL: {vuln['url']}")
                print(f"Açıklama: {vuln['description']}")
                if 'form_action' in vuln:
                    print(f"Form Action: {vuln['form_action']}")

def main():
    parser = argparse.ArgumentParser(description='Web Sitesi Zafiyet Tarama Aracı')
    parser.add_argument('-u', '--url', required=True, help='Taranacak hedef URL')
    parser.add_argument('-o', '--output', choices=['json', 'console'], default='console', 
                       help='Rapor çıktı formatı (json veya console)')
    
    args = parser.parse_args()
    
    scanner = VulnerabilityScanner(args.url)
    scanner.run_scan()
    scanner.generate_report(args.output)

if __name__ == '__main__':
    main()
