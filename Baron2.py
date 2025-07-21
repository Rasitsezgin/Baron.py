# DİREK BAŞLAT VE LİNKİ GİR.
import requests
from urllib.parse import urlparse, urljoin
import datetime
import os
import ssl
import sys

# SSL sertifika doğrulama hatalarını gizlemek için (sadece geliştirme/test için)
# UYARI: Üretim ortamında KESİNLİKLE önerilmez!
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class AdvancedVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = self._normalize_url(target_url)
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.verify = False  # SSL doğrulamasını devre dışı bırak
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        }
        self.session.headers.update(self.headers)

    def _normalize_url(self, url):
        """URL'yi normalize eder ve https:// ile başladığından emin olur."""
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url # Varsayılan olarak HTTPS kullan
        
        parsed_url = urlparse(url)
        if not parsed_url.netloc: # Eğer sadece "example.com" gibi girilmişse
            url = "https://" + url # Tekrar dene
        
        return url.rstrip('/') # Sondaki eğik çizgiyi kaldır

    def _make_request(self, url, method="GET", data=None, allow_redirects=True):
        """Güvenli bir şekilde HTTP isteği yapar."""
        try:
            response = self.session.request(
                method, url, data=data, timeout=15, allow_redirects=allow_redirects
            )
            return response
        except requests.exceptions.RequestException as e:
            # print(f"Hata: {url} adresine erişilemedi - {e}", file=sys.stderr)
            return None

    def _add_vulnerability(self, name, description, severity="Düşük", details=""):
        """Tespit edilen zafiyeti listeye ekler."""
        self.vulnerabilities.append({
            "name": name,
            "description": description,
            "severity": severity,
            "url": self.target_url,
            "details": details
        })
        print(f"[Zafiyet] {name}: {description} (Ciddiyet: {severity})")

    def scan_security_headers(self):
        """HTTP Güvenlik Başlıklarını kontrol eder."""
        print("\n[Tarama] HTTP Güvenlik Başlıkları Kontrolü...")
        response = self._make_request(self.target_url)
        if not response:
            return

        security_headers = {
            "Strict-Transport-Security": "HSTS başlığı yok. HTTPS'ye zorlama yok.",
            "Content-Security-Policy": "CSP başlığı yok. XSS ve veri enjeksiyonuna karşı savunmasızlık.",
            "X-Content-Type-Options": "X-Content-Type-Options başlığı yok. MIME türü koklamaya karşı savunmasızlık.",
            "X-Frame-Options": "X-Frame-Options başlığı yok. Clickjacking'e karşı savunmasızlık.",
            "Referrer-Policy": "Referrer-Policy başlığı yok. Referrer bilgisi sızdırma riski.",
            "Permissions-Policy": "Permissions-Policy başlığı yok. Tarayıcı özelliklerinin kontrolü eksik."
        }

        for header, description in security_headers.items():
            if header not in response.headers:
                self._add_vulnerability(
                    f"Eksik Güvenlik Başlığı: {header}",
                    description,
                    severity="Orta"
                )
        print("HTTP Güvenlik Başlıkları Kontrolü Tamamlandı.")

    def scan_xss(self):
        """Basit yansıtılan XSS zafiyeti denemesi yapar."""
        print("\n[Tarama] Basit Yansıtılan XSS Denemesi...")
        xss_payload = "<script>alert('XSS_TEST');</script>"
        test_url_xss = f"{self.target_url}?param={xss_payload}"
        response = self._make_request(test_url_xss)

        if response and xss_payload in response.text:
            self._add_vulnerability(
                "Potansiyel Reflected XSS",
                f"URL parametresi olarak gönderilen XSS payload'u sayfada yansıtıldı.",
                severity="Yüksek",
                details=f"Payload: {xss_payload}, Test URL: {test_url_xss}"
            )
        print("Basit XSS Denemesi Tamamlandı.")

    def scan_directory_listing(self):
        """Yaygın dizin listeleme zafiyetlerini kontrol eder."""
        print("\n[Tarama] Dizin Listeleme Kontrolü...")
        common_dirs = ["/admin/", "/uploads/", "/images/", "/test/", "/backup/", "/logs/"]
        for directory in common_dirs:
            full_url = urljoin(self.target_url, directory)
            response = self._make_request(full_url)
            if response and response.status_code == 200 and ("Index of /" in response.text or "<title>Index of" in response.text):
                self._add_vulnerability(
                    "Dizin Listeleme Açığı",
                    f"Sunucu '{directory}' dizininin içeriğini listeliyor.",
                    severity="Yüksek",
                    details=f"Erişilebilir Dizin: {full_url}"
                )
        print("Dizin Listeleme Kontrolü Tamamlandı.")

    def scan_backup_files(self):
        """Yaygın yedek dosya uzantılarını arar."""
        print("\n[Tarama] Yedek Dosya Kontrolü...")
        common_extensions = [".bak", ".old", ".zip", ".tar.gz", ".rar", ".sql", "~"]
        common_files = ["index.php", "config.php", "wp-config.php", "database.sql", "admin.php"]

        for file_name in common_files:
            for ext in common_extensions:
                test_url = urljoin(self.target_url, f"{file_name}{ext}")
                response = self._make_request(test_url, allow_redirects=False) # Yönlendirmeleri takip etme
                if response and response.status_code == 200:
                    # Bazı 404 sayfaları 200 döndürebilir, içeriği kontrol et
                    if "Not Found" not in response.text and "Error 404" not in response.text:
                        self._add_vulnerability(
                            "Potansiyel Yedek Dosya Sızdırma",
                            f"Yedek dosya veya hassas dosya bulundu: {file_name}{ext}",
                            severity="Yüksek",
                            details=f"Bulunan URL: {test_url}, Boyut: {len(response.content)} bayt"
                        )
        print("Yedek Dosya Kontrolü Tamamlandı.")

    def scan_robots_txt(self):
        """robots.txt dosyasını analiz eder."""
        print("\n[Tarama] robots.txt Analizi...")
        robots_url = urljoin(self.target_url, "/robots.txt")
        response = self._make_request(robots_url)
        if response and response.status_code == 200:
            if "Disallow: /" in response.text:
                self._add_vulnerability(
                    "robots.txt 'Disallow: /' İçeriyor",
                    "robots.txt tüm siteye erişimi engellemeye çalışıyor, bu da hassas alanları işaret edebilir.",
                    severity="Bilgi",
                    details=f"robots.txt içeriği:\n{response.text[:200]}..." # İlk 200 karakter
                )
            # Daha detaylı Disallow kuralları analizi eklenebilir
            else:
                print("robots.txt bulundu.")
        print("robots.txt Analizi Tamamlandı.")

    def scan_server_banner(self):
        """Sunucu banner bilgilerini kontrol eder."""
        print("\n[Tarama] Sunucu Bilgisi Sızdırma Kontrolü...")
        response = self._make_request(self.target_url)
        if response and 'Server' in response.headers:
            server_info = response.headers['Server']
            self._add_vulnerability(
                "Bilgi Sızdırma: Sunucu Banner",
                f"Sunucu bilgisi açığa çıkıyor: '{server_info}'. Bu, saldırganlara hedef sistem hakkında bilgi verebilir.",
                severity="Düşük",
                details=f"Sunucu Başlığı: {server_info}"
            )
        print("Sunucu Bilgisi Sızdırma Kontrolü Tamamlandı.")

    def run_scan(self):
        """Tüm taramaları çalıştırır."""
        print(f"Hedef URL: {self.target_url}")
        self.scan_security_headers()
        self.scan_xss()
        self.scan_directory_listing()
        self.scan_backup_files()
        self.scan_robots_txt()
        self.scan_server_banner()
        print("\nTarama Tamamlandı.")
        return self.vulnerabilities

    def generate_report(self):
        """Tespit edilen zafiyetler için bir rapor oluşturur."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        parsed_url = urlparse(self.target_url)
        report_filename = f"rapor_{parsed_url.netloc.replace('.', '_')}_{timestamp}.txt"

        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(f"--- Zafiyet Raporu: {self.target_url} ---\n")
            f.write(f"Tarama Tarihi: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Tarama Aracı: Basit Gelişmiş Zafiyet Tarayıcı (Eğitim Amaçlı)\n")
            f.write("-" * 50 + "\n\n")

            if self.vulnerabilities:
                f.write("Tespit Edilen Zafiyetler:\n")
                f.write("=" * 30 + "\n\n")
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"{i}. Zafiyet Adı: {vuln['name']}\n")
                    f.write(f"   Açıklama: {vuln['description']}\n")
                    f.write(f"   Ciddiyet: {vuln['severity']}\n")
                    f.write(f"   Hedef URL: {vuln['url']}\n")
                    if vuln['details']:
                        f.write(f"   Detaylar: {vuln['details']}\n")
                    f.write("-" * 20 + "\n\n")
            else:
                f.write("Herhangi bir temel zafiyet tespit edilmedi.\n\n")

            f.write("--- Rapor Sonu ---\n")
            f.write("Bu rapor, Nessus gibi profesyonel araçların yerini tutmaz ve yalnızca temel tarama yeteneklerini göstermektedir.\n")

        print(f"\nZafiyet raporu '{report_filename}' dosyasına kaydedildi.")

if __name__ == "__main__":
    print("Python ile Gelişmiş Zafiyet Tarayıcı (Eğitim Amaçlı)")
    print("--- Nessus gibi kapsamlı DEĞİLDİR ---")
    print("UYARI: İzinsiz tarama yasa dışıdır. Yalnızca kendi sistemlerinizi veya izinli olduğunuz sistemleri tarayın.")
    print("-" * 60)

    target = input("Taranacak hedef web sitesinin URL'sini girin (örn: example.com veya https://example.com): ")

    scanner = AdvancedVulnerabilityScanner(target)
    
    # Bazı HTTPS sitelerinde SSL handshake hatası alınabilir.
    # Bu durumda, 'requests.exceptions.SSLError' yakalanır.
    # Kodu verify=True yaparak veya sistemdeki CA sertifikalarını güncelleyerek
    # bu hatayı gidermeye çalışmalısınız.
    # verify=False kötü bir uygulamadır.
    
    found_vulnerabilities = scanner.run_scan()
    scanner.generate_report()
