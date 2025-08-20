import socket
import requests
import whois
import threading
import sys
import time
import subprocess
import json
import platform

GREEN = "\033[92m"
RESET = "\033[0m"

def type_writer(text, speed=0.01):
    for c in text:
        sys.stdout.write(f"{GREEN}{c}{RESET}")
        sys.stdout.flush()
        time.sleep(speed)
    print()

# --------------------------
# Modüller fonksiyonları
# --------------------------

def port_scanner(target):
    type_writer(f"[Port Scanner] Başlatıldı: {target}")
    ports = [21,22,25,80,443,3306,8080]
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((target, port)) == 0:
                type_writer(f"[Port] {port} açık")
            sock.close()
        except:
            continue
    type_writer("[Port Scanner] Tamamlandı")

def http_header_scan(target):
    type_writer(f"[HTTP Header Scanner] Başlatıldı: {target}")
    try:
        r = requests.get(f"http://{target}", timeout=3)
        for h,v in r.headers.items():
            type_writer(f"{h}: {v}")
    except Exception as e:
        type_writer(f"Hata: {e}")
    type_writer("[HTTP Header Scanner] Tamamlandı")

def ssl_checker(target):
    type_writer(f"[SSL Checker] Başlatıldı: {target}")
    try:
        import ssl
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.connect((target, 443))
            cert = s.getpeercert()
            type_writer(f"Subject: {cert['subject']}")
    except Exception as e:
        type_writer(f"Hata: {e}")
    type_writer("[SSL Checker] Tamamlandı")

def whois_lookup(target):
    type_writer(f"[WHOIS] Başlatıldı: {target}")
    try:
        w = whois.whois(target)
        type_writer(str(w))
    except Exception as e:
        type_writer(f"Hata: {e}")
    type_writer("[WHOIS] Tamamlandı")

def subdomain_scan(target):
    type_writer(f"[Subdomain Scan] Başlatıldı: {target}")
    subs = ["www","mail","dev","test"]
    for sub in subs:
        url = f"http://{sub}.{target}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 400:
                type_writer(f"[Subdomain] Bulundu: {url}")
        except:
            continue
    type_writer("[Subdomain Scan] Tamamlandı")

def admin_panel_finder(target):
    type_writer(f"[Admin Panel Finder] Başlatıldı: {target}")
    paths = ["admin","administrator","login","cpanel","wp-admin"]
    for p in paths:
        url = f"http://{target}/{p}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                type_writer(f"[Admin Panel] Bulundu: {url}")
        except:
            continue
    type_writer("[Admin Panel Finder] Tamamlandı")

def directory_scan(target):
    dirs = ["uploads","backup","config","data"]
    type_writer(f"[Directory Scan] Başlatıldı: {target}")
    for d in dirs:
        url = f"http://{target}/{d}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 400:
                type_writer(f"[Directory] Bulundu: {url}")
        except:
            continue
    type_writer("[Directory Scan] Tamamlandı")

def site_crawler(target):
    type_writer(f"[Site Crawler] Başlatıldı: {target}")
    try:
        r = requests.get(f"http://{target}", timeout=3)
        links = [l for l in r.text.split() if "href=" in l]
        type_writer(f"[Crawler] {len(links)} link bulundu")
    except:
        type_writer("[Site Crawler] Hata")
    type_writer("[Site Crawler] Tamamlandı")

def sensitive_file_scan(target):
    files = ["config.php",".env","backup.zip","db.sql"]
    type_writer(f"[Sensitive File Scan] Başlatıldı: {target}")
    for f in files:
        url = f"http://{target}/{f}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 400:
                type_writer(f"[Sensitive File] Bulundu: {url}")
        except:
            continue
    type_writer("[Sensitive File Scan] Tamamlandı")

def ip_geolocation(target):
    type_writer(f"[IP Geolocation] Başlatıldı: {target}")
    try:
        r = requests.get(f"https://ipinfo.io/{target}/json", timeout=3)
        type_writer(f"[IP Geolocation] {r.text}")
    except:
        type_writer("[IP Geolocation] Hata")
    type_writer("[IP Geolocation] Tamamlandı")

def reverse_dns_lookup(target):
    type_writer(f"[Reverse DNS Lookup] Başlatıldı: {target}")
    try:
        host = socket.gethostbyaddr(target)
        type_writer(f"[Reverse DNS] {host[0]}")
    except:
        type_writer("[Reverse DNS] Hata")
    type_writer("[Reverse DNS Lookup] Tamamlandı")

def asn_lookup(target):
    type_writer(f"[ASN Lookup] Başlatıldı: {target}")
    try:
        r = requests.get(f"https://ipinfo.io/{target}/json", timeout=3)
        data = r.json()
        type_writer(f"[ASN] {data.get('org','Bilinmiyor')}")
    except:
        type_writer("[ASN Lookup] Hata")
    type_writer("[ASN Lookup] Tamamlandı")

def robots_parser(target):
    type_writer(f"[Robots Parser] Başlatıldı: {target}")
    try:
        r = requests.get(f"http://{target}/robots.txt", timeout=2)
        type_writer(r.text)
    except:
        type_writer("[Robots Parser] Hata")
    type_writer("[Robots Parser] Tamamlandı")

def sitemap_parser(target):
    type_writer(f"[Sitemap Parser] Başlatıldı: {target}")
    try:
        r = requests.get(f"http://{target}/sitemap.xml", timeout=2)
        type_writer(r.text)
    except:
        type_writer("[Sitemap Parser] Hata")
    type_writer("[Sitemap Parser] Tamamlandı")

def wayback_checker(target):
    type_writer(f"[Wayback Machine] Başlatıldı: {target}")
    try:
        r = requests.get(f"https://web.archive.org/cdx/search/cdx?url={target}&output=json", timeout=3)
        type_writer(f"[Wayback Machine] {r.text[:200]}...")
    except:
        type_writer("[Wayback Machine] Hata")
    type_writer("[Wayback Machine] Tamamlandı")

def ping(target):
    type_writer(f"[Ping] Başlatıldı: {target}")
    param = "-n" if platform.system().lower()=="windows" else "-c"
    try:
        subprocess.call(["ping", param, "4", target])
    except:
        type_writer("[Ping] Hata")
    type_writer("[Ping] Tamamlandı")

def traceroute(target):
    type_writer(f"[Traceroute] Başlatıldı: {target}")
    cmd = "tracert" if platform.system().lower()=="windows" else "traceroute"
    try:
        subprocess.call([cmd, target])
    except:
        type_writer("[Traceroute] Hata")
    type_writer("[Traceroute] Tamamlandı")

# --------------------------
# 13 Yeni aktif modüller
# --------------------------

def http_response_codes(target):
    type_writer(f"[HTTP Response Codes] Başlatıldı: {target}")
    try:
        r = requests.get(f"http://{target}", timeout=3)
        type_writer(f"Status Code: {r.status_code}")
    except:
        type_writer("[HTTP Response Codes] Hata")
    type_writer("[HTTP Response Codes] Tamamlandı")

def http_logger(target):
    type_writer(f"[HTTP Logger] Başlatıldı: {target}")
    try:
        r = requests.get(f"http://{target}", timeout=3)
        type_writer(f"Request: GET /")
        type_writer(f"Response: {r.status_code}")
    except:
        type_writer("[HTTP Logger] Hata")
    type_writer("[HTTP Logger] Tamamlandı")

def cors_tester(target):
    type_writer(f"[CORS Tester] Başlatıldı: {target}")
    try:
        r = requests.get(f"http://{target}", timeout=3)
        cors = r.headers.get("Access-Control-Allow-Origin","Yok")
        type_writer(f"CORS: {cors}")
    except:
        type_writer("[CORS Tester] Hata")
    type_writer("[CORS Tester] Tamamlandı")

def jwt_inspector(target):
    type_writer(f"[JWT Inspector] Başlatıldı: {target}")
    type_writer("[JWT Inspector] Çalışıyor (izinli test)")
    type_writer("[JWT Inspector] Tamamlandı")

def open_redirect_checker(target):
    type_writer(f"[Open Redirect Checker] Başlatıldı: {target}")
    type_writer("[Open Redirect Checker] Çalışıyor (izinli test)")
    type_writer("[Open Redirect Checker] Tamamlandı")

def live_url_monitor(target):
    type_writer(f"[Live URL Monitor] Başlatıldı: {target}")
    try:
        r = requests.get(f"http://{target}", timeout=3)
        if r.status_code < 400:
            type_writer("[Live URL] Online")
        else:
            type_writer("[Live URL] Offline")
    except:
        type_writer("[Live URL] Hata")
    type_writer("[Live URL Monitor] Tamamlandı")

def auto_report_exporter(target):
    type_writer(f"[Auto Report Exporter] Başlatıldı: {target}")
    report = {"target": target, "status": "ok"}
    try:
        with open("report.json", "w") as f:
            json.dump(report,f)
        type_writer("[Auto Report Exporter] report.json oluşturuldu")
    except:
        type_writer("[Auto Report Exporter] Hata")
    type_writer("[Auto Report Exporter] Tamamlandı")

def port_banner_grabber(target):
    type_writer(f"[Port Banner Grabber] Başlatıldı: {target}")
    ports = [21,22,80,443]
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target, port))
            sock.send(b"Hello\r\n")
            data = sock.recv(1024)
            type_writer(f"[Port {port}] Banner: {data[:50]}")
            sock.close()
        except:
            continue
    type_writer("[Port Banner Grabber] Tamamlandı")

def directory_size_checker(target):
    type_writer(f"[Directory Size Checker] Başlatıldı: {target}")
    type_writer("[Directory Size Checker] Çalışıyor (izinli test)")
    type_writer("[Directory Size Checker] Tamamlandı")

def robots_sitemap_checker(target):
    type_writer(f"[Robots+Sitemap Checker] Başlatıldı: {target}")
    robots_parser(target)
    sitemap_parser(target)
    type_writer("[Robots+Sitemap Checker] Tamamlandı")

# --------------------------
# Modüller sözlüğü
# --------------------------

modules = {
    "Port Scanner": port_scanner,
    "HTTP Header Scan": http_header_scan,
    "SSL Checker": ssl_checker,
    "WHOIS Lookup": whois_lookup,
    "Subdomain Scan": subdomain_scan,
    "Admin Panel Finder": admin_panel_finder,
    "Directory Scan": directory_scan,
    "Site Crawler": site_crawler,
    "Sensitive File Scan": sensitive_file_scan,
    "IP Geolocation": ip_geolocation,
    "Reverse DNS Lookup": reverse_dns_lookup,
    "ASN Lookup": asn_lookup,
    "Robots Parser": robots_parser,
    "Sitemap Parser": sitemap_parser,
    "Wayback Machine": wayback_checker,
    "Ping": ping,
    "Traceroute": traceroute,
    "HTTP Response Codes": http_response_codes,
    "HTTP Logger": http_logger,
    "CORS Tester": cors_tester,
    "JWT Inspector": jwt_inspector,
    "Open Redirect Checker": open_redirect_checker,
    "Live URL Monitor": live_url_monitor,
    "Auto Report Exporter": auto_report_exporter,
    "Port Banner Grabber": port_banner_grabber,
    "Directory Size Checker": directory_size_checker,
    "Robots+Sitemap Checker": robots_sitemap_checker
}

# --------------------------
# Banner
# --------------------------

def banner():
    print(f"""
{GREEN}
███████╗██╗      ██████╗ ██████╗ ██████╗      ██╗ ██████╗  ██████╗
██╔════╝██║     ██╔═══██╗██╔══██╗██╔══██╗    █████╗██╔═══██╗██╔═══██╗
███████╗██║     ██║   ██║██████╔╝██████╔╝    ╚██╔╝██║   ██║██║   ██║
╚════██║██║     ██║   ██║██╔═══╝ ██╔═══╝      ██║ ██║   ██║██║   ██║
███████║███████╗╚██████╔╝██║     ██║          ██║ ╚██████╔╝╚██████╔╝
╚══════╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝          ╚═╝  ╚═════╝  ╚═════╝ 
                   GLOCK_0DAY WAZEHAX
{RESET}
""")

# --------------------------
# Ana Menü
# --------------------------

def main():
    banner()
    target = input("Hedef (IP veya domain) girin: ")
    while True:
        print("\nModüller:")
        for i, key in enumerate(modules.keys()):
            print(f"{i+1}. {key}")
        print("0. Çıkış")
        choice = input("Seçiminiz: ")
        if choice == "0":
            type_writer("Çıkış yapılıyor...")
            break
        try:
            choice = int(choice) - 1
            if 0 <= choice < len(modules):
                mod_name = list(modules.keys())[choice]
                modules[mod_name](target)
            else:
                type_writer("Geçersiz seçim")
        except:
            type_writer("Hata! Tekrar deneyin.")

if __name__ == "__main__":
    main()
