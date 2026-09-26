# -*- coding: utf-8 -*-
"""
ÜSTAD OSINT — Saldırı Yüzeyi ve SOC Konsolu (yerel arka uç)
============================================================
Tek dosya, yalnız Python standart kütüphanesi. Windows / Linux (Kali) / macOS.

  Çalıştır:  python ustad-osint.py            → http://127.0.0.1:8787
             python ustad-osint.py --port 9000 --disari-ac

Ne yapar:
  · Gerçek ağ taraması      : TCP bağlantı taraması + banner/servis tespiti (soket motoru)
  · nmap entegrasyonu       : nmap varsa -sV ile servis/versiyon taraması (yoksa soket motoru)
  · Saldırı yüzeyi haritası : her cihaz + her servis düğüm, risk ısısı ile
  · Alarm/triyaj motoru     : açık riskli portlar → alarm, önem derecesi, öneri
  · IOC çıkarımı            : banner/log içinden IP, alan adı, e-posta, hash
  · Dünya haritası          : IP konum çözümü (ipwho.is, anahtarsız) + özel ağ işareti
  · Log/SIEM analizi        : syslog / auth.log / Windows olay günlüğü satırlarını çözer
  · Rapor                   : JSON + TXT + yazdırılabilir HTML

YASAL: Bu araç yalnız KENDİ sistemleriniz veya YAZILI İZİN aldığınız sistemler için kullanılır.
İzinsiz tarama TCK 243/244 kapsamında suçtur. Tarama başlatmak için kapsam onayı zorunludur.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# --- Konsol kodlaması koruması (Windows'ta çökme önleyici) -------------------
# Windows'ta çıktı bir DOSYAYA yönlendirilince (ör. .bat içindeki >> gunluk.txt)
# Python yerel ANSI kod sayfasını (Türkçe sistemde cp1254) kullanır. Ok işareti
# (→) ve benzeri simgeler cp1254'te YOKTUR → UnicodeEncodeError ile sunucu
# açılışta ölür. Bu blok stdout/stderr'i UTF-8'e sabitler; kodlanamayan karakter
# olursa çökmek yerine '?' basar. SİLMEYİN.
for _ak in ("stdout", "stderr"):
    try:
        getattr(sys, _ak).reconfigure(encoding="utf-8", errors="replace",
                                      line_buffering=True)
    except Exception:
        pass

SURUM = "1.2"
KOK = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(KOK, "web")

# --- OSINT araç çekirdeği (osint-araclar.py) ---------------------------------
ARACLAR = None
try:
    import importlib.util as _iu

    _sp = _iu.spec_from_file_location("osint_araclar", os.path.join(KOK, "osint-araclar.py"))
    ARACLAR = _iu.module_from_spec(_sp)
    _sp.loader.exec_module(ARACLAR)
except Exception as _e:  # araç çekirdeği yoksa konsol yine çalışır
    ARACLAR = None

AYAR_DOSYA = os.path.join(KOK, "veri", "ayarlar.json")


def ayarlari_oku():
    try:
        with open(AYAR_DOSYA, encoding="utf-8") as f:
            a = json.load(f)
        return a if isinstance(a, dict) else {}
    except Exception:
        return {}


def ayarlari_yaz(a):
    try:
        os.makedirs(os.path.dirname(AYAR_DOSYA), exist_ok=True)
        with open(AYAR_DOSYA, "w", encoding="utf-8") as f:
            json.dump(a, f, ensure_ascii=False, indent=1)
        return True
    except Exception:
        return False


AYARLAR = ayarlari_oku()

# --------------------------------------------------------------------------- #
# 1) SABİTLER: port ön tanımları, servis tablosu, risk kuralları
# --------------------------------------------------------------------------- #

HIZLI_PORTLAR = [21, 22, 23, 25, 53, 69, 80, 110, 111, 135, 137, 139, 143, 161, 389, 443, 445, 465,
                 512, 513, 514, 587, 623, 636, 873, 993, 995, 1025, 1080, 1433, 1521, 1723, 2049,
                 2082, 2083, 2181, 2222, 2375, 3000, 3128, 3260, 3306, 3389, 4443, 5000, 5060, 5357,
                 5432, 5601, 5672, 5900, 5901, 5984, 5985, 6000, 6379, 7001, 8000, 8008, 8080, 8081,
                 8086, 8088, 8090, 8161, 8443, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 9418, 9999,
                 10000, 11211, 27017, 27018, 50000, 50070]

# port → (servis adı, taban önem, gerekçe)
RISK_TABLOSU = {
    21:    ("FTP", "yuksek", "FTP kimlik bilgileri şifresiz gider; anonim erişim riski"),
    23:    ("Telnet", "kritik", "Telnet tüm trafiği açık metin gönderir; yönetim için asla kullanılmamalı"),
    25:    ("SMTP", "orta", "Açık posta aktarımı spam rölesi olarak kullanılabilir"),
    53:    ("DNS", "orta", "Açık DNS çözümleyici amplifikasyon saldırılarında kullanılır"),
    69:    ("TFTP", "yuksek", "Kimlik doğrulaması yok, dosya okuma/yazma açık"),
    111:   ("rpcbind", "orta", "RPC port eşleyici bilgi sızdırır"),
    135:   ("MSRPC", "orta", "Windows RPC uç noktası; dış ağa açık olmamalı"),
    137:   ("NetBIOS-NS", "orta", "NetBIOS ad servisi bilgi sızdırır"),
    139:   ("NetBIOS-SSN", "yuksek", "SMB oturum servisi; yanal hareket için sık kullanılır"),
    161:   ("SNMP", "yuksek", "Varsayılan topluluk dizesi cihaz bilgilerini açığa çıkarır"),
    389:   ("LDAP", "orta", "Dizin servisi; anonim bağlama kapatılmalı"),
    445:   ("SMB", "kritik", "Fidye yazılımlarının ana yayılma yolu (EternalBlue ailesi)"),
    512:   ("rexec", "kritik", "Kimlik doğrulaması zayıf uzak komut çalıştırma"),
    513:   ("rlogin", "kritik", "Kimlik doğrulaması zayıf uzak oturum"),
    514:   ("rsh", "kritik", "Şifresiz uzak kabuk"),
    873:   ("rsync", "yuksek", "Anonim modül listeleme/kopyalama riski"),
    1080:  ("SOCKS", "yuksek", "Açık proxy; trafik yönlendirmesi için kötüye kullanılır"),
    1433:  ("MSSQL", "yuksek", "Veritabanı doğrudan ağa açık; brute-force hedefi"),
    1521:  ("Oracle", "yuksek", "Veritabanı doğrudan ağa açık"),
    2049:  ("NFS", "yuksek", "Paylaşımlar kimlik doğrulamasız bağlanabilir"),
    2375:  ("Docker API", "kritik", "Kimlik doğrulamasız Docker API = tam sunucu ele geçirme"),
    3306:  ("MySQL", "yuksek", "Veritabanı doğrudan ağa açık"),
    3389:  ("RDP", "kritik", "Fidye yazılımlarının en çok kullandığı giriş kapısı; NLA + MFA şart"),
    5060:  ("SIP", "orta", "VoIP; çağrı sahtekârlığı riski"),
    5432:  ("PostgreSQL", "yuksek", "Veritabanı doğrudan ağa açık"),
    5900:  ("VNC", "kritik", "Çoğu kurulumda zayıf/şifresiz ekran erişimi"),
    5901:  ("VNC-1", "kritik", "Çoğu kurulumda zayıf/şifresiz ekran erişimi"),
    5984:  ("CouchDB", "kritik", "Kimlik doğrulamasız ise tüm veriler açık"),
    6379:  ("Redis", "kritik", "Kimlik doğrulamasız Redis = uzaktan kod çalıştırma"),
    9200:  ("Elasticsearch", "kritik", "Kimlik doğrulamasız ise tüm indeksler açık"),
    11211: ("Memcached", "kritik", "Kimlik doğrulama yok; amplifikasyon + veri sızıntısı"),
    27017: ("MongoDB", "kritik", "Kimlik doğrulamasız MongoDB = tüm veritabanı açık"),
    50070: ("Hadoop NN", "kritik", "Kimlik doğrulamasız HDFS yönetim arayüzü"),
}

# banner içeriğinden servis/versiyon tahmini
BANNER_IMZALARI = [
    (re.compile(r"SSH-[\d.]+-([^\s]+)", re.I), "SSH", "ssh"),
    (re.compile(r"^(?:HTTP/[\d.]+ \d+|<!DOCTYPE|<!doctype|<html)", re.I), "HTTP", "http"),
    (re.compile(r"220[ -].*?(?:FTP|ProFTPD|vsFTPd|FileZilla|Microsoft FTP)", re.I), "FTP", "ftp"),
    (re.compile(r"220[ -].*?(?:SMTP|Postfix|Exim|Sendmail|ESMTP)", re.I), "SMTP", "smtp"),
    (re.compile(r"^\+OK.*(?:Dovecot|POP3)", re.I | re.M), "POP3", "pop3"),
    (re.compile(r"^\* OK.*(?:IMAP|Dovecot)", re.I | re.M), "IMAP", "imap"),
    (re.compile(r"(?:MySQL|MariaDB).*?(?:native|handshake)", re.I), "MySQL", "mysql"),
    (re.compile(r"(?:Redis|redis_version)", re.I), "Redis", "redis"),
    (re.compile(r"(?:MongoDB|mongod)", re.I), "MongoDB", "mongo"),
    (re.compile(r"RFB \d+\.\d+", re.I), "VNC", "vnc"),
    (re.compile(r"\x03\x00\x00", re.NOFLAG if hasattr(re, "NOFLAG") else 0), "RDP", "rdp"),
    (re.compile(r"(?:SMB|Windows)", re.I), "SMB", "smb"),
    (re.compile(r"(?:RTSP|Server:)", re.I), "RTSP/HTTP", "http"),
    (re.compile(r"(?:Elasticsearch|You Know, for Search)", re.I), "Elasticsearch", "elastic"),
    (re.compile(r"(?:Docker|Api-Version)", re.I), "Docker API", "docker"),
]

# log/SIEM kural imzaları  (regex, başlık, önem, açıklama)
LOG_KURALLARI = [
    (re.compile(r"\b4625\b|failed password|authentication failure|başarısız oturum", re.I),
     "Başarısız oturum açma", "orta", "Kısa sürede çok sayıda başarısız giriş brute-force işaretidir"),
    (re.compile(r"\b4624\b.*?(?:type\s*3|network)", re.I),
     "Ağ üzerinden oturum açma", "bilgi", "Uzak oturum; beklenmeyen kaynak ise inceleyin"),
    (re.compile(r"\b4720\b|useradd|new user|yeni kullanıcı", re.I),
     "Yeni kullanıcı oluşturma", "yuksek", "Yetkisiz kalıcılık (persistence) yöntemidir"),
    (re.compile(r"\b4672\b|special privileges assigned|sudo:.*COMMAND", re.I),
     "Yetki yükseltme", "yuksek", "Ayrıcalıklı yetki ataması; kim, ne zaman doğrulanmalı"),
    (re.compile(r"\b1102\b|audit log (?:was )?cleared|log temizl", re.I),
     "Denetim günlüğü temizlendi", "kritik", "Saldırgan izini silmeye çalışıyor olabilir"),
    (re.compile(r"\b4688\b.*?(?:powershell|cmd\.exe|wscript|certutil|bitsadmin)", re.I),
     "Şüpheli süreç çalıştırma", "yuksek", "İndirme/çalıştırma araçları tespit edildi"),
    (re.compile(r"nmap|masscan|nikto|sqlmap|hydra|gobuster|dirb", re.I),
     "Tarama aracı izi", "yuksek", "Keşif (recon) aşaması göstergesi"),
    (re.compile(r"union\s+select|or\s+1=1|<script>|\.\./\.\./|%27", re.I),
     "Web uygulama saldırı kalıbı", "kritik", "SQLi / XSS / yol geçişi denemesi"),
    (re.compile(r"segmentation fault|kernel panic|oom-killer", re.I),
     "Sistem kararsızlığı", "orta", "Doğrudan saldırı değil ama hizmet kesintisi riski"),
    (re.compile(r"\b(?:deny|block|drop)\b.*?(?:firewall|iptables|ufw)", re.I),
     "Güvenlik duvarı müdahalesi", "bilgi", "Kural tetiklendi; kaynak IP'yi izleyin"),
]

IOC_DESENLERI = [
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")),
    ("url", re.compile(r"\bhttps?://[^\s\"'<>)]+", re.I)),
    ("alan", re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|tr|info|biz|top|xyz|site|online|shop)\b", re.I)),
    ("eposta", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b", re.I)),
    ("sha256", re.compile(r"\b[a-f0-9]{64}\b", re.I)),
    ("sha1", re.compile(r"\b[a-f0-9]{40}\b", re.I)),
    ("md5", re.compile(r"\b[a-f0-9]{32}\b", re.I)),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)),
]

ONEM_SIRA = {"kritik": 0, "yuksek": 1, "orta": 2, "dusuk": 3, "bilgi": 4}
ONEM_ETIKET = {"kritik": "KRİTİK", "yuksek": "YÜKSEK", "orta": "ORTA", "dusuk": "DÜŞÜK", "bilgi": "BİLGİ"}


# --------------------------------------------------------------------------- #
# 2) YARDIMCILAR
# --------------------------------------------------------------------------- #

def simdi():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ozel_ip(ip):
    """RFC1918 / loopback / link-local / CGNAT → özel ağ."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
            or str(a).startswith("100.64.") or str(a).startswith("169.254."))


def yerel_ip():
    """Dışarı çıkarken kullanılan yerel IP (internet gerekmez)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def alt_ag(ip, maske=24):
    try:
        return str(ipaddress.ip_network(ip + "/" + str(maske), strict=False))
    except Exception:
        return ""


def nmap_yolu():
    y = shutil.which("nmap")
    if y:
        return y
    for aday in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe",
                 "/usr/bin/nmap", "/usr/local/bin/nmap"):
        if os.path.exists(aday):
            return aday
    return None


def port_listesi(mod, ek=""):
    if mod == "hizli":
        p = list(HIZLI_PORTLAR)
    elif mod == "yaygin":
        p = list(range(1, 1025))
    elif mod == "web":
        p = [80, 81, 443, 591, 2082, 2083, 2086, 2087, 2095, 2096, 3000, 4443, 5000, 8000, 8008,
             8080, 8081, 8088, 8090, 8443, 8888, 9000, 9090, 9443, 10000]
    elif mod == "tam":
        p = list(range(1, 65536))
    else:
        p = list(HIZLI_PORTLAR)
    if ek:
        for parca in re.split(r"[,\s]+", ek.strip()):
            if not parca:
                continue
            if "-" in parca:
                try:
                    a, b = parca.split("-")[:2]
                    p += list(range(int(a), int(b) + 1))
                except ValueError:
                    pass
            elif parca.isdigit():
                p.append(int(parca))
    return sorted(set(x for x in p if 1 <= x <= 65535))


def hedef_coz(metin):
    """'192.168.1.0/24', '10.0.0.5', 'localhost', 'ornek.com' → IP listesi."""
    metin = (metin or "").strip()
    if not metin:
        return []
    ip_listesi = []
    try:
        if "/" in metin:
            ag = ipaddress.ip_network(metin, strict=False)
            if ag.num_addresses > 4096:
                raise ValueError("Alt ağ çok büyük (en fazla /20 desteklenir)")
            return [str(x) for x in ag.hosts()]
        ipaddress.ip_address(metin)
        return [metin]
    except ValueError as e:
        if "çok büyük" in str(e):
            raise
    try:
        bilgi = socket.getaddrinfo(metin, None, socket.AF_INET)
        ip_listesi = sorted({x[4][0] for x in bilgi})
    except socket.gaierror:
        return []
    return ip_listesi


# --------------------------------------------------------------------------- #
# 3) TARAMA MOTORU (soket tabanlı)
# --------------------------------------------------------------------------- #

PORT_PROBLARI = {
    80: b"HEAD / HTTP/1.0\r\nHost: hedef\r\n\r\n",
    81: b"HEAD / HTTP/1.0\r\nHost: hedef\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: hedef\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: hedef\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\nHost: hedef\r\n\r\n",
    5000: b"HEAD / HTTP/1.0\r\nHost: hedef\r\n\r\n",
    21: b"", 23: b"", 22: b"", 25: b"EHLO ustad.osint\r\n",
    110: b"", 143: b"", 587: b"EHLO ustad.osint\r\n",
}

TLS_PORTLAR = {443, 465, 636, 993, 995, 8443, 9443, 4443, 2083, 2087, 2096}


def banner_al(ip, port, zaman_asimi=1.6):
    """Bağlan, uygun probu gönder, ilk baytları oku. Servis/versiyon tahmini için."""
    try:
        ham = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ham.settimeout(zaman_asimi)
        ham.connect((ip, port))
    except Exception:
        return None, None, None

    bilgi = {"banner": "", "tls": False, "sertifika": None}
    try:
        if port in TLS_PORTLAR:
            try:
                bag = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                bag.check_hostname = False
                bag.verify_mode = ssl.CERT_NONE
                s2 = bag.wrap_socket(ham, server_hostname=ip)
                bilgi["tls"] = True
                try:
                    sert = s2.getpeercert()
                    if sert:
                        bilgi["sertifika"] = {k: sert.get(k) for k in ("subject", "issuer", "notAfter") if sert.get(k)}
                except Exception:
                    pass
                ham = s2
            except Exception:
                # TLS el sıkışması düşerse Windows'ta alttaki soket geçersizleşir;
                # bu yüzden burada kesip çıkıyoruz (aksi halde WinError 10038).
                return bilgi["banner"], bilgi["sertifika"], bilgi["tls"]
        prob = PORT_PROBLARI.get(port, b"")
        if prob:
            try:
                ham.sendall(prob)
            except Exception:
                pass
        try:
            ham.settimeout(zaman_asimi)
            veri = ham.recv(2048)
        except Exception:
            veri = b""
        metin = veri.decode("utf-8", "replace")
        metin = "".join(c for c in metin if c == "\n" or c == "\t" or ord(c) >= 32)
        bilgi["banner"] = metin.strip()[:600]
    finally:
        try:
            ham.close()
        except Exception:
            pass
    return bilgi["banner"], bilgi["sertifika"], bilgi["tls"]


def servis_tahmin(port, banner):
    b = banner or ""
    for desen, ad, anahtar in BANNER_IMZALARI:
        if desen.search(b):
            m = re.search(r"([\w.\-]+)[/ ]([\d][\w.\-]*)", b)
            surum = (m.group(1) + " " + m.group(2)) if m else ""
            return ad, anahtar, surum
    if port in RISK_TABLOSU:
        return RISK_TABLOSU[port][0], RISK_TABLOSU[port][0].lower(), ""
    try:
        return socket.getservbyport(port).upper(), "bilinmeyen", ""
    except Exception:
        return "bilinmeyen", "bilinmeyen", ""


def port_tara(ip, port, zaman_asimi=0.9, banner_cek=True):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(zaman_asimi)
    try:
        if s.connect_ex((ip, port)) != 0:
            return None
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass
    kayit = {"port": port, "durum": "acik", "servis": "", "banner": "", "surum": "", "tls": False}
    if banner_cek:
        b, sert, tls = banner_al(ip, port)
        kayit["banner"] = b or ""
        kayit["tls"] = bool(tls)
        ad, anahtar, surum = servis_tahmin(port, b)
        kayit["servis"] = ad
        kayit["surum"] = surum
        if sert:
            kayit["sertifika"] = sert
    else:
        ad, anahtar, _ = servis_tahmin(port, "")
        kayit["servis"] = ad
    return kayit


def cihaz_canli(ip, portlar=(80, 443, 22, 445, 3389, 8080), zaman_asimi=0.5):
    """Basit ana makine keşfi: birkaç yaygın porta TCP bağlantısı + ping."""
    if ip in ("127.0.0.1", "localhost"):
        return True
    for p in portlar:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(zaman_asimi)
        try:
            if s.connect_ex((ip, p)) == 0:
                return True
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
    # ICMP ping (izin varsa)
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", "700", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=3)
        return r.returncode == 0
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# 4) RİSK · ALARM · IOC
# --------------------------------------------------------------------------- #

def risk_puani(hostlar):
    """0-100 arası yüzey riski: açık riskli servisler, servis sayısı, kritik protokoller."""
    puan = 0
    nedenler = []
    for h in hostlar:
        kritik = [p for p in h.get("portlar", []) if p.get("onem") == "kritik"]
        yuksek = [p for p in h.get("portlar", []) if p.get("onem") == "yuksek"]
        if kritik:
            puan += 18 * len(kritik)
            nedenler.append("%s: %d kritik servis açık (%s)" % (
                h["ip"], len(kritik), ", ".join(str(p["port"]) for p in kritik[:6])))
        if yuksek:
            puan += 7 * len(yuksek)
            nedenler.append("%s: %d yüksek riskli servis" % (h["ip"], len(yuksek)))
        if len(h.get("portlar", [])) >= 12:
            puan += 8
            nedenler.append("%s: çok sayıda açık port (%d) — gereksiz servisleri kapatın" % (h["ip"], len(h["portlar"])))
    return min(100, puan), nedenler[:12]


def alarm_uret(hostlar, tarama_id):
    alarmlar = []
    sayac = [1]

    def ekle(host, port, servis, onem, baslik, aciklama, kanit, oneri):
        alarmlar.append({
            "id": "%s-A%03d" % (tarama_id[:6], sayac[0]),
            "zaman": simdi(),
            "host": host,
            "port": port,
            "servis": servis,
            "onem": onem,
            "onemEtiket": ONEM_ETIKET.get(onem, onem.upper()),
            "baslik": baslik,
            "aciklama": aciklama,
            "kanit": kanit,
            "oneri": oneri,
            "durum": "yeni",
            "yanlisPozitif": False,
        })
        sayac[0] += 1

    for h in hostlar:
        for p in h.get("portlar", []):
            port = p["port"]
            bilgi = RISK_TABLOSU.get(port)
            if bilgi:
                ekle(h["ip"], port, p.get("servis", ""), bilgi[1],
                     "%s (%d) açık — %s" % (bilgi[0], port, ONEM_ETIKET.get(bilgi[1], bilgi[1])),
                     bilgi[2],
                     "banner: %s" % (p.get("banner", "")[:160] or "(yanıt yok)"),
                     _oneri(port))
            if p.get("banner") and re.search(r"(?:login|admin|default password|root:)", p["banner"], re.I):
                ekle(h["ip"], port, p.get("servis", ""), "yuksek",
                     "Yönetim/giriş arayüzü tespit edildi", "Banner metni giriş arayüzü işaret ediyor; "
                     "varsayılan parola denemesi ve erişim kısıtı kontrol edilmeli",
                     p["banner"][:200], "Arayüzü VPN/iç ağ ile sınırlayın, MFA ekleyin, varsayılan parolaları değiştirin")
            if p.get("tls"):
                ekle(h["ip"], port, p.get("servis", ""), "bilgi",
                     "TLS hizmeti doğrulandı", "Şifreli servis dinliyor; sertifika geçerliliği ve sürüm kontrol edilmeli",
                     "sertifika: %s" % json.dumps(p.get("sertifika"), ensure_ascii=False)[:200],
                     "TLS 1.2+ zorlayın; sertifika süresi ve zayıf takas algoritmalarını denetleyin")
    return alarmlar


def _oneri(port):
    tablo = {
        23: "Telnet yerine SSH kullanın ve 23 numaralı portu kapatın",
        21: "SFTP/FTPS'e geçin; ftp anonim erişimini kapatın (anon_upload, anon_mkdir)",
        3389: "RDP'yi VPN arkasına alın, NLA zorunlu + MFA; dışarıya 3389 açmayın",
        445: "SMB'yi yalnız iç ağa verin; SMBv1'i kapatın, imzalama ve fidye koruması açın",
        5900: "VNC'yi localhost'a bağlayın veya SSH tünelinden geçirin; güçlü parola şart",
        3306: "MySQL'i bind-address ile 127.0.0.1'e alın; kullanıcı bazlı IP kısıtı ekleyin",
        5432: "PostgreSQL'i listen_addresses ile iç ağla sınırlayın; scram-sha-256 kullanın",
        6379: "Redis'e requirepass + bind ekleyin; korumalı mod açık kalsın",
        9200: "Elasticsearch'te X-Pack güvenliğini açın; 9200'ü dışarıya kapatın",
        27017: "MongoDB yetkilendirmeyi açın (authorization: enabled), 27017'yi dışarıya kapatın",
        11211: "Memcached'i localhost'a bağlayın; UDP kapatın",
        2375: "Docker API'yi yalnız TLS + sertifika ile açın; 2375 asla açık olmasın",
        111: "rpcbind'i yalnız gerektiğinde ve iç ağda çalıştırın",
        161: "SNMPv3'e geçin; public/private topluluk dizelerini değiştirin",
        2049: "NFS ihracını IP ile sınırlayın, no_root_squash kullanmayın",
        1433: "MSSQL'i iç ağa alın; karma kimlik doğrulama ve güçlü parola zorunlu",
        1521: "Oracle listener'ı IP ile sınırlayın; gereksiz servisleri kapatın",
    }
    return tablo.get(port, "Bu servisi yalnız ihtiyaç halinde açık tutun; güvenlik duvarında kaynak IP kısıtı uygulayın")


def ioc_cikar(hostlar, alarmlar):
    bulunan = {}
    def ekle(tur, deger, kaynak):
        anahtar = (tur, deger.lower())
        if anahtar not in bulunan:
            bulunan[anahtar] = {"tur": tur, "deger": deger, "kaynak": [], "ilk": simdi()}
        if kaynak not in bulunan[anahtar]["kaynak"]:
            bulunan[anahtar]["kaynak"].append(kaynak)
    for h in hostlar:
        ekle("ipv4", h["ip"], "tarama:%s" % h["ip"])
        for p in h.get("portlar", []):
            metin = (p.get("banner") or "") + " " + (p.get("surum") or "")
            if not metin.strip():
                continue
            for tur, desen in IOC_DESENLERI:
                for eslesme in desen.findall(metin)[:6]:
                    if tur == "ipv4" and ozel_ip(eslesme):
                        continue
                    ekle(tur, eslesme, "%s:%d" % (h["ip"], p["port"]))
    for a in alarmlar:
        for tur, desen in IOC_DESENLERI:
            for eslesme in desen.findall(a.get("kanit") or "")[:4]:
                if tur == "ipv4" and ozel_ip(eslesme):
                    continue
                ekle(tur, eslesme, a["id"])
    return sorted(bulunan.values(), key=lambda x: (x["tur"], x["deger"]))


def saldiri_yuzeyi_grafigi(hostlar):
    """Harita/grafik için düğüm+kenar verisi. Düğümler: merkez(self) → cihaz → servis."""
    dugumler, kenarlar = [], []
    merkez = {"id": "self", "tip": "merkez", "ad": "ANALİZ NOKTASI", "ip": yerel_ip(), "risk": 0}
    dugumler.append(merkez)
    for i, h in enumerate(hostlar):
        kid = "h%d" % i
        deg = sum({"kritik": 34, "yuksek": 20, "orta": 10, "dusuk": 5, "bilgi": 1}.get(p.get("onem", "bilgi"), 3)
                  for p in h.get("portlar", []))
        dugumler.append({
            "id": kid, "tip": "cihaz", "ad": h.get("ad") or h["ip"], "ip": h["ip"],
            "risk": min(100, deg), "portSayisi": len(h.get("portlar", [])),
            "isletim": h.get("isletim", ""),
        })
        kenarlar.append({"kaynak": "self", "hedef": kid, "tip": "ağ"})
        for j, p in enumerate(h.get("portlar", [])):
            sid = "%s_p%d" % (kid, p["port"])
            dugumler.append({
                "id": sid, "tip": "servis", "ad": p.get("servis", "?"), "ip": h["ip"],
                "port": p["port"], "onem": p.get("onem", "bilgi"), "surum": p.get("surum", ""),
                "tls": p.get("tls", False), "riskli": p["port"] in RISK_TABLOSU,
            })
            kenarlar.append({"kaynak": kid, "hedef": sid, "tip": "port" if p["port"] in RISK_TABLOSU else "portN"})
    return {"dugumler": dugumler, "kenarlar": kenarlar}


# --------------------------------------------------------------------------- #
# 5) IP KONUM (dünya haritası)
# --------------------------------------------------------------------------- #

_geo_onbellek = {}
_geo_kilit = threading.Lock()


def konum_bul(ip):
    if ozel_ip(ip):
        return {"ip": ip, "tur": "ozel", "ulke": "Yerel ağ / özel adres", "ulkeKod": "", "sehir": "",
                "enlem": None, "boylam": None, "iss": "", "kaynak": "yerel"}
    with _geo_kilit:
        if ip in _geo_onbellek:
            return _geo_onbellek[ip]
    kaynaklar = [
        ("ipwho.is", "https://ipwho.is/%s", lambda d: {
            "enlem": d.get("latitude"), "boylam": d.get("longitude"), "ulke": d.get("country"),
            "ulkeKod": d.get("country_code"), "sehir": d.get("city"), "iss": (d.get("connection") or {}).get("isp", "")
        }),
        ("ip-api.com", "http://ip-api.com/json/%s?fields=status,country,countryCode,city,lat,lon,isp,query",
         lambda d: {"enlem": d.get("lat"), "boylam": d.get("lon"), "ulke": d.get("country"),
                    "ulkeKod": d.get("countryCode"), "sehir": d.get("city"), "iss": d.get("isp", "")}),
    ]
    for ad, sablon, ayikla in kaynaklar:
        try:
            istek = urllib.request.Request(sablon % ip, headers={"User-Agent": "UstadOSINT/1.0"})
            with urllib.request.urlopen(istek, timeout=6) as c:
                ham = json.loads(c.read().decode("utf-8", "replace"))
            if ham.get("status") in ("fail", False) or ham.get("success") is False:
                continue
            veri = ayikla(ham)
            if veri.get("enlem") is None:
                continue
            veri.update({"ip": ip, "tur": "genel", "kaynak": ad})
            with _geo_kilit:
                _geo_onbellek[ip] = veri
            return veri
        except Exception:
            continue
    veri = {"ip": ip, "tur": "bilinmiyor", "ulke": "çözümlenemedi", "ulkeKod": "", "sehir": "",
            "enlem": None, "boylam": None, "iss": "", "kaynak": "-"}
    with _geo_kilit:
        _geo_onbellek[ip] = veri
    return veri


def dis_ip_konum():
    """Kendi çıkış (genel) IP'mizin konumu — dünya haritasında 'bu cihaz' işareti için."""
    yip = yerel_ip()
    if not ozel_ip(yip):
        return konum_bul(yip)
    try:
        istek = urllib.request.Request("https://ipwho.is/", headers={"User-Agent": "UstadOSINT/1.0"})
        with urllib.request.urlopen(istek, timeout=7) as c:
            d = json.loads(c.read().decode("utf-8", "replace"))
        if d.get("success") is not False and d.get("ip"):
            veri = {"ip": d.get("ip"), "tur": "genel", "enlem": d.get("latitude"), "boylam": d.get("longitude"),
                    "ulke": d.get("country"), "ulkeKod": d.get("country_code"), "sehir": d.get("city"),
                    "iss": (d.get("connection") or {}).get("isp", ""), "kaynak": "ipwho.is", "kendi": True}
            with _geo_kilit:
                _geo_onbellek[veri["ip"]] = veri
            return veri
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------- #
# 6) TARAMA İŞİ (arka planda, ilerleme bildirimli)
# --------------------------------------------------------------------------- #

class TaramaIsi:
    def __init__(self, hedefler, portlar, mod, nmap_kullan, is_adi=""):
        self.id = uuid.uuid4().hex[:10]
        self.hedefler_input = hedefler
        self.port_listesi = portlar
        self.mod = mod
        self.nmap = nmap_kullan
        self.is_adi = is_adi
        self.durum = "hazir"          # hazir · calisiyor · bitti · iptal · hata
        self.asama = "başlatılıyor"
        self.yuzde = 0
        self.baslangic = simdi()
        self.bitis = None
        self.hostlar = []
        self.alarmlar = []
        self.iocler = []
        self.geo = []
        self.graf = {"dugumler": [], "kenarlar": []}
        self.risk = 0
        self.risk_nedenleri = []
        self.loglar = []
        self.hata = ""
        self.motor = "soket"
        self.iptal = False
        self.ham_nmap = ""
        self._kilit = threading.Lock()

    def log(self, metin):
        with self._kilit:
            self.loglar.append({"zaman": simdi(), "metin": metin})
            self.loglar = self.loglar[-400:]

    def ayarla(self, **kw):
        with self._kilit:
            for k, v in kw.items():
                setattr(self, k, v)

    def ozet(self, detay=True):
        d = {
            "id": self.id, "durum": self.durum, "asama": self.asama, "yuzde": self.yuzde,
            "baslangic": self.baslangic, "bitis": self.bitis, "motor": self.motor,
            "risk": self.risk, "riskNedenleri": self.risk_nedenleri,
            "hata": self.hata, "hedefler": self.hedefler_input, "portMod": self.mod,
            "loglar": self.loglar[-40:],
            "sayilar": {
                "cihaz": len(self.hostlar),
                "acikPort": sum(len(h.get("portlar", [])) for h in self.hostlar),
                "alarm": len(self.alarmlar),
                "kritik": len([a for a in self.alarmlar if a["onem"] == "kritik"]),
                "ioc": len(self.iocler),
                "konum": len([g for g in self.geo if g.get("enlem") is not None]),
            },
        }
        if detay:
            d.update({"hostlar": self.hostlar, "alarmlar": self.alarmlar, "iocler": self.iocler,
                      "geo": self.geo, "graf": self.graf, "nmapHam": self.ham_nmap[:20000]})
        return d

    # ---- asıl iş ----
    def calistir(self):
        try:
            self.ayarla(durum="calisiyor", asama="hedefler çözümleniyor")
            ip_listesi = []
            for h in self.hedefler_input:
                try:
                    ip_listesi += hedef_coz(h)
                except ValueError as e:
                    self.log("atlandı: %s (%s)" % (h, e))
            ip_listesi = sorted(set(ip_listesi), key=lambda x: tuple(int(y) for y in x.split(".")))
            if not ip_listesi:
                self.ayarla(durum="hata", hata="Geçerli hedef bulunamadı")
                return
            self.log("%d hedef çözümlendi" % len(ip_listesi))
            self.ayarla(asama="canlı cihazlar aranıyor", yuzde=5)

            canli = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as havuz:
                sonuc = list(havuz.map(cihaz_canli, ip_listesi))
            canli = [ip for ip, x in zip(ip_listesi, sonuc) if x]
            # hedef açıkça verilmiş tek IP ise (ve localhost değilse) yine de tara
            if not canli and len(ip_listesi) <= 4:
                canli = ip_listesi
                self.log("canlı tespiti boş döndü; verilen hedefler yine de taranıyor")
            self.log("%d canlı cihaz" % len(canli))
            self.ayarla(yuzde=12, asama="portlar taranıyor")

            nmap_yolu_ = nmap_yolu()
            if self.nmap and self.mod in ("yaygin", "tam"):
                self.nmap = True
            if self.nmap and self.mod == "tam":
                self.log("tam port nmap ile 1-65535 taranıyor (uzun sürebilir)")
            if self.nmap and nmap_yolu_:
                kalan = self._nmap_ile(canli, nmap_yolu_)
            else:
                if self.nmap and not nmap_yolu_:
                    self.log("nmap bulunamadı → soket motoruna geçildi")
                kalan = canli
            if kalan:
                self._soket_ile(kalan)

            if self.iptal:
                self.ayarla(durum="iptal", asama="kullanıcı iptal etti")
                return

            self.ayarla(asama="risk ve alarm motoru çalışıyor", yuzde=80)
            for h in self.hostlar:
                h["portlar"].sort(key=lambda p: p["port"])
                for p in h["portlar"]:
                    bilgi = RISK_TABLOSU.get(p["port"])
                    p["onem"] = bilgi[1] if bilgi else "bilgi"
                    p["gerekce"] = bilgi[2] if bilgi else ""
            alarmlar = alarm_uret(self.hostlar, self.id)
            iocler = ioc_cikar(self.hostlar, alarmlar)
            puan, nedenler = risk_puani(self.hostlar)
            self.ayarla(alarmlar=alarmlar, iocler=iocler, risk=puan, risk_nedenleri=nedenler,
                        yuzde=92, asama="IP konumları çözümleniyor")

            geo = []
            genel_ip = [h["ip"] for h in self.hostlar if not ozel_ip(h["ip"])]
            for ip in dict.fromkeys(genel_ip):
                geo.append(konum_bul(ip))
            kendi = dis_ip_konum()
            if kendi:
                geo.append(kendi)
            elif ozel_ip(yerel_ip()):
                geo.append({"ip": yerel_ip(), "tur": "ozel", "ulke": "Yerel ağ (özel adres)", "sehir": "",
                            "enlem": None, "boylam": None, "iss": "", "kaynak": "yerel"})
            for h in self.hostlar:
                if ozel_ip(h["ip"]):
                    geo.append({"ip": h["ip"], "tur": "ozel", "ulke": "Yerel ağ (özel adres)", "sehir": "",
                                "enlem": None, "boylam": None, "iss": "", "kaynak": "yerel"})
            self.ayarla(geo=geo, graf=saldiri_yuzeyi_grafigi(self.hostlar),
                        durum="bitti", yuzde=100, asama="tamamlandı", bitis=simdi())
            self.log("tarama tamamlandı: %d cihaz, %d alarm" % (len(self.hostlar), len(alarmlar)))
        except Exception as e:
            # kısmi sonuç varsa kaybetme: rapor yine üretilebilsin
            try:
                alarmlar = alarm_uret(self.hostlar, self.id) if self.hostlar else list(self.alarmlar or [])
                puan, nedenler = risk_puani(self.hostlar) if self.hostlar else (self.risk, self.risk_nedenleri)
                self.ayarla(alarmlar=alarmlar, risk=puan, risk_nedenleri=nedenler)
            except Exception:
                pass
            self.ayarla(durum="hata", hata="%s: %s" % (type(e).__name__, e), bitis=simdi(),
                        asama="hata ile durdu", yuzde=100)
            self.log("HATA: %s" % e)

    # ---- soket motoru ----
    def _soket_ile(self, ip_listesi):
        self.ayarla(motor="soket")
        portlar = self.port_listesi
        toplam = len(ip_listesi) * len(portlar)
        yapilan = [0]
        kilit = threading.Lock()

        def isle(ikili):
            if self.iptal:
                return None
            ip, port = ikili
            try:
                sonuc = port_tara(ip, port, zaman_asimi=0.9, banner_cek=(self.mod != "tam"))
            except Exception as e:
                # tek portluk hata tüm taramayı düşürmesin
                with kilit:
                    self.log("port atlandı %s:%d (%s)" % (ip, port, type(e).__name__))
                sonuc = None
            with kilit:
                yapilan[0] += 1
                if yapilan[0] % max(1, toplam // 100) == 0:
                    oran = 12 + int(65 * yapilan[0] / max(1, toplam))
                    self.ayarla(yuzde=min(77, oran))
            return (ip, sonuc)

        ip_haritasi = {ip: {"ip": ip, "ad": "", "portlar": [], "isletim": ""} for ip in ip_listesi}
        isler = [(ip, p) for ip in ip_listesi for p in portlar]
        with concurrent.futures.ThreadPoolExecutor(max_workers=180) as havuz:
            for ip, sonuc in filter(None, havuz.map(isle, isler)):
                if sonuc:
                    ip_haritasi[ip]["portlar"].append(sonuc)
        self.hostlar = [ip_haritasi[ip] for ip in ip_listesi if ip_haritasi[ip]["portlar"]]
        self.log("soket motoru: %d cihazda açık port bulundu" % len(self.hostlar))

    # ---- nmap motoru ----
    def _nmap_ile(self, ip_listesi, nmap_yolu_):
        """nmap -sT -sV ile zengin tarama; başarısız olursa soket motoruna düşer."""
        self.ayarla(motor="nmap")
        nmap_portlar = ",".join(str(p) for p in self.port_listesi) if self.mod != "tam" else "1-65535"
        basarili = []
        for baslangic in range(0, len(ip_listesi), 16):
            grup = ip_listesi[baslangic:baslangic + 16]
            komut = [nmap_yolu_, "-sT", "-sV", "--version-light", "-Pn", "-n", "--open",
                     "-p", nmap_portlar, "-oX", "-"] + grup
            self.log("nmap: %s" % " ".join(komut[:8] + ["..."]))
            try:
                r = subprocess.run(komut, capture_output=True, timeout=1800)
                xml = r.stdout.decode("utf-8", "replace")
            except Exception as e:
                self.log("nmap çalıştırılamadı (%s) → soket motoru" % e)
                return ip_listesi
            if "<nmaprun" not in xml:
                self.log("nmap çıktısı okunamadı → soket motoru")
                return ip_listesi
            self.ham_nmap = (self.ham_nmap + "\n" + xml)
            self._nmap_xml_isle(xml)
            bulunan = {h["ip"] for h in self.hostlar}
            basarili += grup
            self.ayarla(yuzde=min(78, 12 + int(65 * len(basarili) / max(1, len(ip_listesi)))))
        kalan = [ip for ip in ip_listesi if ip not in {h["ip"] for h in self.hostlar}]
        self.log("nmap bitti: %d cihaz bulundu" % len(self.hostlar))
        return kalan

    def _nmap_xml_isle(self, xml):
        import xml.etree.ElementTree as ET
        try:
            kok = ET.fromstring(xml)
        except ET.ParseError:
            return
        for host in kok.findall("host"):
            durum = host.find("status")
            if durum is not None and durum.get("state") != "up":
                continue
            adres = host.find("address")
            ip = adres.get("addr") if adres is not None else ""
            if not ip:
                continue
            kayit = {"ip": ip, "ad": "", "portlar": [], "isletim": ""}
            hn = host.find("hostnames/hostname")
            if hn is not None:
                kayit["ad"] = hn.get("name", "")
            os_ = host.find("os/osmatch")
            if os_ is not None:
                kayit["isletim"] = os_.get("name", "")
            for port in host.findall("ports/port"):
                if port.find("state") is not None and port.find("state").get("state") != "open":
                    continue
                servis = port.find("service")
                kayit["portlar"].append({
                    "port": int(port.get("portid")),
                    "durum": "acik",
                    "servis": (servis.get("name", "") if servis is not None else "").upper(),
                    "surum": "%s %s" % (servis.get("product", ""), servis.get("version", "")) if servis is not None else "",
                    "banner": (servis.get("extrainfo", "") if servis is not None else ""),
                    "tls": bool(servis is not None and servis.get("tunnel") == "ssl"),
                })
            if kayit["portlar"]:
                self.hostlar.append(kayit)


# --------------------------------------------------------------------------- #
# 7) LOG / SIEM ANALİZİ
# --------------------------------------------------------------------------- #

def log_coz(metin, kaynak_adi=""):
    satirlar = [s for s in metin.splitlines() if s.strip()]
    olaylar, bulgular = [], []
    sayac = {}
    for i, satir in enumerate(satirlar[:20000]):
        ip_m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", satir)
        zaman_m = re.search(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", satir)
        olay_id_m = re.search(r"\b(4\d{3}|11\d{2}|5\d{3})\b", satir)
        kayit = {
            "satir": i + 1, "zaman": zaman_m.group(1) if zaman_m else "",
            "ip": ip_m.group(0) if ip_m else "", "olayId": olay_id_m.group(1) if olay_id_m else "",
            "kural": "", "onem": "", "metin": satir[:400],
        }
        for desen, baslik, onem, aciklama in LOG_KURALLARI:
            if desen.search(satir):
                kayit["kural"], kayit["onem"] = baslik, onem
                anahtar = (baslik, kayit["ip"])
                sayac[anahtar] = sayac.get(anahtar, 0) + 1
                if sayac[anahtar] == 1:
                    bulgular.append({
                        "zaman": kayit["zaman"] or simdi(), "onem": onem, "onemEtiket": ONEM_ETIKET[onem],
                        "baslik": baslik, "ip": kayit["ip"], "olayId": kayit["olayId"],
                        "aciklama": aciklama, "kanit": satir[:300], "adet": 1,
                    })
                break
        olaylar.append(kayit)
    # sayaçları bulgulara işle (brute-force eşiği)
    for b in bulgular:
        b["adet"] = sayac.get((b["baslik"], b["ip"]), 1)
    for b in bulgular:
        if b["adet"] >= 8 and b["onem"] in ("orta", "dusuk"):
            b["onem"], b["onemEtiket"] = "kritik", "KRİTİK"
            b["aciklama"] += " · Aynı kaynaktan %d tekrar: otomatik blok önerilir" % b["adet"]
    iocler = []
    for tur, desen in IOC_DESENLERI:
        for deger in list(dict.fromkeys(desen.findall(metin)))[:80]:
            if tur == "ipv4" and ozel_ip(deger):
                continue
            iocler.append({"tur": tur, "deger": deger, "kaynak": [kaynak_adi or "log"]})
    return {"satirSayisi": len(satirlar), "olaylar": olaylar[:3000], "bulgular": bulgular,
            "iocler": iocler, "ozet": _log_ozet(olaylar, bulgular, kaynak_adi)}


def _log_ozet(olaylar, bulgular, kaynak_adi):
    sayac = {}
    for o in olaylar:
        if o["kural"]:
            sayac[o["kural"]] = sayac.get(o["kural"], 0) + 1
    ip_sayac = {}
    for o in olaylar:
        if o["ip"]:
            ip_sayac[o["ip"]] = ip_sayac.get(o["ip"], 0) + 1
    return {
        "kaynak": kaynak_adi or "yapıştırılan metin",
        "satir": len(olaylar),
        "kuralSayaci": sorted(sayac.items(), key=lambda x: -x[1]),
        "enCokIp": sorted(ip_sayac.items(), key=lambda x: -x[1])[:10],
        "kritik": len([b for b in bulgular if b["onem"] == "kritik"]),
        "yuksek": len([b for b in bulgular if b["onem"] == "yuksek"]),
    }


# --------------------------------------------------------------------------- #
# 8) HTTP SUNUCU (API + arayüz)
# --------------------------------------------------------------------------- #

ISLER = {}
ONAY = {"verildi": False, "metin": "", "zaman": "", "kapsam": []}


class IstekIsleyici(SimpleHTTPRequestHandler):
    sunucu_surum = "UstadOSINT/1.0"

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=WEB, **kw)

    def log_message(self, kalip, *args):
        pass  # konsolu kirletme

    # --- yardımcılar ---
    def _json(self, veri, kod=200):
        govde = json.dumps(veri, ensure_ascii=False).encode("utf-8")
        self.send_response(kod)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(govde)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(govde)

    def _oku(self):
        uzunluk = int(self.headers.get("Content-Length") or 0)
        if not uzunluk:
            return {}
        try:
            return json.loads(self.rfile.read(uzunluk).decode("utf-8", "replace"))
        except Exception:
            return {}

    def _statik(self, yol):
        if yol in ("/", ""):
            yol = "/index.html"
        hedef = os.path.normpath(os.path.join(WEB, yol.lstrip("/")))
        if not hedef.startswith(WEB) or not os.path.exists(hedef):
            # 404 gövdesi ASCII olmalı: http.server durum mesajını latin-1 ile kodlar,
            # Türkçe karakter verilirse UnicodeEncodeError ile istek işleyicisi çöker.
            self._json({"hata": "bulunamadi", "yol": yol}, 404)
            return
        tip = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
               ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
               ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml",
               ".woff2": "font/woff2"}.get(os.path.splitext(hedef)[1], "application/octet-stream")
        with open(hedef, "rb") as f:
            veri = f.read()
        self.send_response(200)
        self.send_header("Content-Type", tip)
        self.send_header("Content-Length", str(len(veri)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(veri)

    # --- GET ---
    def do_GET(self):
        yol = self.path.split("?")[0]
        sorgu = {}
        if "?" in self.path:
            for parca in self.path.split("?", 1)[1].split("&"):
                if "=" in parca:
                    k, v = parca.split("=", 1)
                    sorgu[k] = urllib.request.unquote(v)
        if yol == "/api/durum":
            ip = yerel_ip()
            return self._json({
                "surum": SURUM, "zaman": simdi(), "yerelIp": ip, "altAg": alt_ag(ip),
                "nmap": bool(nmap_yolu()), "nmapYolu": nmap_yolu() or "",
                "isletim": sys.platform, "python": sys.version.split()[0],
                "onay": ONAY, "taramaSayisi": len(ISLER),
                "taramaMotorlari": ["nmap" if nmap_yolu() else "soket(yerleşik)"],
                "disIp": dis_ip_konum(),
            })
        if yol.startswith("/api/geo/"):
            return self._json(konum_bul(yol.split("/")[-1]))
        if yol == "/api/tarama/liste":
            return self._json([t.ozet(False) for t in ISLER.values()][::-1])
        if yol.startswith("/api/tarama/"):
            tid = yol.split("/")[3]
            isi = ISLER.get(tid)
            if not isi:
                return self._json({"hata": "tarama bulunamadı"}, 404)
            return self._json(isi.ozet(True))
        if yol.startswith("/api/rapor/"):
            tid = yol.split("/")[3]
            isi = ISLER.get(tid)
            if not isi:
                return self._json({"hata": "tarama bulunamadı"}, 404)
            tip = sorgu.get("tip", "json")
            if tip == "txt":
                metin = rapor_txt(isi)
                govde = metin.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="ustad-osint-rapor-%s.txt"' % tid)
                self.send_header("Content-Length", str(len(govde)))
                self.end_headers()
                self.wfile.write(govde)
                return
            return self._json({"id": tid, "rapor": rapor_nesne(isi), "metin": rapor_txt(isi)})
        if yol.startswith("/api/arac"):
            if ARACLAR is None:
                return self._json({"hata": "araç çekirdeği yüklenemedi (osint-araclar.py)"}, 500)
            try:
                veri, kod = ARACLAR.uclari_isle(yol, sorgu, {}, AYARLAR)
            except Exception as e:
                veri, kod = {"hata": "araç hatası: %s" % e}, 500
            return self._json(veri, kod)
        if yol == "/api/ayar/anahtarlar":
            return self._json({"github": bool(AYARLAR.get("github_anahtar")),
                               "hibp": bool(AYARLAR.get("hibp_anahtar"))})
        return self._statik(yol)

    # --- POST ---
    def do_POST(self):
        yol = self.path.split("?")[0]
        govde = self._oku()
        if yol == "/api/onay":
            ONAY["verildi"] = bool(govde.get("onay"))
            ONAY["metin"] = str(govde.get("metin") or "")
            ONAY["kapsam"] = govde.get("kapsam") or []
            ONAY["zaman"] = simdi()
            return self._json({"tamam": True, "onay": ONAY})
        if yol == "/api/tarama":
            if not ONAY["verildi"]:
                return self._json({"hata": "Kapsam onayı verilmedi. Yalnız kendi sistemleriniz veya yazılı izin "
                                            "aldığınız sistemler için tarama yapılabilir."}, 403)
            hedefler = govde.get("hedefler") or []
            if isinstance(hedefler, str):
                hedefler = [x for x in re.split(r"[,\s]+", hedefler) if x]
            if not hedefler:
                return self._json({"hata": "Hedef gerekli (ör. 192.168.1.0/24 veya 10.0.0.15)"}, 400)
            mod = govde.get("mod") or "hizli"
            portlar = port_listesi(mod, govde.get("ekPortlar") or "")
            isi = TaramaIsi(hedefler, portlar, mod, bool(govde.get("nmap")),
                            str(govde.get("ad") or ""))
            ISLER[isi.id] = isi
            threading.Thread(target=isi.calistir, daemon=True).start()
            return self._json({"id": isi.id, "portSayisi": len(portlar), "mod": mod,
                               "motor": "nmap" if (isi.nmap and nmap_yolu()) else "soket"})
        if yol.startswith("/api/tarama/") and yol.endswith("/dur"):
            tid = yol.split("/")[3]
            if tid in ISLER:
                ISLER[tid].iptal = True
                return self._json({"tamam": True})
            return self._json({"hata": "yok"}, 404)
        if yol == "/api/logcoz":
            metin = govde.get("metin") or ""
            if not metin.strip():
                return self._json({"hata": "Log metni boş"}, 400)
            return self._json(log_coz(metin, govde.get("kaynak") or ""))
        if yol == "/api/alarm/durum":
            tid, aid, yeni = govde.get("tarama"), govde.get("alarm"), govde.get("durum")
            isi = ISLER.get(tid)
            if not isi:
                return self._json({"hata": "tarama yok"}, 404)
            for a in isi.alarmlar:
                if a["id"] == aid:
                    a["durum"] = yeni
                    if govde.get("yanlisPozitif") is not None:
                        a["yanlisPozitif"] = bool(govde["yanlisPozitif"])
                    return self._json({"tamam": True, "alarm": a})
            return self._json({"hata": "alarm yok"}, 404)
        if yol.startswith("/api/arac"):
            if ARACLAR is None:
                return self._json({"hata": "araç çekirdeği yüklenemedi (osint-araclar.py)"}, 500)
            try:
                veri, kod = ARACLAR.uclari_isle(yol, {}, govde, AYARLAR)
            except Exception as e:
                veri, kod = {"hata": "araç hatası: %s" % e}, 500
            return self._json(veri, kod)
        if yol == "/api/ayar/anahtarlar":
            for k in ("github_anahtar", "hibp_anahtar"):
                if k in govde:
                    v = str(govde.get(k) or "").strip()
                    if v:
                        AYARLAR[k] = v
                    else:
                        AYARLAR.pop(k, None)
            ayarlari_yaz(AYARLAR)
            return self._json({"tamam": True, "github": bool(AYARLAR.get("github_anahtar")),
                               "hibp": bool(AYARLAR.get("hibp_anahtar"))})
        return self._json({"hata": "uç nokta yok"}, 404)


# --------------------------------------------------------------------------- #
# 9) RAPOR
# --------------------------------------------------------------------------- #

def rapor_nesne(isi):
    return {
        "baslik": "ÜSTAD OSINT — Saldırı Yüzeyi Raporu",
        "surum": SURUM, "taramaId": isi.id, "baslangic": isi.baslangic, "bitis": isi.bitis,
        "hedefler": isi.hedefler_input, "portModu": isi.mod, "motor": isi.motor,
        "riskPuani": isi.risk, "riskNedenleri": isi.risk_nedenleri,
        "cihazlar": isi.hostlar, "alarmlar": isi.alarmlar, "iocler": isi.iocler,
        "konumlar": isi.geo,
        "yasal": "Bu rapor, sahibi olduğunuz veya yazılı izin aldığınız sistemlerde yapılan taramaya aittir. "
                 "İzinsiz tarama TCK 243/244 kapsamında suçtur.",
    }


def rapor_txt(isi):
    c = []
    c.append("=" * 78)
    c.append("ÜSTAD OSINT — SALDIRI YÜZEYİ VE SOC RAPORU")
    c.append("Tarama: %s · Motor: %s · Port modu: %s" % (isi.id, isi.motor, isi.mod))
    c.append("Başlangıç: %s · Bitiş: %s" % (isi.baslangic, isi.bitis or "-"))
    c.append("Hedefler: %s" % ", ".join(isi.hedefler_input))
    c.append("=" * 78)
    c.append("")
    c.append("ÖZET")
    c.append("  Cihaz            : %d" % len(isi.hostlar))
    c.append("  Açık port        : %d" % sum(len(h["portlar"]) for h in isi.hostlar))
    c.append("  Alarm            : %d (kritik %d)" % (len(isi.alarmlar),
                                                    len([a for a in isi.alarmlar if a["onem"] == "kritik"])))
    c.append("  IOC              : %d" % len(isi.iocler))
    c.append("  Yüzey risk puanı : %d/100" % isi.risk)
    for n in isi.risk_nedenleri:
        c.append("    - %s" % n)
    c.append("")
    c.append("CİHAZLAR VE AÇIK PORTLAR")
    for h in isi.hostlar:
        c.append("  [%s] %s" % (h["ip"], h.get("ad") or ""))
        for p in h["portlar"]:
            c.append("      %-6d %-18s %-10s %s" % (p["port"], p.get("servis", "?"),
                                                     ONEM_ETIKET.get(p.get("onem", "bilgi"), ""),
                                                     (p.get("surum") or p.get("banner", "")[:60]).replace("\n", " ")))
    c.append("")
    c.append("ALARMLAR")
    for a in sorted(isi.alarmlar, key=lambda x: ONEM_SIRA.get(x["onem"], 9)):
        c.append("  [%s] %s  (%s)" % (a["onemEtiket"], a["baslik"], a["host"]))
        c.append("      %s" % a["aciklama"])
        c.append("      ÖNERİ: %s" % a["oneri"])
        c.append("      KANIT: %s" % (a["kanit"] or "").replace("\n", " ")[:200])
    c.append("")
    c.append("IOC (İZ GÖSTERGELERİ)")
    for i in isi.iocler:
        c.append("  %-7s %s" % (i["tur"], i["deger"]))
    c.append("")
    c.append("IP KONUMLARI")
    for g in isi.geo:
        c.append("  %-16s %-28s %s" % (g["ip"], g.get("ulke") or "-", g.get("iss") or ""))
    c.append("")
    c.append("YASAL UYARI")
    c.append("  Bu rapor, sahibi olduğunuz veya yazılı izin aldığınız sistemlerde yapılan taramaya aittir.")
    c.append("  İzinsiz tarama TCK 243/244 kapsamında suçtur.")
    c.append("  ÜSTAD OSINT v%s · %s" % (SURUM, simdi()))
    return "\n".join(c)


# --------------------------------------------------------------------------- #

class TekSunucu(ThreadingHTTPServer):
    """Windows'ta iki kopyanın aynı portu paylaşmasını engeller."""
    allow_reuse_address = False


def main():
    ap = argparse.ArgumentParser(description="ÜSTAD OSINT — Saldırı Yüzeyi ve SOC Konsolu")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--disari-ac", action="store_true", help="0.0.0.0 üzerinde dinle (telefondan erişim için)")
    ap.add_argument("--tarama", help="arayüzü açmadan komut satırından tarama yap (ör. 192.168.1.0/24)")
    ap.add_argument("--mod", default="hizli", choices=["hizli", "web", "yaygin", "tam"])
    ap.add_argument("--nmap", action="store_true")
    ap.add_argument("--rapor", help="rapor dosyası yolu (txt)")
    a = ap.parse_args()

    if a.tarama:
        ONAY["verildi"] = True
        ONAY["metin"] = "komut satırı kullanımı"
        isi = TaramaIsi([a.tarama], port_listesi(a.mod), a.mod, a.nmap)
        ISLER[isi.id] = isi
        isi.calistir()
        print(rapor_txt(isi))
        if a.rapor:
            with open(a.rapor, "w", encoding="utf-8") as f:
                f.write(rapor_txt(isi))
            print("\nrapor yazıldı: %s" % a.rapor)
        return

    host = "0.0.0.0" if a.disari_ac else "127.0.0.1"
    ip = yerel_ip()
    print("=" * 70)
    print("  ÜSTAD OSINT v%s — Saldırı Yüzeyi ve SOC Konsolu" % SURUM)
    print("=" * 70)
    print("  Arayüz      : http://%s:%d" % ("127.0.0.1" if a.disari_ac else ip, a.port))
    print("  Yerel IP    : %s   (%s)" % (ip, alt_ag(ip)))
    print("  nmap        : %s" % (nmap_yolu() or "YOK → yerleşik soket motoru kullanılacak"))
    print("  Python      : %s" % sys.version.split()[0])
    print("")
    print("  YASAL: Yalnız kendi sistemleriniz veya yazılı izin aldığınız sistemleri tarayın.")
    print("         İzinsiz tarama TCK 243/244 kapsamında suçtur.")
    print("=" * 70)
    srv = None
    try:
        srv = TekSunucu((host, a.port), IstekIsleyici)
    except OSError as e:
        print("")
        print("  [HATA] %d numaralı port kullanımda — konsol zaten açık olabilir." % a.port)
        print("         Açık pencereyi kapatın ya da: python ustad-osint.py --port 8788")
        print("         (%s)" % e)
        print("")
        return
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nkapatıldı.")


if __name__ == "__main__":
    main()
