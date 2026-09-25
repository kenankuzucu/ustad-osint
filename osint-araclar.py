# -*- coding: utf-8 -*-
"""
ÜSTAD OSINT — OSINT ARAÇ ÇEKİRDEĞİ (gerçek veri, demo yok)
Tüm toplayıcılar canlı ücretsiz kaynakları kullanır:
  DNS → dns.google (DoH)          WHOIS → rdap.org          IP/ASN → ip-api.com + RDAP
  Subdomain → subdomain.center, hackertarget, crt.sh
  Web teknoloji → canlı HTTP başlıkları + gövde izleri + TLS sertifikası
  Cloud → S3 / GCS / Azure kova varlık kontrolü
  E-posta → sözdizimi + MX (DoH) + tek kullanımlık liste + Gravatar
  Kullanıcı adı → platform varlık kuralları (durum kodu + içerik işareti)
  GitHub → api.github.com
  Veri sızıntısı → açık dosya/konfig probu (.env, .git/config, yedekler, phpinfo…)
  Tehdit → abuse.ch Feodo + OpenPhish + EmergingThreats + Spamhaus DROP
"""
import base64
import concurrent.futures as cf
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) USTAD-OSINT/1.2", "Accept": "*/*"}
SURUM = "1.5"

for _yol in [os.path.join(os.path.dirname(os.path.abspath(__file__)), "ca-bundle.pem"),
             r"C:\Users\kenan\ca-bundle.pem", os.path.expanduser("~/ca-bundle.pem")]:
    if os.path.exists(_yol):
        os.environ.setdefault("SSL_CERT_FILE", _yol)
        break

BAG = ssl.create_default_context()


# --------------------------------------------------------------------------- #
#  yardımcılar
# --------------------------------------------------------------------------- #
def _cek(url, veri=None, baslik=None, tip=None, zaman=12, ham=False):
    """HTTP isteği → (kod, gövde_metni|bayt, süre). Hata durumunda (0, '', süre)."""
    t0 = time.time()
    b = dict(UA)
    if baslik:
        b.update(baslik)
    if veri is not None and tip is None:
        tip = "application/x-www-form-urlencoded"
    if tip:
        b["Content-Type"] = tip
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=veri, headers=b), timeout=zaman, context=BAG) as y:
            g = y.read(2000000)
            return y.status, (g if ham else g.decode("utf-8", "replace")), round(time.time() - t0, 2)
    except urllib.error.HTTPError as e:
        try:
            g = e.read(2000000)
        except Exception:
            g = b""
        return e.code, (g if ham else g.decode("utf-8", "replace")), round(time.time() - t0, 2)
    except Exception:
        return 0, (b"" if ham else ""), round(time.time() - t0, 2)


def _json(url, veri=None, baslik=None, tip=None, zaman=12):
    kod, govde, sure = _cek(url, veri, baslik, tip, zaman)
    try:
        return kod, json.loads(govde), sure
    except Exception:
        return kod, None, sure


def _kok(hedef):
    """'https://www.ornek.com/yol' → ('ornek.com', 'https://www.ornek.com/yol')"""
    h = (hedef or "").strip()
    if not h:
        return "", ""
    if "://" not in h:
        h = "http://" + h
    p = urllib.parse.urlsplit(h)
    ad = (p.hostname or "").lower()
    return ad, h


def _alan_bul(hedef):
    """Girdiden alan adı çıkar: URL, e-posta, alt alan → kök alan."""
    ad, _ = _kok(hedef)
    if "@" in (hedef or "") and not ad:
        ad = hedef.split("@")[-1].strip().lower()
    ad = ad.strip(".")
    return ad


def ozel_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except Exception:
        return True


# --------------------------------------------------------------------------- #
#  1) DNS  (DoH)
# --------------------------------------------------------------------------- #
DNS_TIPLERI = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA", "SRV"]


def dns_sorgu(ad, tip="A"):
    kod, j, sure = _json("https://dns.google/resolve?name=%s&type=%s" % (urllib.parse.quote(ad), tip), zaman=10)
    kayitlar = []
    if isinstance(j, dict):
        for c in j.get("Answer", []) or []:
            deger = c.get("data", "")
            if tip == "TXT" and isinstance(deger, str):
                deger = deger.strip('"')
            if tip == "MX" and isinstance(deger, str):
                deger = deger.split(" ", 1)[-1].strip(".")
            if tip == "SOA" and isinstance(deger, str):
                deger = deger.split(" ")[0]
            kayitlar.append({"ad": c.get("name", ""), "tip": c.get("type"), "deger": deger,
                             "ttl": c.get("TTL")})
    return {"tip": tip, "kayitlar": kayitlar, "durum": (j or {}).get("Status") if isinstance(j, dict) else None, "sure": sure}


def dns_toplu(ad):
    with cf.ThreadPoolExecutor(max_workers=9) as h:
        sonuc = dict(zip(DNS_TIPLERI, h.map(lambda t: dns_sorgu(ad, t), DNS_TIPLERI)))
    # özet
    a = [k["deger"] for k in sonuc["A"]["kayitlar"]]
    ozet = {
        "a": a[:12], "aaaa": [k["deger"] for k in sonuc["AAAA"]["kayitlar"]][:8],
        "mx": [k["deger"] for k in sonuc["MX"]["kayitlar"]][:12],
        "ns": [k["deger"] for k in sonuc["NS"]["kayitlar"]][:12],
        "txt": [k["deger"] for k in sonuc["TXT"]["kayitlar"]][:20],
        "cname": [k["deger"] for k in sonuc["CNAME"]["kayitlar"]][:6],
    }
    uyari = []
    txt_birlesik = " ".join(ozet["txt"]).lower()
    if "v=spf1" not in txt_birlesik:
        uyari.append({"onem": "yuksek", "baslik": "SPF kaydı yok", "aciklama": "E-posta sahteciliğine açık (spoofing)."})
    if "v=dmarc" not in txt_birlesik:
        uyari.append({"onem": "orta", "baslik": "DMARC kaydı yok", "aciklama": "Alan adı adına sahte e-posta gönderilebilir."})
    if not ozet["mx"]:
        uyari.append({"onem": "bilgi", "baslik": "MX kaydı yok", "aciklama": "Bu alan adı e-posta kabul etmiyor."})
    return {"ad": ad, "kayitlar": sonuc, "ozet": ozet, "uyarilar": uyari,
            "kaynak": "dns.google DoH", "zaman": time.strftime("%Y-%m-%d %H:%M:%S")}


# --------------------------------------------------------------------------- #
#  2) WHOIS / RDAP
# --------------------------------------------------------------------------- #
def whois_rdap(hedef):
    ad = _alan_bul(hedef)
    if not ad:
        return {"hata": "hedef çözümlenemedi"}
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ad):
        return ip_analiz(ad)
    kod, j, sure = _json("https://rdap.org/domain/" + urllib.parse.quote(ad), zaman=15)
    if not isinstance(j, dict):
        kod2, j2, sure2 = _json("https://rdap.org/domain/" + urllib.parse.quote(ad) + "?format=json", zaman=15)
        j, sure = (j2, sure2)
    if not isinstance(j, dict):
        return {"ad": ad, "hata": "RDAP yanıtı alınamadı (kod %s)" % kod, "kaynak": "rdap.org"}
    olay = {}
    for o in j.get("events", []) or []:
        olay[o.get("eventAction", "?")] = o.get("eventDate", "")
    ns = [n.get("ldhName", "").lower() for n in j.get("nameservers", []) or []]
    kayitci = ""
    kisiler = []
    for v in j.get("entities", []) or []:
        roller = v.get("roles", []) or []
        ad_v = ""
        for vc in v.get("vcardArray", [[], []])[1] if v.get("vcardArray") else []:
            if vc[0] == "fn":
                ad_v = vc[3]
        if "registrar" in roller:
            kayitci = ad_v or v.get("handle", "")
        elif roller:
            kisiler.append({"rol": ",".join(roller), "ad": ad_v or v.get("handle", "")})
    durum = j.get("status", []) or []
    uyari = []
    if any(s in ("client hold", "server hold", "suspended") for s in durum):
        uyari.append({"onem": "kritik", "baslik": "Alan adı askıda", "aciklama": " ".join(durum)})
    bitis = olay.get("expiration", "")
    if bitis:
        try:
            kalan = (time.mktime(time.strptime(bitis[:10], "%Y-%m-%d")) - time.time()) / 86400
            if kalan < 30:
                uyari.append({"onem": "orta", "baslik": "Süre yakında bitiyor",
                              "aciklama": "%d gün kaldı (%s)" % (int(kalan), bitis[:10])})
        except Exception:
            pass
    return {"ad": ad, "kaynak": "rdap.org", "olusturma": olay.get("registration", ""),
            "guncelleme": olay.get("last changed", ""), "bitis": bitis, "kayitci": kayitci,
            "ns": ns, "durum": durum, "kisiler": kisiler[:8], "uyarilar": uyari,
            "rdap_url": "https://rdap.org/domain/" + ad, "sure": sure}


# --------------------------------------------------------------------------- #
#  3) IP / ASN analizi
# --------------------------------------------------------------------------- #
def ip_analiz(ip):
    ip = (ip or "").strip()
    if not ip:
        return {"hata": "IP gerekli"}
    kod, j, sure = _json("http://ip-api.com/json/%s?fields=status,message,continent,country,countryCode,regionName,"
                         "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
                         % urllib.parse.quote(ip), zaman=12)
    if not isinstance(j, dict) or j.get("status") != "success":
        # ipwho.is yedeği
        kod2, j2, sure2 = _json("https://ipwho.is/" + urllib.parse.quote(ip), zaman=12)
        if isinstance(j2, dict) and j2.get("success"):
            return {"ip": ip, "kaynak": "ipwho.is", "ulke": j2.get("country"), "ulke_kodu": j2.get("country_code"),
                    "sehir": j2.get("city"), "bolge": j2.get("region"), "enlem": j2.get("latitude"),
                    "boylam": j2.get("longitude"), "iss": (j2.get("connection") or {}).get("isp"),
                    "org": (j2.get("connection") or {}).get("org"), "asn": (j2.get("connection") or {}).get("asn"),
                    "ozel": ozel_ip(ip), "sure": sure2}
        return {"ip": ip, "hata": (j or {}).get("message", "IP bilgisi alınamadı"), "ozel": ozel_ip(ip)}
    asn = (j.get("as") or "").split(" ")[0]
    rdap_ag = {}
    if not ozel_ip(ip):
        kod_r, jr, _ = _json("https://rdap.org/ip/" + urllib.parse.quote(ip), zaman=15)
        if isinstance(jr, dict):
            rdap_ag = {"ag": jr.get("name") or jr.get("handle"), "baslangic": jr.get("startAddress"),
                       "bitis": jr.get("endAddress"), "ulke": jr.get("country"),
                       "tip": jr.get("type"), "kurum": jr.get("port43", "")}
    return {"ip": ip, "kaynak": "ip-api.com", "ulke": j.get("country"), "ulke_kodu": j.get("countryCode"),
            "sehir": j.get("city"), "bolge": j.get("regionName"), "posta": j.get("zip"),
            "enlem": j.get("lat"), "boylam": j.get("lon"), "iss": j.get("isp"), "org": j.get("org"),
            "asn": asn, "as_ad": j.get("asname"), "ters_dns": j.get("reverse"), "mobil": j.get("mobile"),
            "proxy": j.get("proxy"), "hosting": j.get("hosting"), "ag": rdap_ag, "ozel": ozel_ip(ip),
            "sure": sure}


# --------------------------------------------------------------------------- #
#  4) Subdomain tarama
# --------------------------------------------------------------------------- #
def _crt_sh(ad):
    kod, govde, _ = _cek("https://crt.sh/?q=%25." + urllib.parse.quote(ad) + "&output=json", zaman=20)
    if kod != 200:
        return []
    try:
        j = json.loads(govde)
    except Exception:
        return []
    adlar = set()
    for k in j:
        for x in str(k.get("name_value", "")).split("\n"):
            x = x.strip().lower().lstrip("*.")
            if x.endswith(ad) and "@" not in x and " " not in x:
                adlar.add(x)
    return sorted(adlar)


def subdomain_tara(ad, en_fazla=400):
    ad = _alan_bul(ad)
    if not ad:
        return {"hata": "alan adı gerekli"}
    bulunan, kaynak = {}, {}

    def ekle(liste, kaynak_ad):
        yeni = 0
        for x in liste:
            x = (x or "").strip().lower().lstrip("*.").rstrip(".")
            if x and x.endswith(ad) and "@" not in x and " " not in x and len(x) < 200:
                if x not in bulunan:
                    bulunan[x] = {"ad": x, "kaynak": kaynak_ad, "ip": ""}
                    yeni += 1
        kaynak[kaynak_ad] = yeni

    kod, govde, _ = _cek("https://api.subdomain.center/?domain=" + urllib.parse.quote(ad), zaman=25)
    if kod == 200:
        try:
            ekle(json.loads(govde), "subdomain.center")
        except Exception:
            pass
    kod, govde, _ = _cek("https://api.hackertarget.com/hostsearch/?q=" + urllib.parse.quote(ad), zaman=20)
    if kod == 200 and "error" not in govde[:60].lower() and "<html" not in govde[:60].lower():
        ekle([satir.split(",")[0] for satir in govde.splitlines() if "," in satir], "hackertarget")
    ekle(_crt_sh(ad), "crt.sh")

    liste = sorted(bulunan.values(), key=lambda x: x["ad"])[:en_fazla]
    # ilk 40 için IP çözümü
    def coz(k):
        try:
            k["ip"] = socket.gethostbyname(k["ad"])
        except Exception:
            k["ip"] = ""
        return k
    if liste:
        with cf.ThreadPoolExecutor(max_workers=20) as h:
            liste = list(h.map(coz, liste[:60])) + liste[60:]
    canli = [x for x in liste if x["ip"]]
    return {"ad": ad, "toplam": len(bulunan), "kaynaklar": kaynak, "canli": len(canli),
            "alt_alanlar": liste, "kaynak": "subdomain.center + hackertarget + crt.sh",
            "zaman": time.strftime("%Y-%m-%d %H:%M:%S")}


# --------------------------------------------------------------------------- #
#  5) Web teknolojileri
# --------------------------------------------------------------------------- #
TEK_IMZALARI = [
    ("nginx", "sunucu", r"nginx"), ("Apache", "sunucu", r"apache"), ("IIS", "sunucu", r"microsoft-iis"),
    ("Cloudflare", "cdn", r"cloudflare|cf-ray"), ("LiteSpeed", "sunucu", r"litespeed"), ("OpenResty", "sunucu", r"openresty"),
    ("Express", "cerceve", r"^express"), ("PHP", "dil", r"php"), ("ASP.NET", "dil", r"asp\.net"),
    ("WordPress", "cms", r"wp-content|wp-includes|wordpress"), ("Drupal", "cms", r"drupal"),
    ("Joomla", "cms", r"joomla"), ("Shopify", "e-ticaret", r"shopify"), ("WooCommerce", "e-ticaret", r"woocommerce"),
    ("Magento", "e-ticaret", r"magento|mage/"), ("Next.js", "cerceve", r"__next|next/static"),
    ("Nuxt", "cerceve", r"__nuxt"), ("React", "kutuphane", r"react(?:-dom)?[.\-/]"), ("Vue.js", "kutuphane", r"vue(?:\.min)?\.js|__vue__"),
    ("Angular", "cerceve", r"ng-version|angular"), ("jQuery", "kutuphane", r"jquery"), ("Bootstrap", "css", r"bootstrap"),
    ("Tailwind", "css", r"tailwind"), ("Google Analytics", "analitik", r"google-analytics|gtag\("),
    ("Google Tag Manager", "analitik", r"googletagmanager"), ("Facebook Pixel", "analitik", r"connect\.facebook\.net|fbq\("),
    ("Hotjar", "analitik", r"hotjar"), ("Cloudflare Turnstile", "guvenlik", r"turnstile"), ("reCAPTCHA", "guvenlik", r"recaptcha"),
    ("Sentry", "izleme", r"sentry"), ("Stripe", "odeme", r"js\.stripe\.com|stripe\.com/v3"),
    ("PayPal", "odeme", r"paypal\.com/sdk"), ("Font Awesome", "ikon", r"font-awesome|fontawesome"),
    ("Google Fonts", "ikon", r"fonts\.googleapis\.com"), ("Open Graph", "seo", r'property="og:'),
    ("Sitemap", "seo", r"sitemap\.xml"), ("Plesk", "panel", r"plesk"), ("cPanel", "panel", r"cpanel"),
]
GUVENLIK_BASLIKLARI = ["strict-transport-security", "content-security-policy", "x-frame-options",
                       "x-content-type-options", "referrer-policy", "permissions-policy",
                       "cross-origin-opener-policy", "x-xss-protection"]


def web_tek(hedef):
    ad, url = _kok(hedef)
    if not url:
        return {"hata": "hedef gerekli"}
    if "://" not in url:
        url = "https://" + ad
    t0 = time.time()
    kod = 0
    basliklar, govde, sert = {}, "", {}
    for deneme in ([url] if url.startswith("https") else [url, "https://" + ad]):
        try:
            istek = urllib.request.Request(deneme, headers=UA)
            ctx = BAG
            with urllib.request.urlopen(istek, timeout=15, context=ctx) as y:
                kod = y.status
                basliklar = {k.lower(): v for k, v in y.headers.items()}
                govde = y.read(400000).decode("utf-8", "replace")
                try:
                    s = y.fp.raw._sock if hasattr(y.fp, "raw") else None
                    sertifika = y.fp.raw._sock.getpeercert() if s else {}
                except Exception:
                    sertifika = {}
                break
        except urllib.error.HTTPError as e:
            kod = e.code
            basliklar = {k.lower(): v for k, v in (e.headers or {}).items()}
            try:
                govde = e.read(200000).decode("utf-8", "replace")
            except Exception:
                govde = ""
            break
        except Exception:
            continue
    if not basliklar:
        return {"url": url, "ad": ad, "hata": "bağlantı kurulamadı", "sure": round(time.time() - t0, 2)}
    if sertifika:
        sert = {"konu": str(sertifika.get("subject", "")), "veren": str(sertifika.get("issuer", "")),
                "baslangic": sertifika.get("notBefore", ""), "bitis": sertifika.get("notAfter", ""),
                "san": [x[1] for x in sertifika.get("subjectAltName", ()) or ()][:25]}
    birlesik = (govde[:120000] + " " + " ".join("%s=%s" % (k, v) for k, v in basliklar.items())).lower()
    teknolojiler, gorulen = [], set()
    for ad_t, kat, kal in TEK_IMZALARI:
        if ad_t in gorulen:
            continue
        if re.search(kal, birlesik):
            teknolojiler.append({"ad": ad_t, "kategori": kat})
            gorulen.add(ad_t)
    g_eksik = [b for b in GUVENLIK_BASLIKLARI[:6] if b not in basliklar]
    uyari = []
    if govde.startswith("<html") and "https://" not in url[:8]:
        uyari.append({"onem": "yuksek", "baslik": "HTTPS yok", "aciklama": "Trafik şifresiz taşınıyor."})
    for b in g_eksik[:3]:
        uyari.append({"onem": "dusuk", "baslik": "%s başlığı yok" % b, "aciklama": "Tarayıcı koruması zayıflıyor."})
    if "set-cookie" in basliklar and "secure" not in basliklar["set-cookie"].lower():
        uyari.append({"onem": "orta", "baslik": "Çerez Secure bayrağı yok", "aciklama": "Çerez HTTP üzerinden sızabilir."})
    return {"ad": ad, "url": url, "durum_kodu": kod, "sunucu": basliklar.get("server", ""),
            "basliklar": {k: v[:300] for k, v in list(basliklar.items())[:40]},
            "teknolojiler": teknolojiler, "guvenlik_basliklari": {b: (b in basliklar) for b in GUVENLIK_BASLIKLARI},
            "eksik_guvenlik": g_eksik, "sertifika": sert, "uyarilar": uyari,
            "icerik_uzunlugu": len(govde), "kaynak": "canlı HTTP + TLS",
            "sure": round(time.time() - t0, 2)}


# --------------------------------------------------------------------------- #
#  6) Cloud keşfi (S3 / GCS / Azure kova kontrolü)
# --------------------------------------------------------------------------- #
CLOUD_ONEKLER = ["", "www", "mail", "dev", "test", "staging", "prod", "backup", "yedek", "assets", "media",
                 "static", "files", "data", "logs", "cdn", "img", "video", "docs", "db", "api", "app",
                 "public", "private", "storage", "download", "uploads"]


def _kova_dene(ad, saglayici):
    if saglayici == "aws":
        url = "https://%s.s3.amazonaws.com/" % ad
    elif saglayici == "gcp":
        url = "https://storage.googleapis.com/" + ad
    else:
        url = "https://%s.blob.core.windows.net/?comp=list" % ad
    kod, govde, sure = _cek(url, zaman=10)
    durum, aciklama, risk = "yok", "", "bilgi"
    if kod == 200 and ("<ListBucketResult" in govde or "<EnumerationResults" in govde):
        durum, aciklama, risk = "acik", "Kova listelenebiliyor — dosyalar herkese açık.", "kritik"
    elif kod == 403:
        durum, aciklama, risk = "var", "Kova mevcut ama liste erişimi kapalı.", "dusuk"
    elif kod == 404 or "NoSuchBucket" in govde or "The specified bucket does not exist" in govde:
        durum, aciklama = "yok", ""
    elif kod == 400 and "ContainerNotFound" in govde:
        durum, aciklama = "yok", ""
    else:
        durum, aciklama = "bilinmiyor", "kod %s" % kod
    return {"ad": ad, "saglayici": saglayici, "url": url, "durum": durum,
            "aciklama": aciklama, "risk": risk, "kod": kod, "sure": sure}


def cloud_ara(hedef):
    ad = _alan_bul(hedef)
    if not ad:
        return {"hata": "alan adı gerekli"}
    taban = ad.replace(".", "-")
    adaylar = []
    for onek in CLOUD_ONEKLER:
        adaylar.append((onek + taban, "aws") if onek else (taban, "aws"))
        if onek:
            adaylar.append((taban + "-" + onek, "aws"))
    adaylar = list(dict.fromkeys(adaylar))[:70]
    with cf.ThreadPoolExecutor(max_workers=16) as h:
        sonuc = list(h.map(lambda x: _kova_dene(x[0], x[1]), adaylar))
    var_olan = [s for s in sonuc if s["durum"] in ("var", "acik")]
    return {"hedef": ad, "denenen": len(sonuc), "bulunan": len(var_olan),
            "acik": len([s for s in var_olan if s["durum"] == "acik"]),
            "sonuclar": var_olan, "tumu": sonuc[:40],
            "kaynak": "S3 / Google Cloud Storage / Azure Blob",
            "zaman": time.strftime("%Y-%m-%d %H:%M:%S")}


# --------------------------------------------------------------------------- #
#  7) E-posta istihbaratı
# --------------------------------------------------------------------------- #
TEK_KULLANIMLIK = ["mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org",
                   "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com", "dispostable.com",
                   "maildrop.cc", "throwawaymail.com", "fakeinbox.com", "mailnesia.com", "tempr.email",
                   "discard.email", "mohmal.com", "emailondeck.com"]
ROL_HESAPLARI = ["info", "admin", "support", "sales", "contact", "help", "billing", "office", "noreply",
                 "no-reply", "postmaster", "webmaster", "abuse", "security", "hr", "jobs", "press", "marketing"]


def eposta_istihbarat(adres):
    adres = (adres or "").strip().lower()
    if not re.match(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$", adres):
        return {"adres": adres, "gecerli": False,
                "uyarilar": [{"onem": "orta", "baslik": "Sözdizimi hatalı", "aciklama": "Adres biçimi geçersiz."}]}
    kullanici, alan = adres.split("@")
    mx = dns_sorgu(alan, "MX")["kayitlar"]
    txt = " ".join(k["deger"] for k in dns_sorgu(alan, "TXT")["kayitlar"]).lower()
    uyari = []
    tek = alan in TEK_KULLANIMLIK
    rol = kullanici in ROL_HESAPLARI
    if not mx:
        uyari.append({"onem": "yuksek", "baslik": "MX kaydı yok",
                      "aciklama": "%s alan adı e-posta kabul etmiyor — adres çalışmaz." % alan})
    if tek:
        uyari.append({"onem": "orta", "baslik": "Tek kullanımlık servis",
                      "aciklama": "%s geçici e-posta sağlayıcısı." % alan})
    if rol:
        uyari.append({"onem": "bilgi", "baslik": "Rol hesabı", "aciklama": "Kişiye değil birime ait adres görünümünde."})
    if "v=spf1" not in txt:
        uyari.append({"onem": "orta", "baslik": "SPF yok", "aciklama": "Alan adı sahtelenebilir."})
    eps = hashlib.md5(adres.encode()).hexdigest()
    kg, gv, _ = _cek("https://www.gravatar.com/avatar/%s.json" % eps, zaman=10)
    gravatar = kg == 200 and "entry" in gv
    kova = _kova_dene(alan.replace(".", "-"), "aws")
    return {"adres": adres, "gecerli": True, "kullanici": kullanici, "alan": alan,
            "mx": [k["deger"] for k in mx][:8], "spf_var": "v=spf1" in txt, "dmarc_var": "v=dmarc" in txt,
            "tek_kullanimlik": tek, "rol_hesabi": rol, "gravatar": gravatar,
            "gravatar_url": ("https://www.gravatar.com/avatar/" + eps) if gravatar else "",
            "kurumsal_kova": kova if kova["durum"] in ("var", "acik") else None,
            "uyarilar": uyari, "kaynak": "DoH MX/TXT + Gravatar + kova kontrolü",
            "not": "SMTP RCPT doğrulaması yapılmadı: Türkiye'de birçok ISS 25 numaralı portu kapatıyor. "
                   "Bu yüzden varlık kontrolü MX + servis izleriyle yapılır."}


# --------------------------------------------------------------------------- #
#  8) Kullanıcı adı arama (platform varlık kuralları)
# --------------------------------------------------------------------------- #
SITE_DOSYASI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "veri", "kullanici-siteleri.json")
SITE_VARSAYILAN = [
    {"ad": "GitHub", "url": "https://github.com/{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "GitLab", "url": "https://gitlab.com/{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "Telegram", "url": "https://t.me/{k}", "yok_marker": "tgme_page_icon", "guvenilir": True},
    {"ad": "YouTube", "url": "https://www.youtube.com/@{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "Steam", "url": "https://steamcommunity.com/id/{k}", "yok_marker": "The specified profile could not be found", "guvenilir": True},
    {"ad": "Keybase", "url": "https://keybase.io/{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "NPM", "url": "https://www.npmjs.com/~{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "PyPI", "url": "https://pypi.org/user/{k}/", "durum_yok": [404], "guvenilir": True},
    {"ad": "Docker Hub", "url": "https://hub.docker.com/u/{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "HackerNews", "url": "https://news.ycombinator.com/user?id={k}", "yok_marker": "No such user.", "guvenilir": True},
    {"ad": "Twitch", "url": "https://www.twitch.tv/{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "SoundCloud", "url": "https://soundcloud.com/{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "Vimeo", "url": "https://vimeo.com/{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "Flickr", "url": "https://www.flickr.com/people/{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "About.me", "url": "https://about.me/{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "Behance", "url": "https://www.behance.net/{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "Dribbble", "url": "https://dribbble.com/{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "Patreon", "url": "https://www.patreon.com/{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "Mastodon", "url": "https://mastodon.social/@{k}", "durum_yok": [404], "guvenilir": True},
    {"ad": "Pinterest", "url": "https://www.pinterest.com/{k}/", "durum_yok": [404], "guvenilir": False,
     "not": "içerik denetimi gerekli"},
    {"ad": "Instagram", "url": "https://www.instagram.com/{k}/", "yok_marker": "Sorry, this page isn't available",
     "guvenilir": True},
    {"ad": "TikTok", "url": "https://www.tiktok.com/@{k}", "yok_marker": "Couldn't find this account", "guvenilir": True},
    {"ad": "Twitter/X", "url": "https://x.com/{k}", "guvenilir": False, "not": "Giriş duvarı — doğrulanamıyor"},
    {"ad": "Facebook", "url": "https://www.facebook.com/{k}", "guvenilir": False, "not": "Giriş duvarı"},
    {"ad": "Reddit", "url": "https://www.reddit.com/user/{k}/about.json", "durum_yok": [404], "guvenilir": False,
     "not": "Reddit bot engeli (403)"},
]


def _siteler():
    try:
        with open(SITE_DOSYASI, encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, list) and d:
            return d
    except Exception:
        pass
    return SITE_VARSAYILAN


def kullanici_ara(kullanici):
    kullanici = (kullanici or "").strip().lstrip("@")
    if not kullanici or len(kullanici) < 2:
        return {"hata": "kullanıcı adı gerekli"}
    siteler = _siteler()

    def kontrol(s):
        url = s["url"].replace("{k}", urllib.parse.quote(kullanici))
        kod, govde, sure = _cek(url, zaman=12)
        var = None
        if s.get("durum_yok") and kod:
            var = kod not in s["durum_yok"]
        if s.get("var_marker") and kod:
            var = s["var_marker"].lower() in (govde or "").lower()
        if s.get("yok_marker") and kod:
            var = s["yok_marker"].lower() not in (govde or "").lower()
            if kod in (404, 410):
                var = False
        if kod in (401, 403, 429, 0):
            var = None          # bot duvarı / kota: hüküm verme
        if s.get("guvenilir") is False:
            var = None
        if s.get("guvenilir") is False:
            var = None
        return {"ad": s["ad"], "url": url, "kod": kod, "var": var,
                "guvenilir": bool(s.get("guvenilir", True)) and var is not None,
                "not": s.get("not", ""), "sure": sure}

    with cf.ThreadPoolExecutor(max_workers=12) as h:
        sonuc = list(h.map(kontrol, siteler))
    bulunan = [s for s in sonuc if s["var"] is True]
    return {"kullanici": kullanici, "denenen": len(sonuc), "bulunan": len(bulunan),
            "platformlar": sorted(sonuc, key=lambda x: (x["var"] is not True, x["ad"])),
            "kaynak": "platform varlık kuralları (durum kodu + içerik işareti)",
            "zaman": time.strftime("%Y-%m-%d %H:%M:%S")}


# --------------------------------------------------------------------------- #
#  9) GitHub istihbaratı
# --------------------------------------------------------------------------- #
def _gh(yol, anahtar=None):
    b = {"Accept": "application/vnd.github+json"}
    if anahtar:
        b["Authorization"] = "Bearer " + anahtar
    return _json("https://api.github.com" + yol, baslik=b, zaman=15)


def github_istihbarat(kullanici, anahtar=None):
    kullanici = (kullanici or "").strip().lstrip("@")
    if not kullanici:
        return {"hata": "kullanıcı adı gerekli"}
    kod, u, sure = _gh("/users/" + urllib.parse.quote(kullanici), anahtar)
    if not isinstance(u, dict) or kod != 200:
        return {"kullanici": kullanici, "hata": (u or {}).get("message", "kullanıcı bulunamadı (kod %s)" % kod)}
    kod_d, depolar, _ = _gh("/users/%s/repos?per_page=100&sort=updated" % urllib.parse.quote(kullanici), anahtar)
    depolar = depolar if isinstance(depolar, list) else []
    kod_o, org, _ = _gh("/users/%s/orgs" % urllib.parse.quote(kullanici), anahtar)
    kod_e, olay, _ = _gh("/users/%s/events/public?per_page=30" % urllib.parse.quote(kullanici), anahtar)
    diller, yildiz = {}, 0
    for d in depolar:
        diller[d.get("language") or "belirsiz"] = diller.get(d.get("language") or "belirsiz", 0) + 1
        yildiz += d.get("stargazers_count", 0) or 0
    eposta, sizinti = "", []
    for e in (olay if isinstance(olay, list) else []):
        for c in (e.get("commits") or []):
            em = ((c.get("author") or {}).get("email") or "")
            if em and "noreply" not in em and not any(s["eposta"] == em for s in sizinti):
                sizinti.append({"eposta": em, "depo": (e.get("repo") or {}).get("name", ""),
                                "tarih": (e.get("created_at") or "")[:10]})
        if len(sizinti) >= 6:
            break
    uyari = []
    if sizinti:
        uyari.append({"onem": "orta", "baslik": "E-posta adresi açığa çıktı",
                      "aciklama": "Herkese açık commit'lerde %d adres görüldü." % len(sizinti)})
    return {"kullanici": kullanici, "kaynak": "api.github.com",
            "profil": {"ad": u.get("name"), "bio": u.get("bio"), "sirket": u.get("company"),
                       "blog": u.get("blog"), "konum": u.get("location"), "eposta": u.get("email"),
                       "twitter": u.get("twitter_username"), "avatar": u.get("avatar_url"),
                       "takipci": u.get("followers"), "takip": u.get("following"),
                       "depo_sayisi": u.get("public_repos"), "gist": u.get("public_gists"),
                       "olusturma": (u.get("created_at") or "")[:10], "guncelleme": (u.get("updated_at") or "")[:10],
                       "site": u.get("html_url")},
            "toplam_yildiz": yildiz, "diller": diller,
            "kurumlar": [o.get("login") for o in (org if isinstance(org, list) else [])][:10],
            "depolar": [{"ad": d.get("name"), "aciklama": d.get("description"), "dil": d.get("language"),
                         "yildiz": d.get("stargazers_count"), "fork": d.get("forks_count"),
                         "guncelleme": (d.get("updated_at") or "")[:10], "url": d.get("html_url"),
                         "arsiv": d.get("archived"),
                         "lisans": ((d.get("license") or {}) or {}).get("spdx_id")}
                        for d in sorted(depolar, key=lambda x: -(x.get("stargazers_count") or 0))[:25]],
            "sizinti_notlari": sizinti, "uyarilar": uyari, "sure": sure}


# --------------------------------------------------------------------------- #
# 10) Veri sızıntısı tespiti (açık dosya / konfig probu)
# --------------------------------------------------------------------------- #
PROBLAR = [
    {"yol": "/.env", "ris": "kritik", "imza": ["DB_", "APP_KEY", "SECRET", "PASSWORD", "API_KEY", "="],
     "aciklama": "Ortam değişkenleri (veritabanı/API anahtarları) herkese açık."},
    {"yol": "/.env.local", "ris": "kritik", "imza": ["DB_", "APP_KEY", "SECRET", "PASSWORD"], "aciklama": "Yerel ortam dosyası açık."},
    {"yol": "/.env.production", "ris": "kritik", "imza": ["DB_", "APP_KEY", "SECRET", "PASSWORD"], "aciklama": "Üretim ortam dosyası açık."},
    {"yol": "/.git/config", "ris": "kritik", "imza": ["[core]", "repositoryformatversion", "url ="], "aciklama": "Git deposu dizini açık — tüm kaynak kod indirilebilir."},
    {"yol": "/.git/HEAD", "ris": "yuksek", "imza": ["ref: refs/"], "aciklama": "Git baş dosyası açık."},
    {"yol": "/.svn/entries", "ris": "yuksek", "imza": ["dir", "svn"], "aciklama": "SVN dizini açık."},
    {"yol": "/.DS_Store", "ris": "dusuk", "imza": ["Mac OS X"], "aciklama": "macOS dosya listesi sızıntısı."},
    {"yol": "/backup.zip", "ris": "yuksek", "imza": [], "tip": "pk", "aciklama": "Yedek arşivi indirilebilir."},
    {"yol": "/backup.sql", "ris": "kritik", "imza": ["INSERT INTO", "CREATE TABLE", "-- MySQL"], "aciklama": "Veritabanı yedeği açık."},
    {"yol": "/db.sql", "ris": "kritik", "imza": ["INSERT INTO", "CREATE TABLE"], "aciklama": "Veritabanı dökümü açık."},
    {"yol": "/dump.sql", "ris": "kritik", "imza": ["INSERT INTO", "CREATE TABLE"], "aciklama": "Veritabanı dökümü açık."},
    {"yol": "/wp-config.php.bak", "ris": "kritik", "imza": ["DB_PASSWORD", "DB_NAME", "define("], "aciklama": "WordPress yapılandırma yedeği açık."},
    {"yol": "/wp-config.php~", "ris": "kritik", "imza": ["DB_PASSWORD", "DB_NAME"], "aciklama": "WordPress yapılandırma kopyası açık."},
    {"yol": "/config.php.bak", "ris": "kritik", "imza": ["password", "db_", "<?php"], "aciklama": "Yapılandırma yedeği açık."},
    {"yol": "/phpinfo.php", "ris": "yuksek", "imza": ["phpinfo()", "PHP Version"], "aciklama": "phpinfo çıktısı açık — sistem bilgisi sızıyor."},
    {"yol": "/server-status", "ris": "orta", "imza": ["Apache Server Status", "Server Version"], "aciklama": "Apache durum sayfası açık."},
    {"yol": "/swagger.json", "ris": "orta", "imza": ["swagger", "openapi"], "aciklama": "API dokümantasyonu açık."},
    {"yol": "/openapi.json", "ris": "orta", "imza": ["openapi", "paths"], "aciklama": "API şeması açık."},
    {"yol": "/actuator/env", "ris": "kritik", "imza": ["activeProfiles", "propertySources"], "aciklama": "Spring Boot ortam uç noktası açık."},
    {"yol": "/.aws/credentials", "ris": "kritik", "imza": ["aws_access_key_id"], "aciklama": "AWS kimlik dosyası açık."},
    {"yol": "/id_rsa", "ris": "kritik", "imza": ["PRIVATE KEY"], "aciklama": "Özel SSH anahtarı açık."},
    {"yol": "/logs/error.log", "ris": "orta", "imza": ["PHP", "error", "Traceback", "at java"], "aciklama": "Hata günlüğü herkese açık."},
    {"yol": "/.well-known/security.txt", "ris": "bilgi", "imza": ["Contact:"], "aciklama": "Güvenlik iletişim dosyası var (olumlu)."},
    {"yol": "/robots.txt", "ris": "bilgi", "imza": ["User-agent", "Disallow"], "aciklama": "robots.txt — gizlenmeye çalışılan yolları gösterir."},
]


def sizinti_tara(hedef):
    ad, url = _kok(hedef)
    if not url:
        return {"hata": "hedef gerekli"}
    if "://" not in url:
        url = "https://" + ad
    taban = url.rstrip("/")
    bulunan, uyarilar = [], []

    def tek(p):
        u = taban + p["yol"]
        kod, govde, sure = _cek(u, zaman=10)
        if kod not in (200, 206):
            return {"yol": p["yol"], "url": u, "kod": kod, "bulundu": False, "durum": "yok"}
        # doğrulama: imza aranır, imzasız problar için içerik tipi/HTML kontrolü
        imza_var = True
        if p["imza"]:
            imza_var = any(i.lower() in govde[:60000].lower() for i in p["imza"])
        else:
            imza_var = p.get("tip") == "pk" and govde.startswith("PK") or (not govde.lstrip().lower().startswith("<!doctype html"))
        if not imza_var:
            return {"yol": p["yol"], "url": u, "kod": kod, "bulundu": False, "durum": "yanlis_pozitif",
                    "aciklama": "200 döndü ama içerik probla uyuşmuyor (yumuşak 404)."}
        return {"yol": p["yol"], "url": u, "kod": kod, "bulundu": True, "risk": p["ris"],
                "aciklama": p["aciklama"], "boyut": len(govde), "sure": sure,
                "ornek": re.sub(r"\s+", " ", govde[:220])}

    with cf.ThreadPoolExecutor(max_workers=10) as h:
        sonuc = list(h.map(tek, PROBLAR))
    bulunan = [s for s in sonuc if s["bulundu"]]
    for b in bulunan:
        if b.get("risk") in ("kritik", "yuksek"):
            uyarilar.append({"onem": b["risk"], "baslik": "%s açık" % b["yol"], "aciklama": b.get("aciklama", "")})
    sirali = {"kritik": 0, "yuksek": 1, "orta": 2, "dusuk": 3, "bilgi": 4}
    bulunan.sort(key=lambda x: sirali.get(x.get("risk", "bilgi"), 9))
    return {"hedef": ad, "url": taban, "denenen": len(sonuc), "bulunan": len(bulunan),
            "kritik": len([b for b in bulunan if b.get("risk") == "kritik"]),
            "bulgular": bulunan, "tum_problar": sonuc, "uyarilar": uyarilar,
            "kaynak": "canlı HTTP probu (yumuşak 404 ayıklamalı)",
            "zaman": time.strftime("%Y-%m-%d %H:%M:%S")}


# --------------------------------------------------------------------------- #
# 11) Dark web / sızıntı kaydı (HIBP anahtarı gerekir)
# --------------------------------------------------------------------------- #
def darkweb_ara(sorgu, anahtar=None):
    sorgu = (sorgu or "").strip()
    if not sorgu:
        return {"hata": "e-posta veya alan adı gerekli"}
    if not anahtar:
        return {"sorgu": sorgu, "anahtar_gerekli": True,
                "mesaj": "Sızıntı kaydı için Have I Been Pwned API anahtarı gerekir. "
                         "Ayarlar → API Anahtarları bölümüne ekleyin; anahtar olmadan sorgu çalışmaz.",
                "ucretsiz_alternatifler": [
                    {"ad": "Google dork — sızmış dosyalar", "url": "https://www.google.com/search?q=%22" + urllib.parse.quote(sorgu) + "%22+filetype%3Asql"},
                    {"ad": "Arama — yapıştırma siteleri", "url": "https://www.google.com/search?q=%22" + urllib.parse.quote(sorgu) + "%22+site%3Apastebin.com"},
                    {"ad": "Have I Been Pwned", "url": "https://haveibeenpwned.com/account/" + urllib.parse.quote(sorgu)},
                    {"ad": "DeHashed (kayıt gerekir)", "url": "https://dehashed.com/search?query=" + urllib.parse.quote(sorgu)},
                ],
                "kaynak": "HIBP v3"}
    baslik = {"hibp-api-key": anahtar, "User-Agent": "USTAD-OSINT"}
    if "@" in sorgu:
        yol = "/breachedaccount/%s?truncateResponse=false" % urllib.parse.quote(sorgu)
    else:
        yol = "/breacheddomain/" + urllib.parse.quote(sorgu)
    kod, j, sure = _json("https://haveibeenpwned.com/api/v3" + yol, baslik=baslik, zaman=20)
    if kod == 404:
        return {"sorgu": sorgu, "temiz": True, "sizinti_sayisi": 0,
                "mesaj": "Bu sorgu bilinen sızıntılarda bulunamadı (temiz görünüyor).", "kaynak": "HIBP v3"}
    if kod != 200:
        return {"sorgu": sorgu, "hata": "HIBP yanıtı: %s (anahtar geçersiz olabilir)" % kod}
    kayitlar = j if isinstance(j, list) else []
    return {"sorgu": sorgu, "temiz": not kayitlar, "sizinti_sayisi": len(kayitlar),
            "kayitlar": [{"ad": k.get("Name"), "baslik": k.get("Title"), "tarih": k.get("BreachDate"),
                          "etkilenen": k.get("PwnCount"), "veriler": k.get("DataClasses"),
                          "dogrulanmis": k.get("IsVerified"), "aciklama": re.sub("<[^>]+>", "", k.get("Description") or "")[:300]}
                         for k in kayitlar[:20]],
            "kaynak": "HIBP v3", "sure": sure}


# --------------------------------------------------------------------------- #
# 12) Tehdit haritası (gerçek beslemeler + konum)
# --------------------------------------------------------------------------- #
def _besleme(url, zaman=25):
    kod, govde, sure = _cek(url, zaman=zaman)
    return govde if kod == 200 else ""


def _cvss(cve):
    """CVSS puanını sürüm farkını gözeterek bul."""
    m = cve.get("metrics") or {}
    for anahtar in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        d = m.get(anahtar)
        if d:
            try:
                return d[0].get("cvssData", {}).get("baseScore")
            except Exception:
                pass
    return None


def tehdit_verisi(zorla=False):
    onbellek = os.path.join(os.path.dirname(os.path.abspath(__file__)), "veri", "tehdit-onbellek.json")
    try:
        if not zorla and os.path.exists(onbellek):
            with open(onbellek, encoding="utf-8") as f:
                d = json.load(f)
            if time.time() - d.get("_zaman", 0) < 900 and d.get("c2"):
                d["onbellek"] = True
                return d
    except Exception:
        pass

    c2, phishing, ioc = [], [], []
    # --- Feodo Tracker: JSON birincil, CSV yedek ---
    kod, j, _ = _json("https://feodotracker.abuse.ch/downloads/ipblocklist.json", zaman=25)
    if isinstance(j, list):
        for k in j:
            ip = k.get("ip_address")
            if ip and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                c2.append({"ilk_gorulme": k.get("first_seen", ""), "ip": ip, "port": k.get("port"),
                           "durum": k.get("status"), "son_cevrimici": k.get("last_online"),
                           "zararli": k.get("malware"), "asn": k.get("as_number"), "as_ad": k.get("as_name"),
                           "ulke": k.get("country"), "kaynak": "Feodo Tracker"})
    if len(c2) < 5:
        govde = _besleme("https://feodotracker.abuse.ch/downloads/ipblocklist.csv")
        for satir in govde.splitlines():
            if not satir or satir.startswith("#") or "first_seen" in satir:
                continue
            p = [x.strip().strip('"') for x in satir.split(",")]
            if len(p) >= 6 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", p[1]):
                c2.append({"ilk_gorulme": p[0], "ip": p[1], "port": p[2], "durum": p[3],
                           "son_cevrimici": p[4], "zararli": p[5], "kaynak": "Feodo Tracker"})
    govde = _besleme("https://openphish.com/feed.txt")
    for satir in govde.splitlines()[:400]:
        s2 = satir.strip()
        if s2.startswith("http"):
            phishing.append({"url": s2, "kaynak": "OpenPhish"})
    govde = _besleme("https://rules.emergingthreats.net/blockrules/compromised-ips.txt")
    for satir in govde.splitlines():
        s2 = satir.strip()
        if s2 and not s2.startswith("#") and re.match(r"^\d{1,3}(\.\d{1,3}){3}", s2):
            ioc.append({"ip": s2.split()[0], "kaynak": "EmergingThreats"})

    # konum: ilk 60 C2 IP'si toplu sorgu ile
    konumlar, ulkeler = [], {}
    ornek = list(dict.fromkeys([c["ip"] for c in c2[:60]] + [x["ip"] for x in ioc[:60]]))[:80]
    if ornek:
        veri = json.dumps([{"query": ip, "fields": "status,country,countryCode,city,lat,lon,as,query"}
                           for ip in ornek]).encode()
        kod, j, _ = _json("http://ip-api.com/batch", veri, tip="application/json", zaman=25)
        if isinstance(j, list):
            for k in j:
                if k.get("status") == "success":
                    ulkeler[k.get("country", "?")] = ulkeler.get(k.get("country", "?"), 0) + 1
                    konumlar.append({"ip": k.get("query"), "ulke": k.get("country"),
                                     "ulke_kodu": k.get("countryCode"), "sehir": k.get("city"),
                                     "enlem": k.get("lat"), "boylam": k.get("lon"), "asn": k.get("as"), "tur": "c2"})
    # ---- ek doğrulanmış beslemeler: sayı + örnek ----
    ek = []
    govde = _besleme("https://www.spamhaus.org/drop/drop.txt")
    ci = [x.split(";")[0].strip() for x in govde.splitlines() if x and not x.startswith(";") and "/" in x]
    if ci:
        ek.append({"ad": "Spamhaus DROP", "tip": "CIDR bloğu", "sayi": len(ci), "ornek": ci[:5],
                   "url": "https://www.spamhaus.org/drop/drop.txt"})
    govde = _besleme("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt")
    ip_list = []
    for satir in govde.splitlines():
        if not satir or satir.startswith("#"):
            continue
        par = satir.split()
        if len(par) >= 2 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", par[0]):
            ip_list.append((par[1], par[0]))
    if ip_list:
        ip_list.sort(reverse=True)
        ek.append({"ad": "ipsum (yapıştırma/karaliste skoru)", "tip": "skorlu IP", "sayi": len(ip_list),
                   "ornek": ["%s (skor %s)" % (x[1], x[0]) for x in ip_list[:5]],
                   "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"})
    govde = _besleme("https://urlhaus.abuse.ch/downloads/text_recent/")
    uh = [x.strip() for x in govde.splitlines() if x.strip().startswith("http")]
    if uh:
        ek.append({"ad": "URLhaus (son zararlı URL)", "tip": "URL", "sayi": len(uh), "ornek": uh[:5],
                   "url": "https://urlhaus.abuse.ch/downloads/text_recent/"})
    govde = _besleme("https://phishing.army/download/phishing_army_blocklist_extended.txt")
    pa = [x.strip() for x in govde.splitlines() if x.strip() and not x.startswith("#")]
    if pa:
        ek.append({"ad": "Phishing Army", "tip": "phishing alan adı", "sayi": len(pa), "ornek": pa[:5],
                   "url": "https://phishing.army/download/phishing_army_blocklist_extended.txt"})
    # son 1 haftanın CVE sayısı (gerçek, ücretsiz)
    cve = {}
    try:
        son = time.strftime("%Y-%m-%dT00:00:00.000")
        bas = time.strftime("%Y-%m-%dT00:00:00.000", time.localtime(time.time() - 7 * 86400))
        kod, j, _ = _json("https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=%s&pubEndDate=%s&resultsPerPage=6"
                          % (bas, son), zaman=25)
        if isinstance(j, dict):
            cve = {"son_hafta": j.get("totalResults"), "pencere": bas[:10] + " → " + son[:10],
                   "yeni": [{"id": (v.get("cve") or {}).get("id"),
                             "aciklama": (((v.get("cve") or {}).get("descriptions") or [{}])[0]).get("value", "")[:180],
                             "skor": _cvss(v.get("cve") or {})}
                            for v in (j.get("vulnerabilities") or [])[:6]]}
    except Exception:
        cve = {}

    sonuc = {"c2": c2[:300], "c2_toplam": len(c2), "phishing": phishing[:200], "phishing_toplam": len(phishing),
             "ioc": ioc[:300], "ioc_toplam": len(ioc), "konumlar": konumlar, "ulkeler": ulkeler,
             "ek_beslemeler": ek, "cve": cve,
             "kaynaklar": ["abuse.ch Feodo Tracker", "OpenPhish", "EmergingThreats", "Spamhaus DROP",
                           "ipsum", "URLhaus", "Phishing Army", "NVD CVE API"],
             "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S"), "_zaman": time.time(), "onbellek": False}
    try:
        os.makedirs(os.path.dirname(onbellek), exist_ok=True)
        with open(onbellek, "w", encoding="utf-8") as f:
            json.dump(sonuc, f, ensure_ascii=False)
    except Exception:
        pass
    return sonuc


# --------------------------------------------------------------------------- #
# 13) TAM PROFİL — hızlı/detaylı arama (tüm modüller paralel)
# --------------------------------------------------------------------------- #
def _risk_puani(bulgular):
    puan, agirlik = 0, {"kritik": 25, "yuksek": 12, "orta": 5, "dusuk": 2, "bilgi": 0}
    for b in bulgular:
        puan += agirlik.get(b.get("risk", "bilgi"), 0)
    return min(100, puan)


def profil_cikar(hedef, moduller=None, github_anahtar=None, hibp_anahtar=None):
    ad, url = _kok(hedef)
    if not ad:
        return {"hata": "hedef gerekli (alan adı, IP veya URL)"}
    moduller = moduller or ["dns", "whois", "subdomain", "webtek", "cloud", "sizinti", "tehdit"]
    t0 = time.time()
    isler = {}
    ip_mi = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ad))
    if "dns" in moduller and not ip_mi:
        isler["dns"] = lambda: dns_toplu(ad)
    if "whois" in moduller:
        isler["whois"] = (lambda: ip_analiz(ad)) if ip_mi else (lambda: whois_rdap(ad))
    if ip_mi:
        isler["ip"] = lambda: ip_analiz(ad)
    if "subdomain" in moduller and not ip_mi:
        isler["subdomain"] = lambda: subdomain_tara(ad)
    if "webtek" in moduller:
        isler["webtek"] = lambda: web_tek(url)
    if "cloud" in moduller and not ip_mi:
        isler["cloud"] = lambda: cloud_ara(ad)
    if "sizinti" in moduller:
        isler["sizinti"] = lambda: sizinti_tara(url)
    if "tehdit" in moduller:
        isler["tehdit"] = lambda: {"hedef_eslesme": _tehdit_esles(ad)}

    sonuc = {}
    with cf.ThreadPoolExecutor(max_workers=8) as h:
        gecici = {k: h.submit(f) for k, f in isler.items()}
        for k, g in gecici.items():
            try:
                sonuc[k] = g.result(timeout=120)
            except Exception as e:
                sonuc[k] = {"hata": str(e)[:120]}

    # bulgular + istatistik
    bulgular = []
    say = {"subdomain": 0, "ip": 0, "acik_servis": 0, "eposta": 0, "sizinti": 0, "cloud": 0}
    for u in (sonuc.get("sizinti", {}) or {}).get("bulgular", []) or []:
        bulgular.append({"tur": "Veri Sızıntısı", "hedef": u.get("url", ""), "aciklama": u.get("aciklama", ""),
                         "risk": u.get("risk", "dusuk"), "kaynak": "açık dosya probu"})
    say["sizinti"] = len(bulgular)
    for b in (sonuc.get("sizinti", {}) or {}).get("uyarilar", []) or []:
        if b.get("onem") in ("kritik", "yuksek") and not any(x["aciklama"] == b.get("aciklama") for x in bulgular):
            bulgular.append({"tur": "Veri Sızıntısı", "hedef": ad, "aciklama": b.get("aciklama", ""),
                             "risk": b.get("onem"), "kaynak": "probu"})
    d = sonuc.get("dns", {}) or {}
    for u in d.get("uyarilar", []) or []:
        bulgular.append({"tur": "DNS", "hedef": ad, "aciklama": u.get("baslik", "") + " — " + u.get("aciklama", ""),
                         "risk": u.get("onem", "orta"), "kaynak": "dns.google"})
    w = sonuc.get("whois", {}) or {}
    for u in w.get("uyarilar", []) or []:
        bulgular.append({"tur": "WHOIS", "hedef": ad, "aciklama": u.get("baslik", "") + " — " + u.get("aciklama", ""),
                         "risk": u.get("onem", "orta"), "kaynak": "RDAP"})
    s = sonuc.get("subdomain", {}) or {}
    say["subdomain"] = s.get("toplam", 0)
    say["ip"] = len([x for x in (s.get("alt_alanlar") or []) if x.get("ip")]) or len(d.get("ozet", {}).get("a", []))
    wt = sonuc.get("webtek", {}) or {}
    for u in wt.get("uyarilar", []) or []:
        bulgular.append({"tur": "Web Teknolojisi", "hedef": wt.get("url", ad),
                         "aciklama": u.get("baslik", "") + " — " + u.get("aciklama", ""),
                         "risk": u.get("onem", "dusuk"), "kaynak": "canlı HTTP"})
    # açık portlar (localhost taraması varsa sayılır; burada web portu)
    say["acik_servis"] = 1 if wt.get("durum_kodu") else 0
    c = sonuc.get("cloud", {}) or {}
    say["cloud"] = c.get("bulunan", 0)
    for k in (c.get("sonuclar") or []):
        bulgular.append({"tur": "Cloud", "hedef": k.get("url", ""), "aciklama": k.get("aciklama", ""),
                         "risk": k.get("risk", "dusuk"), "kaynak": "kova kontrolü"})
    t = sonuc.get("tehdit", {}) or {}
    for e in (t.get("hedef_eslesme", []) or [])[:5]:
        bulgular.append({"tur": "Tehdit", "hedef": e.get("ip", ""), "aciklama": e.get("aciklama", ""),
                         "risk": "kritik", "kaynak": e.get("kaynak", "")})

    # saldırı yüzeyi grafiği (alan merkezli)
    dugumler = [{"id": "kok", "ad": ad, "tur": "kok"}]
    kenarlar = []
    for x in (s.get("alt_alanlar") or [])[:40]:
        dugumler.append({"id": "sd:" + x["ad"], "ad": x["ad"], "tur": "subdomain"})
        kenarlar.append({"kaynak": "kok", "hedef": "sd:" + x["ad"]})
    for x in d.get("ozet", {}).get("mx", [])[:6]:
        dugumler.append({"id": "mx:" + x, "ad": x, "tur": "eposta"})
        kenarlar.append({"kaynak": "kok", "hedef": "mx:" + x})
    for x in d.get("ozet", {}).get("ns", [])[:6]:
        dugumler.append({"id": "ns:" + x, "ad": x, "tur": "dns"})
        kenarlar.append({"kaynak": "kok", "hedef": "ns:" + x})
    for x in (wt.get("teknolojiler") or [])[:14]:
        dugumler.append({"id": "tk:" + x["ad"], "ad": x["ad"], "tur": "teknoloji"})
        kenarlar.append({"kaynak": "kok", "hedef": "tk:" + x["ad"]})
    for x in (c.get("sonuclar") or [])[:8]:
        dugumler.append({"id": "cl:" + x["ad"], "ad": x["ad"], "tur": "cloud"})
        kenarlar.append({"kaynak": "kok", "hedef": "cl:" + x["ad"]})
    for x in bulgular[:10]:
        dugumler.append({"id": "bz:" + x["aciklama"][:20], "ad": x["tur"], "tur": "risk"})
        kenarlar.append({"kaynak": "kok", "hedef": "bz:" + x["aciklama"][:20]})

    sirali = {"kritik": 0, "yuksek": 1, "orta": 2, "dusuk": 3, "bilgi": 4}
    bulgular.sort(key=lambda x: sirali.get(x.get("risk", "bilgi"), 9))
    ip_bilgi = sonuc.get("ip") or (sonuc.get("whois") if ip_mi else {})
    konum = []
    if isinstance(ip_bilgi, dict) and ip_bilgi.get("enlem"):
        konum.append({"ip": ip_bilgi.get("ip") or ad, "ulke": ip_bilgi.get("ulke"), "sehir": ip_bilgi.get("sehir"),
                      "enlem": ip_bilgi.get("enlem"), "boylam": ip_bilgi.get("boylam"),
                      "iss": ip_bilgi.get("iss"), "tur": "hedef"})
    elif not ip_mi:
        # alan adının A kaydını çöz ve sunucunun konumunu haritaya koy
        try:
            hedef_ip = socket.gethostbyname(ad)
            if hedef_ip and not ozel_ip(hedef_ip):
                ib = ip_analiz(hedef_ip)
                if ib.get("enlem"):
                    konum.append({"ip": hedef_ip, "ulke": ib.get("ulke"), "sehir": ib.get("sehir"),
                                  "enlem": ib.get("enlem"), "boylam": ib.get("boylam"),
                                  "iss": ib.get("iss"), "tur": "hedef"})
                    say["ip"] = max(say.get("ip", 0), 1)
        except Exception:
            pass
    # tehdit beslemesinden konum örneği (harita canlansın)
    tehdit_konum, tehdit_ulke = [], {}
    if "tehdit" in moduller:
        try:
            tv = tehdit_verisi()
            tehdit_konum = tv.get("konumlar") or []
            tehdit_ulke = tv.get("ulkeler") or {}
        except Exception:
            pass
    return {"hedef": ad, "url": url, "moduller": moduller, "sonuclar": sonuc, "bulgular": bulgular[:80],
            "sayilar": say, "risk": _risk_puani(bulgular), "graf": {"dugumler": dugumler[:120], "kenarlar": kenarlar[:200]},
            "konumlar": konum, "tehdit_konumlar": tehdit_konum, "tehdit_ulkeler": tehdit_ulke,
            "sure": round(time.time() - t0, 2), "zaman": time.strftime("%Y-%m-%d %H:%M:%S")}


def _tehdit_esles(ad):
    try:
        t = tehdit_verisi()
    except Exception:
        return []
    esles = []
    ip = ""
    try:
        ip = socket.gethostbyname(ad)
    except Exception:
        pass
    for k in (t.get("c2") or []):
        if k.get("ip") == ip:
            esles.append({"ip": ip, "kaynak": k.get("kaynak", ""), "aciklama":
                          "%s zararlı yazılım C2 adresi olarak listelenmiş (%s)" % (ip, k.get("zararli", ""))})
    for k in (t.get("ioc") or []):
        if k.get("ip") == ip:
            esles.append({"ip": ip, "kaynak": k.get("kaynak", ""), "aciklama": "%s ele geçirilmiş sistem listesinde." % ip})
    return esles


# --------------------------------------------------------------------------- #
# 14) UÇ NOKTA YÖNLENDİRİCİ  (ustad-osint.py bunu çağırır)
# --------------------------------------------------------------------------- #

# ---------------------------------------------------- EK MODÜLLER (osint-ek.py)
import sys as _sys
import importlib.util as _iu

def _ek_yukle():
    """Ek modülleri (Pasif Radar, Arşiv, Savunma, Kanıt...) yükler."""
    yol = os.path.join(os.path.dirname(os.path.abspath(__file__)), "osint-ek.py")
    try:
        sp = _iu.spec_from_file_location("osint_ek", yol)
        m = _iu.module_from_spec(sp)
        sp.loader.exec_module(m)
        _sys.modules["osint_ek"] = m
        try:
            m.ek_ayarla(_sys.modules[__name__])
        except Exception:
            pass
        return m
    except Exception as e:
        print("[ek] yüklenemedi:", e)
        return None

EK = _ek_yukle()


def _ek2_yukle():
    """YENİ NESİL ARAÇLAR (v1.6): osint-ek2a/b/c.py dosyalarını yükler.
    Her dosya kendi `ek2x_isle(yol, sorgu, govde, ayarlar)` dağıtıcısını taşır;
    tanımadığı yolda None döner (zincir sırayla denenir)."""
    kok = os.path.dirname(os.path.abspath(__file__))
    zincir = []
    for ad, fonk in (("osint-ek2a.py", "ek2a_isle"), ("osint-ek2b.py", "ek2b_isle"), ("osint-ek2c.py", "ek2c_isle")):
        yol = os.path.join(kok, ad)
        if not os.path.exists(yol):
            print("[ek2] %s yok (atlandı)" % ad)
            continue
        try:
            sp = _iu.spec_from_file_location(ad[:-3].replace("-", "_"), yol)
            m = _iu.module_from_spec(sp)
            sp.loader.exec_module(m)
            _sys.modules[ad[:-3].replace("-", "_")] = m
            f = getattr(m, fonk, None)
            if f is None:
                print("[ek2] %s içinde %s bulunamadı" % (ad, fonk))
                continue
            zincir.append(f)
            print("[ek2] %s yüklendi" % ad)
        except Exception as e:
            print("[ek2] %s yüklenemedi: %s" % (ad, e))
    return zincir


EK2 = _ek2_yukle()

MODUL_LISTESI = [
    {"kod": "dns", "ad": "DNS Analizi", "aciklama": "A, AAAA, MX, TXT, NS, SOA, CAA kayıtları + SPF/DMARC denetimi"},
    {"kod": "whois", "ad": "WHOIS / RDAP", "aciklama": "Alan adı tescil bilgileri, kayıtçı, süre, askı durumu"},
    {"kod": "ip", "ad": "IP / ASN Analizi", "aciklama": "Konum, ISS, ASN, ağ bloğu, proxy/hosting göstergesi"},
    {"kod": "subdomain", "ad": "Subdomain Tarama", "aciklama": "Sertifika şeffaflığı + pasif DNS kaynakları"},
    {"kod": "webtek", "ad": "Web Teknolojileri", "aciklama": "Sunucu, CMS, dil, analitik, güvenlik başlıkları, TLS sertifikası"},
    {"kod": "cloud", "ad": "Cloud Keşfi", "aciklama": "S3 / GCS / Azure kova varlık ve açıklık kontrolü"},
    {"kod": "eposta", "ad": "E-posta İstihbaratı", "aciklama": "MX, SPF, tek kullanımlık, rol hesabı, Gravatar izi"},
    {"kod": "kullanici", "ad": "Kullanıcı Adı Arama", "aciklama": "25+ platformda hesap varlığı"},
    {"kod": "github", "ad": "GitHub İstihbaratı", "aciklama": "Profil, depolar, diller, commit e-posta sızıntısı"},
    {"kod": "sizinti", "ad": "Veri Sızıntısı Tespiti", "aciklama": "Açık .env/.git/yedek/konfig probu (yumuşak 404 ayıklamalı)"},
    {"kod": "darkweb", "ad": "Dark Web / Sızıntı Kaydı", "aciklama": "HIBP anahtarı ile sızıntı kaydı sorgusu"},
    {"kod": "tehdit", "ad": "Tehdit Haritası", "aciklama": "Botnet C2, phishing ve ele geçirilmiş sistem beslemeleri + konum"},
]


def uclari_isle(yol, sorgu, govde, ayarlar=None):
    """(veri, http_kodu) döndürür. yol: '/api/arac/...'"""
    ayarlar = ayarlar or {}
    gh = ayarlar.get("github_anahtar") or None
    hibp = ayarlar.get("hibp_anahtar") or None
    yol = "/" + yol.strip("/")
    g = lambda k, d="": (sorgu.get(k) or d).strip() if isinstance(sorgu.get(k), str) else (sorgu.get(k) or d)
    bg = lambda k, d="": (govde.get(k) or d) if isinstance(govde, dict) else d

    if yol in ("/api/arac/moduller", "/api/arac"):
        return {"moduller": MODUL_LISTESI, "surum": SURUM}, 200

    if yol == "/api/arac/dns":
        ad = _alan_bul(g("ad") or g("hedef"))
        return (dns_toplu(ad) if ad else {"hata": "ad gerekli"}), 200

    if yol == "/api/arac/whois":
        return whois_rdap(g("ad") or g("hedef")), 200

    if yol == "/api/arac/asn":
        hedef = g("ip") or g("ad") or g("hedef")
        ip = hedef
        if ip and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            try:
                ip = socket.gethostbyname(_alan_bul(ip))
            except Exception:
                pass
        return ip_analiz(ip), 200

    if yol == "/api/arac/ip":
        return ip_analiz(g("ip") or g("ad")), 200

    if yol == "/api/arac/subdomain":
        ad = _alan_bul(g("ad") or g("hedef"))
        return (subdomain_tara(ad) if ad else {"hata": "ad gerekli"}), 200

    if yol == "/api/arac/webtek":
        return web_tek(g("ad") or g("url") or g("hedef")), 200

    if yol == "/api/arac/cloud":
        ad = _alan_bul(g("ad") or g("hedef"))
        return (cloud_ara(ad) if ad else {"hata": "ad gerekli"}), 200

    if yol == "/api/arac/eposta":
        return eposta_istihbarat(g("ad") or g("adres") or g("hedef")), 200

    if yol == "/api/arac/kullanici":
        return kullanici_ara(g("ad") or g("kullanici")), 200

    if yol == "/api/arac/github":
        return github_istihbarat(g("ad") or g("kullanici"), gh), 200

    if yol == "/api/arac/sizinti":
        hedef = g("ad") or g("hedef") or g("url")
        return (sizinti_tara(hedef) if hedef else {"hata": "hedef gerekli"}), 200

    if yol == "/api/arac/darkweb":
        return darkweb_ara(g("ad") or g("sorgu"), hibp), 200

    if yol == "/api/arac/tehdit":
        return tehdit_verisi(bool(g("zorla"))), 200

    if yol == "/api/arac/profil":
        hedef = bg("hedef") or g("hedef") or g("ad")
        moduller = bg("moduller") or None
        if isinstance(moduller, str):
            moduller = [x for x in re.split(r"[,\s]+", moduller) if x]
        return (profil_cikar(hedef, moduller, gh, hibp) if hedef else {"hata": "hedef gerekli"}), 200

    if yol == "/api/arac/ozet":
        t = None
        try:
            t = tehdit_verisi()
        except Exception:
            t = {}
        return {"modul_sayisi": len(MODUL_LISTESI), "tehdit": {"c2": (t or {}).get("c2_toplam", 0),
                "phishing": (t or {}).get("phishing_toplam", 0), "ioc": (t or {}).get("ioc_toplam", 0),
                "guncelleme": (t or {}).get("guncelleme", "")},
                "siteler": len(_siteler())}, 200

    # --- ek uç noktalar (Pasif Radar, CVE, Arşiv, URLScan, Takeover, Savunma, Toplu, Kanıt)
    _ek_bilinmeyen = None
    if EK is not None:
        try:
            v = EK.ek_isle(yol, sorgu, govde, ayarlar)
            if isinstance(v, dict) and str(v.get("hata", "")).startswith("bilinmeyen ek uç nokta"):
                _ek_bilinmeyen = v          # v1.6 zincirine devret, sonuç yoksa bunu döndür
            elif v is not None:
                return v, 200
        except Exception as e:
            return {"hata": "ek modül hatası: " + str(e)[:200]}, 200

    # --- YENİ NESİL ARAÇLAR (v1.6): istismar, posta güvenliği, başlık analizi,
    #     sertifika CT, web yapılandırma, fidye radarı, saldırı akışı, sır avcısı,
    #     yerel ağ, şifre kontrolü, rapor paketi, bildirim
    for _m in EK2:
        try:
            v = _m(yol, sorgu, govde, ayarlar)
            if v is not None:
                return v, 200
        except Exception as e:
            return {"hata": "v1.6 araç hatası (" + getattr(_m, "__name__", "?") + "): " + str(e)[:200]}, 200
    if _ek_bilinmeyen is not None:
        return _ek_bilinmeyen, 200
    return {"hata": "bilinmeyen araç uç noktası: " + yol}, 404


# --- ek modüllere çekirdek fonksiyonlarını ver (profil, subdomain) -----------
class _EkKok(object):
    """osint-ek.py'nin profil_cikar/subdomain_tara çağırabilmesi için sarmalayıcı."""
    subdomain_tara = staticmethod(subdomain_tara)
    profil_cikar = staticmethod(profil_cikar)
    modul_listesi = staticmethod(lambda: MODUL_LISTESI)


if EK is not None:
    try:
        EK.ek_ayarla(_EkKok())
        print("[ek] cekirdek baglandi: profil_cikar + subdomain_tara")
    except Exception as _e:
        print("[ek] cekirdek baglanamadi:", _e)
