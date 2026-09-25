# -*- coding: utf-8 -*-
"""
ÜSTAD OSINT — EK-2A MODÜLLERİ (v1.6)
=====================================
Bu dosya, ana çekirdeğin (osint-araclar.py) ve v1.5 ekinin (osint-ek.py) yanında
DURAN BAĞIMSIZ bir ektir. Hiçbir proje dosyasını import etmez, onlara dokunmaz;
kendi HTTP/JSON/DNS/önbellek yardımcılarını kendi içinde taşır.

Üç modül:
  1) istismar      — CISA KEV (bilinen istismar edilen CVE'ler) + FIRST EPSS (istismar olasılığı)
  2) postaguvenlik — Bir alan adının SPF / DMARC / DKIM / MX durumu ve posta sahteciliği puanı
  3) baslikanaliz  — Ham e-posta başlıklarını ayrıştırıp sahtecilik (phishing) riskini puanlar

Yönlendirici:  ek2a_isle(yol, sorgu, govde, ayarlar)
    /api/arac/istismar?cve=CVE-2024-3094
    /api/arac/istismar?cveler=CVE-2024-3094,CVE-2021-44228
    /api/arac/postaguvenlik?ad=example.com
    /api/arac/baslikanaliz   (POST {"ham": "<mail başlıkları>"})

Her modül hata durumunda {"hata": "<Türkçe açıklama>"} döner ve ASLA çökmez.

Bağımsız deneme:
    python osint-ek2a.py istismar CVE-2024-3094
    python osint-ek2a.py posta example.com
    python osint-ek2a.py baslik basliklar.txt
"""
import ipaddress
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from email.utils import parsedate_to_datetime

# ------------------------------------------------------------------ SABİTLER
KOK = os.path.dirname(os.path.abspath(__file__))
ONBELLEK = os.path.join(KOK, "veri", "ek2a-onbellek.json")

SURUM = "1.6"
UA = "UstadOSINT/1.6 (+kendi sistem, izinli)"

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"
DOH_URL = "https://dns.google/resolve"

# Denenecek DKIM seçicileri (yaygın sağlayıcılar + jenerik isimler)
DKIM_SECICILERI = ["default", "google", "k1", "mail", "dkim",
                   "selector1", "selector2", "s1", "s2", "smtp"]

# Özel (iç) ağa ait sayılanlar yakalanır; "özel IP" risk işaretinde kullanılır
MAX_CVE = 20              # tek sorguda en fazla CVE sayısı
KEV_TTL = 86400           # CISA KEV listesi 24 saat önbellekte (dosya ~2 MB)
EPSS_TTL = 3600
DNS_TTL = 1800
POSTA_TTL = 3600


# ------------------------------------------------------------------- SSL/HTTP
def _ssl_baglam():
    """Kaspersky MITM sertifikası için certifi köklerini kullanır."""
    try:
        import certifi  # noqa: F401
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        try:
            return ssl.create_default_context()
        except Exception:
            return None


BAGLAM = _ssl_baglam()
try:
    # Yedek: sertifika doğrulaması başarısız olursa bu bağlam denenir
    BAGLAM_ZAYIF = ssl._create_unverified_context()
except Exception:
    BAGLAM_ZAYIF = BAGLAM


def _cek(url, veri=None, basliklar=None, yontem="GET", zaman=25):
    """Ortak HTTP istemcisi. (durum_kodu, govde_metni) döner; hata durumunda (0, "").

    veri: dict ise form-urlencoded gövde, str/bytes ise ham gövde.
    Önce sertifika doğrulamalı bağlam, olmazsa doğrulamasız yedek bağlam denenir.
    """
    govde_katar = None
    if isinstance(veri, dict):
        govde_katar = urllib.parse.urlencode(veri).encode("utf-8")
    elif isinstance(veri, str):
        govde_katar = veri.encode("utf-8")
    elif veri is not None:
        govde_katar = veri

    for baglam in (BAGLAM, BAGLAM_ZAYIF):
        try:
            istek = urllib.request.Request(url, data=govde_katar,
                                           method=str(yontem or "GET").upper())
            istek.add_header("User-Agent", UA)
            istek.add_header("Accept", "application/json, text/plain, */*")
            if isinstance(veri, dict):
                istek.add_header("Content-Type",
                                 "application/x-www-form-urlencoded; charset=utf-8")
            for k, v in (basliklar or {}).items():
                istek.add_header(k, v)
        except Exception:
            return 0, ""
        try:
            with urllib.request.urlopen(istek, timeout=zaman, context=baglam) as y:
                return y.status, y.read(2000000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read(200000).decode("utf-8", "replace")
            except Exception:
                return e.code, ""
        except ssl.SSLError:
            # Sertifika doğrulaması düştü → doğrulamasız bağlamla bir kez daha dene
            continue
        except Exception:
            return 0, ""
    return 0, ""


def _json(url, veri=None, basliklar=None, yontem="GET", zaman=25):
    """_cek + json çözümleme. (durum_kodu, nesne_veya_None, ham_govde) döner."""
    kod, govde = _cek(url, veri, basliklar, yontem, zaman)
    try:
        return kod, json.loads(govde), govde
    except Exception:
        return kod, None, govde


# --------------------------------------------------------------------- ONBELLEK
def _onbellek_oku():
    try:
        with open(ONBELLEK, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _onbellek_yaz(d):
    try:
        os.makedirs(os.path.dirname(ONBELLEK), exist_ok=True)
        with open(ONBELLEK, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False)
    except Exception:
        pass


def _onbellekli(anahtar, ttl, fonksiyon):
    """Önbellek sarmalayıcı: taze kayıt varsa onu döner, yoksa fonksiyonu çalıştırır.

    Hata sözlükleri ("hata" anahtarı taşıyanlar) ve sonucu eksik/şüpheli olan
    kayıtlar ("_onbellekleme" işaretliler; ör. ağ kesintisi yüzünden boş dönen
    DNS denetimi) önbelleğe YAZILMAZ — böylece bayat/eksik veri yapışıp kalmaz.
    """
    d = _onbellek_oku()
    kayit = d.get(anahtar)
    if isinstance(kayit, dict) and time.time() - float(kayit.get("_zaman") or 0) < ttl:
        v = dict(kayit.get("veri") or {})
        v["onbellek"] = True
        return v
    v = fonksiyon()
    if isinstance(v, dict) and "hata" not in v:
        if v.pop("_onbellekleme", False):
            return v
        d[anahtar] = {"_zaman": time.time(), "veri": v}
        _onbellek_yaz(d)
    return v


def _onbellek_sil(anahtar):
    """zorla=1 için: ilgili önbellek kaydını düşürür."""
    d = _onbellek_oku()
    if anahtar in d:
        d.pop(anahtar, None)
        _onbellek_yaz(d)


def _zorla_mi(sorgu, govde):
    """?zorla=1 (veya gövdede zorla) → önbelleği atla."""
    for kaynak in (sorgu or {}, govde or {}):
        if str(kaynak.get("zorla") or "").lower() in ("1", "true", "evet", "yes", "var"):
            return True
    return False


# ------------------------------------------------------------------ DNS (DoH)
def _ad_temizle(hedef):
    """Girdiden sade alan adı çıkarır: şema, yol, port, @ ve sondaki nokta atılır."""
    h = str(hedef or "").strip().lower()
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h)
    h = h.split("/")[0]
    if "@" in h:
        h = h.split("@")[-1]
    h = h.split(":")[0].strip().strip(".")
    return h


def _ad_gecerli(ad):
    """Alan adı biçimi: harf/rakam/alt çizgi ile başlar, tire ile bitemez
    (_dmarc.<ad> ve <secici>._domainkey.<ad> gibi adlar da geçerli sayılır)."""
    return bool(re.match(r"^(?!-)[a-z0-9_][a-z0-9_-]{0,62}(\.[a-z0-9_][a-z0-9_-]{0,62})+$",
                         (ad or "").lower()))


def _doh(ad, tip="TXT", zorla=False):
    """Google DNS-over-HTTPS ile kayıt çeker. (yanit_dict, hata_metni) döner."""
    ad = _ad_temizle(ad)
    if not _ad_gecerli(ad):
        return None, "geçersiz alan adı: %s" % (ad or "-")
    anahtar = "doh::%s::%s" % (ad, tip)

    def uret():
        url = "%s?name=%s&type=%s" % (DOH_URL, urllib.parse.quote(ad), tip)
        kod, j, ham = _json(url, zaman=20)
        if kod == 0:
            # Ağ hatası (Kaspersky/geçici kopma) → bir kez daha denenir
            time.sleep(0.6)
            kod, j, ham = _json(url, zaman=20)
        if kod != 200 or not isinstance(j, dict):
            return {"hata": "DoH yanıtı alınamadı (HTTP %s)" % kod}
        return j

    if zorla:
        _onbellek_sil(anahtar)
    j = _onbellekli(anahtar, DNS_TTL, uret)
    if isinstance(j, dict) and j.get("hata"):
        return None, j["hata"]
    return j, None


def _txt_deger(ham_veri):
    """DoH TXT kaydını okunur metne çevirir (parçalı tırnaklı kayıtları birleştirir)."""
    s = str(ham_veri or "")
    parcalar = re.findall(r'"((?:[^"\\]|\\.)*)"', s)
    if parcalar:
        return "".join(parcalar).strip()
    return s.strip().strip('"')


def _dns_txt(ad, zorla=False):
    """Bir adın TXT kayıtlarını metin listesi olarak döner."""
    j, hata = _doh(ad, "TXT", zorla)
    if j is None:
        return [], hata
    liste = []
    for c in (j.get("Answer") or []):
        if c.get("type") == 16 and c.get("data"):
            liste.append(_txt_deger(c.get("data")))
    return liste, None


def _dns_mx(ad, zorla=False):
    """MX kayıtlarını öncelik sırasına göre döner ('0 .' = null MX ayrı işaretlenir)."""
    j, hata = _doh(ad, "MX", zorla)
    if j is None:
        return [], hata
    kayitlar = []
    for c in (j.get("Answer") or []):
        if c.get("type") != 15 or not c.get("data"):
            continue
        d = str(c["data"]).strip()
        p = d.split(None, 1)
        if len(p) == 2 and p[0].isdigit():
            sunucu = p[1].strip().rstrip(".")
            kayit = {"oncelik": int(p[0])}
            if sunucu in ("", "."):
                # RFC 7505 null MX: "bu alan adı posta kabul etmiyor" demek
                kayit["sunucu"] = "."
                kayit["not"] = "null MX (RFC 7505): alan adı posta kabul etmiyor"
            else:
                kayit["sunucu"] = sunucu
            kayitlar.append(kayit)
        else:
            kayitlar.append({"oncelik": None, "sunucu": d.strip().rstrip(".")})
    kayitlar.sort(key=lambda x: (x["oncelik"] is None, x["oncelik"] or 0, x["sunucu"]))
    return kayitlar, None


def ip_coz(ad, zorla=False):
    """Adı IP listesine çevirir (DoH A + AAAA; sonuç yoksa sistem çözücüsü)."""
    ad = _ad_temizle(ad)
    if not ad:
        return []
    try:
        ipaddress.ip_address(ad)
        return [ad]
    except Exception:
        pass
    ipler = []
    for tip in ("A", "AAAA"):
        j, _ = _doh(ad, tip, zorla)
        if isinstance(j, dict):
            for c in (j.get("Answer") or []):
                if c.get("type") in (1, 28) and c.get("data"):
                    ipler.append(str(c["data"]).strip())
    if not ipler:
        import socket
        try:
            ipler = sorted({x[4][0] for x in socket.getaddrinfo(ad, None)})
        except Exception:
            ipler = []
    return list(dict.fromkeys(ipler))


def _ozel_ip(ip):
    """IP gerçekten iç/özel ağa mı ait?

    Yalnız yönlendirilemeyen aralıklar sayılır (RFC1918, CGNAT 100.64/10, döngü,
    bağlantı-yerel, çoklu yayın, fc00::/7, fe80::/10). Python'un geniş "is_private"
    listesi 203.0.113.0/24 gibi belge/test aralıklarını da içerdiği için burada
    kullanılmaz; aksi halde örnek/ayrılmış adresler yanlışlıkla "iç IP" sayılırdı.
    """
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except Exception:
        return False
    ozeller = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("240.0.0.0/4"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
        ipaddress.ip_network("::/128"),
    ]
    for ag in ozeller:
        if a.version == ag.version and a in ag:
            return True
    return bool(a.is_multicast)


# ===================================================================== 1) KEV/EPSS
def _kev_listesi(zorla=False):
    """CISA KEV kataloğunu (cveID → kayıt) sözlüğe indirir. 24 saat önbellekli."""
    anahtar = "kev::katalog"

    def uret():
        kod, j, _ = _json(KEV_URL, zaman=45)
        if kod != 200 or not isinstance(j, dict) or not j.get("vulnerabilities"):
            return {"hata": "CISA KEV listesi alınamadı (HTTP %s)" % kod}
        idx = {}
        for k in j.get("vulnerabilities") or []:
            cid = str(k.get("cveID") or "").strip().upper()
            if cid:
                idx[cid] = k
        return {"kayitlar": idx, "sayi": len(idx),
                "surum": j.get("catalogVersion"),
                "yayin": j.get("dateReleased")}

    if zorla:
        _onbellek_sil(anahtar)
    return _onbellekli(anahtar, KEV_TTL, uret)


def _epss(cve_idler, zorla=False):
    """FIRST EPSS puanlarını çeker: {CVE: {"epss":.., "yuzdelik":.., "tarih":..}}."""
    anahtar = "epss::" + ",".join(sorted(cve_idler))

    def uret():
        url = "%s?cve=%s" % (EPSS_URL, urllib.parse.quote(",".join(cve_idler), safe=","))
        kod, j, _ = _json(url, zaman=25)
        if kod != 200 or not isinstance(j, dict):
            return {"hata": "FIRST EPSS yanıtı alınamadı (HTTP %s)" % kod}
        sozluk = {}
        for d in (j.get("data") or []):
            cid = str(d.get("cve") or "").strip().upper()
            if not cid:
                continue
            try:
                puan = float(d.get("epss")) if d.get("epss") is not None else None
            except Exception:
                puan = None
            try:
                yuzde = float(d.get("percentile")) if d.get("percentile") is not None else None
            except Exception:
                yuzde = None
            sozluk[cid] = {"epss": puan, "yuzdelik": yuzde, "tarih": d.get("date")}
        return {"puanlar": sozluk, "sayi": len(sozluk)}

    if zorla:
        _onbellek_sil(anahtar)
    return _onbellekli(anahtar, EPSS_TTL, uret)


def _karar_ver(kev_var, puan):
    """KEV + EPSS'e göre Türkçe karar metni."""
    if kev_var is True:
        return "ACİL — aktif istismar ediliyor"
    if puan is None:
        return "bilinmiyor — EPSS verisi yok"
    if puan >= 0.5:
        return "YÜKSEK — istismar olasılığı yüksek"
    if puan >= 0.1:
        return "orta"
    return "düşük"


def istismar_sorgu(cve_idler, zorla=False):
    """CISA KEV + FIRST EPSS birleşik sorgu. Tek CVE veya liste (en fazla 20) kabul eder."""
    # --- girdi doğrulama (biçim bozuksa kaynağa hiç gitmeden Türkçe hata döner)
    temiz = []
    for c in (cve_idler or []):
        c = str(c or "").strip().upper()
        if not c:
            continue
        if not re.match(r"^CVE-\d{4}-\d{4,}$", c):
            return {"hata": "geçersiz CVE kimliği: %s (beklenen biçim: CVE-2024-3094)" % c}
        if c not in temiz:
            temiz.append(c)
    if not temiz:
        return {"hata": "CVE kimliği verilmedi (örn: ?cve=CVE-2024-3094)"}
    if len(temiz) > MAX_CVE:
        return {"hata": "en fazla %d CVE sorgulanabilir (%d verildi)" % (MAX_CVE, len(temiz))}

    kev = _kev_listesi(zorla)
    kev_idx = (kev or {}).get("kayitlar") if isinstance(kev, dict) else None
    kev_hata = (kev or {}).get("hata") if isinstance(kev, dict) else None

    epss = _epss(temiz, zorla)
    epss_idx = (epss or {}).get("puanlar") if isinstance(epss, dict) else None
    epss_hata = (epss or {}).get("hata") if isinstance(epss, dict) else None

    # Her iki kaynak da düştüyse dürüst hata döneriz; uydurma veri üretmeyiz.
    if kev_idx is None and epss_idx is None:
        return {"hata": "kaynaklara ulaşılamadı — %s / %s"
                        % (kev_hata or "KEV yok", epss_hata or "EPSS yok")}

    kayitlar = []
    for c in temiz:
        k = (kev_idx or {}).get(c)
        e = (epss_idx or {}).get(c) or {}
        puan = e.get("epss")
        kayit = {
            "cve": c,
            "kev": bool(k),
            "kev_eklenme": (k or {}).get("dateAdded"),
            "fidye_kampanyasi": bool(str((k or {}).get("knownRansomwareCampaignUse") or
                                         "").lower() == "known"),
            "urun": (("%s %s" % ((k or {}).get("vendorProject") or "",
                                 (k or {}).get("product") or "")).strip() or None),
            "epss": (round(puan, 4) if isinstance(puan, (int, float)) else None),
            "epss_yuzdelik": (round(e.get("yuzdelik") * 100, 2)
                              if isinstance(e.get("yuzdelik"), (int, float)) else None),
            "epss_tarih": e.get("tarih"),
            "karar": _karar_ver(bool(k), puan if isinstance(puan, (int, float)) else None),
            "aciklama": (k or {}).get("shortDescription"),
            "kaynak": "CISA KEV + FIRST EPSS",
        }
        notlar = []
        if kev_idx is None:
            notlar.append("CISA KEV listesi alınamadı: %s" % (kev_hata or "bilinmiyor"))
        elif not k:
            notlar.append("CISA KEV kataloğunda yok")
        if epss_idx is None:
            notlar.append("EPSS servisi yanıt vermedi: %s" % (epss_hata or "bilinmiyor"))
        elif not e:
            notlar.append("EPSS bu CVE için kayıt döndürmedi")
        if notlar:
            kayit["not"] = " · ".join(notlar)
        if not kayit["aciklama"]:
            kayit["aciklama"] = None
        kayitlar.append(kayit)

    # --- sıralama: KEV'liler önce, sonra EPSS puana göre azalan
    kayitlar.sort(key=lambda x: (not x["kev"], -(x["epss"] or 0)))

    if len(kayitlar) == 1:
        return kayitlar[0]
    return {"kayitlar": kayitlar, "toplam": len(kayitlar),
            "kev_toplam": len([x for x in kayitlar if x["kev"]]),
            "kaynak": "CISA KEV + FIRST EPSS",
            "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S")}


# =============================================================== 2) POSTA GÜVENLİK
def _spf_politika(spf_kayit):
    """SPF kaydındaki 'all' mekanizmasını (politika) çıkarır."""
    m = re.search(r"([~\-+?])all\b", spf_kayit or "", re.I)
    return (m.group(0).lower() if m else None)


def _dkim_kullanilabilir(kayit):
    """DKIM TXT kaydı gerçekten kullanılabilir bir anahtar mı?

    ('v=DKIM1; p=' gibi BOŞ p= içeren kayıtlar "anahtar iptal edildi" demektir;
    ör. example.com'un joker kaydı. Bunlar bulunmuş sayılmaz.)
    (kullanilabilir, aciklama) döner.
    """
    s = str(kayit or "")
    if not re.search(r"\b(v\s*=\s*DKIM1|k\s*=\s*rsa|p\s*=)", s, re.I):
        return False, "DKIM alanları yok"
    m = re.search(r"(?:^|;)\s*p\s*=\s*([A-Za-z0-9+/=]*)", s)
    if not m:
        return False, "p= alanı yok"
    anahtar = m.group(1).strip()
    if len(anahtar) < 32:
        return False, "p= boş veya çok kısa (anahtar iptal edilmiş olabilir)"
    return True, None


def _dmarc_politika(kayit):
    """DMARC kaydındaki p= ve pct= değerlerini çıkarır."""
    p = re.search(r"(?:^|;)\s*p\s*=\s*([a-z]+)", kayit or "", re.I)
    pct = re.search(r"(?:^|;)\s*pct\s*=\s*(\d{1,3})", kayit or "", re.I)
    return ((p.group(1).lower() if p else None),
            (int(pct.group(1)) if pct else None))


def posta_guvenlik(ad, mx_ip=False, zorla=False):
    """SPF / DMARC / DKIM / MX denetimi + 0-100 posta sahteciliği direnci puanı."""
    ad = _ad_temizle(ad)
    if not ad or not _ad_gecerli(ad):
        return {"hata": "geçerli bir alan adı verilmedi (örn: ?ad=example.com)"}
    anahtar = "posta::" + ad

    def uret():
        kaynak_notlari = []
        spf = {"var": False, "kayit": None, "politika": None, "uyari": None}
        dmarc = {"var": False, "kayit": None, "politika": None,
                 "pct": None, "uyari": None,
                 "onerilen": "v=DMARC1; p=quarantine; pct=100; rua=mailto:rapor@%s" % ad}
        dkim = {"bulunan": [], "denenen": []}
        mx = []
        eksikler, oneriler = [], []

        # ---- SPF: alan adının kendi TXT kayıtları içinde "v=spf1" aranır
        dns_hata = 0
        txtler, hata = _dns_txt(ad, zorla)
        if hata:
            dns_hata += 1
            kaynak_notlari.append("SPF/DMARC TXT sorgusu: %s" % hata)
        for t in txtler:
            if str(t).lower().startswith("v=spf1"):
                spf["var"] = True
                spf["kayit"] = t
                spf["politika"] = _spf_politika(t)
                break

        # ---- DMARC: _dmarc.<ad> TXT
        d_txtler, d_hata = _dns_txt("_dmarc." + ad, zorla)
        if d_hata:
            dns_hata += 1
            kaynak_notlari.append("DMARC (_dmarc.%s) sorgusu: %s" % (ad, d_hata))
        for t in d_txtler:
            if str(t).lower().startswith("v=dmarc1"):
                dmarc["var"] = True
                dmarc["kayit"] = t
                p, pct = _dmarc_politika(t)
                dmarc["politika"] = p
                dmarc["pct"] = pct
                break

        # ---- DKIM: yaygın seçiciler tek tek denenir
        for sec in DKIM_SECICILERI:
            txt, s_hata = _dns_txt("%s._domainkey.%s" % (sec, ad), zorla)
            if s_hata:
                dns_hata += 1
                dkim["denenen"].append({"secici": sec, "var": False, "not": s_hata})
                continue
            bulundu = None
            gecersiz = None
            for t in txt:
                uygun, neden = _dkim_kullanilabilir(t)
                if uygun:
                    bulundu = t
                    break
                gecersiz = gecersiz or neden
            kayit = {"secici": sec, "var": bool(bulundu)}
            if bulundu:
                kayit["kayit"] = bulundu[:200]
                dkim["bulunan"].append(sec)
            elif gecersiz:
                # Kayıt var ama kullanılamaz (iptal edilmiş anahtar vb.)
                kayit["not"] = gecersiz
            dkim["denenen"].append(kayit)

        # ---- MX
        mx, mx_hata = _dns_mx(ad, zorla)
        if mx_hata:
            dns_hata += 1
            kaynak_notlari.append("MX sorgusu: %s" % mx_hata)
        if mx_ip:
            for m in mx:
                m["ip"] = ip_coz(m.get("sunucu"), zorla)

        # ---- PUANLAMA (toplam üst sınır 100)
        puan = 0
        if spf["var"]:
            puan += 25
            if spf["politika"] == "-all":
                puan += 10
        else:
            eksikler.append("SPF kaydı yok: gönderen sunucular doğrulanamıyor")
            oneriler.append("SPF ekleyin, örn: v=spf1 include:_spf.<sağlayıcı>.com -all")

        if dmarc["var"]:
            puan += 20
            if dmarc["politika"] == "quarantine":
                puan += 10
            elif dmarc["politika"] == "reject":
                puan += 20
        else:
            eksikler.append("DMARC kaydı yok: başarısız doğrulamada ne yapılacağı tanımsız")
            oneriler.append("DMARC ekleyin: " + dmarc["onerilen"])

        if dkim["bulunan"]:
            puan += 20
        else:
            eksikler.append("DKIM kaydı bulunamadı (denenen seçiciler: %s)"
                            % ", ".join(DKIM_SECICILERI))
            oneriler.append("Posta sağlayıcınızın DKIM imzalamasını açın ve seçici adını doğrulayın")

        if mx:
            puan += 5
        else:
            eksikler.append("MX kaydı yok: alan adı posta kabul etmiyor olabilir")

        puan = max(0, min(100, puan))
        seviye = "iyi" if puan >= 75 else ("orta" if puan >= 40 else "zayıf")

        # ---- Uyarılar
        if not spf["var"]:
            pass
        elif spf["politika"] is None:
            spf["uyari"] = "'all' mekanizması yok: politika belirsiz (varsayılan ~all gibi davranır)"
            oneriler.append("SPF kaydının sonuna -all ekleyin (yetkisiz sunucuları reddet)")
        elif spf["politika"] in ("+all", "?all"):
            spf["uyari"] = "gevşek SPF politikası (%s): her sunucu gönderici gibi davranabilir" % spf["politika"]
            oneriler.append("SPF 'all' mekanizmasını -all (sert) yapın")
        elif spf["politika"] == "~all":
            spf["uyari"] = "yumuşak SPF politikası (~all): başarısız postalar yine de kabul edilebilir"
            oneriler.append("SPF politikasını -all'e yükseltmeyi değerlendirin")

        if dmarc["var"]:
            if dmarc["politika"] == "none":
                dmarc["uyari"] = "politika none: sahte mailler karantinaya alınmıyor"
                oneriler.append("DMARC politikasını p=quarantine, ardından p=reject'e yükseltin")
            elif dmarc["politika"] is None:
                dmarc["uyari"] = "p= etiketi yok: politika okunamadı"
            if dmarc["pct"] is not None and dmarc["pct"] < 100:
                dmarc["uyari"] = (dmarc["uyari"] + " · " if dmarc["uyari"] else "") + \
                    "pct=%d: postanın yalnız %%%.0f'ine politika uygulanıyor" % (dmarc["pct"], dmarc["pct"])
                oneriler.append("pct değerini 100 yapın")
            if not re.search(r"\brua\s*=", dmarc["kayit"] or "", re.I):
                oneriler.append("DMARC kaydına rua=mailto:... ekleyin (rapor toplama)")

        uyari_metni = "Yalnız sahibi olduğun/izin aldığın alan adlarını sorgula."
        if dns_hata:
            uyari_metni = ("DNS sorgularının %d tanesi başarısız oldu (ağ hatası); "
                           "puan EKSİK VERİYE dayanıyor — tekrar deneyin. " % dns_hata) + uyari_metni

        return {
            "ad": ad,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "mx": mx,
            "puan": puan,
            "seviye": seviye,
            "eksikler": eksikler,
            "oneriler": list(dict.fromkeys(oneriler)),
            "kaynak": "Google DoH (dns.google) + DKIM seçici taraması",
            "not": (" · ".join(kaynak_notlari) if kaynak_notlari else None),
            "uyari": uyari_metni,
            "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S"),
            # DNS hatası varsa sonuç eksiktir → önbelleğe yazılmaz (bayat veri yapışmasın)
            "_onbellekleme": bool(dns_hata),
        }

    if zorla:
        _onbellek_sil(anahtar)
    return _onbellekli(anahtar, POSTA_TTL, uret)


# ================================================================= 3) BAŞLIK ANALİZ
# Görünen ad içinde geçtiğinde "marka taklidi" şüphesi doğuran yaygın adlar
MARKALAR = [
    "microsoft", "apple", "google", "paypal", "amazon", "netflix", "dhl", "ups",
    "fedex", "instagram", "facebook", "meta", "whatsapp", "telegram", "binance",
    "linkedin", "dropbox", "adobe", "steam", "spotify", "twitter", "outlook",
    "office365", "icloud", "gmail", "turkcell", "vodafone", "garanti", "ziraat",
    "akbank", "vakifbank", "halkbank", "denizbank", "isbank", "yapikredi",
]
_TR_HARF = str.maketrans({
    "ı": "i", "İ": "i", "ş": "s", "Ş": "s", "ğ": "g", "Ğ": "g",
    "ü": "u", "Ü": "u", "ö": "o", "Ö": "o", "ç": "c", "Ç": "c",
})


def _sadelestir(metin):
    """Türkçe harfleri sadeleştirip küçük harfe indirir (karşılaştırma için)."""
    return re.sub(r"[^a-z0-9]", "", str(metin or "").translate(_TR_HARF).lower())


def _alanlari_ayristir(ham):
    """Ham başlığı (ad, değer) çiftlerine ayırır; gövde atılır, sürekli satırlar birleşir."""
    s = str(ham or "").replace("\r\n", "\n").replace("\r", "\n")
    alanlar = []
    for satir in s.split("\n"):
        if satir.strip() == "":
            break                      # başlık bloğu bitti, gövdeye geçildi
        if satir[:1] in (" ", "\t") and alanlar:
            alanlar[-1][1] += " " + satir.strip()   # sürekli (folded) satır
            continue
        if ":" in satir:
            ad, _, deger = satir.partition(":")
            alanlar.append([ad.strip(), deger.strip()])
    return alanlar


def _alan(alanlar, ad):
    """Belirli bir başlık alanının tüm değerlerini döner."""
    return [d for (a, d) in alanlar if a.lower() == ad.lower()]


def _adres_ayristir(deger):
    """"Görünen Ad <a@b.com>" → (görünen_ad, adres)."""
    d = str(deger or "").strip()
    m = re.search(r"<([^>]+)>", d)
    if m:
        adres = m.group(1).strip()
        ad = d[:m.start()].strip().strip('"').strip("'").strip()
    else:
        adres = d
        ad = ""
    return ad, adres


def _alan_adi(adres):
    """Adresten alan adını çıkarır."""
    a = str(adres or "").strip().strip("<>").lower()
    if "@" in a:
        a = a.rsplit("@", 1)[-1]
    return a.strip().strip(".")


def _tarih_coz(metin):
    """Posta tarihini datetime'a çevirir; olmazsa None."""
    try:
        return parsedate_to_datetime(str(metin or "").strip())
    except Exception:
        return None


def _received_ayristir(satirlar):
    """Received satırlarını zincire çevirir.

    Başlıklarda en üstteki Received en SON hop'tur; burada zincir GÖNDERİCİDEN
    ALICIYA doğru (en eski hop = 1) sunulur ve iki hop arası saniye hesaplanır.
    """
    zincir = []
    for s in satirlar:
        # Sunucu adı: "from <sunucu>"
        m = re.search(r"\bfrom\s+([^\s(;]+)", s, re.I)
        sunucu = (m.group(1).strip() if m else "") or ""
        # IP: parantez/köşeli parantez içindeki ilk geçerli adres
        ip = ""
        for parca in re.findall(r"[\[(]([0-9a-fA-F:.]+)[\])]", s):
            try:
                ipaddress.ip_address(parca)
                ip = parca
                break
            except Exception:
                continue
        if not sunucu and ip:
            sunucu = ip
        if sunucu.startswith("["):
            sunucu = ip or ""
        # Tarih: satırın son ';' sonrası
        tarih = s.rsplit(";", 1)[1].strip() if ";" in s else ""
        zincir.append({"sunucu": sunucu or None, "ip": ip or None, "tarih": tarih or None})

    zincir = list(reversed(zincir))     # göndericiden alıcıya
    onceki = None
    for i, h in enumerate(zincir):
        h["sira"] = i + 1
        dt = _tarih_coz(h.get("tarih"))
        gecikme = None
        if dt is not None and onceki is not None:
            try:
                gecikme = int((dt - onceki).total_seconds())
                if gecikme < 0:
                    gecikme = None      # saat farkı/tutarsız tarih; negatif gecikme anlamsız
            except Exception:
                gecikme = None
        h["gecikme_sn"] = gecikme
        if dt is not None:
            onceki = dt
    return zincir


def _kimlik_sonuclari(alanlar):
    """Authentication-Results / Received-SPF içinden SPF/DKIM/DMARC sonuçlarını çıkarır."""
    ar = " ; ".join(_alan(alanlar, "authentication-results"))
    rspf = " ; ".join(_alan(alanlar, "received-spf"))
    sonuc = {"spf": None, "dkim": None, "dmarc": None, "ar_var": bool(ar.strip())}
    for anahtar in ("spf", "dkim", "dmarc"):
        m = re.search(r"\b%s\s*=\s*([a-z]+)" % anahtar, ar, re.I)
        if m:
            sonuc[anahtar] = m.group(1).lower()
    if sonuc["spf"] is None and rspf:
        m = re.match(r"\s*(pass|fail|softfail|neutral|none|temperror|permerror)", rspf, re.I)
        if m:
            sonuc["spf"] = m.group(1).lower()
    return sonuc


def _taklit_mi(gorunen_ad, adres):
    """Görünen ad ile adres alan adının uyuşmadığını gösteren POZİTİF kanıt arar.

    Yalnız kesin sayılabilecek durumlar işaretlenir:
      * görünen ad içinde başka bir alan adı veya başka bir e-posta adresi varsa,
      * görünen ad bilinen bir marka adı içeriyor ve adres alan adı o markayla
        anlamlı bir harf örtüşmesi taşımıyorsa.
    Aksi halde işaret konmaz (yanlış pozitif üretmemek için).
    """
    ad_ham = str(gorunen_ad or "").strip()
    if not ad_ham:
        return None
    alan = _alan_adi(adres)
    if not alan:
        return None
    alan_sade = _sadelestir(alan)

    # 1) Görünen ad içinde başka bir e-posta adresi
    m = re.search(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", ad_ham, re.I)
    if m and _alan_adi(m.group(0)) != alan:
        return "görünen ad içinde farklı bir e-posta adresi var (%s)" % m.group(0)

    # 2) Görünen ad içinde alan adı benzeri metin (örn. "paypal.com Destek")
    for mm in re.findall(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+){1,3}\.(?:com|net|org|tr|co|io|info|biz))\b",
                         ad_ham, re.I):
        sade = _sadelestir(mm)
        if sade and sade not in alan_sade and alan_sade not in sade:
            return "görünen ad farklı bir alan adı içeriyor (%s), gerçek adres: %s" % (mm, alan)

    # 3) Bilinen marka taklidi
    ad_sade = _sadelestir(ad_ham)
    for marka in MARKALAR:
        if marka in ad_sade:
            # Alan adı markanın ilk 4 harfiyle örtüşmüyorsa taklit şüphesi
            kok = marka[:4]
            if kok not in alan_sade:
                return "görünen ad '%s' markasına benziyor, adres alan adı: %s" % (marka, alan)
            break
    return None


def baslik_analiz(ham, zorla=False):
    """Ham e-posta başlıklarını ayrıştırır ve sahtecilik riskini 0-100 puanlar."""
    if isinstance(ham, dict):
        ham = ham.get("ham") or ham.get("basliklar") or ham.get("raw") or ""
    ham = str(ham or "")
    if not ham.strip():
        return {"hata": "ham başlık boş (POST gövdesi: {\"ham\": \"...\"} olmalı)"}

    alanlar = _alanlari_ayristir(ham)
    if not alanlar:
        return {"hata": "başlık ayrıştırılamadı (her satır 'Ad: değer' biçiminde olmalı)"}

    # ---- Temel alanlar
    from_ham = (_alan(alanlar, "from") or [""])[0]
    gorunen_ad, from_adres = _adres_ayristir(from_ham)
    from_alan = _alan_adi(from_adres)
    return_path = (_alan(alanlar, "return-path") or [""])[0]
    yanit = (_alan(alanlar, "reply-to") or [""])[0]
    _, yanit_adres = _adres_ayristir(yanit)
    yanit_alan = _alan_adi(yanit_adres)
    kime = (_alan(alanlar, "to") or [""])[0]
    konu = (_alan(alanlar, "subject") or [""])[0]
    mesaj_id = (_alan(alanlar, "message-id") or [""])[0]
    tarih = (_alan(alanlar, "date") or [""])[0]

    # ---- Received zinciri + kimlik doğrulama sonuçları
    received = _alan(alanlar, "received")
    zincir = _received_ayristir(received)
    kimlik = _kimlik_sonuclari(alanlar)

    # ---- İlk DIŞ IP (gönderici tarafından alıcıya doğru ilk genel adres)
    ilk_dis_ip = None
    ic_ip_var = False
    for h in zincir:
        ip = h.get("ip")
        if not ip:
            continue
        if _ozel_ip(ip):
            ic_ip_var = True
        elif ilk_dis_ip is None:
            ilk_dis_ip = ip

    # ---- Risk işaretleri (ağırlıklı)
    isaretler = []

    def ekle(baslik, agirlik, kanit=None):
        kayit = {"baslik": baslik, "agirlik": agirlik}
        if kanit:
            kayit["kanit"] = kanit
        isaretler.append(kayit)

    if kimlik["spf"] in ("fail", "softfail"):
        ekle("SPF doğrulaması başarısız (gönderen sunucu yetkisiz)", 30,
             "spf=%s" % kimlik["spf"])
    if kimlik["dkim"] in ("fail", "permerror"):
        ekle("DKIM imzası geçersiz (içerik/imza uyuşmuyor)", 25,
             "dkim=%s" % kimlik["dkim"])
    if kimlik["dmarc"] == "fail":
        ekle("DMARC doğrulaması başarısız", 30, "dmarc=fail")
    if not kimlik["ar_var"] and not _alan(alanlar, "received-spf"):
        ekle("Authentication-Results başlığı yok (doğrulama kaydı bırakılmamış)", 10)
    if yanit_alan and from_alan and yanit_alan != from_alan:
        ekle("Reply-To farklı alan adı", 20, "%s ≠ %s" % (yanit_alan, from_alan))
    taklit = _taklit_mi(gorunen_ad, from_adres)
    if taklit:
        ekle("Görünen ad ile adres alan adı uyuşmuyor", 20, taklit)
    if ic_ip_var:
        ekle("Received zincirinde özel/iç ağ IP'si var", 10)
    if len(received) <= 1:
        ekle("Tek Received hop'u (normal posta zinciri beklenenden kısa)", 10,
             "%d adet Received başlığı" % len(received))
    # Date tutarsızlığı: Date başlığı ile en son hop'un tarihi 24 saatten fazla oynuyorsa
    dt_baslik = _tarih_coz(tarih)
    dt_hop = _tarih_coz(zincir[-1]["tarih"]) if zincir else None
    try:
        if dt_baslik is not None and dt_hop is not None:
            fark = abs((dt_baslik - dt_hop).total_seconds())
            if fark > 86400:
                ekle("Date başlığı ile Received tarihi tutarsız", 10,
                     "%.1f saat fark" % (fark / 3600.0))
    except Exception:
        pass
    if not mesaj_id:
        ekle("Message-ID başlığı yok", 8)

    risk = max(0, min(100, sum(i["agirlik"] for i in isaretler)))
    karar = ("YÜKSEK — sahte olabilir" if risk >= 60
             else ("ORTA — dikkatli incele" if risk >= 30 else "düşük risk"))

    # ---- Kısa özet (Türkçe)
    parcalar = []
    if from_alan:
        parcalar.append("Kimden: %s" % from_alan)
    if ilk_dis_ip:
        parcalar.append("ilk dış IP: %s" % ilk_dis_ip)
    parcalar.append("kimlik: SPF=%s/DKIM=%s/DMARC=%s"
                    % (kimlik["spf"] or "-", kimlik["dkim"] or "-", kimlik["dmarc"] or "-"))
    parcalar.append("%d hop" % len(received))
    if isaretler:
        parcalar.append("işaretler: " + ", ".join(i["baslik"] for i in isaretler[:4]))
    else:
        parcalar.append("belirgin sahtecilik işareti bulunmadı")

    return {
        "kimden": from_adres or None,
        "ad": gorunen_ad or None,
        "yanit_adresi": yanit_adres or None,
        "return_path": return_path or None,
        "kime": kime or None,
        "konu": konu or None,
        "mesaj_id": mesaj_id or None,
        "tarih": tarih or None,
        "ilk_dis_ip": ilk_dis_ip,
        "received_sayisi": len(received),
        "zincir": zincir,
        "zincir_yonu": "gönderici → alıcı (en eski hop = 1)",
        "kimlik": {"spf": kimlik["spf"], "dkim": kimlik["dkim"], "dmarc": kimlik["dmarc"]},
        "isaretler": isaretler,
        "risk": risk,
        "karar": karar,
        "ozet": " · ".join(parcalar),
        "kaynak": "yerel başlık ayrıştırma (ağ sorgusu yapılmaz)",
        "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


# ================================================================== YÖNLENDİRİCİ
def ek2a_isle(yol, sorgu, govde, ayarlar=None):
    """/api/arac/<ad> yollarını işler. Her modül hata durumunda {"hata": ...} döner.

    TANIMADIĞI YOLDA None DÖNER: ana çekirdek (osint-araclar.py) v1.6 zincirini
    sırayla dener (ek2a → ek2b → ek2c); None dönmezse diğer dosyaların uçları
    asla görülemezdi.
    """
    ad = str(yol or "").rstrip("/").split("/")[-1].split("?")[0].lower()
    sorgu = sorgu if isinstance(sorgu, dict) else {}
    govde = govde if isinstance(govde, dict) else {}
    zorla = _zorla_mi(sorgu, govde)

    # Bu dosyanın sahiplendiği yollar (çakışmayı önlemek için dar tutuldu)
    if ad not in ("istismar", "postaguvenlik", "baslikanaliz", "moduller", "ek2a"):
        return None

    try:
        if ad == "istismar":
            ham = (sorgu.get("cveler") or govde.get("cveler") or "")
            if ham:
                # Virgül / boşluk / noktalı virgülle ayrılmış liste de kabul edilir
                cve_idler = [x for x in re.split(r"[,;\s]+", str(ham)) if x]
            else:
                tek = sorgu.get("cve") or govde.get("cve") or sorgu.get("id") or ""
                cve_idler = [tek] if tek else []
            return istismar_sorgu(cve_idler, zorla)

        if ad == "postaguvenlik":
            hedef = (sorgu.get("ad") or govde.get("ad") or sorgu.get("hedef") or
                     govde.get("hedef") or sorgu.get("domain") or govde.get("domain") or "")
            mx_ip = str(sorgu.get("mxip") or govde.get("mxip") or "").lower() in \
                ("1", "true", "evet", "yes")
            return posta_guvenlik(hedef, mx_ip, zorla)

        if ad == "baslikanaliz":
            ham = govde.get("ham") or govde.get("basliklar") or govde.get("raw")
            if not ham:
                # Ham başlık düz metin olarak da gönderilebilir
                for anahtar in ("veri", "metin", "text"):
                    if govde.get(anahtar):
                        ham = govde[anahtar]
                        break
            if not ham and isinstance(sorgu.get("ham"), str):
                ham = sorgu.get("ham")
            return baslik_analiz(ham)

        # moduller / ek2a → bu dosyanın sunduğu uçların listesi
        return {"surum": SURUM, "dosya": "osint-ek2a.py", "ekler": [
            {"kod": "istismar", "ad": "İstismar Radarı (KEV+EPSS)",
             "aciklama": "CISA KEV + FIRST EPSS: aktif istismar ve olasılık puanı",
             "ornek": "/api/arac/istismar?cve=CVE-2024-3094"},
            {"kod": "postaguvenlik", "ad": "Posta Güvenliği",
             "aciklama": "SPF / DMARC / DKIM / MX denetimi ve direnç puanı",
             "ornek": "/api/arac/postaguvenlik?ad=example.com"},
            {"kod": "baslikanaliz", "ad": "Başlık Analizi",
             "aciklama": "Ham mail başlıklarından sahtecilik risk puanı (POST)",
             "ornek": 'POST /api/arac/baslikanaliz  {"ham": "..."}'},
        ]}
    except Exception as e:
        # Beklenmeyen her hata Türkçe sözlüğe çevrilir; dosya asla çökmez.
        return {"hata": "beklenmeyen hata (%s): %s" % (type(e).__name__, e)}


# ------------------------------------------------------------------ KENDİ TESTİ
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("kullanım: python osint-ek2a.py <istismar|posta|baslik> <arg>")
        raise SystemExit(0)
    eylem = sys.argv[1].lower()
    arg = sys.argv[2] if len(sys.argv) > 2 else ""
    if eylem == "istismar":
        print(json.dumps(istismar_sorgu(re.split(r"[,;\s]+", arg)), ensure_ascii=False, indent=2))
    elif eylem in ("posta", "postaguvenlik"):
        print(json.dumps(posta_guvenlik(arg), ensure_ascii=False, indent=2))
    elif eylem in ("baslik", "baslikanaliz"):
        try:
            with open(arg, "r", encoding="utf-8") as f:
                ham = f.read()
        except Exception:
            ham = arg
        print(json.dumps(baslik_analiz(ham), ensure_ascii=False, indent=2))
    else:
        print("bilinmeyen eylem:", eylem)
