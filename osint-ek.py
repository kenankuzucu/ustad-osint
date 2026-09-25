# -*- coding: utf-8 -*-
"""
ÜSTAD OSINT — EK MODÜLLER (v1.5)
Pasif Radar · CVE Eşleştirme · Arşiv (Wayback) · URLScan · Subdomain Takeover ·
Savunma (IOC → Windows Güvenlik Duvarı) · Toplu Tarama · Kanıt Zinciri

Ana çekirdek (osint-araclar.py) bunu yükler ve "/api/arac/..." yollarını buraya devreder.
Kendi küçük yardımcılarını taşır; tek başına da denenebilir:
    python osint-ek.py pasif example.com
"""
import hashlib
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

KOK = os.path.dirname(os.path.abspath(__file__))
ONBELLEK = os.path.join(KOK, "veri", "ek-onbellek.json")
KANIT = os.path.join(KOK, "veri", "kanit-zinciri.json")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

SURUM = "1.5"
_ANABILGI = None          # ana çekirdek modülü (osint-araclar) buraya verilir


def ek_ayarla(modul):
    """Ana çekirdeği (profil_cikar vb. için) bağlar."""
    global _ANABILGI
    _ANABILGI = modul


# ----------------------------------------------------------------- SOCKET / SSL
def _ssl_baglam():
    try:
        import certifi  # noqa
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        try:
            return ssl.create_default_context(cafile=os.path.join(KOK, "veri", "ca-bundle.pem"))
        except Exception:
            return ssl.create_default_context()


BAGLAM = _ssl_baglam()


def _cek(url, zaman=15, baslik=None, veri=None, tip="GET"):
    """Basit HTTP istemcisi; (durum_kodu, govde) döner."""
    istek = urllib.request.Request(url, data=veri)
    istek.add_header("User-Agent", UA)
    istek.add_header("Accept", "application/json,text/html,text/plain,*/*")
    for k, v in (baslik or {}).items():
        istek.add_header(k, v)
    if tip != "GET":
        istek.get_method = lambda: tip
    try:
        with urllib.request.urlopen(istek, timeout=zaman, context=BAGLAM) as y:
            return y.status, y.read(900000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(200000).decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception:
        return 0, ""


def _json(url, zaman=15, baslik=None, veri=None, tip="GET"):
    kod, govde = _cek(url, zaman, baslik, veri, tip)
    try:
        return kod, json.loads(govde), govde
    except Exception:
        return kod, None, govde


def _ozel_ip(ip):
    try:
        p = [int(x) for x in ip.split(".")]
    except Exception:
        return True
    if p[0] in (10, 127) or (p[0] == 192 and p[1] == 168) or (p[0] == 172 and 16 <= p[1] <= 31):
        return True
    if p[0] == 169 and p[1] == 254:
        return True
    return False


def _ip_mi(ad):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(ad or "").strip()))


def _kok(hedef):
    """Girdiden alan adını çıkarır."""
    h = str(hedef or "").strip().lower()
    h = re.sub(r"^[a-z]+://", "", h).split("/")[0].split("@")[-1].split(":")[0]
    return h


def ip_coz(ad):
    """Adı IP'ye çevirir (dns.google DoH, sonra sistem çözücüsü)."""
    ad = _kok(ad)
    if not ad:
        return []
    if _ip_mi(ad):
        return [ad]
    liste = []
    for tip in ("A", "AAAA"):
        kod, j, _ = _json("https://dns.google/resolve?name=%s&type=%s" % (urllib.parse.quote(ad), tip), 12)
        if isinstance(j, dict):
            for c in j.get("Answer") or []:
                if c.get("type") in (1, 28) and c.get("data"):
                    liste.append(c["data"])
    if not liste:
        try:
            liste = sorted({x[4][0] for x in socket.getaddrinfo(ad, None)})
        except Exception:
            liste = []
    return [x for x in dict.fromkeys(liste) if not _ozel_ip(x)]


# ------------------------------------------------------------------- ÖNBELLEK
def _onbellek_oku():
    try:
        with open(ONBELLEK, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _onbellek_yaz(d):
    try:
        os.makedirs(os.path.dirname(ONBELLEK), exist_ok=True)
        with open(ONBELLEK, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False)
    except Exception:
        pass


def _onbellekli(anahtar, saniye, uret):
    d = _onbellek_oku()
    kayit = d.get(anahtar)
    if kayit and time.time() - kayit.get("_zaman", 0) < saniye:
        v = dict(kayit)
        v["onbellek"] = True
        return v
    v = uret()
    if isinstance(v, dict):
        v["_zaman"] = time.time()
        d[anahtar] = v
        _onbellek_yaz(d)
    return v


# --------------------------------------------------------------- 1) PASİF RADAR
def pasif_radar(hedef, zorla=False):
    """InternetDB (Shodan) ile hedefe DOKUNMADAN açık portlar/teknolojiler + bilinen CVE'ler."""
    anahtar = "pasif::" + _kok(hedef)
    if zorla:
        _onbellek_oku().pop(anahtar, None)

    def uret():
        hedef2 = _kok(hedef)
        ipler = ip_coz(hedef2)
        kayitlar, tum_cve, tum_port, tum_cpe, tum_host = [], {}, set(), set(), set()
        for ip in ipler[:3]:
            kod, j, _ = _json("https://internetdb.shodan.io/" + ip, 15)
            if kod != 200 or not isinstance(j, dict):
                kayitlar.append({"ip": ip, "durum": kod, "not": "InternetDB kaydı yok (IP taranmamış olabilir)"})
                continue
            portlar = [int(x) for x in (j.get("ports") or []) if str(x).isdigit()]
            cve_idler = [str(x) for x in (j.get("vulns") or [])]
            kayitlar.append({"ip": ip, "portlar": portlar, "hostname": j.get("hostnames") or [],
                             "cpe": j.get("cpes") or [], "etiket": j.get("tags") or [],
                             "cve": cve_idler})
            tum_port.update(portlar)
            tum_cpe.update(j.get("cpes") or [])
            tum_host.update(j.get("hostnames") or [])
            for c in cve_idler[:12]:
                tum_cve[c] = {"id": c}
        # CVE ayrıntıları (MITRE CVE AWG — anahtarsız)
        for i, cid in enumerate(list(tum_cve)[:10]):
            if i:
                time.sleep(0.35)
            det = cve_detay(cid)
            if det:
                tum_cve[cid] = det
        sirali = sorted(tum_cve.values(), key=lambda x: -(x.get("skor") or 0))
        return {"hedef": hedef2, "ip": ipler, "kayitlar": kayitlar,
                "portlar": sorted(tum_port), "port_sayisi": len(tum_port),
                "cpe": sorted(tum_cpe), "hostname": sorted(tum_host),
                "cveler": sirali, "cve_sayisi": len(sirali),
                "kritik": len([c for c in sirali if (c.get("skor") or 0) >= 9]),
                "kaynak": "Shodan InternetDB + MITRE CVE",
                "uyari": ("Pasif tarama: hedef sistem bu sorguyu görmez. "
                          "Yalnız sahibi olduğun/izin aldığın sistemler için kullan."),
                "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S")}

    return _onbellekli(anahtar, 1800, uret)


def cve_detay(cid):
    """Tek CVE için başlık, özet ve CVSS puanı (MITRE CVE AWG)."""
    cid = str(cid or "").strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", cid):
        return None
    kod, j, _ = _json("https://cveawg.mitre.org/api/cve/" + cid, 15)
    if kod != 200 or not isinstance(j, dict):
        return {"id": cid, "baslik": "", "ozet": "", "skor": None, "kaynak": "MITRE"}
    cna = (j.get("containers") or {}).get("cna") or {}
    adp = (j.get("containers") or {}).get("adp") or []
    skor, siddet, vektor = None, "", ""
    for m in (cna.get("metrics") or []):
        for anahtar in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            if anahtar in m:
                skor = m[anahtar].get("baseScore")
                siddet = m[anahtar].get("baseSeverity") or ""
                vektor = m[anahtar].get("vectorString") or ""
                break
        if skor:
            break
    if skor is None:
        for blok in adp:
            for m in (blok.get("metrics") or []):
                for anahtar in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                    if anahtar in m:
                        skor = m[anahtar].get("baseScore")
                        siddet = m[anahtar].get("baseSeverity") or ""
                        break
                if skor:
                    break
            if skor is not None:
                break
    ozet = ""
    for d in (cna.get("descriptions") or []):
        if str(d.get("lang", "")).lower().startswith("en"):
            ozet = d.get("value") or ""
            break
    return {"id": cid, "baslik": (cna.get("title") or "").strip(), "ozet": ozet[:300],
            "skor": skor, "siddet": siddet, "vektor": vektor,
            "tarih": (j.get("cveMetadata") or {}).get("datePublished", "")[:10],
            "url": "https://www.cve.org/CVERecord?id=" + cid, "kaynak": "MITRE CVE AWG"}


# ---------------------------------------------------- 2) TEKNOLOJİ → CVE EŞLEME
def cve_esle(tek, surum="", en_fazla=8):
    """Tespit edilen teknoloji (+sürüm) için NVD'de olası CVE'leri bulur."""
    tek = str(tek or "").strip().lower()
    if not tek:
        return {"hata": "teknoloji adı gerekli", "ornek": "nginx, apache, wordpress, openssh"}
    surum = str(surum or "").strip()
    anahtar = "cve::" + tek + "::" + surum

    def uret():
        # NVD anahtar kelime araması çok kelimede boş dönüyor: yalnız ürün adıyla ara,
        # sürüm eşleşmesini açıklama metninde kendimiz arayalım.
        sorgu = urllib.parse.quote(tek)
        kod, j, _ = _json("https://services.nvd.nist.gov/rest/json/cves/2.0"
                          "?keywordSearch=%s&resultsPerPage=120" % sorgu, 30)
        kayitlar = []
        if kod == 200 and isinstance(j, dict):
            for v in (j.get("vulnerabilities") or []):
                c = v.get("cve") or {}
                metin = ""
                for d in (c.get("descriptions") or []):
                    if str(d.get("lang", "")).lower().startswith("en") and d.get("value"):
                        metin = d["value"]
                        break
                if tek not in metin.lower():
                    continue
                skor, siddet = None, ""
                for m in (c.get("metrics") or {}).values():
                    try:
                        skor = m[0].get("cvssData", {}).get("baseScore")
                        siddet = (m[0].get("cvssData", {}).get("baseSeverity")
                                  or m[0].get("baseSeverity") or "")
                    except Exception:
                        pass
                    if skor:
                        break
                # sürüm izi: tam sürüm, ya da ilk iki hane (1.24.0 -> 1.24)
                ipuclari = []
                if surum:
                    ipuclari = [surum, ".".join(surum.split(".")[:2])]
                    if surum.count(".") == 1:
                        ipuclari.append(surum + ".0")
                ipucleri = [i for i in ipuclari if len(i) >= 3]
                eslesti = bool(ipucleri) and any(i in metin for i in ipucleri)
                kayitlar.append({"id": c.get("id"), "ozet": metin[:260], "skor": skor, "siddet": siddet,
                                 "yayin": (c.get("published") or "")[:10], "surum_geciyor": eslesti,
                                 "url": "https://www.cve.org/CVERecord?id=" + str(c.get("id"))})
        eslesen = [k for k in kayitlar if k["surum_geciyor"]]
        kalan = [k for k in kayitlar if not k["surum_geciyor"]]
        eslesen.sort(key=lambda x: -(x.get("skor") or 0))
        if surum and not eslesen:
            kalan.sort(key=lambda x: (x.get("yayin") or "", x.get("skor") or 0), reverse=True)
        else:
            kalan.sort(key=lambda x: -(x.get("skor") or 0))
        if surum:
            secili = (eslesen + kalan)[:en_fazla]
        else:
            secili = kalan[:en_fazla]
        return {"teknoloji": tek, "surum": surum, "toplam_bulunan": len(kayitlar),
                "surum_eslesen": len(eslesen), "kayitlar": secili,
                "kaynak": "NVD CVE API 2.0 (anahtar kelime + sürüm izi)",
                "uyari": ("Olası eşleşme: NVD açıklamasında '" + tek + "' geçen kayıtlar listelendi. "
                          + ("Sürüm izi bulunanlar (\"" + str(surum) + "\") başta. " if surum else "")
                          + "Kesin zafiyet tespiti için ürün sürüm aralığı doğrulanmalı."),
                "ornek": "nginx + 1.24.0 → açıklamasında 1.24 geçen CVE'ler ilk sırada",
                "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S")}

        kayitlar.sort(key=lambda x: (-(1 if x["surum_geciyor"] else 0), -(x.get("skor") or 0)))
        return {"teknoloji": tek, "surum": surum, "toplam_bulunan": len(kayitlar),
                "kayitlar": kayitlar[:en_fazla],
                "kaynak": "NVD CVE API 2.0 (anahtar kelime)",
                "uyari": ("Olası eşleşme: NVD açıklamasında sürüm geçen kayıtlar öne alındı. "
                          "Kesin zafiyet tespiti için sürüm aralığı doğrulanmalı."),
                "ornek": "nginx + 1.24.0 → o sürümü içeren kayıtlar üste gelir",
                "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S")}

    return _onbellekli(anahtar, 21600, uret)


# ------------------------------------------------------- 3) ARŞİV (WAYBACK CDX)
def arsiv_wayback(hedef, en_fazla=200):
    """Sitenin arşivlenmiş eski sürümleri, eski alan adları ve eski yolları."""
    anahtar = "arsiv::" + _kok(hedef)

    def uret():
        d = _kok(hedef)
        url = ("http://web.archive.org/cdx/search/cdx?url=%s&matchType=domain&output=json"
               "&fl=timestamp,original,statuscode&collapse=urlkey&limit=%d&filter=statuscode:200"
               % (urllib.parse.quote(d), min(max(en_fazla, 20), 800)))
        kod, govde = _cek(url, 35)
        satirlar = []
        try:
            ham = json.loads(govde) if govde.strip().startswith("[") else []
            satirlar = ham[1:] if ham and ham[0] and ham[0][0] == "timestamp" else ham
        except Exception:
            satirlar = []
        eski_host, eski_yol, yillar = {}, {}, {}
        for s in satirlar:
            try:
                ts, org = s[0], s[1]
            except Exception:
                continue
            yil = ts[:4]
            yillar[yil] = yillar.get(yil, 0) + 1
            try:
                u = urllib.parse.urlparse(org if org.startswith("http") else "http://" + org)
                eski_host[u.netloc] = eski_host.get(u.netloc, 0) + 1
                yol = u.path or ""
                if yol and yol != "/" and "%" not in yol and len(yol) <= 60:
                    eski_yol[yol] = eski_yol.get(yol, 0) + 1
            except Exception:
                pass
        # eski host listesinde hedef dışı / vahşi alan adı varsa dikkat çek
        disari = [h for h in eski_host if d not in h]
        return {"hedef": d, "toplam_kayit": len(satirlar),
                "ilk_kayit": (satirlar[0][0] if satirlar else ""), "son_kayit": (satirlar[-1][0] if satirlar else ""),
                "yillar": dict(sorted(yillar.items())),
                "eski_hostlar": sorted(eski_host.items(), key=lambda x: -x[1])[:12],
                "dis_hostlar": sorted(disari)[:12],
                "eski_yollar": sorted(eski_yol.items(), key=lambda x: -x[1])[:15],
                "kaynak": "Wayback Machine CDX (archive.org)",
                "ornek": ("Silinmiş sayfalar ve eski parametreler burada görünür — "
                          "ör. /admin, /eski-site, test.php gibi yollar hâlâ sunucuda olabilir."),
                "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S")}

    return _onbellekli(anahtar, 86400, uret)


# ------------------------------------------------------------- 4) URLSCAN.IO
def urlscan_ara(hedef, en_fazla=10):
    """Dünyada yapılmış gerçek taramalar: ekran görüntüsü, DOM, sunucu bilgisi."""
    anahtar = "urlscan::" + _kok(hedef)

    def uret():
        d = _kok(hedef)
        kod, j, _ = _json("https://urlscan.io/api/v1/search/?q=%s&size=%d"
                          % (urllib.parse.quote("page.domain:" + d), min(max(en_fazla, 1), 50)), 25)
        kayitlar = []
        if isinstance(j, dict):
            for x in (j.get("results") or []):
                uuid = x.get("_id") or (x.get("task") or {}).get("uuid") or ""
                kayitlar.append({
                    "url": (x.get("page") or {}).get("url") or (x.get("task") or {}).get("url"),
                    "zaman": (x.get("task") or {}).get("time", "")[:19].replace("T", " "),
                    "ip": (x.get("page") or {}).get("ip"),
                    "sunucu": (x.get("page") or {}).get("server"),
                    "ulke": (x.get("page") or {}).get("country"),
                    "durum": (x.get("page") or {}).get("status"),
                    "sonuc": "https://urlscan.io/result/%s/" % uuid if uuid else "",
                    "ekran": "https://urlscan.io/screenshots/%s.png" % uuid if uuid else "",
                    "malzeme": "https://urlscan.io/dom/%s/" % uuid if uuid else ""})
        return {"hedef": d, "kayitlar": kayitlar, "toplam": len(kayitlar),
                "kaynak": "urlscan.io genel API (anahtarsız)",
                "ornek": ("Başkasının yaptığı gerçek taramadan ekran görüntüsü/DOM çekilir: "
                          "ör. eski bir phishing sayfasının kopyası veya sitenin 2019 hâli."),
                "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S")}

    return _onbellekli(anahtar, 3600, uret)


# -------------------------------------------------- 5) SUBDOMAIN TAKEOVER TARAMASI
TAKEOVER_IMZALARI = [
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("herokuapp.com", "No such app", "Heroku"),
    ("s3.amazonaws.com", "NoSuchBucket", "AWS S3"),
    ("cloudfront.net", "Bad request", "CloudFront"),
    ("azureedge.net", "", "Azure CDN"),
    ("blob.core.windows.net", "BlobNotFound", "Azure Blob"),
    ("fastly.net", "Fastly error: unknown domain", "Fastly"),
    ("pantheonsite.io", "The gods are wise, but do not know of the site", "Pantheon"),
    ("myshopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("wordpress.com", "Do you want to register", "WordPress.com"),
    ("tumblr.com", "There's nothing here.", "Tumblr"),
    ("readthedocs.io", "unknown to Read the Docs", "Read the Docs"),
    ("surge.sh", "project not found", "Surge.sh"),
    ("netlify.app", "Not Found - Request ID", "Netlify"),
    ("vercel.app", "The deployment could not be found", "Vercel"),
    ("webflow.io", "The page you are looking for doesn't exist", "Webflow"),
    ("zendesk.com", "Help Center Closed", "Zendesk"),
    ("statuspage.io", "Status page not found", "Statuspage"),
    ("freshdesk.com", "May be this is still fresh", "Freshdesk"),
    ("cargo.site", "404 Not Found", "Cargo"),
]

TAKEOVER_CHAIN = [
    ("CNAME", "CNAME"), ("A", "A"), ("AAAA", "AAAA"), ("NS", "NS"),
]


def cname_zinciri(ad, derinlik=6):
    """CNAME zincirini çözer."""
    zincir, mevcut, gorulen = [], ad, set()
    for _ in range(derinlik):
        if not mecvcut_tamam(mevcut) or mevcut in gorulen:
            break
        gorulen.add(mevcut)
        kod, j, _ = _json("https://dns.google/resolve?name=%s&type=CNAME" % urllib.parse.quote(mevcut), 12)
        hedef = ""
        if isinstance(j, dict):
            for c in j.get("Answer") or []:
                if c.get("type") == 5 and c.get("data"):
                    hedef = c["data"].rstrip(".")
                    break
        if not hedef:
            break
        zincir.append({"kaynak": mevcut, "hedef": hedef})
        mevcut = hedef
    return mevcut, zincir


def mecvcut_tamam(ad):
    return bool(ad)


def takeover_tara(hedef, alt_alanlar=None, en_fazla=60):
    """Subdomain'lerde sahipsiz CNAME (takeover) arar."""
    anahtar = "takeover::" + _kok(hedef)

    def uret():
        d = _kok(hedef)
        altlar = alt_alanlar
        if not altlar:
            altlar = []
            if _ANABILGI and hasattr(_ANABILGI, "subdomain_tara"):
                try:
                    s = _ANABILGI.subdomain_tara(d, en_fazla=400)
                    for k in (s.get("alt_alanlar") or s.get("kayitlar") or []):
                        ad = k.get("ad") if isinstance(k, dict) else k
                        if ad:
                            altlar.append(str(ad))
                except Exception:
                    altlar = []
            if not altlar:
                kod, govde = _cek("https://api.hackertarget.com/hostsearch/?q=" + urllib.parse.quote(d), 30)
                if kod == 200 and govde and "<html" not in govde.lower() and "exceeded" not in govde.lower():
                    for satir in govde.splitlines():
                        par = satir.split(",")
                        if par and par[0] and d in par[0]:
                            altlar.append(par[0].strip())
        altlar = list(dict.fromkeys([a for a in altlar if a and d in a]))[:en_fazla]
        supheli, bulgular, zincirler = [], [], []
        for ad in altlar:
            son, zincir = cname_zinciri(ad)
            if not zincir:
                continue
            nihai = zincir[-1]["hedef"]
            zincirler.append({"ad": ad, "cname": nihai, "zincir": zincir, "servis": "—"})
            for kalip, imza, servis in TAKEOVER_IMZALARI:
                if kalip in nihai:
                    supheli.append({"ad": ad, "cname": nihai, "servis": servis})
                    break
        # şüphelileri HTTP ile doğrula (kendi ağından DEĞİL, sadece okuma)
        for s in supheli[:12]:
            kod, govde = _cek("http://" + s["ad"], 10)
            if kod in (0, 404):
                kod2, govde2 = _cek("https://" + s["ad"], 10)
                kod, govde = (kod2, govde2) if kod2 else (kod, govde)
            imza = ""
            for kalip, im, servis in TAKEOVER_IMZALARI:
                if im and im.lower() in (govde or "").lower():
                    imza = im
                    break
            s["durum_kodu"] = kod
            s["imza_bulundu"] = bool(imza)
            s["imza"] = imza
            s["risk"] = "yüksek" if (imza or kod == 404) else "orta"
            bulgular.append(s)
        return {"hedef": d, "denenen": len(altlar), "supheli": len(supheli),
                "kayitlar": bulgular, "cname_zincirleri": zincirler[:20], "subdomain_sayisi": len(altlar),
                "kaynak": "dns.google (CNAME) + servis imzaları",
                "ornek": ("Sahipsiz kalan subdomain (ör. eski.magaza.com → silinmiş Shopify mağazası) "
                          "başkası tarafından ele geçirilebilir; imza bulunursa risk 'yüksek' yazılır."),
                "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S")}

    return _onbellekli(anahtar, 3600, uret)


# --------------------------------------------- 6) SAVUNMA: IOC → GÜVENLİK DUVARI
def savunma_kurallari():
    """Tehdit beslemelerindeki ele geçirilmiş sistemleri Windows Güvenlik Duvarı'na çevirir."""
    def uret():
        ipler, kaynaklar = [], []
        for url, ad in (("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "EmergingThreats"),
                        ("https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "ET Block IPs"),
                        ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "Feodo Tracker")):
            kod, govde = _cek(url, 25)
            sayi = 0
            if kod == 200 and govde:
                for satir in govde.splitlines():
                    satir = satir.strip()
                    if not satir or satir.startswith("#"):
                        continue
                    ip = satir.split(";")[0].split()[0] if satir.split() else ""
                    ip = ip.replace("http://", "").replace("https://", "").split("/")[0]
                    if _ip_mi(ip) and not _ozel_ip(ip):
                        ipler.append(ip)
                        sayi += 1
            kaynaklar.append({"ad": ad, "sayi": sayi, "url": url})
        ipler = sorted(set(ipler))
        ps1 = _ps1_uret(ipler)
        geri = _ps1_geri(ipler)
        return {"ip_sayisi": len(ipler), "ipler": ipler[:400], "kaynaklar": kaynaklar,
                "ps1": ps1, "geri_alma": geri,
                "dosya_adi": "ustad-osint-guvenlik-duvari-" + time.strftime("%Y%m%d-%H%M") + ".ps1",
                "kaynak": "EmergingThreats + Feodo Tracker + ET Block IPs",
                "ornek": ("Bu betiği yönetici olarak çalıştırınca listelenen zararlı IP'ler Windows'a "
                          "engellenir; 'geri_alma' betiği temizler. Kendi ağını korumak için."),
                "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S")}

    return _onbellekli("savunma", 3600, uret)


def _ps1_uret(ipler):
    satir = "\n".join('  "%s"' % ip for ip in ipler)
    return ("# ÜSTAD OSINT — Windows Güvenlik Duvarı engel listesi\n"
            "# " + time.strftime("%d.%m.%Y %H:%M") + " · " + str(len(ipler)) + " IP\n"
            "# YÖNETİCİ olarak çalıştır:  powershell -ExecutionPolicy Bypass -File <bu-dosya>\n"
            "$liste = @(\n" + satir + "\n)\n"
            "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()"
            ").IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {\n"
            "  Write-Host 'HATA: Bu betiği yönetici olarak çalıştırmalısın.' -ForegroundColor Red; exit 1\n"
            "}\n"
            "# eski kuralı temizle\n"
            "Get-NetFirewallRule -DisplayName 'USTAD-OSINT-Engel-*' -ErrorAction SilentlyContinue | "
            "Remove-NetFirewallRule -ErrorAction SilentlyContinue\n"
            "$i = 0\n"
            "foreach ($ip in $liste) {\n"
            "  $i++\n"
            "  try {\n"
            "    New-NetFirewallRule -DisplayName (\"USTAD-OSINT-Engel-$i\") -Direction Outbound "
            "-Action Block -RemoteAddress $ip -Profile Any -ErrorAction Stop | Out-Null\n"
            "    New-NetFirewallRule -DisplayName (\"USTAD-OSINT-Engel-Gelen-$i\") -Direction Inbound "
            "-Action Block -RemoteAddress $ip -Profile Any -ErrorAction Stop | Out-Null\n"
            "  } catch { Write-Host \"atlandı: $ip\" }\n"
            "}\n"
            "Write-Host \"TAMAM: $($liste.Count) zararlı IP engellendi.\" -ForegroundColor Green\n"
            "Write-Host 'Kaldırmak için: ustad-osint-duvar-geri.ps1' -ForegroundColor Yellow\n")


def _ps1_geri(ipler):
    return ("# ÜSTAD OSINT — engel listesini KALDIRIR\n"
            "Get-NetFirewallRule -DisplayName 'USTAD-OSINT-Engel-*' -ErrorAction SilentlyContinue | "
            "Remove-NetFirewallRule\n"
            "Write-Host 'TAMAM: ÜSTAD OSINT engel kuralları kaldırıldı.' -ForegroundColor Green\n")


# ------------------------------------------------------------- 7) TOPLU TARAMA
def toplu_tarama(hedefler, moduller=None, en_fazla=25):
    """Birden çok hedefi sırayla profiller, risk sıralı tablo döndürür."""
    if isinstance(hedefler, str):
        hedefler = [x.strip() for x in re.split(r"[\s,;]+", hedefler) if x.strip()]
    hedefler = [x for x in (hedefler or []) if x][: min(max(en_fazla, 1), 100)]
    moduller = moduller or ["dns", "whois", "ip", "subdomain", "webtek"]
    sonuclar = []
    for h in hedefler:
        try:
            if _ANABILGI and hasattr(_ANABILGI, "profil_cikar"):
                r = _ANABILGI.profil_cikar(h, moduller)
                sonuclar.append({"hedef": h, "risk": r.get("risk"), "sayilar": r.get("sayilar"),
                                 "bulgu": len(r.get("bulgular") or []),
                                 "ilk_bulgular": [(b.get("baslik") or b.get("aciklama") or b.get("tur") or "")[:90]
                                     for b in (r.get("bulgular") or [])[:3]]})
            else:
                sonuclar.append({"hedef": h, "risk": -1, "hata": "profil çekirdeği bağlı değil"})
        except Exception as e:
            sonuclar.append({"hedef": h, "risk": -1, "hata": str(e)[:120]})
    sonuclar.sort(key=lambda x: -(x.get("risk") or 0))
    return {"adet": len(sonuclar), "kayitlar": sonuclar,
            "kaynak": "ÜSTAD OSINT profil çekirdeği",
            "ornek": ("Elindeki 50 alan adını tek seferde tarar, riski yüksekten aşağıya sıralar — "
                      "ör. hangi sitende eski bir panel var?"),
            "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S")}


# ------------------------------------------------------------ 8) KANIT ZİNCİRİ
def kanit_ekle(rapor):
    """Raporun SHA-256'sını alır, zaman damgasıyla zincire yazar."""
    ham = json.dumps(rapor, ensure_ascii=False, sort_keys=True) if not isinstance(rapor, str) else rapor
    ozet = hashlib.sha256(ham.encode("utf-8")).hexdigest()
    kayit = {"sha256": ozet, "zaman": time.strftime("%Y-%m-%d %H:%M:%S"),
             "boyut": len(ham.encode("utf-8")),
             "hedef": (rapor or {}).get("hedef") if isinstance(rapor, dict) else ""}
    zincir = []
    try:
        if os.path.exists(KANIT):
            with open(KANIT, "r", encoding="utf-8") as f:
                zincir = json.load(f) or []
    except Exception:
        zincir = []
    onceki = zincir[-1]["sha256"] if zincir else "0" * 64
    kayit["onceki"] = onceki
    kayit["zincir_no"] = len(zincir) + 1
    # zincir kaydı: önceki özeti de içine kat → sonradan değiştirilirse zincir bozulur
    kayit["muhur"] = hashlib.sha256((ozet + onceki).encode("utf-8")).hexdigest()
    zincir.append(kayit)
    try:
        os.makedirs(os.path.dirname(KANIT), exist_ok=True)
        with open(KANIT, "w", encoding="utf-8") as f:
            json.dump(zincir[-200:], f, ensure_ascii=False, indent=1)
    except Exception:
        pass
    return {"kayit": kayit, "zincir_uzunluk": len(zincir),
            "kaynak": "SHA-256 + yerel zincir (veri/kanit-zinciri.json)",
            "ornek": ("Raporu sonradan değiştirirsen mühür tutmaz; mahkemeye/karşı tarafa "
                      "'bu rapor değiştirilmedi' kanıtı olur."),
            "guncelleme": kayit["zaman"]}


def kanit_listesi(en_fazla=20):
    try:
        with open(KANIT, "r", encoding="utf-8") as f:
            z = json.load(f) or []
    except Exception:
        z = []
    return {"zincir": z[-en_fazla:][::-1], "toplam": len(z), "dosya": KANIT}


# ----------------------------------------------------------------- YÖNLENDİRİCİ
def ek_isle(yol, sorgu, govde, ayarlar=None):
    """"/api/arac/<ad>" yollarını işler (ana çekirdek bilmediği yolları buraya verir)."""
    ad = str(yol or "").rstrip("/").split("/")[-1].lower()
    sorgu = sorgu or {}
    govde = govde if isinstance(govde, dict) else {}
    hedef = sorgu.get("ad") or sorgu.get("hedef") or govde.get("hedef") or govde.get("ad") or ""
    zorla = str(sorgu.get("zorla") or govde.get("zorla") or "").lower() in ("1", "true", "evet")

    if ad == "moduller":
        return {"ekler": [
            {"kod": "pasif", "ad": "Pasif Radar", "aciklama": "InternetDB ile dokunmadan port + CVE"},
            {"kod": "cve", "ad": "CVE Eşleştirme", "aciklama": "Teknoloji/sürüm → olası CVE listesi"},
            {"kod": "arsiv", "ad": "Arşiv (Wayback)", "aciklama": "Eski sürümler, silinmiş yollar"},
            {"kod": "urlscan", "ad": "URLScan", "aciklama": "Dünyada yapılmış taramalar + ekran"},
            {"kod": "takeover", "ad": "Takeover Taraması", "aciklama": "Sahipsiz subdomain (CNAME)"},
            {"kod": "savunma", "ad": "Savunma Duvarı", "aciklama": "IOC → Windows Güvenlik Duvarı .ps1"},
            {"kod": "toplu", "ad": "Toplu Tarama", "aciklama": "Çoklu hedef, risk sıralı tablo"},
            {"kod": "kanit", "ad": "Kanıt Zinciri", "aciklama": "Rapor SHA-256 + zaman damgası"},
        ]}
    if ad == "pasif":
        return pasif_radar(hedef, zorla)
    if ad == "cve":
        return cve_esle(sorgu.get("tek") or hedef, sorgu.get("surum") or "")
    if ad == "arsiv":
        return arsiv_wayback(hedef)
    if ad == "urlscan":
        return urlscan_ara(hedef)
    if ad == "takeover":
        return takeover_tara(hedef)
    if ad == "savunma":
        return savunma_kurallari()
    if ad == "toplu":
        return toplu_tarama(govde.get("hedefler") or sorgu.get("hedefler"), govde.get("moduller"))
    if ad == "kanit":
        if govde.get("rapor"):
            return kanit_ekle(govde.get("rapor"))
        return kanit_listesi()
    return {"hata": "bilinmeyen ek uç nokta: " + ad, "mevcut": [
        "pasif", "cve", "arsiv", "urlscan", "takeover", "savunma", "toplu", "kanit", "moduller"]}


# ------------------------------------------------------------------ KENDİ TESTİ
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("kullanım: python osint-ek.py <pasif|cve|arsiv|urlscan|takeover|savunma|kanit> <hedef>")
        raise SystemExit(0)
    eylem, arg = sys.argv[1], sys.argv[2]
    if eylem == "pasif":
        r = pasif_radar(arg, True)
        print("IP:", r["ip"], "| port:", r["portlar"], "| CVE:", r["cve_sayisi"])
        for c in r["cveler"][:5]:
            print("   ", c.get("id"), "| CVSS", c.get("skor"), "|", (c.get("ozet") or "")[:70])
    elif eylem == "cve":
        r = cve_esle(arg, sys.argv[3] if len(sys.argv) > 3 else "")
        print("bulunan:", r.get("toplam_bulunan"))
        for c in (r.get("kayitlar") or [])[:5]:
            print("   ", c["id"], "| CVSS", c.get("skor"), "| sürüm geçiyor:", c.get("surum_geciyor"))
    elif eylem == "arsiv":
        r = arsiv_wayback(arg)
        print("kayıt:", r["toplam_kayit"], "| ilk:", r["ilk_kayit"], "| son:", r["son_kayit"])
        print("   yollar:", [y[0] for y in r["eski_yollar"][:6]])
    elif eylem == "urlscan":
        r = urlscan_ara(arg)
        print("kayıt:", r["toplam"])
        for k in r["kayitlar"][:3]:
            print("   ", k["url"], "|", k.get("ip"), "|", k.get("sonuc"))
    elif eylem == "takeover":
        r = takeover_tara(arg)
        print("denenen:", r["denenen"], "| şüpheli:", r["supheli"])
        for k in r["kayitlar"][:5]:
            print("   ", k["ad"], "→", k["cname"], "| risk:", k.get("risk"), "| imza:", k.get("imza_bulundu"))
    elif eylem == "savunma":
        r = savunma_kurallari()
        print("IP sayısı:", r["ip_sayisi"], "| dosya:", r["dosya_adi"])
        print(r["ps1"][:400])
    elif eylem == "kanit":
        print(json.dumps(kanit_ekle({"hedef": arg, "deneme": 1}), ensure_ascii=False, indent=1)[:400])
