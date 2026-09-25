# -*- coding: utf-8 -*-
"""
ÜSTAD OSINT — EK MODÜLLER v1.6 (dosya: osint-ek2b.py)
Sertifika Şeffaflığı (CT log → alt alan adları) · Web Zafiyet Ön Kontrolü ·
Fidye Yazılımı İzleme (ransomware.live)

Ana çekirdek (osint-araclar.py) bilmediği "/api/arac/..." yollarını
`ek2b_isle(yol, sorgu, govde, ayarlar)` dağıtıcısına verir.

KAPSAM KURALI (yasal):
    webzafiyet modülü YALNIZCA veri/izleme.json içindeki alan adlarında çalışır.
    Liste dışı bir hedef verilirse tarama yapılmaz, {"hata": "...kapsam dışı..."} döner.
    İstekler zararsız HEAD/GET çağrılarıdır, sabit bir User-Agent kullanılır ve
    istekler arasında 250 ms beklenir (hedef sunucuya yük bindirmemek için).

Tek başına denemek için:
    python osint-ek2b.py sertifika ustadkenankuzucu.com.tr
    python osint-ek2b.py webzafiyet ustadkenankuzucu.com.tr
    python osint-ek2b.py fidye TR
"""
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

KOK = os.path.dirname(os.path.abspath(__file__))
VERI = os.path.join(KOK, "veri")

ONBELLEK = os.path.join(VERI, "ek2-onbellek.json")            # ortak önbellek
SERTIFIKA_GECMIS = os.path.join(VERI, "ek2-sertifika-gecmis.json")  # önceki taramalar
IZLEME = os.path.join(VERI, "izleme.json")                    # kapsam listesi (izinli alan adları)

UA = "UstadOSINT/1.6 (+kendi sistem, izinli)"

# Önbellek süreleri (saniye)
TTL_SERTIFIKA = 6 * 3600     # 6 saat  — CT logları yavaş değişir
TTL_WEBZAFIYET = 30 * 60     # 30 dakika — başlıklar değişebilir
TTL_FIDYE = 3600             # 1 saat  — besleme saatte bir güncellenir

ISTEK_ARASI = 0.25           # istekler arası bekleme (saniye)


# =============================================================== SSL / HTTP
def _ssl_baglam():
    """certifi kök sertifikalarıyla SSL bağlamı kurar (Kaspersky MITM'e karşı)."""
    try:
        import certifi  # noqa
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass
    try:
        return ssl.create_default_context(cafile=os.path.join(VERI, "ca-bundle.pem"))
    except Exception:
        return ssl.create_default_context()


BAGLAM = _ssl_baglam()
# Yedek: sertifika doğrulaması yapılmayan bağlam (yalnız doğrulanmış bağlam
# başarısız olursa kullanılır — kurumsal MITM proxy arkasında gerekebilir).
try:
    BAGLAM_YEDEK = ssl._create_unverified_context()
except Exception:
    BAGLAM_YEDEK = BAGLAM


class _YonlendirmeYok(urllib.request.HTTPRedirectHandler):
    """Yönlendirmeleri takip etmeyen işleyici (durum kodunu görmek istediğimizde)."""

    def redirect_request(self, *a, **kw):
        return None


def _baslik_sozlugu(basliklar):
    """HTTP başlıklarını küçük harfli sözlüğe çevirir; Set-Cookie listesi ayrı tutulur."""
    d = {}
    try:
        for k, v in basliklar.items():
            d[str(k).lower()] = str(v)
        cerezler = basliklar.get_all("Set-Cookie") or []
        d["_set_cookie"] = [str(x) for x in cerezler]
    except Exception:
        pass
    return d


def _tek_istek(url, zaman, baslik, veri, tip, yonlendir, baglam):
    """Tek bir HTTP çağrısı; (kod, gövde, başlıklar, hata) döner. ASLA çökmez."""
    try:
        istek = urllib.request.Request(url, data=veri)
        istek.add_header("User-Agent", UA)
        istek.add_header("Accept", "application/json,text/html,text/plain,*/*")
        for k, v in (baslik or {}).items():
            istek.add_header(k, v)
        if tip and tip.upper() != "GET":
            istek.get_method = lambda: tip.upper()
        sinif = urllib.request.HTTPRedirectHandler if yonlendir else _YonlendirmeYok
        acici = urllib.request.build_opener(sinif, urllib.request.HTTPSHandler(context=baglam))
        with acici.open(istek, timeout=zaman) as y:
            govde = y.read(900000).decode("utf-8", "replace")
            return y.status, govde, _baslik_sozlugu(y.headers), ""
    except urllib.error.HTTPError as e:                       # 4xx / 5xx (hata değil, cevap)
        try:
            govde = e.read(200000).decode("utf-8", "replace")
        except Exception:
            govde = ""
        return e.code, govde, _baslik_sozlugu(e.headers), ""
    except Exception as e:
        return 0, "", {}, str(e)[:200]


def _cek(url, zaman=20, baslik=None, veri=None, tip="GET", yonlendir=True):
    """
    Ortak HTTP istemcisi. Önce certifi kökleriyle dener; bağlantı kurulamazsa
    (imza doğrulama hatası / proxy) doğrulamasız yedek bağlamla tekrar dener.
    Dönen: (kod, govde, basliklar) — kod 0 ise istek hiç yapılamadı.
    """
    kod, govde, bas, hata = _tek_istek(url, zaman, baslik, veri, tip, yonlendir, BAGLAM)
    if kod == 0:
        # SSL/bağlantı hatası olabilir: doğrulamasız yedekle son bir deneme
        kod2, govde2, bas2, hata2 = _tek_istek(url, zaman, baslik, veri, tip, yonlendir, BAGLAM_YEDEK)
        if kod2 != 0:
            return kod2, govde2, bas2
        return 0, "", {"_hata": hata or hata2}
    return kod, govde, bas


def _json_cek(url, zaman=20, baslik=None, tip="GET", yonlendir=True):
    """JSON döndürmesi beklenen uçlar için kısayol: (kod, nesne|None, govde)."""
    kod, govde, bas = _cek(url, zaman, baslik, None, tip, yonlendir)
    try:
        return kod, json.loads(govde), govde, bas
    except Exception:
        return kod, None, govde, bas


def _kok(hedef):
    """Girdiden çıplak alan adını çıkarır (şema/yol/port atılır)."""
    h = str(hedef or "").strip().lower()
    h = re.sub(r"^[a-z]+://", "", h).split("/")[0].split("@")[-1].split(":")[0]
    return h.strip(".")


# ================================================================== ÖNBELLEK
def _onbellek_oku():
    try:
        with open(ONBELLEK, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _onbellek_yaz(d):
    try:
        os.makedirs(VERI, exist_ok=True)
        with open(ONBELLEK, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False)
    except Exception:
        pass


def onbellek_temizle(anahtar=None):
    """`?zorla=1` geldiğinde ilgili kaydı (ya da tümünü) siler."""
    d = _onbellek_oku()
    if anahtar is None:
        _onbellek_yaz({})
        return
    if anahtar in d:
        d.pop(anahtar, None)
        _onbellek_yaz(d)


def _onbellekli(anahtar, saniye, uret, zorla=False):
    """Sonucu TTL boyunca önbellekten döndürür; `zorla` ise yeniden üretir."""
    if zorla:
        onbellek_temizle(anahtar)
    d = _onbellek_oku()
    kayit = d.get(anahtar)
    if isinstance(kayit, dict) and kayit.get("_zaman") and time.time() - kayit["_zaman"] < saniye:
        v = dict(kayit)
        v.pop("_zaman", None)
        v["onbellek"] = True
        return v
    v = uret()
    if isinstance(v, dict) and "hata" not in v:      # hatalı sonucu önbelleğe yazma
        v["_zaman"] = time.time()
        d[anahtar] = v
        _onbellek_yaz(d)
    return v


# =========================================================== 1) SERTİFİKA (CT)
def _sertifika_certspotter(ad):
    """
    certspotter (CT log) — birincil kaynak.
    `expand=dns_names` alt alan adlarını verir; API aynı çağrıda hem `issuer`
    hem `dns_names` döndürmediği için veren bilgisi ikinci (küçük) çağrıyla alınır.
    Ücretsiz kota nedeniyle ikinci çağrı 429 dönebilir; bu bir hata değil,
    yalnızca 'veren' alanı boş kalır (notlar ile bildirilir).
    Dönen: (kayitlar, verenler, hata_metni, notlar)
    """
    temel = ("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true"
             % urllib.parse.quote(ad))
    kod, j, _, _ = _json_cek(temel + "&expand=dns_names", 30)
    if kod != 200 or not isinstance(j, list):
        if kod == 404:      # CT kaydı yok = hata değil, boş sonuç
            return [], [], "certspotter: bu alan adı için CT kaydı bulunamadı", []
        if kod == 429:
            return [], [], ("certspotter ücretsiz kota sınırı (HTTP 429) — "
                            "birkaç dakika sonra tekrar deneyin"), []
        return [], [], "certspotter yanıtı alınamadı (HTTP %s)" % kod, []

    kayitlar = []
    for x in j:
        if not isinstance(x, dict):
            continue
        adlar = [str(a) for a in (x.get("dns_names") or []) if a]
        kayitlar.append({
            "id": str(x.get("id") or ""),
            "veren": "",                                  # aşağıda ikinci çağrıyla doldurulur
            "yayin": str(x.get("not_before") or "")[:10],
            "bitis": str(x.get("not_after") or "")[:10],
            "yeni": _yeni_mi(x.get("not_before")),
            "_adlar": adlar,
        })

    # Veren (issuer) bilgisi: ikinci çağrı — hata olursa boş kalır, modül çökmez
    verenler, notlar = [], []
    try:
        time.sleep(ISTEK_ARASI)
        kod2, j2, _, _ = _json_cek(temel + "&expand=issuer", 25)
        if kod2 == 200 and isinstance(j2, list):
            for i, x in enumerate(j2):
                if not isinstance(x, dict):
                    continue
                v = x.get("issuer") or {}
                ad_veren = ""
                if isinstance(v, dict):
                    ad_veren = v.get("friendly_name") or v.get("name") or ""
                elif isinstance(v, str):
                    ad_veren = v
                ad_veren = str(ad_veren).strip()
                if ad_veren and i < len(kayitlar):
                    kayitlar[i]["veren"] = ad_veren
            verenler = sorted({k["veren"] for k in kayitlar if k["veren"]})
            if not verenler:
                notlar.append("certspotter veren (issuer) alanını boş döndürdü")
        else:
            notlar.append("veren bilgisi alınamadı (certspotter HTTP %s%s) — alt alan adları yine de tam" %
                          (kod2, ", ücretsiz kota sınırı" if kod2 == 429 else ""))
    except Exception:
        notlar.append("veren bilgisi alınamadı (beklenmeyen yanıt)")
    return kayitlar, verenler, "", notlar


def _sertifika_crtsh(ad):
    """crt.sh — isteğe bağlı kaynak (`?crtsh=1`); sık sık 502 döner."""
    url = "https://crt.sh/?q=%%25.%s&output=json" % urllib.parse.quote(ad)
    kod, j, govde, _ = _json_cek(url, 40)
    if kod != 200 or not isinstance(j, list):
        return [], [], "crt.sh yanıt vermedi (HTTP %s%s)" % (
            kod, ", sık görülen 502 hatası" if kod in (502, 503, 504, 0) else "")
    kayitlar, verenler = [], set()
    for x in j:
        if not isinstance(x, dict):
            continue
        adlar = []
        for parca in str(x.get("name_value") or "").split("\n"):
            parca = parca.strip().lower().lstrip("*.")
            if parca:
                adlar.append(parca)
        if not adlar:
            continue
        veren = str(x.get("issuer_name") or "").strip()
        if veren:
            # "C=US, O=Let's Encrypt, CN=R3" → "Let's Encrypt"
            m = re.search(r"O=([^,]+)", veren)
            veren = (m.group(1).strip() if m else veren)[:80]
            verenler.add(veren)
        kayitlar.append({
            "id": str(x.get("id") or ""),
            "veren": veren,
            "yayin": str(x.get("not_before") or "")[:10],
            "bitis": str(x.get("not_after") or "")[:10],
            "yeni": _yeni_mi(x.get("not_before")),
            "_adlar": adlar,
        })
    return kayitlar, sorted(verenler), ""


def _yeni_mi(tarih_metni):
    """Sertifika son 30 günde mi düzenlendi?"""
    s = str(tarih_metni or "")
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", s)
    if not m:
        return False
    try:
        import calendar
        yil, ay, gun = int(m.group(1)), int(m.group(2)), int(m.group(3))
        duzenleme = calendar.timegm((yil, ay, gun, 0, 0, 0, 0, 0, 0))
    except Exception:
        return False
    return (time.time() - duzenleme) < 30 * 86400


def _sertifika_gecmis_oku():
    try:
        with open(SERTIFIKA_GECMIS, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _sertifika_gecmis_yaz(d):
    try:
        os.makedirs(VERI, exist_ok=True)
        with open(SERTIFIKA_GECMIS, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def sertifika_alt_alanlar(hedef, crtsh=False, zorla=False):
    """
    Certificate Transparency loglarından alan adının sertifikalarını ve
    alt alan adlarını çıkarır. Birincil kaynak certspotter; `crtsh=True` ise
    önce crt.sh denenir, başarısız olursa certspotter'a düşülür.
    """
    d = _kok(hedef)
    if not d or "." not in d or re.match(r"^\d+\.\d+\.\d+\.\d+$", d):
        return {"hata": "geçerli bir alan adı girin (ör. ornek.com)"}
    anahtar = "ek2-sertifika::" + d + ("::crtsh" if crtsh else "")

    def uret():
        kayitlar, verenler, notlar, kaynak = [], [], [], ""
        if crtsh:
            kayitlar, verenler, hata = _sertifika_crtsh(d)
            if kayitlar:
                kaynak = "crt.sh (CT log)"
            else:
                notlar.append(hata or "crt.sh sonuç döndürmedi")
        if not kayitlar:
            time.sleep(ISTEK_ARASI)
            k2, v2, hata2, not2 = _sertifika_certspotter(d)
            notlar.extend(not2 or [])
            if k2:
                kayitlar, verenler, kaynak = k2, v2, "certspotter (CT log)"
            elif hata2:
                notlar.append(hata2)
            if crtsh and kayitlar:
                notlar.append("crt.sh 502 verdiğinde yedek kaynak: certspotter")
        if not kayitlar:
            return {"hata": "sertifika kaydı bulunamadı — " +
                            ("; ".join(notlar) or "CT loglarına ulaşılamadı"),
                    "ad": d, "kaynak": "certspotter / crt.sh"}

        # --- alt alan adlarını topla (joker yıldızı atılır, hedef dışı süzülür)
        alt = set()
        for k in kayitlar:
            for a in k.pop("_adlar", []):
                a = str(a).strip().lower().lstrip("*.")
                if a and (a == d or a.endswith("." + d)):
                    alt.add(a)
        alt.add(d)
        alt_alanlar = sorted(alt)

        # --- önceki taramayla karşılaştır → yeni çıkanlar
        gecmis = _sertifika_gecmis_oku()
        onceki = set(gecmis.get(d) or [])
        yeni_alt = sorted([a for a in alt_alanlar if a not in onceki])
        gecmis[d] = alt_alanlar
        gecmis["_guncelleme::" + d] = time.strftime("%Y-%m-%d %H:%M:%S")
        _sertifika_gecmis_yaz(gecmis)

        kayitlar.sort(key=lambda x: x.get("yayin") or "", reverse=True)
        yeniler = [k for k in kayitlar if k.get("yeni")]
        return {
            "ad": d,
            "sertifika_sayisi": len(kayitlar),
            "alt_alan_sayisi": len(alt_alanlar),
            "alt_alanlar": alt_alanlar,
            "verenler": verenler,
            "kayitlar": kayitlar[:60],
            "yeni_sertifikalar": len(yeniler),
            "yeni_alt_alanlar": yeni_alt,
            "ilk_tarama": not onceki,
            "kaynak": kaynak or "certspotter (CT log)",
            "not": (" ".join(notlar) or "crt.sh 502 verdiğinde yedek kaynak: certspotter"),
            "ornek": ("CT logları herkese açıktır: bir alan adı için alınan TÜM sertifikalar "
                      "burada görünür — yeni bir joker sertifika (ör. *.site.com) çıkmışsa "
                      "yeni bir alt alan adı yayına alınmış demektir."),
            "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    return _onbellekli(anahtar, TTL_SERTIFIKA, uret, zorla)


# ============================================ 2) WEB ZAFİYET (yalnız izinli)
HASSAS_YOLLAR = [
    ("/.env", "kritik", "Ortam değişkenleri: veritabanı şifresi, API anahtarı"),
    ("/.git/config", "kritik", "Git deposu: tüm kaynak kod geçmişi indirilebilir"),
    ("/.svn/entries", "kritik", "SVN çalışma kopyası kalıntısı"),
    ("/backup.zip", "kritik", "Yedek arşivi"),
    ("/db.sql", "kritik", "Veritabanı dökümü"),
    ("/.htaccess", "yüksek", "Sunucu yapılandırması (yönlendirme kuralları sızar)"),
    ("/wp-config.php.bak", "kritik", "WordPress yapılandırma yedeği: DB şifresi"),
    ("/.DS_Store", "orta", "Dizin içeriği listesi sızar"),
    ("/config.php~", "kritik", "Editör yedeği: yapılandırma dosyası"),
    ("/server-status", "orta", "Apache durum sayfası: ziyaretçi yolları sızar"),
]

GUVENLIK_BASLIKLARI = [
    ("strict-transport-security", "HSTS", "Kullanıcıyı HTTPS'e zorlar", "kritik"),
    ("content-security-policy", "CSP", "XSS ve enjeksiyon kaynaklarını kısıtlar", "yüksek"),
    ("x-frame-options", "X-Frame-Options", "Clickjacking (iframe ile tıklama hırsızlığı)", "orta"),
    ("x-content-type-options", "X-Content-Type-Options", "MIME tipi karışıklığı", "orta"),
    ("referrer-policy", "Referrer-Policy", "Dış sitelere URL sızması", "düşük"),
    ("permissions-policy", "Permissions-Policy", "Kamera/mikrofon/konum izinleri", "düşük"),
]

_ONERI_NGINX = [
    '# --- NGINX (cPanel: Ek Yapılandırma / nginx.conf include) ---',
    'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
    'add_header X-Content-Type-Options "nosniff" always;',
    'add_header X-Frame-Options "SAMEORIGIN" always;',
    'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
    'add_header Content-Security-Policy "default-src \'self\'; img-src \'self\' data:; '
    'style-src \'self\' \'unsafe-inline\'; script-src \'self\'" always;',
    'location ~ /\\.(env|git|svn|htaccess|DS_Store) { deny all; return 403; }',
    'location ~* \\.(zip|sql|bak|old|swp|tar|gz)$ { deny all; return 403; }',
    'location = /server-status { deny all; return 403; }',
]

_ONERI_APACHE = [
    '# --- Apache / .htaccess (public_html içine) ---',
    'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
    'Header always set X-Content-Type-Options "nosniff"',
    'Header always set X-Frame-Options "SAMEORIGIN"',
    'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"',
    'Header always set Content-Security-Policy "default-src \'self\'; img-src \'self\' data:; '
    'style-src \'self\' \'unsafe-inline\'; script-src \'self\'"',
    'RedirectMatch 403 ^/\\.(env|git|svn|htaccess|DS_Store)',
    'RedirectMatch 403 (?i)\\.(zip|sql|bak|old|swp|tar|gz)$',
    'TraceEnable off',
    'Options -Indexes',
    '# Not: Header/RedirectMatch için mod_headers ve mod_alias açık olmalı '
    '(cPanel\'de genelde açıktır).',
]


def _izleme_listesi():
    """veri/izleme.json → kapsam içindeki alan adları listesi."""
    try:
        with open(IZLEME, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        return []
    if isinstance(d, dict):
        ham = d.get("hedefler") or d.get("siteler") or d.get("alan_adlari") or []
    elif isinstance(d, list):
        ham = d
    else:
        ham = []
    liste = []
    for x in ham:
        ad = x.get("ad") if isinstance(x, dict) else x
        ad = _kok(ad)
        if ad:
            liste.append(ad)
    return sorted(set(liste))


def _cerezleri_coz(ham_liste):
    """Set-Cookie başlıklarını ad + güvenlik bayraklarına ayırır."""
    out = []
    for c in (ham_liste or [])[:20]:
        parcalar = [p.strip() for p in str(c).split(";")]
        if not parcalar or "=" not in parcalar[0]:
            continue
        kucuk = [p.lower() for p in parcalar[1:]]
        ad = parcalar[0].split("=")[0].strip()[:60]
        samesite = None
        for p in parcalar[1:]:
            if p.lower().startswith("samesite="):
                samesite = p.split("=", 1)[1].strip().capitalize()
        out.append({
            "ad": ad,
            "httponly": any(p == "httponly" for p in kucuk),
            "secure": any(p == "secure" for p in kucuk),
            "samesite": samesite,
        })
    return out


def _dosya_durumu(kod):
    """HTTP durum kodunu Türkçe durum + önem derecesine çevirir."""
    if kod == 200:
        return "AÇIK", "kritik"
    if kod in (401, 403):
        return "kapalı", ""
    if kod in (404, 410):
        return "yok", ""
    if kod == 0:
        return "erişilemedi", ""
    return "belirsiz", "düşük"


def web_zafiyet(hedef, zorla=False):
    """
    Kendi alan adlarınız için pasif/zararsız web yapılandırma kontrolü:
    hassas dosyalar (HEAD), HTTP metotları, CORS, güvenlik başlıkları, çerez bayrakları.
    KAPSAM: yalnızca veri/izleme.json içindeki alan adları.
    """
    d = _kok(hedef)
    if not d or "." not in d:
        return {"hata": "geçerli bir alan adı girin (ör. ornek.com)"}
    izinli = _izleme_listesi()
    if not izinli:
        return {"hata": "izleme listesi boş — veri/izleme.json içine kendi alan adlarınızı ekleyin"}
    if d not in izinli:
        return {"hata": "kapsam dışı — yalnız kendi alan adlarınız taranır",
                "ad": d, "izinli": izinli}
    anahtar = "ek2-webzafiyet::" + d

    def uret():
        # --- temel adres: önce HTTPS, açılmazsa HTTP
        temel = "https://" + d
        kod0, _, bas0 = _cek(temel + "/", 20, tip="HEAD")
        if kod0 == 0:
            temel = "http://" + d
            kod0, _, bas0 = _cek(temel + "/", 20, tip="HEAD")
        if kod0 == 0:
            return {"hata": "siteye ulaşılamadı (sunucu kapalı ya da ağ engelli)",
                    "ad": d, "url": temel}
        if not bas0 and kod0 not in (0,):
            # HEAD desteklenmiyorsa gövdesiz GET ile başlıkları al
            kod0, _, bas0 = _cek(temel + "/", 20, tip="GET")

        bulgular, oneriler = [], []
        # --------------------------------------------------- (a) hassas dosyalar
        hassas = []
        for yol, onem, aciklama in HASSAS_YOLLAR:
            time.sleep(ISTEK_ARASI)
            kod, _, bas = _cek(temel + yol, 15, tip="HEAD")
            if kod == 405:                                  # HEAD yoksa GET ile dene
                time.sleep(ISTEK_ARASI)
                kod, _, bas = _cek(temel + yol, 15, tip="GET")
            durum, derece = _dosya_durumu(kod)
            hassas.append({"yol": yol, "kod": kod, "durum": durum,
                           "onem": derece or onem, "aciklama": aciklama})
            if durum == "AÇIK":
                bulgular.append({"tur": "hassas_dosya", "onem": "kritik",
                                 "aciklama": "%s adresi HTTP %s döndü — dosya dışarıdan okunabilir (%s)"
                                             % (yol, kod, aciklama)})
            elif durum == "belirsiz":
                bulgular.append({"tur": "hassas_dosya", "onem": "düşük",
                                 "aciklama": "%s için beklenmedik kod: HTTP %s" % (yol, kod)})

        acik_sayisi = len([h for h in hassas if h["durum"] == "AÇIK"])
        if not acik_sayisi:
            bulgular.append({"tur": "hassas_dosya", "onem": "bilgi",
                             "aciklama": "Test edilen %d hassas yol açık değil "
                                         "(403/404 döndü)." % len([h for h in hassas if h["kod"] not in (0,)])})

        # ------------------------------------------------------ (b) HTTP metotları
        time.sleep(ISTEK_ARASI)
        kod_opt, _, bas_opt = _cek(temel + "/", 15, tip="OPTIONS")
        allow = (bas_opt or {}).get("allow", "")
        time.sleep(ISTEK_ARASI)
        kod_trace, _, _ = _cek(temel + "/", 15, tip="TRACE")
        trace_acik = kod_trace == 200
        metotlar = {"OPTIONS": kod_opt or "kapalı",
                    "TRACE": "AÇIK" if trace_acik else "kapalı",
                    "allow": allow}
        if trace_acik:
            bulgular.append({"tur": "metot", "onem": "kritik",
                             "aciklama": "TRACE metodu açık (HTTP 200) — Cross-Site Tracing (XST) riski. "
                                         "Apache'de 'TraceEnable off' ekleyin."})
        else:
            bulgular.append({"tur": "metot", "onem": "bilgi",
                             "aciklama": "TRACE metodu kapalı (HTTP %s)." % (kod_trace or "yanıt yok")})

        # ---------------------------------------------------------------- (c) CORS
        time.sleep(ISTEK_ARASI)
        kotu_kok = "https://kotu-site.example"
        _, _, bas_cors = _cek(temel + "/", 15, tip="GET",
                              baslik={"Origin": kotu_kok})
        acao = (bas_cors or {}).get("access-control-allow-origin", "")
        acao = acao.strip()
        cors_uyari = None
        if acao == "*":
            cors_uyari = ("Access-Control-Allow-Origin: * — kimlik doğrulamalı sayfalarda "
                          "başka siteler veri okuyabilir")
        elif kotu_kok in acao or "kotu-site.example" in acao:
            cors_uyari = ("Sunucu isteğin Origin başlığını yansıtıyor (%s) — "
                          "yansıtma (reflected CORS) riski" % acao)
        if cors_uyari:
            bulgular.append({"tur": "cors", "onem": "yüksek", "aciklama": cors_uyari})

        # ------------------------------------------------------ (d) güvenlik başlıkları
        eksik, mevcut = [], []
        for bas_ad, etiket, aciklama, onem in GUVENLIK_BASLIKLARI:
            var = bool((bas0 or {}).get(bas_ad))
            (mevcut if var else eksik).append(etiket)
            if not var:
                bulgular.append({"tur": "baslik", "onem": onem,
                                 "aciklama": "%s başlığı yok — %s" % (etiket, aciklama)})
        baslik_puan = int(round(100.0 * len(mevcut) / len(GUVENLIK_BASLIKLARI)))

        # ---------------------------------------------------------------- (e) çerezler
        cerezler = _cerezleri_coz((bas0 or {}).get("_set_cookie"))
        eksik_bayrak = 0
        for c in cerezler:
            sorun = []
            if not c["httponly"]:
                sorun.append("HttpOnly")
            if not c["secure"]:
                sorun.append("Secure")
            if not c["samesite"]:
                sorun.append("SameSite")
            c["sorun"] = sorun
            eksik_bayrak += len(sorun)
            if sorun:
                bulgular.append({"tur": "cerez", "onem": "yüksek",
                                 "aciklama": "'%s' çerezinde eksik bayrak: %s"
                                             % (c["ad"], ", ".join(sorun))})

        # ------------------------------------------------------------------ puanlama
        puan = 100
        puan -= 5 * len(eksik)                       # eksik güvenlik başlıkları (en fazla 30)
        puan -= 20 * acik_sayisi                     # açık hassas dosya
        puan -= 5 * len([h for h in hassas if h["durum"] == "belirsiz"])
        if trace_acik:
            puan -= 10
        if cors_uyari:
            puan -= 10
        puan -= 3 * eksik_bayrak
        puan = max(0, min(100, puan))
        seviye = "iyi" if puan >= 85 else ("orta" if puan >= 60 else "zayıf")

        # ---------------------------------------------------------------- öneriler
        oneriler.extend(_ONERI_NGINX)
        oneriler.extend(_ONERI_APACHE)
        if acik_sayisi:
            oneriler.insert(0, "ÖNCE ŞUNU YAPIN: %d hassas yol açık. Bu dosyaları sunucudan "
                               "silin/yeniden adlandırın (ör. .env yerine .env-local, web kökü "
                               "dışına taşıyın) ve yedekleri public_html dışında tutun."
                               % acik_sayisi)
        if cors_uyari:
            oneriler.append('# CORS: yansıtma yerine sabit liste kullanın → '
                            'add_header Access-Control-Allow-Origin "https://kendi-siteniz.com" always;')
        if trace_acik:
            oneriler.append("# TRACE kapalı değil → Apache .htaccess: TraceEnable off "
                            "(NGINX TRACE'i zaten yanıtlamaz)")
        if cerezler:
            oneriler.append("# Çerez bayrakları (PHP örneği): "
                            "setcookie($ad, $deger, ['httponly'=>true,'secure'=>true,"
                            "'samesite'=>'Lax']);")

        return {
            "ad": d,
            "url": temel + "/",
            "http_durum": kod0,
            "hassas_dosyalar": hassas,
            "metotlar": metotlar,
            "cors": {"uyari": cors_uyari, "test_origin": kotu_kok,
                     "access_control_allow_origin": acao},
            "basliklar": {"eksik": eksik, "mevcut": mevcut, "puan": baslik_puan},
            "cerezler": cerezler,
            "puan": puan,
            "seviye": seviye,
            "bulgular": bulgular,
            "oneriler": oneriler,
            "kaynak": "kendi sunucunuz (pasif başlık kontrolü)",
            "uyari": ("Bu modül yalnızca veri/izleme.json içindeki alan adlarında çalışır. "
                      "Yapılan istekler zararsız HEAD/GET çağrılarıdır; istekler arası 250 ms beklenir."),
            "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    return _onbellekli(anahtar, TTL_WEBZAFIYET, uret, zorla)


# ================================================== 3) FİDYE YAZILIMI İZLEME
def _tarih_kirp(deger):
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", str(deger or ""))
    return m.group(1) if m else ""


def _teslim_tarihi(aciklama):
    """Açıklama metninde 'deadline YYYY-MM-DD' varsa çıkarır."""
    m = re.search(r"deadline\s+(\d{4}-\d{2}-\d{2})", str(aciklama or ""), re.I)
    return m.group(1) if m else None


def _say(anahtar_fn, kayitlar, en_fazla=15):
    """Alan adına göre sayıp büyükten küçüğe sıralı liste döndürür."""
    sayac = {}
    for k in kayitlar:
        v = anahtar_fn(k)
        if v:
            sayac[v] = sayac.get(v, 0) + 1
    return [{"adet": v, "deger": k} for k, v in
            sorted(sayac.items(), key=lambda x: -x[1])[:en_fazla]]


def fidye_izleme(ulke="", sektor="", limit=100, zorla=False):
    """
    ransomware.live son kurban listesini çeker; ülke/sektör süzgeci uygular.
    .onion bağlantıları bilinçli olarak listelenmez (yasal).
    """
    try:
        limit = int(limit)
    except Exception:
        limit = 100
    limit = max(10, min(limit, 100))
    ulke = str(ulke or "").strip().upper()[:3]
    sektor = str(sektor or "").strip().lower()
    anahtar = "ek2-fidye::%s::%s::%d" % (ulke, sektor, limit)

    def uret():
        kod, j, govde, _ = _json_cek("https://api.ransomware.live/recentvictims", 35)
        if kod not in (200, 301, 302) or not isinstance(j, list):
            if kod == 0:
                return {"hata": "ransomware.live beslemesine ulaşılamadı (ağ/SSL)"}
            return {"hata": "ransomware.live beklenmeyen yanıt (HTTP %s)" % kod}

        ham = [x for x in j if isinstance(x, dict)][:limit]
        tum_kurumlar = []
        for x in ham:
            aciklama = str(x.get("description") or "").strip()
            tum_kurumlar.append({
                "kurum": (str(x.get("post_title") or "").strip() or "—")[:160],
                "ulke": str(x.get("country") or "").strip().upper() or "—",
                "sektor": str(x.get("activity") or "").strip() or "—",
                "grup": str(x.get("group_name") or "").strip() or "—",
                "tarih": _tarih_kirp(x.get("published") or x.get("discovered")),
                "veri_boyutu": x.get("data_size"),
                "teslim": _teslim_tarihi(aciklama),
                "aciklama": aciklama[:300],
                "site": str(x.get("website") or "").strip()[:120],
            })

        suzulmus = [k for k in tum_kurumlar
                    if (not ulke or k["ulke"] == ulke)
                    and (not sektor or sektor in k["sektor"].lower())]
        turkiye = [k for k in tum_kurumlar if k["ulke"] == "TR"]

        return {
            "toplam": len(tum_kurumlar),
            "gosterilen": len(suzulmus),
            "kurumlar": suzulmus,
            "gruplar": [{"grup": x["deger"], "adet": x["adet"]}
                        for x in _say(lambda k: k["grup"], suzulmus)],
            "ulkeler": [{"ulke": x["deger"], "adet": x["adet"]}
                        for x in _say(lambda k: k["ulke"], suzulmus)],
            "sektorler": [{"sektor": x["deger"], "adet": x["adet"]}
                          for x in _say(lambda k: k["sektor"], suzulmus)],
            "turkiye": turkiye,
            "uyari": "son %d kayıtta Türkiye'den %d kurum" % (len(tum_kurumlar), len(turkiye)),
            "kaynak": "ransomware.live",
            "not": ".onion bağlantıları listelenmez",
            "suzgec": {"ulke": ulke or "hepsi", "sektor": sektor or "hepsi", "limit": limit},
            "ornek": ("Yeni bir fidye yazılımı kurbanı kendi sektörünüzde görünüyorsa "
                      "aynı grup sizi de hedefleyebilir: teslim tarihi ve grup adı "
                      "üzerinden önlem alın (yedek, EDR, MFA)."),
            "guncelleme": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    return _onbellekli(anahtar, TTL_FIDYE, uret, zorla)


# =============================================================== YÖNLENDİRİCİ
MEVCUT = ["sertifika", "webzafiyet", "fidye", "moduller"]


def ek2b_isle(yol, sorgu, govde, ayarlar=None):
    """
    "/api/arac/<ad>" yollarını işler. Her modül hata durumunda
    {"hata": "<Türkçe açıklama>"} döndürür; fonksiyon ASLA çökmez.
    """
    try:
        ad = str(yol or "").rstrip("/").split("/")[-1].split("?")[0].lower()
        sorgu = sorgu if isinstance(sorgu, dict) else {}
        govde = govde if isinstance(govde, dict) else {}

        def _deger(*adlar, **kw):
            for a in adlar:
                for k in (sorgu, govde):
                    v = k.get(a)
                    if v not in (None, ""):
                        return v
            return kw.get("varsayilan")

        hedef = _deger("ad", "hedef", "domain", "alan", varsayilan="")
        zorla = str(_deger("zorla", "force", varsayilan="")).lower() in ("1", "true", "evet", "yes")
        crtsh = str(_deger("crtsh", varsayilan="")).lower() in ("1", "true", "evet", "yes")

        if ad in ("moduller", ""):
            return {"ekler": [
                {"kod": "sertifika", "ad": "Sertifika Şeffaflığı (CT)",
                 "aciklama": "CT loglarından alt alan adları + yeni sertifikalar",
                 "ornek": "/api/arac/sertifika?ad=ornek.com"},
                {"kod": "webzafiyet", "ad": "Web Zafiyet Ön Kontrolü",
                 "aciklama": "Hassas yol, metot, CORS, başlık, çerez kontrolü (yalnız izleme listesi)",
                 "ornek": "/api/arac/webzafiyet?ad=ornek.com"},
                {"kod": "fidye", "ad": "Fidye Yazılımı İzleme",
                 "aciklama": "ransomware.live son kurbanlar, ülke/sektör süzgeci",
                 "ornek": "/api/arac/fidye?ulke=TR&limit=100"},
            ]}

        if ad == "sertifika":
            return sertifika_alt_alanlar(hedef, crtsh=crtsh, zorla=zorla)

        if ad == "webzafiyet":
            return web_zafiyet(hedef, zorla=zorla)

        if ad == "fidye":
            return fidye_izleme(_deger("ulke", varsayilan=""),
                                _deger("sektor", varsayilan=""),
                                _deger("limit", varsayilan=100),
                                zorla=zorla)

        # Tanımadığımız yol: ana çekirdek zincirdeki diğer ek dosyaları denesin diye
        # None döneriz ({"hata": ...} dönmek zinciri burada keserdi).
        return None
    except Exception as e:
        return {"hata": "beklenmeyen hata: " + str(e)[:200]}


# =============================================================== KENDİ TESTİ
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("kullanım: python osint-ek2b.py <sertifika|webzafiyet|fidye> <hedef|ulke>")
        raise SystemExit(0)
    eylem, arg = sys.argv[1], sys.argv[2]
    if eylem == "sertifika":
        r = sertifika_alt_alanlar(arg, crtsh="--crtsh" in sys.argv, zorla=True)
        print("kaynak:", r.get("kaynak"), "| sertifika:", r.get("sertifika_sayisi"))
        print("alt alanlar:", r.get("alt_alanlar"))
    elif eylem == "webzafiyet":
        r = web_zafiyet(arg, zorla=True)
        print("puan:", r.get("puan"), "| seviye:", r.get("seviye"))
        print("açık:", [h["yol"] for h in (r.get("hassas_dosyalar") or []) if h["durum"] == "AÇIK"])
    elif eylem == "fidye":
        r = fidye_izleme(arg, zorla=True)
        print(r.get("uyari"), "| toplam:", r.get("toplam"))
    else:
        print("bilinmeyen eylem:", eylem)
