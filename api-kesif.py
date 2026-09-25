# -*- coding: utf-8 -*-
"""Ücretsiz OSINT kaynaklarını gerçek ağdan sınar: hangi uç nokta çalışıyor, veri ne veriyor."""
import json, os, socket, ssl, sys, time, urllib.request, urllib.error

# Kaspersky MITM sertifikası
for yol in [r"C:\Users\kenan\ca-bundle.pem", os.path.expanduser("~/ca-bundle.pem")]:
    if os.path.exists(yol):
        os.environ["SSL_CERT_FILE"] = yol
        break

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) USTAD-OSINT/1.1", "Accept": "*/*"}
BAG = ssl.create_default_context()


def dene(ad, url, tip="json", veri=None, ek_baslik=None):
    t0 = time.time()
    baslik = dict(UA)
    if ek_baslik:
        baslik.update(ek_baslik)
    try:
        istek = urllib.request.Request(url, data=veri, headers=baslik)
        with urllib.request.urlopen(istek, timeout=12, context=BAG) as y:
            kod = y.status
            ham = y.read(400000)
    except urllib.error.HTTPError as e:
        kod = e.code
        ham = e.read(20000)
    except Exception as e:
        print("  %-22s HATA  %s" % (ad, str(e)[:70]))
        return None
    sure = round(time.time() - t0, 2)
    ozet = ""
    try:
        if tip == "json":
            j = json.loads(ham.decode("utf-8", "replace"))
            if isinstance(j, list):
                ozet = "liste[%d] ilk=%s" % (len(j), json.dumps(j[0], ensure_ascii=False)[:110])
            elif isinstance(j, dict):
                ozet = json.dumps({k: j[k] for k in list(j)[:6]}, ensure_ascii=False)[:150]
        else:
            ozet = ham.decode("utf-8", "replace")[:120].replace("\n", " ")
    except Exception as e:
        ozet = "çözümleme: %s" % str(e)[:50]
    print("  %-22s %s  %ss  %s" % (ad, kod, sure, ozet))
    return kod


print("=" * 78)
print("1) DOMAIN / DNS / WHOIS")
print("=" * 78)
dene("dns.google A", "https://dns.google/resolve?name=example.com&type=A")
dene("dns.google MX", "https://dns.google/resolve?name=example.com&type=MX")
dene("cloudflare DoH", "https://cloudflare-dns.com/dns-query?name=example.com&type=TXT", ek_baslik={"Accept": "application/dns-json"})
dene("rdap.org domain", "https://rdap.org/domain/example.com")
dene("rdap.org ip", "https://rdap.org/ip/8.8.8.8")
dene("crt.sh subdomain", "https://crt.sh/?q=%25.github.com&output=json")

print()
print("=" * 78)
print("2) IP / ASN")
print("=" * 78)
dene("ip-api.com", "http://ip-api.com/json/8.8.8.8?fields=status,country,regionName,city,lat,lon,isp,org,as,asname,reverse,mobile,proxy,hosting")
dene("ipwho.is", "https://ipwho.is/8.8.8.8")
dene("bgpview ASN", "https://api.bgpview.io/asn/15169")
dene("bgpview prefix", "https://api.bgpview.io/ip/8.8.8.8")

print()
print("=" * 78)
print("3) E-POSTA / SOSYAL / GITHUB")
print("=" * 78)
dene("github user", "https://api.github.com/users/torvalds")
dene("github repos", "https://api.github.com/users/torvalds/repos?per_page=3&sort=updated")
dene("gravatar", "https://www.gravatar.com/avatar/" + __import__("hashlib").md5(b"test@example.com").hexdigest() + ".json")
dene("hibp (anahtarsız)", "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com")
for site, url in [("github.com", "https://github.com/octocat"), ("reddit", "https://www.reddit.com/user/spez/about.json"),
                  ("instagram", "https://www.instagram.com/instagram/"), ("tiktok", "https://www.tiktok.com/@rihanna")]:
    dene("kullanıcı/" + site, url, tip="metin")

print()
print("=" * 78)
print("4) CLOUD / SIZINTI / TEHDİT")
print("=" * 78)
dene("s3 var olan", "https://s3.amazonaws.com/ustad-test-bucket-xyz", tip="metin")
dene("s3 rastgele", "https://s3.amazonaws.com/qwerty-xyz-1234567890", tip="metin")
dene("azure blob", "https://ustadtest.blob.core.windows.net/", tip="metin")
dene("gcp storage", "https://storage.googleapis.com/ustad-test-bucket-xyz", tip="metin")
dene(".env sızıntı", "https://example.com/.env", tip="metin")
dene(".git/config", "https://example.com/.git/config", tip="metin")
dene("feodo blocklist", "https://feodotracker.abuse.ch/downloads/ipblocklist.csv", tip="metin")
dene("urlhaus recent", "https://urlhaus-api.abuse.ch/v1/urls/recent/", veri=b"", ek_baslik={"Content-Type": "application/x-www-form-urlencoded"})
dene("openphish", "https://openphish.com/feed.txt", tip="metin")

print()
print("=" * 78)
print("5) SMTP (e-posta doğrulama) ve port erişimi")
print("=" * 78)
for host, port, ad in [("gmail-smtp-in.l.google.com", 25, "SMTP 25 gmail"),
                       ("aspmx.l.google.com", 25, "SMTP 25 aspmx"),
                       ("smtp.gmail.com", 587, "SMTP 587")]:
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=8)
        veri_ilk = s.recv(200).decode("utf-8", "replace").strip()
        s.close()
        print("  %-22s AÇIK  %ss  %s" % (ad, round(time.time()-t0, 2), veri_ilk[:60]))
    except Exception as e:
        print("  %-22s KAPALI %s" % (ad, str(e)[:60]))

print()
print("=" * 78)
print("6) WEB TEKNOLOJİSİ (başlık okuma)")
print("=" * 78)
try:
    istek = urllib.request.Request("https://github.com", headers=UA)
    with urllib.request.urlopen(istek, timeout=12, context=BAG) as y:
        h = dict(y.headers)
        ilgi = {k: v for k, v in h.items() if k.lower() in ("server", "x-powered-by", "x-generator", "via", "cf-ray", "x-aspnet-version", "x-drupal-cache", "set-cookie")}
        print("  başlık sayısı:", len(h), "| ilgi:", json.dumps(ilgi, ensure_ascii=False)[:200])
except Exception as e:
    print("  HATA", str(e)[:80])
