# -*- coding: utf-8 -*-
"""2. tur: alternatif kaynaklar — subdomain, azure, kullanıcı adı mantığı."""
import json, os, ssl, time, urllib.request, urllib.error

for yol in [r"C:\Users\kenan\ca-bundle.pem", os.path.expanduser("~/ca-bundle.pem")]:
    if os.path.exists(yol):
        os.environ["SSL_CERT_FILE"] = yol
        break
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) USTAD-OSINT/1.1", "Accept": "*/*"}
BAG = ssl.create_default_context()


def dene(ad, url, tip="json", kes=140):
    t0 = time.time()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=15, context=BAG) as y:
            kod, ham = y.status, y.read(300000)
    except urllib.error.HTTPError as e:
        kod, ham = e.code, e.read(30000)
    except Exception as e:
        print("  %-26s HATA  %s" % (ad, str(e)[:60])); return None, None
    sure = round(time.time() - t0, 2)
    ozet = ""
    try:
        if tip == "json":
            j = json.loads(ham.decode("utf-8", "replace"))
            ozet = ("liste[%d] %s" % (len(j), json.dumps(j[0], ensure_ascii=False)[:100])) if isinstance(j, list) \
                else json.dumps(j, ensure_ascii=False)[:kes]
        else:
            ozet = ham.decode("utf-8", "replace")[:kes].replace("\n", " ")
    except Exception as e:
        ozet = ham.decode("utf-8", "replace")[:kes].replace("\n", " ")
    print("  %-26s %s %ss %s" % (ad, kod, sure, ozet))
    return kod, ham


print("=" * 78); print("SUBDOMAIN KAYNAKLARI"); print("=" * 78)
dene("crt.sh tekrar", "https://crt.sh/?q=%25.github.com&output=json")
dene("hackertarget", "https://api.hackertarget.com/hostsearch/?q=github.com", tip="metin")
dene("subdomain.center", "https://api.subdomain.center/?domain=github.com")
dene("rapiddns", "https://rapiddns.io/subdomain/github.com?full=1", tip="metin", kes=100)
dene("dns.bufferover", "https://dns.bufferover.run/dns?q=.github.com")
dene("otx alienvault", "https://otx.alienvault.com/api/v1/indicators/domain/github.com/passive_dns")
dene("crt.sh farkli", "https://crt.sh/json?q=github.com")

print(); print("=" * 78); print("CLOUD (gerçek karşılaştırma: var olan / olmayan)"); print("=" * 78)
dene("s3 var (aws konsol örnek)", "https://aws-managed-waf-logs-us-east-1.s3.amazonaws.com/", tip="metin", kes=90)
dene("azure blob liste", "https://ustadtest1234.blob.core.windows.net/?comp=list", tip="metin", kes=120)
dene("azure blob rastgele", "https://qwertyxyz9988.blob.core.windows.net/?comp=list", tip="metin", kes=120)

print(); print("=" * 78); print("KULLANICI ADI: var olan vs olmayan"); print("=" * 78)
for ad, url in [
    ("gh var/octocat", "https://github.com/octocat"),
    ("gh yok/xyzabc9988", "https://github.com/xyzabc9988qwerty"),
    ("tw var", "https://twitter.com/x"),
    ("insta var", "https://www.instagram.com/instagram/"),
    ("insta yok", "https://www.instagram.com/zzqqxx99887766/"),
    ("tiktok var", "https://www.tiktok.com/@rihanna"),
    ("tiktok yok", "https://www.tiktok.com/@zzqqxx99887766aa"),
    ("reddit var", "https://www.reddit.com/user/spez.json"),
    ("pinterest var", "https://www.pinterest.com/pinterest/"),
    ("medium var", "https://medium.com/@medium"),
    ("telegram var", "https://t.me/telegram"),
    ("youtube var", "https://www.youtube.com/@MrBeast"),
    ("stackoverflow var", "https://stackoverflow.com/users/1"),
    ("gitlab var", "https://gitlab.com/gitlab-org"),
    ("keybase var", "https://keybase.io/example"),
    ("steam var", "https://steamcommunity.com/id/example"),
    ("facebook var", "https://www.facebook.com/zuck"),
]:
    dene(ad, url, tip="metin", kes=60)
