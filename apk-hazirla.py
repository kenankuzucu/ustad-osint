# -*- coding: utf-8 -*-
"""ÜSTAD OSINT — APK iskeletini kurar: kabuk kopyası + web/ içeriği + simgeler.
Kaynak kabuk: kenan-osint-app (Java köprüsü hazır). Hedef: AndroidBuild/ustad-osint-app
"""
import os, shutil, re
from PIL import Image, ImageDraw

EV = r"C:\Users\kenan\AndroidBuild"
KABUK = os.path.join(EV, "kenan-osint-app")
HEDEF = os.path.join(EV, "ustad-osint-app")
WEB = r"C:\Users\kenan\OneDrive\Desktop\USTAD-OSINT\web"
IKON = os.path.join(WEB, "ikon-512.png")

PAKET_YOLU = os.path.join("src", "tr", "com", "ustadkenankuzucu", "osint")

# ------------------------------------------------------------------ 1) kabuk
if os.path.isdir(HEDEF):
    shutil.rmtree(HEDEF, ignore_errors=True)
os.makedirs(HEDEF)
shutil.copy(os.path.join(KABUK, "AndroidManifest.xml"), HEDEF)
shutil.copytree(os.path.join(KABUK, "res"), os.path.join(HEDEF, "res"))
shutil.copytree(os.path.join(KABUK, "src"), os.path.join(HEDEF, "src"))
os.makedirs(os.path.join(HEDEF, "assets"))
print("kabuk kopyalandı:", HEDEF)

# ------------------------------------------------------------------ 2) assets
sayi = 0
for ad in sorted(os.listdir(WEB)):
    kaynak = os.path.join(WEB, ad)
    if not os.path.isfile(kaynak):
        continue
    if ad.lower().endswith((".geojson",)):
        continue
    shutil.copy(kaynak, os.path.join(HEDEF, "assets", ad))
    sayi += 1
print("assets dosyası:", sayi, sorted(os.listdir(os.path.join(HEDEF, "assets"))))

# ------------------------------------------------------------------ 3) manifest / strings
man_yolu = os.path.join(HEDEF, "AndroidManifest.xml")
man = open(man_yolu, encoding="utf-8").read()
man = man.replace('android:versionCode="1"', 'android:versionCode="1"')
man = man.replace('android:versionName="1.0"', 'android:versionName="1.0"')
if 'android:usesCleartextTraffic="true"' not in man:
    man = man.replace('android:supportsRtl="false"',
                      'android:supportsRtl="false"\n        android:usesCleartextTraffic="true"')
open(man_yolu, "w", encoding="utf-8").write(man)

st = os.path.join(HEDEF, "res", "values", "strings.xml")
s = open(st, encoding="utf-8").read()
s = re.sub(r"<string name=\"uygulama_adi\">.*?</string>",
           "<string name=\"uygulama_adi\">ÜSTAD OSINT</string>", s, flags=re.S)
open(st, "w", encoding="utf-8").write(s)
print("etiket:", re.search(r"uygulama_adi\">(.*?)<", open(st, encoding="utf-8").read()).group(1))

# ------------------------------------------------------------------ 4) simgeler
ana = Image.open(IKON).convert("RGBA").resize((1024, 1024), Image.LANCZOS)
def kare_maske(img, yaricap_oran=0.22):
    m = Image.new("L", img.size, 0)
    d = ImageDraw.Draw(m)
    r = int(img.size[0] * yaricap_oran)
    d.rounded_rectangle([0, 0, img.size[0] - 1, img.size[1] - 1], radius=r, fill=255)
    out = img.copy(); out.putalpha(m); return out
def daire_maske(img):
    m = Image.new("L", img.size, 0)
    ImageDraw.Draw(m).ellipse([0, 0, img.size[0] - 1, img.size[1] - 1], fill=255)
    out = img.copy(); out.putalpha(m); return out

yogunluk = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
for ad, px in yogunluk.items():
    klasor = os.path.join(HEDEF, "res", "mipmap-" + ad)
    os.makedirs(klasor, exist_ok=True)
    kucuk = ana.resize((px, px), Image.LANCZOS)
    kare_maske(kucuk).save(os.path.join(klasor, "ic_launcher.png"))
    daire_maske(kucuk).save(os.path.join(klasor, "ic_launcher_round.png"))
    # uyarlanabilir ön plan: içerik %72 güvenli alanda
    tuval = Image.new("RGBA", (px, px), (0, 0, 0, 0))
    ic = int(px * 0.72)
    tuval.paste(ana.resize((ic, ic), Image.LANCZOS), ((px - ic) // 2, (px - ic) // 2))
    tuval.save(os.path.join(klasor, "ic_launcher_foreground.png"))
print("simgeler yazıldı: 5 yoğunluk × 3 dosya")
print("HAZIR")
