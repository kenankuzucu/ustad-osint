# -*- coding: utf-8 -*-
"""ÜSTAD OSINT — madalyon amblem işleyici (proje içi araç).

Kaynak: Masaüstü'ndeki UUID adlı altın madalyon PNG'si (düz koyu zemin, şeffaf değil).
Yaptığı: koyu zemini eşikleyip dairesel keser, zeminini şeffaf yapar, altın çerçeve +
dış ışıma ekler ve LOGO BOYUTLARINDA okunacak şekilde aydınlatır.

Neden aydınlatma var: madalyonun kendi zemini koyu; 104 px'e küçültülünce sayfada
muddy/soluk görünüyordu (ölçüm: saydam olmayan piksellerde ortalama parlaklık düşük).
Bu yüzden parlaklık 1.42 ile çarpılır, doygunluk 1.20, kontrast 1.12.

Üretir (web/ içine):
  foto-kurucu.png     256px → sol ALT logo (menü altı künye) ve üst şerit künyesi
  amblem-medalyon.png  96px → sol ÜST logo (eylem şeridi markası)
  yedek/madalyon-560.png    → ana kopya (yeniden üretim için)

Çalıştır:  python madalyon-uret.py
"""
import os
import sys

from PIL import Image, ImageDraw, ImageEnhance, ImageFilter

KOK = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(KOK, "web")
YEDEK = os.path.join(KOK, "yedek")
VARSAYILAN_KAYNAK = r"C:\Users\kenan\OneDrive\Desktop\f063ec25-fbce-4fbe-9a32-47e41b149477.png"

ALTIN = (255, 205, 110)
ALTIN_KOYU = (196, 140, 42)


def medalyon(kaynak_yolu):
    src = Image.open(kaynak_yolu).convert("RGB")

    # 1) Koyu zemini eşikleyip madalyonun sınırlarını bul
    gri = src.convert("L")
    esikli = gri.point(lambda v: 255 if v > 38 else 0)
    kutu = esikli.getbbox()
    if not kutu:
        raise RuntimeError("madalyon sınırı bulunamadı (görsel tamamen koyu?)")
    x0, y0, x1, y1 = kutu
    cap = y1 - y0                      # kanat uçları yatayda taşar → çap = yükseklik
    cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
    yari = cap // 2
    kirp = src.crop((cx - yari, cy - yari, cx + yari, cy + yari))
    print("esik kutusu:", kutu, "| kirpilan:", kirp.size)

    # 2) Aydınlatma (küçük ikonda okunurluk için şart)
    kirp = ImageEnhance.Brightness(kirp).enhance(1.42)
    kirp = ImageEnhance.Contrast(kirp).enhance(1.12)
    kirp = ImageEnhance.Color(kirp).enhance(1.20)

    # 3) Yumuşak kenarlı dairesel maske (büyük tuvalde çiz, sonra küçült → kenar yumuşar)
    olcek = 4
    buyuk = kirp.size[0] * olcek
    kirp_b = kirp.resize((buyuk, buyuk), Image.LANCZOS)
    maske = Image.new("L", (buyuk, buyuk), 0)
    ciz = ImageDraw.Draw(maske)
    ic = int(buyuk * 0.965)
    ciz.ellipse((0, 0, ic, ic), fill=255)
    maske = maske.filter(ImageFilter.GaussianBlur(buyuk * 0.006))

    # 4) Altın çerçeve + cam parlaması
    cerceve = Image.new("RGBA", (buyuk, buyuk), (0, 0, 0, 0))
    c2 = ImageDraw.Draw(cerceve)
    kalinlik = max(2, int(buyuk * 0.012))
    c2.ellipse((1, 1, ic - 1, ic - 1), outline=ALTIN + (200,), width=kalinlik)
    c2.ellipse((kalinlik, kalinlik, ic - kalinlik, ic - kalinlik),
               outline=ALTIN_KOYU + (150,), width=max(1, kalinlik // 2))
    parlak = Image.new("RGBA", (buyuk, buyuk), (0, 0, 0, 0))
    p2 = ImageDraw.Draw(parlak)
    p2.ellipse((int(buyuk * 0.16), int(buyuk * 0.06), int(buyuk * 0.84), int(buyuk * 0.50)),
               fill=(255, 255, 255, 26))
    parlak = parlak.filter(ImageFilter.GaussianBlur(buyuk * 0.03))

    # 5) Gövde + parlaklık + çerçeve
    govde = kirp_b.convert("RGBA")
    govde.putalpha(maske)
    govde = Image.alpha_composite(govde, parlak)
    govde = Image.alpha_composite(govde, cerceve)

    # 6) Dış ışıma (altın hale)
    hale = Image.new("RGBA", (buyuk, buyuk), (0, 0, 0, 0))
    h = ImageDraw.Draw(hale)
    h.ellipse((int(buyuk * .01), int(buyuk * .01), ic, ic), outline=(255, 196, 92, 190),
              width=max(2, int(buyuk * .02)))
    hale = hale.filter(ImageFilter.GaussianBlur(buyuk * 0.022))

    tuval = Image.new("RGBA", (buyuk, buyuk), (0, 0, 0, 0))
    tuval = Image.alpha_composite(tuval, hale)
    tuval = Image.alpha_composite(tuval, govde)
    return tuval


def kaydet(im, yol, boy):
    if not os.path.isdir(os.path.dirname(yol)):
        os.makedirs(os.path.dirname(yol), exist_ok=True)
    im.resize((boy, boy), Image.LANCZOS).save(yol, optimize=True)
    print("  yazildi: %-44s %3dpx  %6.1f KB" % (os.path.basename(yol), boy, os.path.getsize(yol) / 1024))


def main():
    kaynak = sys.argv[1] if len(sys.argv) > 1 else VARSAYILAN_KAYNAK
    if not os.path.exists(kaynak):
        print("HATA: kaynak görsel yok:", kaynak)
        return 1
    ana = medalyon(kaynak)
    kaydet(ana, os.path.join(YEDEK, "madalyon-560.png"), 560)
    kaydet(ana, os.path.join(WEB, "foto-kurucu.png"), 256)      # sol ALT logo
    kaydet(ana, os.path.join(WEB, "amblem-medalyon.png"), 96)   # sol ÜST logo
    return 0


if __name__ == "__main__":
    sys.exit(main())
