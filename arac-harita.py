# -*- coding: utf-8 -*-
"""Dünya haritası katmanını üretir: assets/dunya.geojson → web/dunya-kara.png
Kara parçaları BEYAZ ve şeffaf zeminde çizilir; arayüz bu katmanı tema rengine boyar."""
import json
import os
from PIL import Image, ImageDraw

KOK = os.path.dirname(os.path.abspath(__file__))
GEOJSON = os.path.join(KOK, "assets", "dunya.geojson")
CIKTI = os.path.join(KOK, "web", "dunya-kara.png")
GEN, YUK = 1440, 720          # 4 piksel / derece (equirectangular)


def proj(lon, lat):
    return ((lon + 180.0) * (GEN / 360.0), (90.0 - lat) * (YUK / 180.0))


def main():
    d = json.load(open(GEOJSON, encoding="utf-8"))
    katman = Image.new("RGBA", (GEN, YUK), (255, 255, 255, 0))
    ciz = ImageDraw.Draw(katman)

    def halka(koor):
        return [proj(x, y) for x, y in koor]

    def poligon(koorlar):
        for h in koorlar:
            if len(h) >= 3:
                ciz.polygon(halka(h), fill=(255, 255, 255, 255))

    def cizgi(koorlar):
        for h in koorlar:
            if len(h) >= 2:
                ciz.line(halka(h), fill=(255, 255, 255, 210), width=2)

    sayi = 0
    for f in d.get("features", []):
        g = f.get("geometry") or {}
        tip = g.get("type")
        koordinat = g.get("coordinates") or []
        if tip == "Polygon":
            poligon(koordinat); sayi += 1
        elif tip == "MultiPolygon":
            for p in koordinat:
                poligon(p)
            sayi += 1
        elif tip == "LineString":
            cizgi([koordinat]); sayi += 1
        elif tip == "MultiLineString":
            cizgi(koordinat); sayi += 1
    katman.save(CIKTI, optimize=True)
    print("harita üretildi: %s · %dx%d · %d parça · %.1f KB" % (
        CIKTI, GEN, YUK, sayi, os.path.getsize(CIKTI) / 1024))

    # önizleme (kanıt): koyu zemin üzerinde
    onizleme = Image.new("RGB", (GEN, YUK), (10, 22, 34))
    onizleme.paste((46, 230, 168), (0, 0), katman)
    onizleme.resize((900, 450), Image.LANCZOS).save(os.path.join(KOK, "assets", "harita-onizleme.png"))
    print("önizleme: assets/harita-onizleme.png")


if __name__ == "__main__":
    main()
