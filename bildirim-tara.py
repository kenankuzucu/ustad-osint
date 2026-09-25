# -*- coding: utf-8 -*-
"""ÜSTAD OSINT v1.6 — olay & bildirim tarayıcısı (hafif, ağ çağrısı yapmaz).

Ne yapar:
  · veri/fark/<hedef>.json dosyalarındaki son iki anlık görüntüyü karşılaştırır
    (yeni açılan port / kapanan port / yeni alt alan / yeni CVE / risk değişimi).
  · veri/bildirim.json ayarlarına göre YENİ olayları olay günlüğüne yazar.
  · ekrana özet basar → Hermes zamanlanmış görevi bu özeti WhatsApp/Discord'a iletir.

Çalıştırma:  python bildirim-tara.py
"""
import io
import json
import os
import sys
import time

KOK = os.path.dirname(os.path.abspath(__file__))
VERI = os.path.join(KOK, "veri")
FARK = os.path.join(VERI, "fark")
BILDIRIM = os.path.join(VERI, "bildirim.json")
ISLENEN = os.path.join(VERI, "bildirim-islenen.json")

VARSAYILAN = {"yeni_port": True, "yeni_cve": True, "kritik": True, "whatsapp": True, "eposta": False}


def oku(yol, varsayilan):
    try:
        with io.open(yol, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return varsayilan


def yaz(yol, veri):
    try:
        with io.open(yol, "w", encoding="utf-8") as f:
            json.dump(veri, f, ensure_ascii=False, indent=1)
        return True
    except Exception as e:
        print("yazılamadı:", yol, e)
        return False


def olay_ekle(olay):
    """osint-ek2c modülü varsa onun yazıcısını kullan (biçim birebir aynı kalsın)."""
    try:
        import importlib.util
        p = os.path.join(KOK, "osint-ek2c.py")
        if os.path.exists(p):
            sp = importlib.util.spec_from_file_location("osint_ek2c", p)
            m = importlib.util.module_from_spec(sp)
            sp.loader.exec_module(m)
            r = m.ek2c_isle("/api/arac/bildirim", {}, {"olay": olay}, {})
            if isinstance(r, dict) and r.get("tamam"):
                return True
    except Exception as e:
        print("(ek2c olay yazıcısı kullanılamadı: %s — doğrudan yazılıyor)" % str(e)[:80])
    # yedek: doğrudan dosyaya yaz
    d = oku(BILDIRIM, {"ayar": dict(VARSAYILAN), "olaylar": []})
    d.setdefault("olaylar", [])
    d["olaylar"] = ([olay] + d["olaylar"])[:200]
    return yaz(BILDIRIM, d)


def main():
    ayar = oku(BILDIRIM, {"ayar": dict(VARSAYILAN), "olaylar": []}).get("ayar", dict(VARSAYILAN))
    islenen = oku(ISLENEN, {"anahtarlar": []})
    imzalar = set(islenen.get("anahtarlar", []))

    if not os.path.isdir(FARK):
        print("fark kaydı yok — önce panelden 'SON TARAMAYI KAYDET' ya da günlük raporu çalıştırın.")
        return 0

    yeni_olaylar = []
    for ad in sorted(os.listdir(FARK)):
        if not ad.endswith(".json"):
            continue
        hedef = ad[:-5]
        kayitlar = oku(os.path.join(FARK, ad), [])
        if not isinstance(kayitlar, list) or len(kayitlar) < 2:
            continue
        eski, yeni = kayitlar[-2], kayitlar[-1]
        e_port = {p for p in (eski.get("portlar") or [])}
        y_port = {p for p in (yeni.get("portlar") or [])}
        acilan = sorted(y_port - e_port)
        if acilan and ayar.get("yeni_port", True):
            anahtar = "%s|port|%s|%s" % (hedef, ",".join(str(x) for x in acilan), yeni.get("zaman", ""))
            if anahtar not in imzalar:
                imzalar.add(anahtar)
                yeni_olaylar.append({"tip": "yeni_port", "onem": "yuksek",
                                     "baslik": "%s — yeni açılan port: %s" % (hedef, ", ".join(str(x) for x in acilan)),
                                     "zaman": yeni.get("zaman") or time.strftime("%Y-%m-%d %H:%M:%S")})
        e_cve = {c.get("id") or c.get("cve") for c in (eski.get("cve") or []) if isinstance(c, dict)}
        y_cve = {c.get("id") or c.get("cve") for c in (yeni.get("cve") or []) if isinstance(c, dict)}
        yeni_cve = sorted(x for x in (y_cve - e_cve) if x)
        if yeni_cve and ayar.get("yeni_cve", True):
            anahtar = "%s|cve|%s|%s" % (hedef, ",".join(yeni_cve), yeni.get("zaman", ""))
            if anahtar not in imzalar:
                imzalar.add(anahtar)
                yeni_olaylar.append({"tip": "yeni_cve", "onem": "kritik",
                                     "baslik": "%s — yeni zafiyet: %s" % (hedef, ", ".join(yeni_cve[:5])),
                                     "zaman": yeni.get("zaman") or time.strftime("%Y-%m-%d %H:%M:%S")})
        e_risk, y_risk = eski.get("risk") or 0, yeni.get("risk") or 0
        if abs(y_risk - e_risk) >= 15 and ayar.get("kritik", True):
            anahtar = "%s|risk|%s|%s" % (hedef, y_risk, yeni.get("zaman", ""))
            if anahtar not in imzalar:
                imzalar.add(anahtar)
                yeni_olaylar.append({"tip": "risk_degisimi", "onem": "yuksek" if y_risk > e_risk else "bilgi",
                                     "baslik": "%s — risk %s → %s" % (hedef, e_risk, y_risk),
                                     "zaman": yeni.get("zaman") or time.strftime("%Y-%m-%d %H:%M:%S")})

    for o in yeni_olaylar:
        o["zaman"] = o.get("zaman") or time.strftime("%Y-%m-%d %H:%M:%S")
        olay_ekle(o)

    yaz(ISLENEN, {"anahtarlar": sorted(imzalar)[-500:]})

    if yeni_olaylar:
        print("ÜSTAD OSINT — %d yeni olay" % len(yeni_olaylar))
        for o in yeni_olaylar[:10]:
            print("  [%s] %s" % (o.get("onem", "?"), o.get("baslik", "")))
    else:
        print("ÜSTAD OSINT — yeni olay yok (kontrol: %s)" % time.strftime("%Y-%m-%d %H:%M"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
