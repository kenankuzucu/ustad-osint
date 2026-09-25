# -*- coding: utf-8 -*-
"""ÜSTAD OSINT v1.5 — günlük otomatik tarama + DEĞİŞİM (fark) raporu.

Kenan'ın kendi alan adlarını her gün tarar, bir önceki güne göre NE DEĞİŞTİĞİNİ
(yeni açılan/kapanan port, yeni bulgu, risk değişimi, yeni alt alan) yazar:
  - Masaüstü\\USTAD-OSINT-RAPORLAR\\YYYY-AA-GG-rapor.html
  - veri\\fark\\<hedef>.json  (karşılaştırma için saklanan anlık görüntü)
  - veri\\gunluk.log

Elle:  python gunluk-rapor.py
İzlenen liste: veri/izleme.json  ({"hedefler": ["ornek.com", ...]})
"""
import io
import json
import os
import time

KOK = os.path.dirname(os.path.abspath(__file__))
IZLEME = os.path.join(KOK, "veri", "izleme.json")
FARK_KOK = os.path.join(KOK, "veri", "fark")
LOG = os.path.join(KOK, "veri", "gunluk.log")
RAPOR_KOK = os.path.join(os.path.expanduser("~"), "OneDrive", "Desktop", "USTAD-OSINT-RAPORLAR")

VARSAYILAN = {"hedefler": ["ustadkenankuzucu.com.tr", "ustadcyber.com.tr"]}


def _oku(yol, varsayilan):
    try:
        with io.open(yol, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return varsayilan


def _yaz(yol, veri):
    os.makedirs(os.path.dirname(yol), exist_ok=True)
    with io.open(yol, "w", encoding="utf-8", newline="") as f:
        json.dump(veri, f, ensure_ascii=False, indent=1)


def _cekirdek():
    """Ana çekirdeği (profil_cikar) ve ek modülleri yükler."""
    import importlib.util
    import sys
    sys.path.insert(0, KOK)
    yol = os.path.join(KOK, "osint-araclar.py")
    sp = importlib.util.spec_from_file_location("osint_araclar", yol)
    m = importlib.util.module_from_spec(sp)
    sys.modules["osint_araclar"] = m
    sp.loader.exec_module(m)
    ek = None
    try:
        ek = m.EK
    except Exception:
        pass
    return m, ek


def anlik_goruntu(hedef, cekirdek, ek=None):
    """Bir hedefin şu anki durumu: portlar, alt alanlar, bulgular, risk."""
    r = cekirdek.profil_cikar(hedef, ["dns", "whois", "ip", "subdomain", "webtek", "sizinti"])
    sub = []
    try:
        s = cekirdek.subdomain_tara(hedef, en_fazla=300)
        sub = [x.get("ad") if isinstance(x, dict) else x for x in (s.get("alt_alanlar") or [])]
    except Exception:
        pass
    portlar = []
    try:
        w = (r.get("sonuclar") or {}).get("webtek") or {}
        for p in (w.get("portlar") or []):
            portlar.append(int(p.get("port")) if isinstance(p, dict) else int(p))
    except Exception:
        pass
    pasif = {}
    if ek is not None:
        try:
            p = ek.pasif_radar(hedef)
            pasif = {"portlar": p.get("portlar") or [], "cve": [c.get("id") for c in (p.get("cveler") or [])],
                     "kritik": p.get("kritik") or 0, "ip": p.get("ip") or []}
        except Exception:
            pasif = {}
    return {"hedef": hedef, "zaman": time.strftime("%Y-%m-%d %H:%M:%S"),
            "risk": r.get("risk"), "sayilar": r.get("sayilar") or {},
            "bulgular": [(b.get("tur") or "") + ": " + (b.get("aciklama") or "")[:140] for b in (r.get("bulgular") or [])],
            "portlar": sorted(set(portlar + (pasif.get("portlar") or []))),
            "alt_alanlar": sorted(set(sub)), "pasif": pasif}


def fark(eski, yeni):
    """İki anlık görüntü arasındaki farkı sözlük olarak döndürür."""
    if not eski:
        return {"ilk_kez": True, "ozet": "İlk kayıt — karşılaştırma yok."}
    ep, yp = set(eski.get("portlar") or []), set(yeni.get("portlar") or [])
    ea, ya = set(eski.get("alt_alanlar") or []), set(yeni.get("alt_alanlar") or [])
    ebu, ybu = set(eski.get("bulgular") or []), set(yeni.get("bulgular") or [])
    ec = set((eski.get("pasif") or {}).get("cve") or [])
    yc = set((yeni.get("pasif") or {}).get("cve") or [])
    return {
        "onceki_zaman": eski.get("zaman"), "simdi": yeni.get("zaman"),
        "risk_eski": eski.get("risk"), "risk_yeni": yeni.get("risk"),
        "risk_degisim": (yeni.get("risk") or 0) - (eski.get("risk") or 0),
        "yeni_portlar": sorted(yp - ep), "kapanan_portlar": sorted(ep - yp),
        "yeni_alt_alanlar": sorted(ya - ea), "kaybolan_alt_alanlar": sorted(ea - ya),
        "yeni_bulgular": sorted(ybu - ebu), "duzelen_bulgular": sorted(ebu - ybu),
        "yeni_cve": sorted(yc - ec), "kapanan_cve": sorted(ec - yc),
        "ilk_kez": False,
    }


def html_rapor(gun, kayitlar):
    s = ['<!DOCTYPE html><html lang="tr"><meta charset="utf-8">',
         '<title>ÜSTAD OSINT — Günlük Değişim Raporu</title>',
         '<style>body{background:#07090d;color:#d8e6f2;font-family:"Segoe UI",sans-serif;padding:26px}',
         'h1{color:#ffd479;font-size:22px}h2{color:#00ffa3;font-size:17px;margin-top:22px}',
         'table{border-collapse:collapse;width:100%;margin-top:8px}',
         'th,td{border-bottom:1px solid #1d2a38;padding:6px 9px;text-align:left;font-size:14px}',
         'th{color:#8fb4d0;font-size:12px;text-transform:uppercase}',
         '.iyi{color:#33d17a}.kotu{color:#ff5d5d}.notr{color:#ffcf4d}',
         'code{color:#b6ff3d;font-family:Consolas,monospace}</style>',
         '<h1>🛰️ ÜSTAD OSINT — Günlük Değişim Raporu</h1>',
         '<p>%s · Kaynak: kendi sunucunuzdaki ÜSTAD OSINT çekirdeği (pasif + aktif, yalnız kendi alan adlarınız).</p>'
         % time.strftime("%d.%m.%Y %H:%M")]
    for k in kayitlar:
        y = k["yeni"]
        f = k["fark"]
        s.append("<h2>%s — risk <span class='%s'>%s/100</span></h2>" % (
            y["hedef"], "kotu" if (y.get("risk") or 0) >= 35 else "iyi", y.get("risk")))
        if f.get("ilk_kez"):
            s.append("<p>İlk kayıt; sonraki güne göre karşılaştırma yapılacak.</p>")
        else:
            ok = "kotu" if (f["risk_degisim"] or 0) > 0 else ("iyi" if (f["risk_degisim"] or 0) < 0 else "notr")
            s.append("<p>Önceki tarama: <b>%s</b> · risk değişimi: <span class='%s'>%+d</span></p>"
                     % (f.get("onceki_zaman"), ok, f.get("risk_degisim") or 0))
        satir = [
            ("Yeni açılan port", f.get("yeni_portlar")), ("Kapanan port", f.get("kapanan_portlar")),
            ("Yeni alt alan", f.get("yeni_alt_alanlar")), ("Kaybolan alt alan", f.get("kaybolan_alt_alanlar")),
            ("Yeni CVE", f.get("yeni_cve")), ("Kapanan CVE", f.get("kapanan_cve")),
            ("Yeni bulgu", f.get("yeni_bulgular")), ("Düzelen bulgu", f.get("duzelen_bulgular")),
        ]
        s.append("<table><tr><th>Değişim</th><th>Kayıt</th></tr>")
        for ad, liste in satir:
            if liste:
                s.append("<tr><td>%s</td><td><code>%s</code></td></tr>" % (ad, "<br>".join(str(x) for x in liste[:25])))
        s.append("</table>")
        s.append("<p>Portlar: <code>%s</code><br>Alt alan: %s adet · Zafiyet kaydı: %s · Kritik: %s</p>" % (
            ", ".join(str(p) for p in y.get("portlar") or []), len(y.get("alt_alanlar") or []),
            len((y.get("pasif") or {}).get("cve") or []), (y.get("pasif") or {}).get("kritik") or 0))
    s.append("<p style='opacity:.6;margin-top:26px'>ÜSTAD OSINT v1.5 · yalnız kendi sistemleriniz için · TCK 243/244</p></body></html>")
    return "\n".join(s)


def main():
    izleme = _oku(IZLEME, VARSAYILAN)
    hedefler = izleme.get("hedefler") or VARSAYILAN["hedefler"]
    if not os.path.exists(IZLEME):
        _yaz(IZLEME, VARSAYILAN)
    cekirdek, ek = _cekirdek()
    kayitlar = []
    for h in hedefler:
        try:
            yeni = anlik_goruntu(h, cekirdek, ek)
        except Exception as e:
            print("[!] %s taranamadı: %s" % (h, str(e)[:160]))
            continue
        yol = os.path.join(FARK_KOK, h.replace("/", "_") + ".json")
        eski = _oku(yol, None)
        f = fark(eski, yeni)
        _yaz(yol, yeni)
        kayitlar.append({"yeni": yeni, "fark": f})
        print("%-28s risk %-3s | yeni port %-2d | yeni alt alan %-3d | yeni CVE %-3d | risk %+d" % (
            h, yeni.get("risk"), len(f.get("yeni_portlar") or []), len(f.get("yeni_alt_alanlar") or []),
            len(f.get("yeni_cve") or []), f.get("risk_degisim") or 0))
    if not kayitlar:
        print("sonuç yok")
        return
    gun = time.strftime("%Y-%m-%d")
    os.makedirs(RAPOR_KOK, exist_ok=True)
    rapor = os.path.join(RAPOR_KOK, gun + "-rapor.html")
    with io.open(rapor, "w", encoding="utf-8", newline="") as f:
        f.write(html_rapor(gun, kayitlar))
    with io.open(LOG, "a", encoding="utf-8") as f:
        f.write("%s · %d hedef · rapor: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), len(kayitlar), rapor))
    print("\nrapor:", rapor)


if __name__ == "__main__":
    main()
