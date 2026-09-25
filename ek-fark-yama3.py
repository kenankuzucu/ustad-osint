# -*- coding: utf-8 -*-
"""ek.js — farkGoster: canlı taramayı pasif veriyle zenginleştirip karşılaştır."""
import io
import os

KOK = os.path.dirname(os.path.abspath(__file__))
p = os.path.join(KOK, "web", "ek.js")
s = io.open(p, encoding="utf-8").read()
if "farkGoster2" in s:
    print("zaten var")
    raise SystemExit(0)

ESKI_BAS = """  function farkGoster() {
    var h = (($('farkGirdi') || {}).value || '').trim();
    var liste = farkOku(h);
    var s = (window.Osint && Osint.S && Osint.S.sonuc) ? Osint.S.sonuc : null;
    var yeni = null, eski = null;
    if (s && (!h || String(s.hedef || '').toLowerCase().indexOf(h.toLowerCase()) >= 0)) {
      yeni = anlikGoruntu(s.hedef || h, s);
      eski = liste.length ? liste[liste.length - 1] : null;
    } else {"""

YENI_BAS = """  function farkGoster() {
    var h = (($('farkGirdi') || {}).value || '').trim();
    var liste = farkOku(h);
    var s = (window.Osint && Osint.S && Osint.S.sonuc) ? Osint.S.sonuc : null;
    var yeni = null, eski = null;
    // Canlı tarama varsa onu kullan ama port/CVE'yi pasif radarla tamamla
    if (s && liste.length >= 1 && (!h || String(s.hedef || '').toLowerCase().indexOf(h.toLowerCase()) >= 0)) {
      eski = liste[liste.length - 1];
      yeni = anlikGoruntu(s.hedef || h, s);
      durum('farkDurum', 'pasif veri ile tamamlanıyor…');
      api('/api/arac/pasif?ad=' + encodeURIComponent(eski.hedef || s.hedef || h)).then(function (p) {
        if (p && !p.hata) yeni = pasifVerisiyle(yeni, p);
        cizFark(farkHesapla(eski, yeni), yeni);
        farkGecmisCiz(eski.hedef || h);
        durum('farkDurum', 'tamamlandı');
      }).catch(function () {
        cizFark(farkHesapla(eski, yeni), yeni);
        farkGecmisCiz(eski.hedef || h);
        durum('farkDurum', 'pasif veri alınamadı');
      });
      return;
    }
    if (false) {"""

if ESKI_BAS not in s:
    print("HATA: farkGoster başlangıcı bulunamadı")
    raise SystemExit(1)
s = s.replace(ESKI_BAS, YENI_BAS, 1)
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("farkGoster yamalandı:", "pasif veri ile tamamlanıyor" in s)
