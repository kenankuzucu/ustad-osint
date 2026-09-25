# -*- coding: utf-8 -*-
"""ek.js — farkKaydet: profil portu yoksa pasif radardan port/CVE çeker."""
import io
import os

KOK = os.path.dirname(os.path.abspath(__file__))
p = os.path.join(KOK, "web", "ek.js")
s = io.open(p, encoding="utf-8").read()
if "pasifVerisiyle" in s:
    print("zaten var")
    raise SystemExit(0)

ESKI = """  function farkKaydet() {
    var s = (window.Osint && Osint.S && Osint.S.sonuc) ? Osint.S.sonuc : null;
    if (!s) { balon('⚠ Önce OSINT Gösterge panelinden tarama yap', 'kotu'); return; }
    var hedef = s.hedef || (($('farkGirdi') || {}).value || '').trim();
    if (!hedef) { balon('⚠ Hedef bilinmiyor', 'kotu'); return; }
    var liste = farkOku(hedef);
    liste.push(anlikGoruntu(hedef, s));
    farkYaz(hedef, liste);
    if ($('farkGirdi')) $('farkGirdi').value = hedef;
    balon('💾 <b>' + kac(hedef) + '</b> görüntüsü kaydedildi (' + liste.length + '. kayıt)', 'iyi');
    farkGecmisCiz(hedef);
    durum('farkDurum', 'kaydedildi');
  }"""

YENI = """  function farkKaydet() {
    var s = (window.Osint && Osint.S && Osint.S.sonuc) ? Osint.S.sonuc : null;
    if (!s) { balon('⚠ Önce OSINT Gösterge panelinden tarama yap', 'kotu'); return; }
    var hedef = s.hedef || (($('farkGirdi') || {}).value || '').trim();
    if (!hedef) { balon('⚠ Hedef bilinmiyor', 'kotu'); return; }
    durum('farkDurum', 'pasif veri alınıyor…');
    iskelet('farkSonuc', 'anlık görüntü hazırlanıyor (port + CVE + alt alan)…');
    // profil portları taşımaz: port ve CVE'yi pasif radardan al, sonra kaydet
    api('/api/arac/pasif?ad=' + encodeURIComponent(hedef)).then(function (p) {
      var g = anlikGoruntu(hedef, s);
      if (p && !p.hata) g = pasifVerisiyle(g, p);
      var liste = farkOku(hedef);
      liste.push(g);
      farkYaz(hedef, liste);
      if ($('farkGirdi')) $('farkGirdi').value = hedef;
      yaz('farkSonuc', '<div class="osIskelet">Kaydedildi: <b>' + sayi((g.portlar || []).length) + '</b> port · ' +
        sayi((g.cve || []).length) + ' CVE · ' + sayi((g.alt_alanlar || []).length) + ' alt alan · risk ' +
        sayi(g.risk) + '/100</div>');
      balon('💾 <b>' + kac(hedef) + '</b> görüntüsü kaydedildi (' + liste.length + '. kayıt)', 'iyi');
      farkGecmisCiz(hedef);
      durum('farkDurum', 'kaydedildi');
    }).catch(function (e) {
      // pasif veri alınamazsa yine de kaydet (eksik veriyle)
      var g = anlikGoruntu(hedef, s);
      var liste = farkOku(hedef);
      liste.push(g);
      farkYaz(hedef, liste);
      farkGecmisCiz(hedef);
      durum('farkDurum', 'pasif veri alınamadı, temel kayıt yapıldı');
      balon('⚠ Pasif veri alınamadı: ' + kac(e.message), 'kotu');
    });
  }

  function pasifVerisiyle(goruntu, p) {
    var portlar = (goruntu.portlar || []).slice();
    (p.portlar || []).forEach(function (x) {
      var n = Number(x);
      if (n && portlar.indexOf(n) < 0) portlar.push(n);
    });
    goruntu.portlar = portlar.sort(function (a, b) { return a - b; });
    goruntu.cve = (p.cveler || []).map(function (c) { return c.id || c; });
    goruntu.kritik = p.kritik || 0;
    goruntu.ip = p.ip || [];
    return goruntu;
  }"""

if ESKI not in s:
    print("HATA: farkKaydet gövdesi bulunamadı")
    raise SystemExit(1)
s = s.replace(ESKI, YENI, 1)
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("farkKaydet pasif veriyle güçlendirildi:", "pasifVerisiyle" in s)
