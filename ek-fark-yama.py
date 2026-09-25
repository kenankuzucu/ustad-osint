# -*- coding: utf-8 -*-
"""ek.js içine DEĞİŞİM (FARK) modülünü ekler."""
import io
import os

KOK = os.path.dirname(os.path.abspath(__file__))
p = os.path.join(KOK, "web", "ek.js")
s = io.open(p, encoding="utf-8").read()
if "farkHesapla" in s:
    print("zaten var")
    raise SystemExit(0)

FONK = r'''
  /* ============================== 9) DEĞİŞİM (FARK) ============================== */
  function farkAnahtar(hedef) { return 'ustad_fark_' + String(hedef || '').toLowerCase(); }

  function farkOku(hedef) {
    try { return JSON.parse(localStorage.getItem(farkAnahtar(hedef)) || '[]') || []; }
    catch (e) { return []; }
  }
  function farkYaz(hedef, liste) {
    try { localStorage.setItem(farkAnahtar(hedef), JSON.stringify(liste.slice(-30))); } catch (e) {}
  }

  function anlikGoruntu(hedef, veri) {
    veri = veri || {};
    var portlar = [], altlar = [];
    var w = ((veri.sonuclar || {}).webtek) || {};
    (w.portlar || []).forEach(function (p) {
      var n = (p && typeof p === 'object') ? p.port : p;
      if (n) portlar.push(Number(n));
    });
    var s = (veri.sonuclar || {}).subdomain || {};
    (s.alt_alanlar || s.kayitlar || []).forEach(function (x) {
      var ad = (x && typeof x === 'object') ? x.ad : x;
      if (ad) altlar.push(String(ad));
    });
    var tekil = function (v, i, a) { return a.indexOf(v) === i; };
    return {
      zaman: veri.zaman || (new Date()).toLocaleString('tr-TR'),
      hedef: veri.hedef || hedef,
      risk: veri.risk == null ? 0 : veri.risk,
      portlar: portlar.filter(tekil).sort(function (a, b) { return a - b; }),
      alt_alanlar: altlar.filter(tekil),
      bulgular: (veri.bulgular || []).map(function (b) {
        return (b.tur || '') + ': ' + String(b.aciklama || b.baslik || '').slice(0, 140);
      }),
      cve: (((veri.sonuclar || {}).pasif || {}).cve || []).map(function (c) { return c.id || c; })
    };
  }

  function farkKaydet() {
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
  }

  function farkHesapla(eski, yeni) {
    var fark = function (a, b) {
      var A = {}, B = {};
      (a || []).forEach(function (x) { A[String(x)] = 1; });
      (b || []).forEach(function (x) { B[String(x)] = 1; });
      return {
        yeni: (b || []).filter(function (x) { return !A[String(x)]; }),
        giden: (a || []).filter(function (x) { return !B[String(x)]; })
      };
    };
    var p = fark(eski.portlar, yeni.portlar);
    var a = fark(eski.alt_alanlar, yeni.alt_alanlar);
    var b = fark(eski.bulgular, yeni.bulgular);
    var c = fark(eski.cve, yeni.cve);
    return { yeni_portlar: p.yeni, kapanan_portlar: p.giden, yeni_alt_alanlar: a.yeni,
             kaybolan_alt_alanlar: a.giden, yeni_bulgular: b.yeni, duzelen_bulgular: b.giden,
             yeni_cve: c.yeni, kapanan_cve: c.giden, risk_eski: eski.risk, risk_yeni: yeni.risk,
             risk_degisim: (yeni.risk || 0) - (eski.risk || 0), onceki_zaman: eski.zaman, simdi: yeni.zaman };
  }

  function farkGoster() {
    var h = (($('farkGirdi') || {}).value || '').trim();
    var liste = farkOku(h);
    var s = (window.Osint && Osint.S && Osint.S.sonuc) ? Osint.S.sonuc : null;
    var yeni = null, eski = null;
    if (s && (!h || String(s.hedef || '').toLowerCase().indexOf(h.toLowerCase()) >= 0)) {
      yeni = anlikGoruntu(s.hedef || h, s);
      eski = liste.length ? liste[liste.length - 1] : null;
    } else {
      if (liste.length < 2) {
        yaz('farkSonuc', '<div class="osIskelet">Karşılaştırma için en az 2 kayıt gerekiyor. "TARAMAYI KAYDET" ile birkaç kez kaydet.</div>');
        farkGecmisCiz(h);
        return;
      }
      yeni = liste[liste.length - 1]; eski = liste[liste.length - 2];
    }
    if (!eski) {
      yaz('farkSonuc', '<div class="osIskelet">Önceki kayıt yok: bu ilk anlık görüntü. Sonraki taramada fark çıkacak.<br>Şimdiki durum: <b>' +
        sayi((yeni.portlar || []).length) + '</b> port · risk <b>' + sayi(yeni.risk) + '/100</b></div>');
      farkGecmisCiz(h || yeni.hedef);
      durum('farkDurum', 'ilk kayıt');
      return;
    }
    var f = farkHesapla(eski, yeni);
    cizFark(f, yeni);
    farkGecmisCiz(h || yeni.hedef);
    durum('farkDurum', 'tamamlandı');
  }

  function cizFark(f, yeni) {
    var degisti = f.yeni_portlar.length + f.kapanan_portlar.length + f.yeni_alt_alanlar.length +
      f.kaybolan_alt_alanlar.length + f.yeni_bulgular.length + f.yeni_cve.length;
    var h = '<div class="ekAnahtar"><b>Önceki kayıt</b><span>' + kac(f.onceki_zaman) + '</span></div>';
    h += '<div class="ekAnahtar"><b>Şimdiki kayıt</b><span>' + kac(f.simdi) + '</span></div>';
    var renk = f.risk_degisim > 0 ? 'yuksek' : (f.risk_degisim < 0 ? 'iyi' : 'orta');
    h += '<div class="ekAnahtar"><b>Risk değişimi</b><span class="ekRisk ' + renk + '">' + sayi(f.risk_eski) + ' → ' +
      sayi(f.risk_yeni) + ' (' + (f.risk_degisim > 0 ? '+' : '') + sayi(f.risk_degisim) + ')</span></div>';
    h += '<div class="ekAnahtar"><b>Toplam değişim</b><span>' + (degisti ? sayi(degisti) + ' kalem' : 'Değişim yok') + '</span></div>';
    [['Yeni açılan port', f.yeni_portlar, 'kritik'], ['Kapanan port', f.kapanan_portlar, 'iyi'],
     ['Yeni alt alan', f.yeni_alt_alanlar, 'kritik'], ['Kaybolan alt alan', f.kaybolan_alt_alanlar, 'iyi'],
     ['Yeni CVE', f.yeni_cve, 'kritik'], ['Kapanan CVE', f.kapanan_cve, 'iyi'],
     ['Yeni bulgu', f.yeni_bulgular, 'orta'], ['Düzelen bulgu', f.duzelen_bulgular, 'iyi']].forEach(function (x) {
      if (!x[1].length) return;
      h += '<div style="margin-top:8px"><b class="ekRisk ' + x[2] + '">' + kac(x[0]) + ' (' + x[1].length + ')</b>' +
        '<ul class="ekSirali">' + x[1].slice(0, 25).map(function (y) { return '<li><code>' + kac(y) + '</code></li>'; }).join('') + '</ul></div>';
    });
    if (!degisti) h += '<div class="osIskelet" style="margin-top:8px">Önceki taramaya göre değişiklik yok. Sakin gün.</div>';
    h += '<div class="osIskelet" style="margin-top:8px">Şimdiki durum: ' + sayi((yeni.portlar || []).length) + ' port · ' +
      sayi((yeni.alt_alanlar || []).length) + ' alt alan · ' + sayi((yeni.cve || []).length) + ' CVE kaydı</div>';
    yaz('farkSonuc', h);
    durum('farkOzet', degisti ? sayi(degisti) + ' değişiklik' : 'değişim yok');
    sonOzet = 'Değişim radarı: ' + (yeni.hedef || '') + ' · ' + (degisti ? sayi(degisti) + ' değişiklik' : 'değişim yok');
    balon(degisti ? '⚖️ <b>' + sayi(degisti) + '</b> değişiklik bulundu' : '⚖️ Değişiklik yok', degisti ? 'uyari' : 'iyi');
  }

  function farkGecmisCiz(hedef) {
    var liste = farkOku(hedef);
    if (!liste.length) {
      yaz('farkGecmis', '<div class="osIskelet">Bu hedef için kayıt yok. Tarama yapıp "TARAMAYI KAYDET"e bas.</div>');
      durum('farkGecmisOzet', '0 kayıt');
      return;
    }
    var h = '<table class="ekTablo"><thead><tr><th>#</th><th>Zaman</th><th>Risk</th><th>Port</th><th>Alt alan</th><th>Bulgu</th></tr></thead><tbody>';
    liste.slice().reverse().forEach(function (x, i) {
      h += '<tr><td>' + (liste.length - i) + '</td><td>' + kac(x.zaman) + '</td><td>' + sayi(x.risk) + '/100</td>' +
        '<td>' + sayi((x.portlar || []).length) + '</td><td>' + sayi((x.alt_alanlar || []).length) + '</td>' +
        '<td>' + sayi((x.bulgular || []).length) + '</td></tr>';
    });
    h += '</tbody></table>';
    yaz('farkGecmis', h);
    durum('farkGecmisOzet', sayi(liste.length) + ' kayıt');
  }

  function farkTemizle() {
    var h = (($('farkGirdi') || {}).value || '').trim();
    if (!h) { balon('⚠ Hedef yaz (ör. ornek.com)', 'kotu'); return; }
    if (!window.confirm('"' + h + '" için kayıtlı değişim geçmişi silinsin mi?')) return;
    try { localStorage.removeItem(farkAnahtar(h)); } catch (e) {}
    yaz('farkSonuc', '<div class="osIskelet">Geçmiş silindi.</div>');
    farkGecmisCiz(h);
    balon('🗑️ <b>' + kac(h) + '</b> geçmişi silindi', 'iyi');
  }

'''

s = s.replace("  /* ============================== KURULUM ============================== */",
              FONK + "  /* ============================== KURULUM ============================== */", 1)

s = s.replace("    bagla('kanitDug', kanitMuhurle);",
              """    bagla('farkKaydet', farkKaydet);
    bagla('farkGoster', farkGoster);
    bagla('farkTemizle', farkTemizle);
    var fk = $('farkGirdi');
    if (fk) {
      fk.onchange = function () { farkGecmisCiz(fk.value.trim()); };
      fk.onkeydown = function (e) { if (e.key === 'Enter') farkGoster(); };
    }

    bagla('kanitDug', kanitMuhurle);""", 1)

s = s.replace("        if (id === 'kanit') setTimeout(kanitListele, 60);",
              """        if (id === 'kanit') setTimeout(kanitListele, 60);
        if (id === 'fark') setTimeout(function () {
          var sv = (window.Osint && Osint.S && Osint.S.sonuc) ? Osint.S.sonuc : null;
          var girdi = $('farkGirdi');
          var h = (girdi && girdi.value ? girdi.value : '').trim() || (sv ? sv.hedef : '');
          if (girdi && !girdi.value && h) girdi.value = h;
          farkGecmisCiz(h);
        }, 90);""", 1)

s = s.replace("           kanitListele: kanitListele, sesliOzet: sesliOzet };",
              """           kanitListele: kanitListele, sesliOzet: sesliOzet, farkKaydet: farkKaydet,
           farkGoster: farkGoster, farkGecmisCiz: farkGecmisCiz, farkTemizle: farkTemizle };""", 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("ek.js fark:", "farkHesapla" in s, "| düğme bağlama:", "bagla('farkKaydet'" in s,
      "| panel:", "id === 'fark'" in s, "| dışa aktarım:", "farkGoster: farkGoster" in s)
