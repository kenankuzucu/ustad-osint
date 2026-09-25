/* ==========================================================================
   ÜSTAD OSINT — RAPOR & KANIT
   Kanıt zinciri (sha256) · TXT/JSON dışa aktarma · yazdırılabilir rapor
   ========================================================================== */
var Rapor = (function () {
  'use strict';

  var son = null;

  function kur() {
    OS.$('raporTxt').onclick = function () {
      if (!OS.S.taramaId) { OS.balon('⚠ Önce tarama yap.', 'kotu'); return; }
      window.open('/api/rapor/' + OS.S.taramaId + '?tip=txt', '_blank');
      OS.balon('⤓ TXT raporu indiriliyor…');
    };
    OS.$('raporJson').onclick = function () {
      if (!OS.S.tarama) { OS.balon('⚠ Önce tarama yap.', 'kotu'); return; }
      Alarm.indir('ustad-osint-ham-' + OS.S.taramaId + '.json', JSON.stringify(OS.S.tarama, null, 2), 'application/json');
      OS.balon('⤓ JSON ham veri indirildi.', 'iyi');
    };
    OS.$('raporYazdir').onclick = function () {
      var p = OS.$('raporOnizleme').textContent;
      if (!p || p.indexOf('tarama sonrası') === 0) { OS.balon('⚠ Yazdırılacak rapor yok.', 'kotu'); return; }
      var w = window.open('', '_blank');
      w.document.write('<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8">' +
        '<title>ÜSTAD OSINT Rapor</title><style>body{font-family:Consolas,monospace;font-size:12px;' +
        'white-space:pre-wrap;padding:20px;line-height:1.5}h1{font-size:16px}</style></head><body>' +
        ('ÜSTAD OSINT — SALDIRI YÜZEYİ RAPORU\n\n' + p).replace(/[<>&]/g, function (c) { return { '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]; }) +
        '</body></html>');
      w.document.close();
      setTimeout(function () { w.print(); }, 400);
    };
  }

  function veri(tarama) {
    son = tarama;
    bilgi(tarama);
    if (tarama && tarama.id) onizleme(tarama.id);
  }

  function bilgi(t) {
    var kap = OS.$('raporBilgi');
    if (!kap) return;
    if (!t) { kap.innerHTML = '<div class="bos">Tarama yapılmadı.</div>'; return; }
    var imza = t.id + '|' + (t.baslangic || '') + '|' + (t.bitis || '') + '|' +
      ((t.sayilar && t.sayilar.cihaz) || 0) + '|' + ((t.sayilar && t.sayilar.acikPort) || 0) + '|' + (t.risk || 0);
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(imza)).then(function (h) {
      var sha = Array.prototype.map.call(new Uint8Array(h), function (b) {
        return ('0' + b.toString(16)).slice(-2);
      }).join('');
      kap.innerHTML = '';
      var satirlar = [
        ['TARAMA NO', t.id], ['MOTOR', t.motor], ['PORT MODU', t.portMod],
        ['BAŞLANGIÇ', t.baslangic], ['BİTİŞ', t.bitis || '-'],
        ['HEDEFLER', (t.hedefler || []).join(', ')],
        ['ÖZET', 'cihaz ' + ((t.sayilar || {}).cihaz || 0) + ' · port ' + ((t.sayilar || {}).acikPort || 0) +
          ' · alarm ' + ((t.sayilar || {}).alarm || 0) + ' · kritik ' + ((t.sayilar || {}).kritik || 0) +
          ' · IOC ' + ((t.sayilar || {}).ioc || 0)],
        ['YÜZEY RİSKİ', (t.risk || 0) + '/100'],
        ['KANIT ZİNCİRİ (sha256)', sha]
      ];
      satirlar.forEach(function (x) {
        var d = document.createElement('div');
        d.className = 'satir';
        d.innerHTML = '<span class="etiket">' + OS.kac(x[0]) + '</span><span class="anahtar">' + OS.kac(x[1]) + '</span>';
        kap.appendChild(d);
      });
    });
  }

  function onizleme(id) {
    OS.api('/api/rapor/' + id).then(function (d) {
      if (d.hata) return;
      OS.$('raporOnizleme').textContent = (d.metin || '').slice(0, 6000);
    }).catch(function () {});
  }

  return { kur: kur, veri: veri };
})();
