/* ==========================================================================
   ÜSTAD OSINT — AYARLAR & KAPSAM ONAYI
   Yasal beyan · izinli hedef listesi · sistem durumu · tercihler
   ========================================================================== */
var Ayar = (function () {
  'use strict';

  function kur() {
    OS.$('kapsamKaydet').onclick = kaydet;
    OS.$('kapsamOnay').onchange = function () {
      OS.$('kapsamDurum').textContent = this.checked ? 'onay işaretlendi — kaydet' : 'onay bekleniyor';
    };
    OS.$('ayarYenile').onclick = function () {
      OS.durumYenile().then(function () { OS.balon('⟳ Sistem durumu yenilendi.', 'iyi'); });
    };
    OS.$('ayarTema').onclick = function () {
      var liste = ['gece', 'gunduz', 'orman', 'deniz', 'mor', 'altin', 'kizil', 'buz', 'kum', 'kalem'];
      var i = liste.indexOf(OS.S.tema);
      OS.tema(liste[(i + 1) % liste.length]);
    };
    onayGeriYukle();
  }

  function onayGeriYukle() {
    try {
      var k = JSON.parse(localStorage.getItem('osint_kapsam') || 'null');
      if (k && k.onay) {
        OS.$('kapsamOnay').checked = true;
        OS.$('kapsamMetin').value = (k.kapsam || []).join(', ');
        OS.$('kapsamDurum').textContent = '✔ onaylı · ' + (k.zaman || '');
        sunucuyaBildir(k);          /* arka uç kapısı da açılsın (sayfa yenilense bile) */
      }
    } catch (e) {}
  }

  function sunucuyaBildir(k) {
    return OS.api('/api/onay', {
      yol: 'POST',
      govde: { onay: true, metin: (k.kapsam || []).join(', '), kapsam: k.kapsam || [] }
    }).catch(function () {});
  }

  function kaydet() {
    var onay = OS.$('kapsamOnay').checked;
    var metin = OS.$('kapsamMetin').value.trim();
    var kapsam = metin ? metin.split(/[,\s]+/).filter(function (x) { return x; }) : [];
    if (!onay) {
      OS.balon('⛔ Onay kutusu işaretlenmedi — tarama başlatılamaz.', 'kotu');
      OS.$('kapsamDurum').textContent = 'onay bekleniyor';
      try { localStorage.removeItem('osint_kapsam'); } catch (e) {}
      return;
    }
    var k = { onay: true, kapsam: kapsam, zaman: new Date().toISOString().slice(0, 19).replace('T', ' ') };
    try { localStorage.setItem('osint_kapsam', JSON.stringify(k)); } catch (e) {}
    OS.api('/api/onay', { yol: 'POST', govde: { onay: true, metin: metin, kapsam: kapsam } }).catch(function () {});
    OS.$('kapsamDurum').textContent = '✔ onaylı · ' + k.zaman;
    OS.balon('✅ Kapsam kaydedildi. İzinli hedefler: <b>' + OS.kac(kapsam.join(', ') || '(boş)') + '</b>', 'iyi');
  }

  return { kur: kur, onayGeriYukle: onayGeriYukle, kaydet: kaydet, sunucuyaBildir: sunucuyaBildir };
})();
