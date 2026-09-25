/* ==========================================================================
   ÜSTAD OSINT — TARAMA MERKEZİ: gerçek TCP taraması, canlı ilerleme, cihaz listesi
   ========================================================================== */
var Tarama = (function () {
  'use strict';

  var zaman = null, id = null;

  function kur() {
    OS.$('taraBasla').onclick = basla;
    OS.$('taraDurdur').onclick = durdur;
    OS.$('hedefKendi').onclick = kendiAg;
  }

  function kendiAg() {
    var d = OS.S.durum;
    if (!d) { OS.balon('⚠ Sistem durumu okunamadı, ayarlardan yenile.', 'kotu'); return; }
    var hedef = d.altAg || (d.yerelIp + '/32');
    OS.$('hedef').value = hedef;
    OS.$('kapsamMetin').value = hedef;
    OS.balon('⤓ Kendi ağın yazıldı: <b>' + OS.kac(hedef) + '</b><br><span class="soluk">Kapsam onayı verilmeden tarama başlamaz.</span>');
  }

  function log(metin) {
    var k = OS.$('taramaLog');
    k.textContent += '\n[' + OS.saat() + '] ' + metin;
    k.scrollTop = k.scrollHeight;
  }

  function yuzde(p, yazi) {
    OS.$('ilerlemeCubuk').style.width = Math.max(0, Math.min(100, p || 0)) + '%';
    OS.$('ilerlemeYazi').textContent = yazi || (p + '%');
  }

  function basla() {
    if (!OS.S.durum) { OS.balon('⚠ Önce sistem durumunu okuyun.', 'kotu'); return; }
    var onay = null;
    try { onay = JSON.parse(localStorage.getItem('osint_kapsam') || 'null'); } catch (e) {}
    if (!onay || !onay.onay) {
      OS.balon('⛔ Kapsam onayı yok. <b>Ayarlar &amp; Kapsam</b> panelinden beyan verilmeden tarama başlatılamaz.', 'kotu');
      OS.panelAc('ayar');
      return;
    }
    var hedefler = OS.$('hedef').value.trim();
    if (!hedefler) { OS.balon('⚠ Hedef gir (ör. 192.168.1.0/24 veya 127.0.0.1).', 'kotu'); return; }
    OS.$('taramaLog').textContent = 'tarama başlatılıyor…';
    yuzde(2, 'gönderildi');
    /* kapsamı arka uca da bildir (sunucu kapısı), sonra taramayı başlat */
    var onayGonder = (window.Ayar && Ayar.sunucuyaBildir) ? Ayar.sunucuyaBildir(onay) : Promise.resolve();
    onayGonder.then(function () {
    return OS.api('/api/tarama', {
      yol: 'POST',
      govde: {
        hedefler: hedefler,
        mod: OS.$('portMod').value,
        ekPortlar: OS.$('ekPort').value,
        nmap: OS.$('nmapKullan').checked
      }
    }).then(function (d) {
      if (d.hata) { OS.balon('⛔ ' + OS.kac(d.hata), 'kotu'); log('HATA: ' + d.hata); yuzde(0, 'hata'); return; }
      id = d.id;
      log('tarama no: ' + id + ' · port sayısı: ' + d.portSayisi + ' · motor: ' + d.motor);
      OS.balon('📡 Tarama başladı · ' + OS.kac(d.portSayisi) + ' port · motor: <b>' + OS.kac(d.motor) + '</b>');
      takip();
    }).catch(function (e) {
      OS.balon('⛔ Tarama başlatılamadı: ' + OS.kac(e.message), 'kotu');
      yuzde(0, 'hata');
    });
    });
  }

  function takip() {
    if (zaman) clearInterval(zaman);
    zaman = setInterval(function () {
      if (!id) return;
      OS.api('/api/tarama/' + id).then(function (t) {
        if (t.hata) { clearInterval(zaman); return; }
        yuzde(t.yuzde, t.asama + ' · %' + t.yuzde);
        if (t.loglar && t.loglar.length) {
          var k = OS.$('taramaLog');
          k.textContent = t.loglar.map(function (x) { return '[' + x.zaman + '] ' + x.metin; }).join('\n');
          k.scrollTop = k.scrollHeight;
        }
        if (t.hostlar) cihazlariCiz(t.hostlar);
        if (t.durum === 'bitti' || t.durum === 'iptal' || t.durum === 'hata') {
          clearInterval(zaman); zaman = null;
          OS.S.tarama = t; OS.S.taramaId = t.id;
          yuzde(t.yuzde, t.durum === 'bitti' ? 'tamamlandı' : t.durum);
          OS.gostergeCiz(t); OS.menüSayac(t);
          if (window.Yuzey) Yuzey.veri(t);
          if (window.Dunya) Dunya.veri(t);
          if (window.Alarm) Alarm.veri(t);
          if (window.Rapor) Rapor.veri(t);
          if (window.Olay) Olay.veri(t);
          var s = t.sayilar || {};
          OS.balon('✅ Tarama tamamlandı · cihaz ' + OS.sayi(s.cihaz) + ' · açık port ' + OS.sayi(s.acikPort) +
            ' · alarm ' + OS.sayi(s.alarm), 'iyi');
          if (s.kritik) OS.balon('🚨 <b>' + s.kritik + ' kritik alarm</b> var — Alarm &amp; Triyaj panelini aç.', 'kotu');
        }
      }).catch(function () {});
    }, 1200);
  }

  function durdur() {
    if (!id) { OS.balon('⚠ Çalışan tarama yok.'); return; }
    OS.api('/api/tarama/' + id + '/dur', { yol: 'POST', govde: {} }).then(function () {
      OS.balon('■ Durdurma isteği gönderildi.');
    });
  }

  function cihazlariCiz(hostlar) {
    var kap = OS.$('cihazListesi');
    OS.$('cihazToplam').textContent = (hostlar || []).length + ' cihaz';
    if (!hostlar || !hostlar.length) { kap.innerHTML = '<div class="bos">Henüz açık port bulunamadı.</div>'; return; }
    kap.innerHTML = '';
    hostlar.forEach(function (h) {
      var d = document.createElement('div');
      d.className = 'cihaz';
      var ports = (h.portlar || []).map(function (p) {
        return '<span class="portCip ' + OS.kac(p.onem || 'bilgi') + '" title="' + OS.kac((p.surum || p.banner || '').slice(0, 120)) + '">' +
          p.port + ' · ' + OS.kac(p.servis || '?') + '</span>';
      }).join('');
      d.innerHTML =
        '<div class="bas"><b>' + OS.kac(h.ip) + (h.ad ? ' · ' + OS.kac(h.ad) : '') + '</b>' +
        '<span class="soluk">' + (h.portlar || []).length + ' açık port</span></div>' +
        (h.isletim ? '<div class="soluk">' + OS.kac(h.isletim) + '</div>' : '') +
        '<div class="portlar">' + ports + '</div>';
      kap.appendChild(d);
    });
  }

  return { kur: kur, basla: basla, durdur: durdur, takip: takip, yuzde: yuzde, cihazlariCiz: cihazlariCiz };
})();
