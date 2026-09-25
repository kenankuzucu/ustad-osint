/* ==========================================================================
   ÜSTAD OSINT — DÜNYA HARİTASI (IP konum)
   Çevrimdışı kara katmanı (equirectangular) + konum işaretçileri + ülke etiketleri
   ========================================================================== */
var Dunya = (function () {
  'use strict';

  var t, g, G = 0, Y = 0, dpr = 1, kara = null, karaHazir = false;
  var noktalar = [], kendi = null, cizgiGoster = false, isimGoster = true, secili = null;

  function kur() {
    t = OS.$('dunyaTuval');
    g = t.getContext('2d');
    kara = new Image();
    kara.onload = function () { karaHazir = true; ciz(); };
    kara.src = 'dunya-kara.png';
    OS.$('dunyaYenile').onclick = yenile;
    OS.$('dunyaCizgi').onchange = function () { cizgiGoster = this.checked; ciz(); };
    OS.$('dunyaIsim').onchange = function () { isimGoster = this.checked; ciz(); };
    t.addEventListener('click', tikla);
    boyutla();
    window.addEventListener('resize', boyutla);
    /* sürekli animasyon: yalnız panel görünürken çizer */
    HaritaGercek.canli('dunyaTuval', 'p-dunya', function (zaman) { ciz(zaman); }, 33);
    return { ciz: ciz, boyutla: boyutla, veri: veri };
  }

  function boyutla() {
    if (!t) return;
    dpr = window.devicePixelRatio || 1;
    G = t.clientWidth || (t.parentNode && t.parentNode.clientWidth) || 900;
    Y = t.clientHeight || parseInt(t.getAttribute('height'), 10) || 440;
    t.width = Math.floor(G * dpr); t.height = Math.floor(Y * dpr);
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    ciz();
  }

  function veri(tarama) {
    noktalar = [];
    secili = null;
    var geo = (tarama && tarama.geo) || [];
    geo.forEach(function (k) {
      if (k.tur === 'ozel' || k.enlem === null || k.enlem === undefined) {
        noktalar.push({ ip: k.ip, yerel: true, ulke: k.ulke || 'Yerel ağ' });
      } else {
        noktalar.push({
          ip: k.ip, yerel: false, ulke: k.ulke || '?', sehir: k.sehir || '', iss: k.iss || '',
          enlem: Number(k.enlem), boylam: Number(k.boylam), kaynak: k.kaynak || ''
        });
      }
    });
    if (OS.S.durum && OS.S.durum.disIp && OS.S.durum.disIp.enlem !== null && OS.S.durum.disIp.enlem !== undefined) {
      kendi = { ip: OS.S.durum.disIp.ip, enlem: Number(OS.S.durum.disIp.enlem), boylam: Number(OS.S.durum.disIp.boylam),
                ulke: OS.S.durum.disIp.ulke, sehir: OS.S.durum.disIp.sehir, iss: OS.S.durum.disIp.iss };
      var varMi = noktalar.some(function (n) { return n.ip === kendi.ip && !n.yerel; });
      if (!varMi) noktalar.push({ ip: kendi.ip, yerel: false, ulke: kendi.ulke, sehir: kendi.sehir,
                                  iss: kendi.iss, enlem: kendi.enlem, boylam: kendi.boylam, kendi: true });
    }
    var genel = noktalar.filter(function (n) { return !n.yerel; }).length;
    OS.$('dunyaSayac').textContent = genel + ' konum · ' + noktalar.filter(function (n) { return n.yerel; }).length + ' yerel adres';
    liste();
    ciz();
  }

  function yenile() {
    var isler = noktalar.map(function (n) {
      return OS.api('/api/geo/' + encodeURIComponent(n.ip)).then(function (d) {
        if (d && d.enlem !== null && d.enlem !== undefined) {
          n.enlem = Number(d.enlem); n.boylam = Number(d.boylam); n.ulke = d.ulke; n.sehir = d.sehir; n.iss = d.iss;
          n.kaynak = d.kaynak;
        }
      }).catch(function () {});
    });
    OS.balon('⟳ Konumlar yenileniyor (' + isler.length + ' adres)…');
    Promise.all(isler).then(function () { liste(); ciz(); OS.balon('✅ Konum çözümü tamamlandı.', 'iyi'); });
  }

  function proj(lon, lat) {
    return [(lon + 180) / 360 * G, (90 - lat) / 180 * Y];
  }

  function ciz(zaman) {
    if (!g) return;
    zaman = zaman || ((window.performance && performance.now) ? performance.now() : Date.now());
    var st = getComputedStyle(document.documentElement);
    g.clearRect(0, 0, G, Y);
    /* ulta gerçekçi arka plan: okyanus derinliği + iklimli kara + kıyı parlaması + atmosfer */
    HaritaGercek.arkaplan(g, G, Y, karaHazir ? kara : null);
    /* hareketli sinyaller: kendi çıkışından (yoksa ağırlık merkezinden) her konuma akan paketler */
    if (cizgiGoster) {
      var gecerli = noktalar.filter(function (n) { return !n.yerel && typeof n.enlem === 'number'; });
      var cift = HaritaGercek.ciftler(gecerli, kendi, ['#5cffc0', '#37e0ff', '#ffcf4d', '#ff5470']);
      HaritaGercek.sinyaller(g, G, Y, cift, zaman);
      if (kendi && typeof kendi.enlem === 'number') {
        HaritaGercek.isaretci(g, HaritaGercek.proj(kendi.boylam, kendi.enlem, G, Y)[0],
          HaritaGercek.proj(kendi.boylam, kendi.enlem, G, Y)[1], '#2ee6a8', zaman, false, 'BURASI · ' + (kendi.ulke || 'çıkış'));
      }
    }
    /* işaretçiler */
    noktalar.forEach(function (n) {
      if (n.yerel) return;
      var p = proj(n.boylam, n.enlem);
      var renk = n.kendi ? '#2ee6a8' : '#ff5470';
      var yazi = isimGoster ? ((n.sehir ? n.sehir + ', ' : '') + (n.ulke || '')).slice(0, 24) : '';
      HaritaGercek.isaretci(g, p[0], p[1], renk, zaman, secili === n.ip, yazi, n.kendi ? 6 : 4.6);
    });
    if (!noktalar.filter(function (n) { return !n.yerel; }).length) {
      g.fillStyle = st.getPropertyValue('--soluk').trim();
      g.font = '13px Consolas, monospace'; g.textAlign = 'center';
      g.fillText('Konum çözümlenecek genel IP yok — hedefler yerel ağda olabilir.', G / 2, Y - 18);
    }
  }

  function liste() {
    var kap = OS.$('dunyaListe');
    if (!kap) return;
    kap.innerHTML = '';
    if (!noktalar.length) { kap.innerHTML = '<div class="bos">Konum verisi yok — tarama sonrası dolar.</div>'; return; }
    noktalar.forEach(function (n) {
      var d = document.createElement('div');
      d.className = 'konumKart';
      d.style.borderLeftColor = n.yerel ? '#6f8ba3' : (n.kendi ? '#2ee6a8' : '#ff5470');
      d.innerHTML = '<b>' + OS.kac(n.ip) + (n.kendi ? ' · bu cihazın çıkışı' : '') + '</b>' +
        '<span>' + (n.yerel ? 'özel / yerel adres — haritada gösterilmez'
          : OS.kac((n.sehir || '-') + ' · ' + (n.ulke || '-')) + (n.iss ? ' · ' + OS.kac(n.iss) : '')) + '</span>' +
        (n.yerel ? '' : '<span class="soluk">' + n.enlem.toFixed(3) + ', ' + n.boylam.toFixed(3) + ' · ' + OS.kac(n.kaynak || '') + '</span>');
      d.onclick = function () { secili = n.ip; ciz(); };
      kap.appendChild(d);
    });
  }

  function tikla(e) {
    var r = t.getBoundingClientRect();
    var px = e.clientX - r.left, py = e.clientY - r.top;
    var bulunan = null;
    noktalar.forEach(function (n) {
      if (n.yerel) return;
      var p = proj(n.boylam, n.enlem);
      if (Math.sqrt(Math.pow(p[0] - px, 2) + Math.pow(p[1] - py, 2)) < 14) bulunan = n;
    });
    if (!bulunan) return;
    secili = bulunan.ip;
    OS.balon('📍 <b>' + OS.kac(bulunan.ip) + '</b> · ' + OS.kac((bulunan.sehir || '') + ' ' + (bulunan.ulke || '')) +
      (bulunan.iss ? '<br><span class="soluk">' + OS.kac(bulunan.iss) + '</span>' : ''));
    ciz();
  }

  return { kur: kur, ciz: ciz, boyutla: boyutla, veri: veri, yenile: yenile };
})();
