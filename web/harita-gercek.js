/* ==========================================================================
   ÜSTAD OSINT v1.5 — ULTRA GERÇEKÇİ HARİTA + HAREKETLİ SİNYALLER
   Ortak çizim motoru (Dünya haritası, tehdit haritası, OSINT haritası).
   Çevrimdışı çalışır: kara katmanı dunya-kara.png (1440x720 equirectangular).

   Neler var:
     · Okyanus: derinlik gradyanı + sonar ızgarası + vinyet (gerçekçi derinlik hissi)
     · Kara: enlem bazlı iklim renkleri (kutuplar buz, ekvator yeşil) + kabartma gölgesi
     · Kıyı: parlama (shadowBlur) ile ışıyan kıyı şeridi
     · Izgara: enlem/boylam + ekvator/boylam-0 vurgusu
     · Sinyal: iki nokta arasında kayan ışık paketleri (kuyruklu), yay izi, çarpan halkalar
     · Atmosfer: kenar ışıması + gece tarafı yumuşak gölgesi
   ========================================================================== */
var HaritaGercek = (function () {
  'use strict';

  var donguSayaci = {}, sonZaman = 0;

  /* arka plan ara tuvalleri: her karede yeniden ayırmamak için önbellek */
  var araOnbellek = {};
  function araTuval(G, Y) {
    var anahtar = G + 'x' + Y;
    if (araOnbellek[anahtar]) return araOnbellek[anahtar];
    function yap() { var c = document.createElement('canvas'); c.width = G; c.height = Y; return c; }
    var of = yap(), kal = yap(), kiyi = yap();
    var A = { of: of, oc: of.getContext('2d'), kal: kal, kc: kal.getContext('2d'),
              kiyi: kiyi, kcg: kiyi.getContext('2d') };
    araOnbellek[anahtar] = A;
    return A;
  }

  function proj(lon, lat, G, Y) {
    return [(lon + 180) / 360 * G, (90 - lat) / 180 * Y];
  }

  /* ---------------------------------------------------------- renk yardımı */
  function tema() {
    var st = getComputedStyle(document.documentElement);
    var al = function (a, d) { var v = (st.getPropertyValue(a) || '').trim(); return v || d; };
    return {
      arka2: al('--arka2', '#050b14'),
      cizgi: al('--cizgi', '#1b2b3a'),
      yazi: al('--yazi', '#d8e6f2'),
      yazi2: al('--yazi2', '#9ab'),
      soluk: al('--soluk', '#6f8ba3'),
      renk1: al('--renk1', '#2d7dff'),
      renk2: al('--renk2', '#37e0ff'),
      kara: al('--kart', '#0d1620')
    };
  }

  /* ------------------------------------------------- 1) GERÇEKÇİ ARKAPLAN */
  function arkaplan(g, G, Y, kara, sec) {
    sec = sec || {};
    var t = tema();
    g.save();
    g.clearRect(0, 0, G, Y);

    // --- okyanus: enlemle koyulaşan derinlik gradyanı
    var og = g.createLinearGradient(0, 0, 0, Y);
    og.addColorStop(0, '#03080f');
    og.addColorStop(0.28, '#061423');
    og.addColorStop(0.5, '#0a2038');
    og.addColorStop(0.72, '#061423');
    og.addColorStop(1, '#03080f');
    g.fillStyle = og;
    g.fillRect(0, 0, G, Y);

    // --- sonar ızgarası (okyanus dokusu)
    g.globalAlpha = 0.05;
    g.strokeStyle = '#4fd1ff';
    g.lineWidth = 1;
    var adim = Math.max(22, G / 60);
    g.beginPath();
    for (var x = 0; x < G; x += adim) { g.moveTo(x, 0); g.lineTo(x, Y); }
    for (var y = 0; y < Y; y += adim) { g.moveTo(0, y); g.lineTo(G, y); }
    g.stroke();
    g.globalAlpha = 1;

    // --- enlem/boylam ızgarası
    g.strokeStyle = t.cizgi;
    g.globalAlpha = 0.34;
    g.lineWidth = 1;
    for (var lon = -180; lon <= 180; lon += 30) {
      var px = proj(lon, 0, G, Y)[0];
      g.beginPath(); g.moveTo(px, 0); g.lineTo(px, Y); g.stroke();
    }
    for (var lat = -60; lat <= 60; lat += 30) {
      var py = proj(0, lat, G, Y)[1];
      g.beginPath(); g.moveTo(0, py); g.lineTo(G, py); g.stroke();
    }
    g.globalAlpha = 0.6;
    g.strokeStyle = t.renk2;
    g.beginPath(); g.moveTo(0, Y / 2); g.lineTo(G, Y / 2); g.stroke();     // ekvator
    g.beginPath(); g.moveTo(G / 2, 0); g.lineTo(G / 2, Y); g.stroke();      // boylam 0
    g.globalAlpha = 1;

    // --- kara katmanı: iklim renkleri (karanın kendi beyaz dolgusu ezilir)
    if (kara && kara.complete !== false && kara.naturalWidth) {
      var A = araTuval(G, Y);
      var of = A.of, oc = A.oc, kal = A.kal, kc = A.kc, kiyi = A.kiyi, kcg = A.kcg;
      oc.setTransform(1, 0, 0, 1, 0, 0);
      oc.globalCompositeOperation = 'source-over';
      oc.globalAlpha = 1;
      oc.clearRect(0, 0, G, Y);
      oc.drawImage(kara, 0, 0, G, Y);
      var iklim = oc.createLinearGradient(0, 0, 0, Y);
      iklim.addColorStop(0.00, '#cfe6f2');                 // kutup buz
      iklim.addColorStop(0.09, '#9fbcc4');
      iklim.addColorStop(0.20, '#5c7a4e');                 // tayga / kuzey orman
      iklim.addColorStop(0.33, '#7d8a4a');                 // bozkır
      iklim.addColorStop(0.42, '#b09355');                 // kuzey çöl (Sahara kuşağı)
      iklim.addColorStop(0.50, '#2f6b3a');                 // ekvator ormanı
      iklim.addColorStop(0.58, '#9c8347');                 // güney çöl
      iklim.addColorStop(0.70, '#6f7f46');
      iklim.addColorStop(0.84, '#4e6b52');
      iklim.addColorStop(1.00, '#cfe6f2');                 // güney buz
      oc.globalCompositeOperation = 'source-in';
      oc.fillStyle = iklim;
      oc.fillRect(0, 0, G, Y);
      oc.globalCompositeOperation = 'source-over';
      oc.globalCompositeOperation = 'multiply';            // PNG gölgeleri korunur
      oc.globalAlpha = 0.92;
      oc.drawImage(kara, 0, 0, G, Y);
      oc.globalCompositeOperation = 'destination-out';     // karanın dışı temiz kalsın
      oc.globalAlpha = 1;
      kc.setTransform(1, 0, 0, 1, 0, 0);
      kc.globalCompositeOperation = 'source-over';
      kc.clearRect(0, 0, G, Y);
      kc.drawImage(kara, 0, 0, G, Y);
      oc.globalCompositeOperation = 'destination-in';
      oc.drawImage(kal, 0, 0);
      g.drawImage(of, 0, 0);

      // --- kıyı şeridi ışıması: yalnız parlama (karanın kendisi basılmaz)
      kcg.setTransform(1, 0, 0, 1, 0, 0);
      kcg.globalCompositeOperation = 'source-over';
      kcg.globalAlpha = 1;
      kcg.clearRect(0, 0, G, Y);
      kcg.shadowColor = sec.kiyiRenk || 'rgba(120,225,255,.95)';
      kcg.shadowBlur = 9;
      kcg.drawImage(kal, 0, 0);                            // parlama oluşur
      kcg.shadowBlur = 0;
      kcg.globalCompositeOperation = 'destination-out';
      kcg.drawImage(kal, 0, 0);                            // iç gövde silinir → yalnız ışıma kalır
      kcg.globalCompositeOperation = 'source-over';
      g.save();
      g.globalAlpha = 0.85;
      g.drawImage(kiyi, 0, 0);
      g.globalAlpha = 0.5;
      g.globalCompositeOperation = 'lighter';
      g.drawImage(kiyi, 0, 0);                             // ikinci geçiş: daha canlı kıyı
      g.restore();
    }

    // --- gece tarafı (gerçekçi terminatör hissi, çok yumuşak)
    var ge = g.createLinearGradient(0, 0, G, Y * 0.7);
    ge.addColorStop(0, 'rgba(0,0,0,.34)');
    ge.addColorStop(0.45, 'rgba(0,0,0,0)');
    ge.addColorStop(1, 'rgba(0,0,0,.10)');
    g.fillStyle = ge;
    g.fillRect(0, 0, G, Y);

    // --- atmosfer kenar ışıması + vinyet
    var vg = g.createRadialGradient(G / 2, Y / 2, Math.min(G, Y) * 0.35, G / 2, Y / 2, Math.max(G, Y) * 0.78);
    vg.addColorStop(0, 'rgba(0,0,0,0)');
    vg.addColorStop(1, 'rgba(0,0,0,.5)');
    g.fillStyle = vg;
    g.fillRect(0, 0, G, Y);
    g.strokeStyle = 'rgba(79,209,255,.18)';
    g.lineWidth = 1.5;
    g.strokeRect(0.75, 0.75, G - 1.5, Y - 1.5);
    g.restore();
  }

  /* ---------------------------------------------------- 2) HAREKETLİ SİNYAL
     ciftler: [{kaynak:[lon,lat], hedef:[lon,lat], renk:'#hex', hiz:1}]            */
  function sinyaller(g, G, Y, ciftler, zaman, sec) {
    sec = sec || {};
    if (!ciftler || !ciftler.length) return;
    var t = tema();
    var egri = Math.min(1, ciftler.length / 26);          // kalabalıkta sadeleş
    g.save();
    ciftler.slice(0, 42).forEach(function (c, i) {
      var a = proj(c.kaynak[0], c.kaynak[1], G, Y);
      var b = proj(c.hedef[0], c.hedef[1], G, Y);
      var renk = c.renk || '#00ffa3';
      // kontrol noktası: ekvatora doğru kavis (uçuş rotası hissi)
      var orta = [(a[0] + b[0]) / 2, Math.min(a[1], b[1]) - Math.abs(a[0] - b[0]) * 0.16 - 26];

      // yayın kendisi: çok hafif iz
      g.globalAlpha = (0.16 + 0.10 * egri);
      g.strokeStyle = renk;
      g.lineWidth = 1;
      g.beginPath(); g.moveTo(a[0], a[1]);
      g.quadraticCurveTo(orta[0], orta[1], b[0], b[1]);
      g.stroke();

      // kayan ışık paketleri (kuyruklu)
      var hiz = c.hiz || 1;
      var adet = c.adet || (ciftler.length > 18 ? 1 : 2);
      for (var k = 0; k < adet; k++) {
        var faz = ((zaman * 0.00020 * hiz) + (i * 0.13) + k * (1 / adet)) % 1;
        var q = faz;
        var bx = (1 - q) * (1 - q) * a[0] + 2 * (1 - q) * q * orta[0] + q * q * b[0];
        var by = (1 - q) * (1 - q) * a[1] + 2 * (1 - q) * q * orta[1] + q * q * b[1];

        // kuyruk: geriye doğru 10 parça
        for (var j = 10; j >= 1; j--) {
          var qq = q - j * 0.016;
          if (qq < 0) continue;
          var tx = (1 - qq) * (1 - qq) * a[0] + 2 * (1 - qq) * qq * orta[0] + qq * qq * b[0];
          var ty = (1 - qq) * (1 - qq) * a[1] + 2 * (1 - qq) * qq * orta[1] + qq * qq * b[1];
          g.globalAlpha = 0.30 * (1 - j / 11);
          g.fillStyle = renk;
          g.beginPath(); g.arc(tx, ty, 1.9 - j * 0.11, 0, 6.2832); g.fill();
        }
        // baş: parlama
        var gr = g.createRadialGradient(bx, by, 0, bx, by, 9);
        gr.addColorStop(0, 'rgba(255,255,255,.95)');
        gr.addColorStop(0.35, renk);
        gr.addColorStop(1, 'rgba(0,0,0,0)');
        g.globalAlpha = 0.95;
        g.fillStyle = gr;
        g.beginPath(); g.arc(bx, by, 9, 0, 6.2832); g.fill();
        g.fillStyle = '#fff';
        g.beginPath(); g.arc(bx, by, 1.5, 0, 6.2832); g.fill();
      }

      // hedefte çarpan halkalar (radar)
      if (sec.halka !== false) {
        for (var r = 0; r < 3; r++) {
          var faz2 = (((zaman * 0.0006) + i * 0.21 + r / 3) % 1);
          g.globalAlpha = (1 - faz2) * 0.42;
          g.strokeStyle = renk;
          g.lineWidth = 1.3;
          g.beginPath(); g.arc(b[0], b[1], 5 + faz2 * 22, 0, 6.2832); g.stroke();
        }
      }
    });
    g.globalAlpha = 1;
    g.restore();
  }

  /* --------------------------------------------------------- 3) İŞARETÇİ */
  function isaretci(g, x, y, renk, zaman, secili, etiket, buyuk) {
    buyuk = buyuk || 4.6;
    // dış ışıma
    var gr = g.createRadialGradient(x, y, 0, x, y, buyuk * 5);
    gr.addColorStop(0, hexA(renk, 0.55));
    gr.addColorStop(0.45, hexA(renk, 0.18));
    gr.addColorStop(1, hexA(renk, 0));
    g.fillStyle = gr;
    g.beginPath(); g.arc(x, y, buyuk * 5, 0, 6.2832); g.fill();
    // nabız halkası
    var faz = (zaman * 0.0007) % 1;
    g.globalAlpha = (1 - faz) * 0.5;
    g.strokeStyle = renk; g.lineWidth = 1.2;
    g.beginPath(); g.arc(x, y, buyuk + faz * 16, 0, 6.2832); g.stroke();
    g.globalAlpha = 1;
    // gövde
    g.beginPath(); g.arc(x, y, buyuk, 0, 6.2832);
    g.fillStyle = renk; g.fill();
    g.strokeStyle = 'rgba(255,255,255,.9)'; g.lineWidth = 1.1; g.stroke();
    if (secili) {
      g.strokeStyle = '#fff'; g.lineWidth = 2;
      g.beginPath(); g.arc(x, y, buyuk + 6, 0, 6.2832); g.stroke();
    }
    if (etiket) {
      g.font = '11px "Cascadia Mono", Consolas, monospace';
      g.textAlign = 'left';
      g.fillStyle = 'rgba(0,0,0,.55)';
      g.fillText(etiket, x + buyuk + 7, y + 6.5);
      g.fillStyle = '#eaf4ff';
      g.fillText(etiket, x + buyuk + 6, y + 5.5);
    }
  }

  function hexA(hex, a) {
    hex = String(hex || '#2d7dff').replace('#', '');
    if (hex.length === 3) hex = hex[0] + hex[0] + hex[1] + hex[1] + hex[2] + hex[2];
    var n = parseInt(hex, 16);
    return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')';
  }

  /* --------------------------------------------- 4) SİNYAL ÇİFTLERİ ÜRETİCİ
     Noktaları bir merkeze (kendi konum ya da ağırlık merkezi) bağlar.        */
  function ciftler(noktalar, merkez, renkler) {
    var gecerli = (noktalar || []).filter(function (n) {
      return typeof n.enlem === 'number' && typeof n.boylam === 'number';
    });
    if (!gecerli.length) return [];
    var m = merkez;
    if (!m || typeof m.enlem !== 'number') {
      var sx = 0, sy = 0;
      gecerli.forEach(function (n) { sx += n.boylam; sy += n.enlem; });
      m = { boylam: sx / gecerli.length, enlem: sy / gecerli.length };
    }
    return gecerli.map(function (n, i) {
      if (Math.abs(n.boylam - m.boylam) < 0.6 && Math.abs(n.enlem - m.enlem) < 0.6) return null;
      return {
        kaynak: [m.boylam, m.enlem],
        hedef: [n.boylam, n.enlem],
        renk: (renkler && renkler[i % renkler.length]) || n.renk || '#00ffa3',
        hiz: 0.7 + ((i * 37) % 60) / 100
      };
    }).filter(Boolean);
  }

  /* -------------------------------------------------- 5) CANLI DÖNGÜ YÖNETİMİ
     Yalnız panel görünürken çalışır; sekme arka plandayken durur.            */
  function canli(tuvalId, kapId, cizFonk, hzMs) {
    var anahtar = tuvalId || kapId;
    if (donguSayaci[anahtar]) return donguSayaci[anahtar];
    var t = document.getElementById(tuvalId);
    var kap = document.getElementById(kapId);
    var durum = { acik: false, durdur: durdur, basla: basla };
    function gorunur() {
      if (!t || !kap) return false;
      if (kap.className && kap.className.indexOf('panel') >= 0 && kap.className.indexOf('acik') < 0) return false;
      var r = t.getBoundingClientRect();
      return r.width > 20 && r.height > 20;
    }
    var son = 0;
    var sayac = durum;
    function adim(zaman) {
      if (!durum.acik) return;
      if (gorunur() && zaman - son > (hzMs || 33)) {
        son = zaman;
        durum.kare = (durum.kare || 0) + 1;
        durum.gorunurluk = true;
        try { cizFonk(zaman); } catch (e) { durum.sonHata = String(e && e.message); }
      } else if (!gorunur()) { durum.gorunurluk = false; }
      requestAnimationFrame(adim);
    }
    function basla() {
      if (durum.acik) return;
      durum.acik = true;
      requestAnimationFrame(adim);
    }
    function durdur() { durum.acik = false; }
    donguSayaci[anahtar] = durum;
    basla();
    return durum;
  }

  return { proj: proj, tema: tema, arkaplan: arkaplan, sinyaller: sinyaller,
           isaretci: isaretci, ciftler: ciftler, canli: canli, hexA: hexA,
           durum: function () { return donguSayaci; } };
})();
