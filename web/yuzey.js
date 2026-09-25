/* ==========================================================================
   ÜSTAD OSINT — SALDIRI YÜZEYİ HARİTASI
   Kuvvet yönelimli canlı grafik: merkez → cihaz → servis düğümleri.
   Risk ısısı renge, kritiklik kenar kalınlığına yansır. Sürükle · yakınlaş · tıkla.
   ========================================================================== */
var Yuzey = (function () {
  'use strict';

  var t = null, g = null, G = 0, Y = 0, dpr = 1;
  var dugumler = [], kenarlar = [];
  var kamera = { x: 0, y: 0, z: 1 };
  var surukle = null, kaydirma = null, secili = null, kosu = false, adim = 0, etiket = true, isi = true;

  function kur() {
    t = OS.$('yuzeyTuval');
    g = t.getContext('2d');
    OS.$('yuzeySifir').onclick = function () { yerlesim(); OS.balon('☰ Yerleşim sıfırlandı.'); };
    OS.$('yuzeyYakinlas').onclick = function () { kamera.z = Math.min(3, kamera.z * 1.2); ciz(); };
    OS.$('yuzeyUzaklas').onclick = function () { kamera.z = Math.max(.35, kamera.z / 1.2); ciz(); };
    OS.$('yuzeyEtiket').onchange = function () { etiket = this.checked; ciz(); };
    OS.$('yuzeyIsi').onchange = function () { isi = this.checked; ciz(); };
    t.addEventListener('mousedown', basla_t);
    t.addEventListener('mousemove', hareket);
    window.addEventListener('mouseup', bitir);
    t.addEventListener('wheel', function (e) {
      e.preventDefault();
      kamera.z = Math.max(.35, Math.min(3, kamera.z * (e.deltaY < 0 ? 1.12 : .89)));
      ciz();
    }, { passive: false });
    t.addEventListener('click', tikla);
    boyutla();
    window.addEventListener('resize', boyutla);
    if (window.HaritaGercek) HaritaGercek.canli('yuzeyTuval', 'p-yuzey', function (z) { ciz(z); }, 33);
    return { ciz: ciz, boyutla: boyutla, veri: veri };
  }

  function boyutla() {
    if (!t) return;
    dpr = window.devicePixelRatio || 1;
    G = t.clientWidth || (t.parentNode && t.parentNode.clientWidth) || 900;
    Y = t.clientHeight || parseInt(t.getAttribute('height'), 10) || 520;
    t.width = Math.floor(G * dpr); t.height = Math.floor(Y * dpr);
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (!kosu && dugumler.length) sigdir(); else ciz();
  }

  function veri(tarama) {
    var graf = (tarama && tarama.graf) || { dugumler: [], kenarlar: [] };
    var eski = {};
    dugumler.forEach(function (d) { eski[d.id] = d; });
    dugumler = (graf.dugumler || []).map(function (d) {
      var e = eski[d.id];
      var yeni = JSON.parse(JSON.stringify(d));
      yeni.x = e ? e.x : (d.tip === 'merkez' ? 0 : (Math.random() - .5) * 320);
      yeni.y = e ? e.y : (d.tip === 'merkez' ? 0 : (Math.random() - .5) * 240);
      yeni.vx = 0; yeni.vy = 0;
      return yeni;
    });
    kenarlar = graf.kenarlar || [];
    OS.$('yuzeySayac').textContent = dugumler.length + ' düğüm · ' + kenarlar.length + ' bağlantı';
    adim = 0; kosu = true; cevir();
    ciz();
  }

  function yerlesim() {
    dugumler.forEach(function (d, i) {
      var a = i / Math.max(1, dugumler.length) * Math.PI * 2;
      d.x = d.tip === 'merkez' ? 0 : Math.cos(a) * (140 + (i % 5) * 26);
      d.y = d.tip === 'merkez' ? 0 : Math.sin(a) * (110 + (i % 4) * 22);
      d.vx = 0; d.vy = 0;
    });
    adim = 0; kosu = true; cevir();
    kamera = { x: 0, y: 0, z: 1 };
    ciz();
  }

  /* ------------------------------ kuvvetler ------------------------------ */
  function kuvvet() {
    var i, j, d, a, b, dx, dy, uzak, f;
    for (i = 0; i < dugumler.length; i++) {
      d = dugumler[i];
      if (d.sabit) continue;
      d.fx = 0; d.fy = 0;
    }
    for (i = 0; i < dugumler.length; i++) {
      a = dugumler[i];
      for (j = i + 1; j < dugumler.length; j++) {
        b = dugumler[j];
        dx = b.x - a.x; dy = b.y - a.y;
        uzak = Math.max(26, Math.sqrt(dx * dx + dy * dy));
        f = (a.tip === 'servis' && b.tip === 'servis') ? -1500 / uzak : -2600 / uzak;
        var ux = dx / uzak, uy = dy / uzak;
        a.fx = (a.fx || 0) + ux * f; a.fy = (a.fy || 0) + uy * f;
        b.fx = (b.fx || 0) - ux * f; b.fy = (b.fy || 0) - uy * f;
      }
    }
    kenarlar.forEach(function (k) {
      var a = dugumler.filter(function (x) { return x.id === k.kaynak; })[0];
      var b = dugumler.filter(function (x) { return x.id === k.hedef; })[0];
      if (!a || !b) return;
      var dx = b.x - a.x, dy = b.y - a.y;
      var uzak = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      var ideal = a.tip === 'merkez' ? 190 : (a.tip === 'cihaz' ? 118 : 70);
      var f = (uzak - ideal) * (a.tip === 'merkez' ? .05 : .10);
      var ux = dx / uzak, uy = dy / uzak;
      a.fx = (a.fx || 0) + ux * f; a.fy = (a.fy || 0) + uy * f;
      b.fx = (b.fx || 0) - ux * f; b.fy = (b.fy || 0) - uy * f;
    });
    dugumler.forEach(function (d) {
      if (d.sabit) return;
      /* merkeze çekim (dağılmayı engeller) */
      d.fx = (d.fx || 0) - d.x * .05;
      d.fy = (d.fy || 0) - d.y * .05;
      d.vx = ((d.vx || 0) + d.fx * .45) * .78;
      d.vy = ((d.vy || 0) + d.fy * .45) * .78;
      d.x += d.vx; d.y += d.vy;
    });
  }

  function cevir() {
    if (!kosu) return;
    kuvvet();
    adim++;
    var hiz = 0;
    dugumler.forEach(function (d) { hiz = Math.max(hiz, Math.abs(d.vx || 0) + Math.abs(d.vy || 0)); });
    ciz();
    if (adim > 500 || hiz < .06) { kosu = false; sigdir(); return; }
    requestAnimationFrame(cevir);
  }

  /* tüm düğümleri görünür alana sığdır */
  function sigdir() {
    if (!dugumler.length) return;
    var xs = dugumler.map(function (d) { return d.x; }), ys = dugumler.map(function (d) { return d.y; });
    var enAz = Math.min.apply(null, xs), enCok = Math.max.apply(null, xs);
    var alt = Math.min.apply(null, ys), ust = Math.max.apply(null, ys);
    var gx = Math.max(120, enCok - enAz), gy = Math.max(100, ust - alt);
    var olcek = Math.min((G * 0.78) / gx, (Y * 0.78) / gy);
    kamera.z = Math.max(.35, Math.min(1.6, olcek));
    kamera.x = -((enAz + enCok) / 2);
    kamera.y = -((alt + ust) / 2);
    ciz();
  }

  /* ------------------------------ çizim ------------------------------ */
  function ekran(x, y) {
    return [G / 2 + (x + kamera.x) * kamera.z, Y / 2 + (y + kamera.y) * kamera.z];
  }
  function dunya(px, py) {
    return [(px - G / 2) / kamera.z - kamera.x, (py - Y / 2) / kamera.z - kamera.y];
  }
  function riskRenk(p) {
    if (p >= 70) return '#ff5470';
    if (p >= 45) return '#ff8f00';
    if (p >= 20) return '#ffc107';
    return '#2ee6a8';
  }
  function onemRenk(o) {
    return { kritik: '#ff5470', yuksek: '#ff8f00', orta: '#ffc107', dusuk: '#7cffb2', bilgi: '#37e0ff' }[o] || '#37e0ff';
  }

  function ciz(zaman) {
    if (!g) return;
    zaman = zaman || ((window.performance && performance.now) ? performance.now() : Date.now());
    var st = getComputedStyle(document.documentElement);
    g.clearRect(0, 0, G, Y);
    // ızgara
    g.save();
    g.strokeStyle = st.getPropertyValue('--cizgi').trim();
    g.globalAlpha = .35; g.lineWidth = 1;
    var aralik = 60 * kamera.z;
    for (var x = (G / 2 + kamera.x * kamera.z) % aralik; x < G; x += aralik) { g.beginPath(); g.moveTo(x, 0); g.lineTo(x, Y); g.stroke(); }
    for (var y = (Y / 2 + kamera.y * kamera.z) % aralik; y < Y; y += aralik) { g.beginPath(); g.moveTo(0, y); g.lineTo(G, y); g.stroke(); }
    g.restore();

    // kenarlar
    kenarlar.forEach(function (k) {
      var a = dugumler.filter(function (x) { return x.id === k.kaynak; })[0];
      var b = dugumler.filter(function (x) { return x.id === k.hedef; })[0];
      if (!a || !b) return;
      var p1 = ekran(a.x, a.y), p2 = ekran(b.x, b.y);
      g.beginPath(); g.moveTo(p1[0], p1[1]); g.lineTo(p2[0], p2[1]);
      if (k.tip === 'port' && b.riskli) {
        g.strokeStyle = onemRenk(b.onem); g.globalAlpha = .75; g.lineWidth = 2.4;
      } else {
        g.strokeStyle = st.getPropertyValue('--cizgi').trim(); g.globalAlpha = .5; g.lineWidth = 1.2;
      }
      g.stroke(); g.globalAlpha = 1;
    });

    /* ---------- AKAN SİNYAL: bağlantılar üzerinde kayan ışık paketleri ---------- */
    kenarlar.forEach(function (k, ki) {
      var a = dugumler.filter(function (x) { return x.id === k.kaynak; })[0];
      var b = dugumler.filter(function (x) { return x.id === k.hedef; })[0];
      if (!a || !b) return;
      var p1 = ekran(a.x, a.y), p2 = ekran(b.x, b.y);
      var kritik = (k.tip === 'port' && b.riskli);
      var renk = kritik ? onemRenk(b.onem) : '#37e0ff';
      var adet = kritik ? 3 : 1;
      for (var q = 0; q < adet; q++) {
        var faz = ((zaman * (kritik ? 0.00045 : 0.00028)) + ki * 0.17 + q / adet) % 1;
        var x = p1[0] + (p2[0] - p1[0]) * faz;
        var y = p1[1] + (p2[1] - p1[1]) * faz;
        // kuyruk
        for (var j = 6; j >= 1; j--) {
          var qf = faz - j * 0.03;
          if (qf < 0) continue;
          g.globalAlpha = (kritik ? 0.34 : 0.20) * (1 - j / 7);
          g.fillStyle = renk;
          g.beginPath();
          g.arc(p1[0] + (p2[0] - p1[0]) * qf, p1[1] + (p2[1] - p1[1]) * qf, 2.1 - j * 0.16, 0, 6.2832);
          g.fill();
        }
        // baş: parlama
        var rg2 = g.createRadialGradient(x, y, 0, x, y, kritik ? 10 : 7);
        rg2.addColorStop(0, 'rgba(255,255,255,.95)');
        rg2.addColorStop(0.4, renk);
        rg2.addColorStop(1, 'rgba(0,0,0,0)');
        g.globalAlpha = kritik ? 1 : 0.75;
        g.fillStyle = rg2;
        g.beginPath(); g.arc(x, y, kritik ? 10 : 7, 0, 6.2832); g.fill();
      }
      g.globalAlpha = 1;
    });

    // düğümler
    dugumler.forEach(function (d) {
      var p = ekran(d.x, d.y);
      if (p[0] < -80 || p[0] > G + 80 || p[1] < -80 || p[1] > Y + 80) return;
      var sec = secili === d.id;
      if (d.tip === 'merkez') {
        var rg = g.createRadialGradient(p[0], p[1], 2, p[0], p[1], 34);
        rg.addColorStop(0, 'rgba(46,230,168,.35)'); rg.addColorStop(1, 'rgba(46,230,168,0)');
        g.fillStyle = rg; g.beginPath(); g.arc(p[0], p[1], 34, 0, Math.PI * 2); g.fill();
        g.fillStyle = '#2ee6a8'; g.beginPath(); g.arc(p[0], p[1], 11, 0, Math.PI * 2); g.fill();
        g.strokeStyle = '#04121a'; g.lineWidth = 2; g.stroke();
      } else if (d.tip === 'cihaz') {
        var yar = 13 * kamera.z + 4;
        g.beginPath();
        g.rect(p[0] - yar, p[1] - yar, yar * 2, yar * 2);
        var renk = isi ? riskRenk(d.risk) : st.getPropertyValue('--renk1').trim();
        g.fillStyle = renk; g.globalAlpha = .28; g.fill(); g.globalAlpha = 1;
        g.strokeStyle = renk; g.lineWidth = sec ? 3.4 : 2; g.stroke();
        g.fillStyle = st.getPropertyValue('--yazi').trim();
        g.font = 'bold ' + Math.max(9, 11 * kamera.z) + 'px Consolas, monospace';
        g.textAlign = 'center'; g.fillText(String(d.portSayisi || 0), p[0], p[1] + 4);
      } else {
        var r = (d.riskli ? 7 : 5) * kamera.z + 2;
        g.beginPath(); g.arc(p[0], p[1], r, 0, Math.PI * 2);
        var rc = isi && d.riskli ? onemRenk(d.onem) : st.getPropertyValue('--renk2').trim();
        g.fillStyle = rc; g.globalAlpha = d.riskli ? .95 : .55; g.fill(); g.globalAlpha = 1;
        if (sec) { g.strokeStyle = st.getPropertyValue('--yazi').trim(); g.lineWidth = 2; g.stroke(); }
      }
      if (etiket && (kamera.z > .55 || d.tip !== 'servis')) {
        g.fillStyle = st.getPropertyValue('--yazi2').trim();
        g.font = Math.max(9, 10.5 * kamera.z) + 'px Consolas, monospace';
        g.textAlign = 'center';
        var yz = d.tip === 'servis' ? (d.port + ' ' + d.ad) : (d.ip || d.ad);
        g.fillText(String(yz).slice(0, 22), p[0], p[1] + (d.tip === 'servis' ? -12 : 26));
      }
    });

    if (!dugumler.length) {
      g.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--soluk').trim();
      g.font = '14px Consolas, monospace'; g.textAlign = 'center';
      g.fillText('Tarama yapılmadı — harita tarama tamamlanınca dolar.', G / 2, Y / 2);
    }
  }

  /* ------------------------------ etkileşim ------------------------------ */
  function dugumBul(px, py) {
    var en = null, enUzak = 26;
    dugumler.forEach(function (d) {
      var p = ekran(d.x, d.y);
      var uzak = Math.sqrt(Math.pow(p[0] - px, 2) + Math.pow(p[1] - py, 2));
      if (uzak < enUzak) { enUzak = uzak; en = d; }
    });
    return en;
  }

  function basla_t(e) {
    var r = t.getBoundingClientRect();
    var px = e.clientX - r.left, py = e.clientY - r.top;
    var d = dugumBul(px, py);
    if (d) {
      surukle = d; d.sabit = true;
      var u = dunya(px, py); d.kaydirX = d.x - u[0]; d.kaydirY = d.y - u[1];
    } else {
      kaydirma = { x: px, y: py, kx: kamera.x, ky: kamera.y };
    }
  }
  function hareket(e) {
    var r = t.getBoundingClientRect();
    var px = e.clientX - r.left, py = e.clientY - r.top;
    if (surukle) {
      var u = dunya(px, py);
      surukle.x = u[0] + surukle.kaydirX; surukle.y = u[1] + surukle.kaydirY;
      surukle.vx = 0; surukle.vy = 0;
      ciz();
      return;
    }
    if (kaydirma) {
      kamera.x = kaydirma.kx + (px - kaydirma.x) / kamera.z;
      kamera.y = kaydirma.ky + (py - kaydirma.y) / kamera.z;
      ciz();
      return;
    }
    t.style.cursor = dugumBul(px, py) ? 'pointer' : 'grab';
  }
  function bitir() {
    if (surukle) { surukle.sabit = false; surukle = null; kosu = true; adim = 0; cevir(); }
    kaydirma = null;
  }

  function tikla(e) {
    var r = t.getBoundingClientRect();
    var d = dugumBul(e.clientX - r.left, e.clientY - r.top);
    if (!d) return;
    secili = d.id;
    var kap = OS.$('yuzeyBilgi');
    if (d.tip === 'servis') {
      kap.innerHTML = '<b>' + OS.kac(d.ip) + ':' + d.port + ' · ' + OS.kac(d.ad) + '</b><br>' +
        'önem: <span class="onemEtiket ' + OS.kac(d.onem) + '">' + OS.kac(d.onem.toUpperCase()) + '</span>' +
        (d.tls ? ' <span class="etiket">TLS</span>' : '') +
        (d.surum ? '<br>sürüm: ' + OS.kac(d.surum) : '') +
        '<br><span class="soluk">Zafiyet &amp; Öneri panelinde bu servisin sertleştirme adımları var.</span>';
    } else if (d.tip === 'cihaz') {
      kap.innerHTML = '<b>' + OS.kac(d.ip) + '</b> · risk ' + d.risk + '/100 · ' + (d.portSayisi || 0) + ' açık port' +
        (d.isletim ? '<br>işletim sistemi: ' + OS.kac(d.isletim) : '') +
        '<br><span class="soluk">Kenarlar: açık portlar; renkli olanlar kritik/yüksek riskli servisler.</span>';
    } else {
      kap.innerHTML = '<b>ANALİZ NOKTASI</b> · ' + OS.kac(d.ip) + '<br><span class="soluk">Bu cihazdan yapılan taramanın merkezi.</span>';
    }
    ciz();
  }

  return { kur: kur, ciz: ciz, boyutla: boyutla, veri: veri };
})();
