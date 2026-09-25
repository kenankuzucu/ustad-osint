/* ==========================================================================
   ÜSTAD OSINT — OSINT SÜİTİ (resimdeki düzenin işleyen hâli)
   Gerçek veri: /api/arac/* uç noktaları (Windows/Kali) veya APK köprüsü
   ========================================================================== */
var Osint = (function () {
  'use strict';

  var S = { hedef: '', moduller: [], sonuc: null, sekme: 'hizli', graf: null, harita: null, hazir: false };
  var $ = function (id) { return document.getElementById(id); };

  /* ------------------------------ yardımcılar ------------------------------ */
  function kopruVar() { return !!(window.Kopru && typeof window.Kopru !== 'undefined'); }

  function kac(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function sayi(n) { return (n == null ? 0 : n).toLocaleString('tr-TR'); }

  function api(yol, secenek) { return OS.api(yol, secenek); }

  function balon(m, t) { if (OS.balon) OS.balon(m, t); else console.log(m); }

  function yukleniyor(kapId, yazi) {
    var k = $(kapId); if (!k) return;
    k.innerHTML = '<div class="osIskelet">' + (yazi || 'yükleniyor…') + '</div>';
  }

  function hataGoster(kapId, m) {
    var k = $(kapId); if (!k) return;
    k.innerHTML = '<div class="osIskelet" style="color:#ff5470">⚠ ' + kac(m) + '</div>';
  }

  function saat() {
    var d = new Date();
    return ('0' + d.getDate()).slice(-2) + '.' + ('0' + (d.getMonth() + 1)).slice(-2) + '.' + d.getFullYear() +
      ' ' + ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
  }

  var RISK_AD = { kritik: 'Yüksek', yuksek: 'Yüksek', orta: 'Orta', dusuk: 'Düşük', bilgi: 'Bilgi' };

  function riskCip(r) {
    r = (r || 'bilgi').toLowerCase();
    return '<span class="riskCip ' + kac(r) + '">' + kac(RISK_AD[r] || r) + '</span>';
  }

  var TUR_RENK = {
    'Subdomain': '#8b5cf6', 'DNS': '#00d4a0', 'WHOIS': '#ffc107', 'IP': '#2ee6a8', 'IP/ASN': '#2ee6a8',
    'Web Teknolojisi': '#22d3ee', 'Güvenlik Başlığı': '#4f9dff', 'Veri Sızıntısı': '#f43f5e', 'Cloud': '#60a5fa',
    'Tehdit': '#ef4444', 'E-posta': '#ff8f00', 'GitHub': '#a9c2d6', 'Sosyal Medya': '#ff5470'
  };

  /* ------------------------- görünür olunca çiz ------------------------- */
  function gorunurOlunca(fn, deneme, kapId) {
    deneme = deneme || 0;
    var kap = $(kapId || 'osGrafKap');
    if (kap && kap.clientWidth > 40) { fn(); return; }
    if (deneme > 40) { fn(); return; }
    setTimeout(function () { gorunurOlunca(fn, deneme + 1, kapId); }, 90);
  }

  function boyutla(canvasId, kapId, varsayilanY) {
    var t = $(canvasId), kap = $(kapId);
    if (!t) return null;
    var g = Math.max(320, (kap && kap.clientWidth) || t.clientWidth || 640);
    var y = Math.max(200, (kap && kap.clientHeight) || t.clientHeight || varsayilanY || 290);
    var ip = window.devicePixelRatio || 1;
    t.width = Math.round(g * ip); t.height = Math.round(y * ip);
    t.style.width = '100%'; t.style.height = '100%';
    var b = t.getContext('2d');
    b.setTransform(ip, 0, 0, ip, 0, 0);
    return { b: b, g: g, y: y };
  }

  function temaRenk() {
    var st = getComputedStyle(document.documentElement);
    var al = function (a, b) { return (st.getPropertyValue(a) || '').trim() || b; };
    return { yazi: al('--yazi', '#e8f2fb'), soluk: al('--soluk', '#6f8ba3'), cizgi: al('--cizgi', '#24405a'),
             kart: al('--kart', '#132434'), renk1: al('--renk1', '#2ee6a8'), renk2: al('--renk2', '#37e0ff') };
  }

  /* ============================ SALDIRI YÜZEYİ GRAFİĞİ ============================ */
  var GRAFKENAR = { kaynak: 'kaynak', hedef: 'hedef' };

  function grafikCiz(graf) {
    if (!graf || !(graf.dugumler || []).length) {
      $('osGrafNot').textContent = 'veri yok';
      return;
    }
    gorunurOlunca(function () {
      var t = boyutla('osGraf', 'osGrafKap', 290); if (!t) return;
      var b = t.b, renk = temaRenk();
      var dug = graf.dugumler.map(function (d, i) {
        return { id: d.id, ad: d.ad, tur: d.tur, x: t.g / 2 + Math.cos(i * 2.399) * (26 + i * 1.6),
                 y: t.y / 2 + Math.sin(i * 2.399) * (22 + i * 1.4), vx: 0, vy: 0 };
      });
      var kenar = (graf.kenarlar || []).map(function (k) { return { a: k.kaynak, b: k.hedef }; });
      var TUR = { kok: renk.renk2, subdomain: '#8b5cf6', dns: '#00d4a0', eposta: '#ff8f00',
                  teknoloji: '#22d3ee', cloud: '#60a5fa', risk: '#ff5470' };
      var dongu = 0;
      function adim() {
        var it = 0;
        function kuvvet() {
          dug.forEach(function (d) {
            if (d.tur === 'kok') { d.x += (t.g / 2 - d.x) * .12; d.y += (t.y / 2 - d.y) * .12; return; }
            dug.forEach(function (o) {
              if (o === d) return;
              var dx = d.x - o.x, dy = d.y - o.y, m2 = dx * dx + dy * dy + .01;
              var f = 780 / m2;
              d.vx += dx * f; d.vy += dy * f;
            });
            d.vx += (t.g / 2 - d.x) * .004; d.vy += (t.y / 2 - d.y) * .004;
          });
          kenar.forEach(function (k) {
            var a = dug.filter(function (x) { return x.id === k.a; })[0];
            var c = dug.filter(function (x) { return x.id === k.b; })[0];
            if (!a || !c) return;
            var dx = c.x - a.x, dy = c.y - a.y, uz = Math.sqrt(dx * dx + dy * dy) + .01;
            var f = (uz - 88) * .012;
            var ux = dx / uz * f, uy = dy / uz * f;
            a.vx += ux; a.vy += uy; c.vx -= ux; c.vy -= uy;
          });
          dug.forEach(function (d) {
            if (d.tur === 'kok') return;
            d.vx *= .82; d.vy *= .82;
            d.x += d.vx; d.y += d.vy;
            d.x = Math.max(34, Math.min(t.g - 34, d.x));
            d.y = Math.max(24, Math.min(t.y - 24, d.y));
          });
        }
        function cizim() {
          b.clearRect(0, 0, t.g, t.y);
          b.strokeStyle = renk.cizgi; b.globalAlpha = .35; b.lineWidth = 1;
          kenar.forEach(function (k) {
            var a = dug.filter(function (x) { return x.id === k.a; })[0];
            var c = dug.filter(function (x) { return x.id === k.b; })[0];
            if (!a || !c) return;
            b.beginPath(); b.moveTo(a.x, a.y); b.lineTo(c.x, c.y); b.stroke();
          });
          b.globalAlpha = 1;
          dug.forEach(function (d) {
            var r = d.tur === 'kok' ? 26 : 8;
            var cl = TUR[d.tur] || renk.renk1;
            var gr = b.createRadialGradient(d.x, d.y, 0, d.x, d.y, r * 2.2);
            gr.addColorStop(0, cl + 'cc'); gr.addColorStop(1, cl + '00');
            b.fillStyle = gr; b.beginPath(); b.arc(d.x, d.y, r * 2.2, 0, 7); b.fill();
            b.fillStyle = cl; b.beginPath(); b.arc(d.x, d.y, r, 0, 7); b.fill();
            b.strokeStyle = 'rgba(255,255,255,.55)'; b.lineWidth = 1.4; b.stroke();
            if (r === 26 || it > 30) {
              b.fillStyle = renk.yazi; b.font = (r === 26 ? 'bold 13px ' : '10.5px ') + 'Segoe UI, sans-serif';
              b.textAlign = 'center';
              b.fillText(d.ad.length > 26 ? d.ad.slice(0, 25) + '…' : d.ad, d.x, d.y - r - 6);
            }
          });
        }
        for (var i = 0; i < 26; i++) kuvvet();
        cizim();
        it++;
        if (dongu++ < 90) requestAnimationFrame(adim);
      }
      adim();
      $('osGrafNot').textContent = dug.length + ' düğüm · ' + kenar.length + ' bağlantı';
    });
  }

  /* ================================ DÜNYA HARİTASI ================================ */
  var karaResim = null, karaHazir = false;

  var sonHarita = {};          /* tuval başına son veri: canlı animasyon için */

  /* ---------- yalnız tuval çizimi: ultra gerçekçi harita + hareketli sinyaller ---------- */
  function haritaKare(konumlar, tuvalId, kapId, zaman) {
    var t = boyutla(tuvalId, kapId, 290);
    if (!t) return null;
    var kap0 = $(kapId);
    if (kap0 && kap0.clientWidth < 40) return null;
    var b = t.b, G = t.g, Y = t.y, renk = temaRenk();
    zaman = zaman || ((window.performance && performance.now) ? performance.now() : Date.now());

    if (window.HaritaGercek) {
      HaritaGercek.arkaplan(b, G, Y, karaHazir ? karaResim : null);
    } else {
      b.clearRect(0, 0, G, Y);
      b.fillStyle = 'rgba(10,30,50,.35)'; b.fillRect(0, 0, G, Y);
      if (karaHazir) { b.globalAlpha = .85; b.drawImage(karaResim, 0, 0, G, Y); b.globalAlpha = 1; }
    }

    var noktalar = (konumlar || []).filter(function (k) { return typeof k.enlem === 'number' && k.enlem !== null; });
    var renkli = noktalar.map(function (k) {
      return { enlem: k.enlem, boylam: k.boylam,
               renk: k.tur === 'c2' ? '#ff5470' : (k.tur === 'threat' ? '#ff8f00' : '#37e0ff') };
    });

    /* hareketli sinyaller: ağırlık merkezinden her konuma akan ışık paketleri */
    if (window.HaritaGercek && renkli.length) {
      HaritaGercek.sinyaller(b, G, Y,
        HaritaGercek.ciftler(renkli, null, ['#ff5470', '#ff8f00', '#37e0ff', '#5cffc0']), zaman);
    }

    noktalar.forEach(function (k) {
      var x = (k.boylam + 180) / 360 * G, y = (90 - k.enlem) / 180 * Y;
      var cl = k.tur === 'c2' ? '#ff5470' : (k.tur === 'threat' ? '#ff8f00' : '#37e0ff');
      if (window.HaritaGercek) {
        HaritaGercek.isaretci(b, x, y, cl, zaman, false, '', 4.4);
      } else {
        var gr = b.createRadialGradient(x, y, 0, x, y, 20);
        gr.addColorStop(0, cl + '88'); gr.addColorStop(1, cl + '00');
        b.fillStyle = gr; b.beginPath(); b.arc(x, y, 20, 0, 7); b.fill();
        b.fillStyle = cl; b.beginPath(); b.arc(x, y, 4.4, 0, 7); b.fill();
        b.strokeStyle = '#fff'; b.lineWidth = 1.1; b.stroke();
      }
    });

    /* ilk 6 noktaya etiket */
    noktalar.slice(0, 6).forEach(function (k) {
      var x = (k.boylam + 180) / 360 * G, y = (90 - k.enlem) / 180 * Y;
      b.fillStyle = renk.yazi; b.font = '10.5px "Cascadia Mono", Segoe UI, sans-serif'; b.textAlign = 'left';
      b.fillText((k.ip || '') + (k.sehir ? ' · ' + k.sehir : ''), Math.min(x + 8, G - 120), y + 3.5);
    });
    return t;
  }

  function haritaCiz(konumlar, ulkeler, kapId, tuvalId, notId, ulkeId) {
    kapId = kapId || 'osHaritaKap'; tuvalId = tuvalId || 'osHarita';
    notId = notId || 'osHaritaNot'; ulkeId = ulkeId || 'osUlkeListe';
    var kap0 = $(kapId);
    if (kap0 && kap0.clientWidth < 40) {           /* panel henüz görünmez: bekle */
      setTimeout(function () { haritaCiz(konumlar, ulkeler, kapId, tuvalId, notId, ulkeId); }, 180);
      return;
    }
    if (!karaResim) {
      karaResim = new Image();
      karaResim.onload = function () { karaHazir = true; haritaCiz(konumlar, ulkeler, kapId, tuvalId, notId, ulkeId); };
      karaResim.src = 'dunya-kara.png';
    }
    sonHarita[tuvalId] = { konumlar: konumlar, kapId: kapId };
    haritaKare(konumlar, tuvalId, kapId);
    var noktalar = (konumlar || []).filter(function (k) { return typeof k.enlem === 'number' && k.enlem !== null; });
    if ($(notId)) $(notId).textContent = noktalar.length + ' konum';
    var kap = $(ulkeId);
    if (kap) {
      var s2 = Object.keys(ulkeler || {}).map(function (k) { return [k, ulkeler[k]]; })
        .sort(function (a, c) { return c[1] - a[1]; }).slice(0, 7);
      var renkler = ['#ff5470', '#ff8f00', '#ffc107', '#2ee6a8', '#37e0ff', '#8b5cf6', '#e879f9'];
      kap.innerHTML = s2.length ? s2.map(function (x, i) {
        return '<div class="ulkeSatir"><s style="background:' + renkler[i % 7] + '"></s>' + kac(x[0]) +
          '<b>' + sayi(x[1]) + '</b></div>';
      }).join('') : '';
    }
  }

  /* canlı animasyon döngüleri: yalnız panel görünürken çizer */
  if (window.HaritaGercek) {
    setTimeout(function () {
      [['osHarita', 'p-osint'], ['tehditHarita', 'p-tehdit']].forEach(function (c) {
        HaritaGercek.canli(c[0], c[1], function (z) {
          var v = sonHarita[c[0]];
          if (v) haritaKare(v.konumlar, c[0], v.kapId, z);
        }, 40);
      });
    }, 1500);
  }

  /* ================================ KARTLAR ================================ */
  function kartlariCiz(sayilar, sonuclar) {
    sayilar = sayilar || {};
    var d = sonuclar && sonuclar.dns ? sonuclar.dns : {};
    var eposta = ((sonuclar && sonuclar.eposta) || {});
    var mxSay = (d.ozet && d.ozet.mx ? d.ozet.mx.filter(function (x) { return x; }).length : 0) + (eposta.mx || []).length;
    $('osSaySubdomain').textContent = sayi(sayilar.subdomain);
    $('osSayIp').textContent = sayi(sayilar.ip);
    $('osSayServis').textContent = sayi(sayilar.acik_servis);
    $('osSayEposta').textContent = sayi(sayilar.eposta || mxSay);
    $('osSaySizinti').textContent = sayi(sayilar.sizinti);
    $('osSayCloud').textContent = sayi(sayilar.cloud);
  }

  /* ================================ BULGULAR ================================ */
  function bulgulariCiz(bulgular) {
    var kap = $('osBulgular');
    bulgular = bulgular || [];
    $('osBulguNot').textContent = bulgular.length + ' kayıt';
    if (!bulgular.length) {
      kap.innerHTML = '<div class="osIskelet">Belirgin bir bulgu yok — sonuçlar temiz görünüyor.</div>';
      return;
    }
    var h = '<table class="osTablo"><thead><tr><th>Tarih/Saat</th><th>Tür</th><th>Hedef</th><th>Açıklama</th><th>Risk</th></tr></thead><tbody>';
    bulgular.slice(0, 40).forEach(function (b) {
      var renk = TUR_RENK[b.tur] || '#4f9dff';
      h += '<tr><td style="white-space:nowrap;color:var(--soluk)">' + kac(saat()) + '</td>' +
        '<td><span class="turCip" style="--c:' + renk + '">' + kac(b.tur || '—') + '</span></td>' +
        '<td class="hedef" title="' + kac(b.hedef) + '">' + kac(b.hedef) + '</td>' +
        '<td>' + kac(b.aciklama) + '</td><td>' + riskCip(b.risk) + '</td></tr>';
    });
    kap.innerHTML = h + '</tbody></table>';
  }

  /* ================================ TEKNOLOJİ ================================ */
  function teknolojiCiz(tek) {
    var kap = $('osTeknoloji'); tek = tek || [];
    $('osTekNot').textContent = tek.length;
    if (!tek.length) { kap.innerHTML = '<div class="osIskelet">Teknoloji imzası bulunamadı.</div>'; return; }
    var gruplar = {};
    tek.forEach(function (x) { gruplar[x.kategori || 'diğer'] = (gruplar[x.kategori || 'diğer'] || 0) + 1; });
    var toplam = tek.length;
    kap.innerHTML = tek.slice(0, 14).map(function (x) {
      var yuzde = Math.max(6, Math.round(100 / Math.max(1, tek.filter(function (y) { return (y.kategori || 'diğer') === (x.kategori || 'diğer'); }).length + 3)));
      return '<div class="tekSatir"><b title="' + kac(x.ad) + '">' + kac(x.ad) + '</b>' +
        '<div class="tekCubuk"><i style="width:' + (20 + yuzde) + '%"></i></div>' +
        '<span>' + kac(x.kategori || '') + '</span></div>';
    }).join('') + '<div class="sonucYazi">toplam ' + toplam + ' imza</div>';
  }

  /* ================================ PORTLAR ================================ */
  var PORT_AD = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'MSRPC',
    139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 1433: 'MSSQL', 1521: 'Oracle',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8008: 'HTTP-Alt', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 9000: 'Uygulama', 27017: 'MongoDB' };

  function portlariCiz(webtek, tarama) {
    var kap = $('osPortlar');
    var liste = [];
    var acikMi = {}; var kullanilan = {};
    var host = tarama && (tarama.hostlar || [])[0];
    (host ? host.portlar || [] : []).forEach(function (p) { liste.push(p.port); acikMi[p.port] = true; kullanilan[p.port] = true; });
    var onerilen = [80, 443, 22, 21, 3306, 8080, 8443, 445, 3389, 53];
    onerilen.forEach(function (p) { if (!kullanilan[p]) liste.push(p); });
    if (webtek && webtek.durum_kodu) {
      var p2 = (webtek.url || '').indexOf('https') === 0 ? 443 : 80;
      if (!kullanilan[p2]) { liste.unshift(p2); kullanilan[p2] = true; }
      acikMi[p2] = true;
    }
    liste = liste.filter(function (x, i) { return liste.indexOf(x) === i; }).slice(0, 14);
    var acikSay = liste.filter(function (p) { return acikMi[p]; }).length;
    $('osPortNot').textContent = acikSay + ' açık';
    kap.innerHTML = liste.map(function (p) {
      var acik = !!acikMi[p];
      return '<div class="portSatir"><span class="portNo">' + p + '</span>' +
        '<span class="portAd">' + kac(PORT_AD[p] || 'bilinmiyor') + '</span>' +
        '<span class="portDurum ' + (acik ? 'acik' : 'kapali') + '">' + (acik ? 'Açık' : 'Kapalı') + '</span></div>';
    }).join('') || '<div class="osIskelet">—</div>';
  }

  /* ============================== ANA TARAMA ============================== */
  function modulleriTopla(tumu) {
    var kutular = document.querySelectorAll('#osModuller input[data-mod]');
    var liste = [];
    Array.prototype.forEach.call(kutular, function (k) {
      if (k.checked) liste.push(k.getAttribute('data-mod'));
    });
    if (!liste.length) liste = ['dns', 'whois', 'subdomain', 'webtek', 'sizinti', 'cloud', 'tehdit'];
    return liste;
  }

  function ilerleme(yuzde, yazi) {
    var k = $('osIlerleme'); if (k) k.style.display = 'block';
    if ($('osIlerlemeCubuk')) $('osIlerlemeCubuk').style.width = Math.max(4, Math.min(100, yuzde)) + '%';
    if ($('osIlerlemeYazi')) $('osIlerlemeYazi').textContent = yazi || (yuzde + '%');
  }

  function calistir(hedef, moduller) {
    hedef = (hedef || '').trim();
    if (!hedef) { balon('⚠ Hedef girin (ör. example.com · 8.8.8.8)', 'kotu'); return Promise.resolve(null); }
    moduller = moduller || modulleriTopla();
    S.hedef = hedef; S.moduller = moduller;
    ilerleme(8, 'bağlantı kuruluyor…');
    var dugme = $('osBasla'); if (dugme) dugme.disabled = true;
    var adimlar = [['dns', 'DNS kayıtları'], ['whois', 'WHOIS/RDAP'], ['subdomain', 'alt alanlar'],
                   ['webtek', 'web teknolojisi'], ['cloud', 'cloud kovaları'], ['sizinti', 'sızıntı probu'],
                   ['tehdit', 'tehdit beslemeleri']];
    var i = 0;
    var zaman = setInterval(function () {
      var s = adimlar[i % adimlar.length];
      if (moduller.indexOf(s[0]) >= 0) { i++; ilerleme(Math.min(92, 15 + i * 11), s[1] + ' taranıyor…'); }
    }, 1400);
    return api('/api/arac/profil', { yol: 'POST', govde: { hedef: hedef, moduller: moduller } })
      .then(function (d) {
        clearInterval(zaman);
        if (dugme) dugme.disabled = false;
        if (!d || d.hata) { ilerleme(100, 'hata'); hataGoster('osBulgular', (d && d.hata) || 'yanıt yok'); return null; }
        S.sonuc = d;
        ilerleme(100, 'tamamlandı · ' + sayi((d.bulgular || []).length) + ' bulgu · risk ' + sayi(d.risk) + '/100');
        kartlariCiz(d.sayilar, d.sonuclar);
        bulgulariCiz(d.bulgular);
        teknolojiCiz(((d.sonuclar || {}).webtek || {}).teknolojiler);
        portlariCiz((d.sonuclar || {}).webtek, OS.S.tarama);
        grafikCiz(d.graf);
        haritaCiz((d.konumlar || []).concat(d.tehdit_konumlar || []), d.tehdit_ulkeler || {});
        ozetCiz();
        balon('✅ <b>' + kac(hedef) + '</b> tarandı · ' + sayi((d.bulgular || []).length) + ' bulgu · risk ' + d.risk + '/100', d.risk > 40 ? 'kotu' : 'iyi');
        return d;
      })
      .catch(function (e) {
        clearInterval(zaman);
        if (dugme) dugme.disabled = false;
        ilerleme(100, 'hata');
        balon('⚠ OSINT isteği başarısız: ' + kac(e.message), 'kotu');
        return null;
      });
  }

  function ozetCiz() {
    var kap = $('osRaporOzet'); if (!kap || !S.sonuc) return;
    var d = S.sonuc, s = d.sayilar || {};
    kap.innerHTML = '<div class="osAnahtar"><b>Hedef</b><span>' + kac(d.hedef) + '</span></div>' +
      '<div class="osAnahtar"><b>Zaman</b><span>' + kac(d.zaman) + '</span></div>' +
      '<div class="osAnahtar"><b>Risk puanı</b><span>' + sayi(d.risk) + ' / 100</span></div>' +
      '<div class="osAnahtar"><b>Bulgu sayısı</b><span>' + sayi((d.bulgular || []).length) + '</span></div>' +
      '<div class="osAnahtar"><b>Subdomain</b><span>' + sayi(s.subdomain) + '</span></div>' +
      '<div class="osAnahtar"><b>Cloud bulgusu</b><span>' + sayi(s.cloud) + '</span></div>' +
      '<div class="osAnahtar"><b>Sızıntı bulgusu</b><span>' + sayi(s.sizinti) + '</span></div>' +
      '<div class="osAnahtar"><b>Süre</b><span>' + kac(d.sure) + ' sn</span></div>';
  }

  /* ============================== MODÜL PANELLERİ ============================== */
  function tabloSatirlari(liste, kolonlar) {
    if (!(liste || []).length) return '<div class="osIskelet">kayıt yok</div>';
    var h = '<table class="osTablo"><thead><tr>';
    kolonlar.forEach(function (k) { h += '<th>' + kac(k.ad) + '</th>'; });
    h += '</tr></thead><tbody>';
    liste.forEach(function (k) {
      h += '<tr>';
      kolonlar.forEach(function (c) {
        var v = c.al(k);
        h += '<td class="' + (c.mono ? 'hedef' : '') + '">' + (c.html ? v : kac(v == null ? '' : v)) + '</td>';
      });
      h += '</tr>';
    });
    return h + '</tbody></table>';
  }

  function anahtarDeger(nesne, baslik) {
    var h = baslik ? '<div class="kutuAltBaslik" style="font-weight:700;color:var(--yazi);padding:8px 0 4px">' + kac(baslik) + '</div>' : '';
    var i = 0;
    Object.keys(nesne || {}).forEach(function (k) {
      var v = nesne[k];
      var m = (typeof v === 'object') ? JSON.stringify(v) : String(v == null ? '' : v);
      if (typeof v === 'boolean') m = v ? 'evet' : 'hayır';
      h += '<div class="osAnahtar"><b>' + kac(k) + '</b><span>' + kac(m.length > 220 ? m.slice(0, 219) + '…' : m) + '</span></div>';
      i++;
    });
    return i ? h : '';
  }

  function uyariListesi(uyarilar) {
    if (!(uyarilar || []).length) return '';
    return uyarilar.map(function (u) {
      var ik = u.onem === 'kritik' ? '🔴' : u.onem === 'yuksek' ? '🟠' : u.onem === 'orta' ? '🟡' : '🔵';
      return '<div class="osUyariSatir"><i>' + ik + '</i><div><b>' + kac(u.baslik) + '</b><span>' + kac(u.aciklama) + '</span></div></div>';
    }).join('');
  }

  var MODUL_CALISTIR = {
    osarama: function (hedef) { return calistir(hedef, modulleriTopla()); },
    domain: function (hedef) {
      return Promise.all([api('/api/arac/dns?ad=' + encodeURIComponent(hedef)), api('/api/arac/whois?ad=' + encodeURIComponent(hedef)),
                          api('/api/arac/webtek?ad=' + encodeURIComponent(hedef))]);
    },
    subdomain: function (h) { return api('/api/arac/subdomain?ad=' + encodeURIComponent(h)); },
    ipasn: function (h) { return api('/api/arac/asn?ip=' + encodeURIComponent(h)); },
    whois: function (h) { return api('/api/arac/whois?ad=' + encodeURIComponent(h)); },
    dns: function (h) { return api('/api/arac/dns?ad=' + encodeURIComponent(h)); },
    eposta: function (h) { return api('/api/arac/eposta?ad=' + encodeURIComponent(h)); },
    sosyal: function (h) { return api('/api/arac/kullanici?ad=' + encodeURIComponent(h)); },
    kullanici: function (h) { return api('/api/arac/kullanici?ad=' + encodeURIComponent(h)); },
    github: function (h, ek) { return api('/api/arac/github?ad=' + encodeURIComponent(h) + (ek ? ek : '')); },
    webtek: function (h) { return api('/api/arac/webtek?ad=' + encodeURIComponent(h)); },
    cloud: function (h) { return api('/api/arac/cloud?ad=' + encodeURIComponent(h)); },
    sizinti: function (h) { return api('/api/arac/sizinti?ad=' + encodeURIComponent(h)); },
    darkweb: function (h) { return api('/api/arac/darkweb?ad=' + encodeURIComponent(h)); },
    tehdit: function () { return api('/api/arac/tehdit'); }
  };

  var MODUL_KAP = {};   // pid → sonuç çizici

  function cizDNS(kap, d) {
    var kay = d.kayitlar || {};
    var h = '<div class="osAnahtar"><b>Alan adı</b><span>' + kac(d.ad) + '</span></div>' +
      uyariListesi(d.uyarilar);
    Object.keys(kay).forEach(function (tip) {
      var k = (kay[tip] || {}).kayitlar || [];
      if (!k.length) return;
      h += '<div style="font-weight:700;color:var(--yazi);padding:9px 0 3px">' + kac(tip) + ' · ' + k.length + ' kayıt</div>';
      k.slice(0, 14).forEach(function (x) {
        h += '<div class="osAnahtar"><b>' + kac(x.ad) + '</b><span>' + kac(x.deger) + (x.ttl ? '  (TTL ' + x.ttl + ')' : '') + '</span></div>';
      });
    });
    kap.innerHTML = h;
  }

  function cizWhois(kap, d) {
    if (d.hata) { hataGoster(kap.id, d.hata); return; }
    var h = uyariListesi(d.uyarilar) +
      '<div class="osAnahtar"><b>Alan adı</b><span>' + kac(d.ad) + '</span></div>' +
      '<div class="osAnahtar"><b>Kayıtçı</b><span>' + kac(d.kayitci) + '</span></div>' +
      '<div class="osAnahtar"><b>Oluşturma</b><span>' + kac(d.olusturma) + '</span></div>' +
      '<div class="osAnahtar"><b>Son değişiklik</b><span>' + kac(d.guncelleme) + '</span></div>' +
      '<div class="osAnahtar"><b>Bitiş</b><span>' + kac(d.bitis) + '</span></div>' +
      '<div class="osAnahtar"><b>Durum</b><span>' + kac((d.durum || []).join(', ')) + '</span></div>' +
      '<div class="osAnahtar"><b>Ad sunucuları</b><span>' + kac((d.ns || []).join(', ')) + '</span></div>' +
      (d.kisiler || []).map(function (k) {
        return '<div class="osAnahtar"><b>' + kac(k.rol) + '</b><span>' + kac(k.ad) + '</span></div>';
      }).join('');
    kap.innerHTML = h;
  }

  function cizIp(kap, d) {
    if (d.hata) { hataGoster(kap.id, d.hata); return; }
    kap.innerHTML = '<div class="osAnahtar"><b>IP</b><span>' + kac(d.ip) + '</span></div>' +
      '<div class="osAnahtar"><b>Ülke</b><span>' + kac(d.ulke) + ' (' + kac(d.ulke_kodu || '') + ')</span></div>' +
      '<div class="osAnahtar"><b>Şehir / bölge</b><span>' + kac((d.sehir || '') + ' · ' + (d.bolge || '')) + '</span></div>' +
      '<div class="osAnahtar"><b>Konum</b><span>' + kac(d.enlem) + ', ' + kac(d.boylam) + '</span></div>' +
      '<div class="osAnahtar"><b>ISS</b><span>' + kac(d.iss) + '</span></div>' +
      '<div class="osAnahtar"><b>Kuruluş</b><span>' + kac(d.org) + '</span></div>' +
      '<div class="osAnahtar"><b>ASN</b><span>' + kac(d.asn) + ' — ' + kac(d.as_ad || '') + '</span></div>' +
      '<div class="osAnahtar"><b>Ağ bloğu</b><span>' + kac((d.ag || {}).ag || '') + ' ' + kac((d.ag || {}).baslangic || '') + '-' + kac((d.ag || {}).bitis || '') + '</span></div>' +
      '<div class="osAnahtar"><b>Ters DNS</b><span>' + kac(d.ters_dns || '—') + '</span></div>' +
      '<div class="osAnahtar"><b>Proxy / hosting</b><span>' + (d.proxy ? 'proxy' : '—') + ' / ' + (d.hosting ? 'veri merkezi' : '—') + '</span></div>';
  }

  function cizSubdomain(kap, d) {
    if (d.hata) { hataGoster(kap.id, d.hata); return; }
    var kay = d.kaynaklar || {};
    kap.innerHTML = '<div class="osAnahtar"><b>Toplam</b><span>' + sayi(d.toplam) + ' alt alan</span></div>' +
      '<div class="osAnahtar"><b>IP çözülen</b><span>' + sayi(d.canli) + '</span></div>' +
      '<div class="osAnahtar"><b>Kaynaklar</b><span>' + kac(Object.keys(kay).map(function (k) { return k + ': ' + kay[k]; }).join(' · ')) + '</span></div>' +
      tabloSatirlari((d.alt_alanlar || []).slice(0, 120), [
        { ad: 'Alt alan', al: function (x) { return x.ad; }, mono: true },
        { ad: 'IP', al: function (x) { return x.ip || 'çözülemedi'; }, mono: true },
        { ad: 'Kaynak', al: function (x) { return x.kaynak; } }
      ]);
  }

  function cizWebtek(kap, d) {
    if (d.hata) { hataGoster(kap.id, d.hata); return; }
    var gh = Object.keys(d.guvenlik_basliklari || {}).map(function (k) {
      return '<div class="osUyariSatir"><i>' + (d.guvenlik_basliklari[k] ? '✅' : '⚠️') + '</i><div><b>' + kac(k) + '</b><span>' +
        (d.guvenlik_basliklari[k] ? 'gönderiliyor' : 'yok') + '</span></div></div>';
    }).join('');
    var sert = d.sertifika || {};
    kap.innerHTML = '<div class="osAnahtar"><b>URL</b><span>' + kac(d.url) + '</span></div>' +
      '<div class="osAnahtar"><b>Durum kodu</b><span>' + kac(d.durum_kodu) + '</span></div>' +
      '<div class="osAnahtar"><b>Sunucu</b><span>' + kac(d.sunucu || '—') + '</span></div>' +
      '<div class="osAnahtar"><b>Sayfa boyutu</b><span>' + sayi(d.icerik_uzunlugu) + ' bayt</span></div>' +
      uyariListesi(d.uyarilar) +
      '<div style="font-weight:700;color:var(--yazi);padding:9px 0 3px">Teknolojiler (' + (d.teknolojiler || []).length + ')</div>' +
      ((d.teknolojiler || []).length ? (d.teknolojiler || []).map(function (t) {
        return '<span class="turCip" style="--c:#22d3ee;margin:2px 4px 2px 0;display:inline-block">' + kac(t.ad) + ' · ' + kac(t.kategori) + '</span>';
      }).join('') : '<div class="osIskelet">imza bulunamadı</div>') +
      '<div style="font-weight:700;color:var(--yazi);padding:11px 0 3px">Güvenlik başlıkları</div>' + gh +
      (sert.konu ? '<div style="font-weight:700;color:var(--yazi);padding:11px 0 3px">TLS sertifikası</div>' +
        '<div class="osAnahtar"><b>Konu</b><span>' + kac(sert.konu) + '</span></div>' +
        '<div class="osAnahtar"><b>Veren</b><span>' + kac(sert.veren) + '</span></div>' +
        '<div class="osAnahtar"><b>Geçerlilik</b><span>' + kac(sert.baslangic) + ' → ' + kac(sert.bitis) + '</span></div>' +
        '<div class="osAnahtar"><b>Alternatif adlar</b><span>' + kac((sert.san || []).slice(0, 12).join(', ')) + '</span></div>' : '');
  }

  function cizCloud(kap, d) {
    if (d.hata) { hataGoster(kap.id, d.hata); return; }
    kap.innerHTML = '<div class="osAnahtar"><b>Hedef</b><span>' + kac(d.hedef) + '</span></div>' +
      '<div class="osAnahtar"><b>Denenen</b><span>' + sayi(d.denenen) + ' kova adı</span></div>' +
      '<div class="osAnahtar"><b>Bulunan</b><span>' + sayi(d.bulunan) + ' (' + sayi(d.acik) + ' açık)</span></div>' +
      tabloSatirlari(d.sonuclar || [], [
        { ad: 'Kova adı', al: function (x) { return x.ad; }, mono: true },
        { ad: 'Sağlayıcı', al: function (x) { return x.saglayici; } },
        { ad: 'Durum', al: function (x) { return x.durum === 'acik' ? 'Herkese açık' : 'Mevcut (kapalı)'; } },
        { ad: 'Risk', al: function (x) { return riskCip(x.risk); }, html: true },
        { ad: 'Açıklama', al: function (x) { return x.aciklama; } }
      ]);
  }

  function cizEposta(kap, d) {
    kap.innerHTML = '<div class="osAnahtar"><b>Adres</b><span>' + kac(d.adres) + '</span></div>' +
      (d.gecerli === false ? '<div class="osIskelet" style="color:#ff8f00">Sözdizimi geçersiz</div>' : '') +
      uyariListesi(d.uyarilar) +
      '<div class="osAnahtar"><b>MX sunucuları</b><span>' + kac((d.mx || []).join(', ') || '—') + '</span></div>' +
      '<div class="osAnahtar"><b>SPF / DMARC</b><span>' + (d.spf_var ? 'SPF var' : 'SPF yok') + ' · ' + (d.dmarc_var ? 'DMARC var' : 'DMARC yok') + '</span></div>' +
      '<div class="osAnahtar"><b>Tek kullanımlık</b><span>' + (d.tek_kullanimlik ? 'evet' : 'hayır') + '</span></div>' +
      '<div class="osAnahtar"><b>Rol hesabı</b><span>' + (d.rol_hesabi ? 'evet' : 'hayır') + '</span></div>' +
      '<div class="osAnahtar"><b>Gravatar</b><span>' + (d.gravatar ? 'kayıtlı — ' + kac(d.gravatar_url) : 'yok') + '</span></div>' +
      (d.kurumsal_kova ? '<div class="osAnahtar"><b>İlgili kova</b><span>' + kac(d.kurumsal_kova.url) + ' · ' + kac(d.kurumsal_kova.durum) + '</span></div>' : '') +
      '<div class="osUyariSatir"><i>ℹ️</i><div><b>Not</b><span>' + kac(d.not || '') + '</span></div></div>';
  }

  function cizKullanici(kap, d) {
    if (d.hata) { hataGoster(kap.id, d.hata); return; }
    kap.innerHTML = '<div class="osAnahtar"><b>Kullanıcı adı</b><span>' + kac(d.kullanici) + '</span></div>' +
      '<div class="osAnahtar"><b>Bulunan</b><span>' + sayi(d.bulunan) + ' / ' + sayi(d.denenen) + ' platform</span></div>' +
      tabloSatirlari(d.platformlar || [], [
        { ad: 'Platform', al: function (x) { return x.ad; } },
        { ad: 'Durum', al: function (x) { return x.var === true ? '✅ hesap var' : (x.var === false ? '— yok' : '❔ doğrulanamadı'); } },
        { ad: 'Kod', al: function (x) { return x.kod; }, mono: true },
        { ad: 'Not', al: function (x) { return x.not || ''; } },
        { ad: 'Bağlantı', al: function (x) { return '<a href="' + kac(x.url) + '" target="_blank" style="color:var(--renk2)">aç</a>'; }, html: true }
      ]);
  }

  function cizGithub(kap, d) {
    if (d.hata) { hataGoster(kap.id, d.hata); return; }
    var p = d.profil || {};
    kap.innerHTML = '<div class="osAnahtar"><b>Kullanıcı</b><span>' + kac(d.kullanici) + '</span></div>' +
      '<div class="osAnahtar"><b>Ad</b><span>' + kac(p.ad || '—') + '</span></div>' +
      '<div class="osAnahtar"><b>Biyografi</b><span>' + kac(p.bio || '—') + '</span></div>' +
      '<div class="osAnahtar"><b>Şirket / konum</b><span>' + kac((p.sirket || '—') + ' · ' + (p.konum || '—')) + '</span></div>' +
      '<div class="osAnahtar"><b>Site / blog</b><span>' + kac(p.blog || '—') + '</span></div>' +
      '<div class="osAnahtar"><b>Açık e-posta</b><span>' + kac(p.eposta || '—') + '</span></div>' +
      '<div class="osAnahtar"><b>Takipçi / takip</b><span>' + sayi(p.takipci) + ' / ' + sayi(p.takip) + '</span></div>' +
      '<div class="osAnahtar"><b>Depo sayısı</b><span>' + sayi(p.depo_sayisi) + ' · toplam yıldız ' + sayi(d.toplam_yildiz) + '</span></div>' +
      '<div class="osAnahtar"><b>Katıldı</b><span>' + kac(p.olusturma) + ' · son güncelleme ' + kac(p.guncelleme) + '</span></div>' +
      '<div class="osAnahtar"><b>Kurumlar</b><span>' + kac((d.kurumlar || []).join(', ') || '—') + '</span></div>' +
      '<div class="osAnahtar"><b>Diller</b><span>' + kac(Object.keys(d.diller || {}).join(', ')) + '</span></div>' +
      uyariListesi(d.uyarilar) +
      ((d.sizinti_notlari || []).length ? '<div style="font-weight:700;color:var(--yazi);padding:9px 0 3px">Commit e-posta izleri</div>' +
        tabloSatirlari(d.sizinti_notlari, [
          { ad: 'E-posta', al: function (x) { return x.eposta; }, mono: true },
          { ad: 'Depo', al: function (x) { return x.depo; } },
          { ad: 'Tarih', al: function (x) { return x.tarih; } }]) : '') +
      '<div style="font-weight:700;color:var(--yazi);padding:11px 0 3px">Depolar</div>' +
      tabloSatirlari(d.depolar || [], [
        { ad: 'Depo', al: function (x) { return '<a href="' + kac(x.url) + '" target="_blank" style="color:var(--renk2)">' + kac(x.ad) + '</a>'; }, html: true },
        { ad: 'Dil', al: function (x) { return x.dil || '—'; } },
        { ad: 'Yıldız', al: function (x) { return sayi(x.yildiz); }, mono: true },
        { ad: 'Güncelleme', al: function (x) { return x.guncelleme; }, mono: true },
        { ad: 'Açıklama', al: function (x) { return x.aciklama || ''; } }
      ]);
  }

  function cizSizinti(kap, d) {
    if (d.hata) { hataGoster(kap.id, d.hata); return; }
    kap.innerHTML = '<div class="osAnahtar"><b>Hedef</b><span>' + kac(d.url) + '</span></div>' +
      '<div class="osAnahtar"><b>Denenen yol</b><span>' + sayi(d.denenen) + '</span></div>' +
      '<div class="osAnahtar"><b>Bulunan</b><span>' + sayi(d.bulunan) + ' (' + sayi(d.kritik) + ' kritik)</span></div>' +
      uyariListesi(d.uyarilar) +
      tabloSatirlari(d.bulgular || [], [
        { ad: 'Yol', al: function (x) { return x.yol; }, mono: true },
        { ad: 'Kod', al: function (x) { return x.kod; }, mono: true },
        { ad: 'Risk', al: function (x) { return riskCip(x.risk); }, html: true },
        { ad: 'Açıklama', al: function (x) { return x.aciklama; } },
        { ad: 'Bağlantı', al: function (x) { return '<a href="' + kac(x.url) + '" target="_blank" style="color:var(--renk2)">aç</a>'; }, html: true }
      ]) +
      '<div class="sonucYazi">Yumuşak 404 (her isteğe aynı sayfayı dönen sunucular) ayıklandı: ' +
      sayi((d.tum_problar || []).filter(function (x) { return x.durum === 'yanlis_pozitif'; }).length) + ' yanlış pozitif atıldı.</div>';
  }

  function cizDarkweb(kap, d) {
    if (d.hata) { hataGoster(kap.id, d.hata); return; }
    if (d.anahtar_gerekli) {
      kap.innerHTML = '<div class="osUyariSatir"><i>🔑</i><div><b>API anahtarı gerekli</b><span>' + kac(d.mesaj) + '</span></div></div>' +
        '<div style="font-weight:700;color:var(--yazi);padding:9px 0 3px">Ücretsiz alternatifler</div>' +
        (d.ucretsiz_alternatifler || []).map(function (x) {
          return '<div class="osAnahtar"><b>' + kac(x.ad) + '</b><span><a href="' + kac(x.url) + '" target="_blank" style="color:var(--renk2)">' + kac(x.url) + '</a></span></div>';
        }).join('') +
        '<div class="sonucYazi">Ayarlar → API Anahtarları bölümüne HIBP anahtarını eklediğinizde sorgu gerçek sızıntı kayıtlarını listeler.</div>';
      return;
    }
    kap.innerHTML = '<div class="osAnahtar"><b>Sorgu</b><span>' + kac(d.sorgu) + '</span></div>' +
      '<div class="osAnahtar"><b>Sonuç</b><span>' + (d.temiz ? 'bilinen sızıntıda bulunamadı' : sayi(d.sizinti_sayisi) + ' sızıntı') + '</span></div>' +
      tabloSatirlari(d.kayitlar || [], [
        { ad: 'Sızıntı', al: function (x) { return x.baslik || x.ad; } },
        { ad: 'Tarih', al: function (x) { return x.tarih; }, mono: true },
        { ad: 'Etkilenen', al: function (x) { return sayi(x.etkilenen); }, mono: true },
        { ad: 'Veriler', al: function (x) { return (x.veriler || []).join(', '); } }
      ]);
  }

  function cizTehdit(kap, d) {
    if (d.hata) { hataGoster(kap.id, d.hata); return; }
    var ulke = Object.keys(d.ulkeler || {}).map(function (k) { return [k, d.ulkeler[k]]; }).sort(function (a, b) { return b[1] - a[1]; });
    kap.innerHTML = '<div class="osAnahtar"><b>Botnet C2 (Feodo)</b><span>' + sayi(d.c2_toplam) + ' adres</span></div>' +
      '<div class="osAnahtar"><b>Phishing (OpenPhish)</b><span>' + sayi(d.phishing_toplam) + ' URL</span></div>' +
      '<div class="osAnahtar"><b>Ele geçirilmiş sistem (ET)</b><span>' + sayi(d.ioc_toplam) + ' IP</span></div>' +
      '<div class="osAnahtar"><b>Güncelleme</b><span>' + kac(d.guncelleme) + (d.onbellek ? ' (önbellek)' : '') + '</span></div>' +
      '<div style="font-weight:700;color:var(--yazi);padding:9px 0 3px">En çok görülen ülkeler</div>' +
      (ulke.length ? ulke.slice(0, 8).map(function (x) {
        return '<div class="osAnahtar"><b>' + kac(x[0]) + '</b><span>' + sayi(x[1]) + ' C2</span></div>';
      }).join('') : '<div class="osIskelet">konum verisi yok</div>') +
      '<div style="font-weight:700;color:var(--yazi);padding:11px 0 3px">Son C2 kayıtları</div>' +
      tabloSatirlari((d.c2 || []).slice(0, 40), [
        { ad: 'IP', al: function (x) { return x.ip; }, mono: true },
        { ad: 'Port', al: function (x) { return x.port; }, mono: true },
        { ad: 'Zararlı', al: function (x) { return x.zararli; } },
        { ad: 'İlk görülme', al: function (x) { return String(x.ilk_gorulme || '').slice(0, 19); }, mono: true }
      ]) +
      '<div style="font-weight:700;color:var(--yazi);padding:11px 0 3px">Phishing URL örnekleri</div>' +
      (d.phishing || []).slice(0, 15).map(function (x) {
        return '<div class="osAnahtar"><b>🔗</b><span>' + kac(x.url) + '</span></div>';
      }).join('') +
      ((d.ek_beslemeler || []).length ? '<div style="font-weight:700;color:var(--yazi);padding:11px 0 3px">Ek tehdit beslemeleri</div>' +
        (d.ek_beslemeler || []).map(function (x) {
          return '<div class="osAnahtar"><b>' + kac(x.ad) + '</b><span>' + sayi(x.sayi) + ' ' + kac(x.tip) +
            ' · örnek: ' + kac((x.ornek || []).slice(0, 2).join(' · ')) + '</span></div>';
        }).join('') : '') +
      (((d.cve || {}).son_hafta) ? '<div style="font-weight:700;color:var(--yazi);padding:11px 0 3px">Son 1 haftada yayınlanan CVE</div>' +
        '<div class="osAnahtar"><b>Toplam</b><span>' + sayi(d.cve.son_hafta) + ' (' + kac(d.cve.pencere) + ')</span></div>' +
        (d.cve.yeni || []).map(function (x) {
          return '<div class="osAnahtar"><b>' + kac(x.id) + '</b><span>' + kac(x.aciklama) +
            (x.skor ? '  [CVSS ' + kac(x.skor) + ']' : '') + '</span></div>';
        }).join('') : '');
    haritaCiz(d.konumlar, d.ulkeler, 'tehditHaritaKap', 'tehditHarita', 'tehditHaritaNot', 'tehditUlkeListe');
  }

  function cizDomain(kap, liste) {
    kap.innerHTML = '';
    var kapDNS = document.createElement('div'); kapDNS.id = 'dnsAlt';
    var kapW = document.createElement('div');
    var kapWT = document.createElement('div');
    kap.appendChild(kapDNS); kap.appendChild(kapW); kap.appendChild(kapWT);
    cizDNS(kapDNS, liste[0] || {});
    cizWhois(kapW, liste[1] || {});
    cizWebtek(kapWT, liste[2] || {});
  }

  var CIZICILER = {
    dns: cizDNS, whois: cizWhois, ipasn: cizIp, ip: cizIp, subdomain: cizSubdomain, webtek: cizWebtek,
    cloud: cizCloud, eposta: cizEposta, kullanici: cizKullanici, sosyal: cizKullanici, github: cizGithub,
    sizinti: cizSizinti, darkweb: cizDarkweb, tehdit: cizTehdit, domain: cizDomain
  };

  function modulCalistir(pid) {
    var girdi = $(pid + 'Girdi'), dugme = $(pid + 'Dug'), kap = $(pid + 'Sonuc'), ozet = $(pid + 'Ozet'), durum = $(pid + 'Durum');
    var h = girdi ? girdi.value.trim() : '';
    if (pid !== 'tehdit' && !h) { balon('⚠ Önce hedef girin.', 'kotu'); return; }
    if (dugme) dugme.disabled = true;
    if (durum) durum.textContent = 'çalışıyor…';
    if (kap) yukleniyor(pid + 'Sonuc', 'sorgulanıyor…');
    var t0 = Date.now();
    var calistirici = MODUL_CALISTIR[pid];
    Promise.resolve(calistirici ? calistirici(h) : null).then(function (d) {
      if (dugme) dugme.disabled = false;
      if (durum) durum.textContent = ((Date.now() - t0) / 1000).toFixed(1) + ' sn';
      if (!d) return;
      if (Array.isArray(d)) { d = d[0]; }   // domain: üç isteğin ilkini durum için kullan
      if (d.hata) { hataGoster(pid + 'Sonuc', d.hata); if (ozet) ozet.textContent = 'hata'; return; }
      try {
        var cizici = CIZICILER[pid];
        if (cizici) cizici(kap || $(pid + 'Sonuc'), pid === 'domain' ? arguments : d);
      } catch (e) { hataGoster(pid + 'Sonuc', 'çizim hatası: ' + e.message); }
      if (ozet) {
        if (pid === 'subdomain') ozet.textContent = sayi(d.toplam) + ' alt alan · ' + sayi(d.canli) + ' IP';
        else if (pid === 'sizinti') ozet.textContent = sayi(d.bulunan) + ' bulgu';
        else if (pid === 'tehdit') ozet.textContent = sayi(d.c2_toplam) + ' C2 · ' + sayi(d.phishing_toplam) + ' phishing';
        else if (pid === 'kullanici' || pid === 'sosyal') ozet.textContent = sayi(d.bulunan) + '/' + sayi(d.denenen) + ' platform';
        else if (pid === 'cloud') ozet.textContent = sayi(d.bulunan) + ' kova';
        else if (pid === 'dns') ozet.textContent = sayi(Object.keys(d.ozet || {}).length) + ' kayıt tipi';
        else ozet.textContent = 'tamam';
      }
      if (window.OS && OS.balon) balon('✅ ' + pid.toUpperCase() + ' tamamlandı', 'iyi');
    }).catch(function (e) {
      if (dugme) dugme.disabled = false;
      hataGoster(pid + 'Sonuc', e.message);
      if (durum) durum.textContent = 'hata';
    });
  }

  /* ================================ RAPORLAR ================================ */
  function kaydet(dosyaAdi, icerik, mime) {
    try {
      if (window.Kopru && window.Kopru.dosyaYaz) {
        var b64 = btoa(unescape(encodeURIComponent(icerik)));
        window.Kopru.dosyaYaz(dosyaAdi, b64, mime || 'text/plain');
        balon('💾 Kaydedildi: İndirilenler/KENAN-OSINT/' + kac(dosyaAdi), 'iyi');
        return;
      }
    } catch (e) { }
    try {
      var b = new Blob([icerik], { type: (mime || 'text/plain') + ';charset=utf-8' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(b); a.download = dosyaAdi;
      document.body.appendChild(a); a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 900);
      balon('💾 Rapor indirildi: <b>' + kac(dosyaAdi) + '</b>', 'iyi');
    } catch (e) { balon('⚠ Kaydedilemedi: ' + kac(e.message), 'kotu'); }
  }

  function raporHtml() {
    var d = S.sonuc;
    if (!d) { balon('⚠ Önce bir OSINT taraması yapın.', 'kotu'); return; }
    var s = d.sayilar || {};
    var satir = function (b) {
      return '<tr><td>' + kac(saat()) + '</td><td>' + kac(b.tur) + '</td><td>' + kac(b.hedef) + '</td><td>' +
        kac(b.aciklama) + '</td><td>' + kac(RISK_AD[b.risk] || b.risk) + '</td></tr>';
    };
    var html = '<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>ÜSTAD OSINT Raporu — ' + kac(d.hedef) + '</title>' +
      '<style>body{font-family:Segoe UI,sans-serif;background:#0b1622;color:#e8f2fb;padding:26px}' +
      'h1{color:#37e0ff;margin:0}h2{color:#2ee6a8;font-size:16px;margin:22px 0 6px}' +
      'table{width:100%;border-collapse:collapse;font-size:12.5px}th,td{padding:7px;border-bottom:1px solid #24405a;text-align:left}' +
      'th{color:#6f8ba3;font-size:11px;text-transform:uppercase}.k{display:inline-block;background:#132434;border:1px solid #24405a;border-radius:9px;padding:9px 14px;margin:4px 6px 4px 0}' +
      '.k b{display:block;font-size:20px;color:#37e0ff}.sup{color:#6f8ba3;font-size:11px}footer{margin-top:26px;color:#6f8ba3;font-size:11.5px}</style></head><body>' +
      '<h1>ÜSTAD OSINT — Saldırı Yüzeyi ve OSINT Raporu</h1>' +
      '<p class="sup">Hedef: <b>' + kac(d.hedef) + '</b> · Zaman: ' + kac(d.zaman) + ' · Risk: ' + sayi(d.risk) + '/100 · Süre: ' + kac(d.sure) + ' sn</p>' +
      '<div>' + ['Subdomain:' + sayi(s.subdomain), 'IP:' + sayi(s.ip), 'Açık servis:' + sayi(s.acik_servis),
      'Veri sızıntısı:' + sayi(s.sizinti), 'Cloud:' + sayi(s.cloud)].map(function (x) {
        var p = x.split(':');
        return '<span class="k"><b>' + kac(p[1]) + '</b>' + kac(p[0]) + '</span>';
      }).join('') + '</div>' +
      '<h2>Bulgular (' + sayi((d.bulgular || []).length) + ')</h2><table><thead><tr><th>Tarih</th><th>Tür</th><th>Hedef</th><th>Açıklama</th><th>Risk</th></tr></thead><tbody>' +
      (d.bulgular || []).map(satir).join('') + '</tbody></table>' +
      '<h2>Kullanılan modüller</h2><p class="sup">' + kac((d.moduller || []).join(', ')) + '</p>' +
      '<footer>Bu rapor ÜSTAD OSINT tarafından, sahibi olduğunuz veya yazılı izin aldığınız sistemlerde üretilmiştir. ' +
      'Her bulgu canlı kaynaktan doğrulanmıştır; izinsiz kullanım TCK 243/244 kapsamında suçtur.</footer></body></html>';
    kaydet('ustad-osint-' + d.hedef.replace(/[^a-z0-9.\-]/gi, '_') + '-' + Date.now() + '.html', html, 'text/html');
  }

  function raporJson() {
    if (!S.sonuc) { balon('⚠ Önce bir OSINT taraması yapın.', 'kotu'); return; }
    kaydet('ustad-osint-' + S.sonuc.hedef.replace(/[^a-z0-9.\-]/gi, '_') + '.json',
      JSON.stringify(S.sonuc, null, 2), 'application/json');
  }

  function raporCsv() {
    if (!S.sonuc) { balon('⚠ Önce bir OSINT taraması yapın.', 'kotu'); return; }
    var s = "tarih,tur,hedef,aciklama,risk\n";
    (S.sonuc.bulgular || []).forEach(function (b) {
      s += [saat(), b.tur, b.hedef, b.aciklama, RISK_AD[b.risk] || b.risk].map(function (x) {
        return '"' + String(x == null ? '' : x).replace(/"/g, '""') + '"';
      }).join(',') + "\n";
    });
    kaydet('ustad-osint-' + S.sonuc.hedef.replace(/[^a-z0-9.\-]/gi, '_') + '.csv', s, 'text/csv');
  }

  function raporEkran() {
    if (!S.sonuc) { balon('⚠ Önce bir OSINT taraması yapın.', 'kotu'); return; }
    var d = S.sonuc, s = d.sayilar || {};
    var t = document.createElement('canvas');
    t.width = 1200; t.height = 630;
    var b = t.getContext('2d');
    var gr = b.createLinearGradient(0, 0, 1200, 630);
    gr.addColorStop(0, '#08111c'); gr.addColorStop(1, '#0f2437');
    b.fillStyle = gr; b.fillRect(0, 0, 1200, 630);
    b.fillStyle = '#37e0ff'; b.font = 'bold 40px Segoe UI, sans-serif';
    b.fillText('ÜSTAD OSINT', 54, 88);
    b.fillStyle = '#6f8ba3'; b.font = '16px Segoe UI, sans-serif';
    b.fillText('OSINT ARAŞTIRMA ÖZETİ · ' + saat(), 54, 118);
    b.fillStyle = '#e8f2fb'; b.font = 'bold 34px Consolas, monospace';
    b.fillText(d.hedef, 54, 186);
    var k = [['Subdomain', s.subdomain], ['IP', s.ip], ['Açık servis', s.acik_servis],
             ['Sızıntı', s.sizinti], ['Cloud', s.cloud], ['Risk', d.risk + '/100']];
    k.forEach(function (x, i) {
      var cx = 54 + (i % 3) * 370, cy = 240 + Math.floor(i / 3) * 150;
      b.fillStyle = '#132434'; b.strokeStyle = '#24405a';
      b.beginPath(); b.roundRect ? b.roundRect(cx, cy, 340, 120, 16) : b.rect(cx, cy, 340, 120);
      b.fill(); b.stroke();
      b.fillStyle = '#37e0ff'; b.font = 'bold 42px Consolas, monospace';
      b.fillText(String(x[1]), cx + 22, cy + 66);
      b.fillStyle = '#6f8ba3'; b.font = '15px Segoe UI, sans-serif';
      b.fillText(String(x[0]).toUpperCase(), cx + 22, cy + 96);
    });
    b.fillStyle = '#a9c2d6'; b.font = '14px Segoe UI, sans-serif';
    b.fillText('Üstad Kenan Kuzucu · OSINT Araştırmacısı · "Bilgi, gücün en temiz halidir."', 54, 588);
    try {
      var veri = t.toDataURL('image/png').split(',')[1];
      if (window.Kopru && window.Kopru.dosyaYaz) {
        window.Kopru.dosyaYaz('ustad-osint-ozet.png', veri, 'image/png');
        balon('🖼️ Özet görseli kaydedildi: İndirilenler/KENAN-OSINT/', 'iyi');
        return;
      }
      var a = document.createElement('a');
      a.href = t.toDataURL('image/png'); a.download = 'ustad-osint-ozet.png';
      document.body.appendChild(a); a.click(); a.remove();
      balon('🖼️ Özet görseli indirildi.', 'iyi');
    } catch (e) { balon('⚠ Görsel üretilemedi: ' + kac(e.message), 'kotu'); }
  }

  function raporListe() {
    var kap = $('osRaporListe'); if (!kap) return;
    api('/api/tarama/liste').then(function (d) {
      if (!Array.isArray(d) || !d.length) { kap.innerHTML = '<div class="osIskelet">Kayıtlı ağ taraması yok.</div>'; return; }
      kap.innerHTML = tabloSatirlari(d.slice(0, 12), [
        { ad: 'No', al: function (x) { return x.id; }, mono: true },
        { ad: 'Hedef', al: function (x) { return (x.hedefler || []).join(', '); } },
        { ad: 'Cihaz', al: function (x) { return sayi((x.sayilar || {}).cihaz); }, mono: true },
        { ad: 'Alarm', al: function (x) { return sayi((x.sayilar || {}).alarm); }, mono: true },
        { ad: 'Risk', al: function (x) { return sayi(x.risk) + '/100'; }, mono: true }
      ]);
    }).catch(function () { kap.innerHTML = '<div class="osIskelet">liste alınamadı</div>'; });
  }

  /* ================================ SEKMELER ================================ */
  function sekme(id) {
    S.sekme = id;
    var dugmeler = document.querySelectorAll('#osSekmeler .sekme');
    Array.prototype.forEach.call(dugmeler, function (b) { b.classList.toggle('sec', b.getAttribute('data-sekme') === id); });
    var kutular = document.querySelectorAll('#osModuller input[data-mod]');
    var sec = {
      hizli: ['dns', 'whois', 'subdomain', 'ip'],
      detay: ['dns', 'whois', 'subdomain', 'ip', 'webtek', 'cloud', 'sizinti', 'tehdit'],
      ozel: ['kullanici', 'github', 'eposta', 'sosyal', 'darkweb'],
      toplu: ['dns', 'whois', 'subdomain', 'webtek', 'cloud', 'sizinti']
    }[id];
    if (sec) {
      Array.prototype.forEach.call(kutular, function (k) {
        k.checked = sec.indexOf(k.getAttribute('data-mod')) >= 0;
      });
    }
    if (id === 'rapor') { raporListe(); }
  }

  /* ================================ BAŞLATMA ================================ */
  function kur() {
    if (S.hazir) return;
    S.hazir = true;

    if ($('osBasla')) $('osBasla').onclick = function () { calistir($('osHedef').value); };
    if ($('osHedef')) $('osHedef').onkeydown = function (e) { if (e.key === 'Enter') calistir(this.value); };
    var tumu = $('osTumModul');
    if (tumu) tumu.onchange = function () {
      var v = this.checked;
      Array.prototype.forEach.call(document.querySelectorAll('#osModuller input[data-mod]'), function (k) { k.checked = v; });
    };
    Array.prototype.forEach.call(document.querySelectorAll('#osSekmeler .sekme'), function (b) {
      b.onclick = function () { sekme(this.getAttribute('data-sekme')); };
    });
    // eylem şeridi
    Array.prototype.forEach.call(document.querySelectorAll('.esDug'), function (b) {
      b.onclick = function () {
        var g = this.getAttribute('data-git');
        Array.prototype.forEach.call(document.querySelectorAll('.esDug'), function (x) { x.classList.remove('sec'); });
        this.classList.add('sec');
        if (g === 'scan') OS.panelAc('tarama');
        else if (g === 'analyze') OS.panelAc('osint');
        else if (g === 'discover') OS.panelAc('domain');
        else if (g === 'map') { OS.panelAc('tehdit'); modulCalistir('tehdit'); }
        else if (g === 'report') { OS.panelAc('osrapor'); raporListe(); }
      };
    });
    // modül panelleri
    Object.keys(MODUL_CALISTIR).forEach(function (pid) {
      var d = $(pid + 'Dug');
      if (d) d.onclick = function () { modulCalistir(pid); };
      var g = $(pid + 'Girdi');
      if (g) g.onkeydown = function (e) { if (e.key === 'Enter') modulCalistir(pid); };
    });
    // rapor düğmeleri
    [['osRaporHtml', raporHtml], ['osRaporJson', raporJson], ['osRaporCsv', raporCsv], ['osRaporEkran', raporEkran],
     ['osRaporHtml2', raporHtml], ['osRaporJson2', raporJson], ['osRaporCsv2', raporCsv]].forEach(function (x) {
      var d = $(x[0]); if (d) d.onclick = x[1];
    });
    var tum = $('osRaporTum');
    if (tum) tum.onclick = function () { raporHtml(); setTimeout(raporJson, 700); };
    var tum2 = $('osRaporTum2');
    if (tum2) tum2.onclick = function () { raporHtml(); setTimeout(raporJson, 700); };
    // pencere boyutu değişince yeniden çiz
    window.addEventListener('resize', function () {
      if (S.sonuc) { grafikCiz(S.sonuc.graf); haritaCiz(S.sonuc.konumlar, {}); }
    });
    raporListe();
  }

  return { kur: kur, calistir: calistir, sekme: sekme, modulCalistir: modulCalistir,
           raporHtml: raporHtml, raporJson: raporJson, raporCsv: raporCsv, raporEkran: raporEkran,
           grafikCiz: grafikCiz, haritaCiz: haritaCiz, S: S };
})();

/* OSINT panelleri açılınca tuvali tazele */
(function () {
  if (typeof OS === 'undefined') return;
  var eski = OS.panelAc;
  OS.panelAc = function (id, sessiz) {
    eski.call(OS, id, sessiz);
    if (id === 'osint' && Osint.S.sonuc) {
      setTimeout(function () { Osint.grafikCiz(Osint.S.sonuc.graf); }, 90);
    }
    if (id === 'tehdit') { setTimeout(function () { Osint.modulCalistir('tehdit'); }, 60); }
  };
  document.addEventListener('DOMContentLoaded', function () {
    setTimeout(function () { Osint.kur(); }, 60);
  });
})();
