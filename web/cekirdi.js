/* ==========================================================================
   ÜSTAD OSINT — çekirdek: durum, API, gezinme, tema, gösterge paneli
   Aynı kod üç ortamda çalışır:  yerel arka uç (PC/Kali) · Android köprüsü · tarayıcı önizleme
   ========================================================================== */
var OS = (function () {
  'use strict';

  var S = {
    surum: '1.0',
    panel: 'gosterge',
    durum: null,
    tarama: null,          // son tarama nesnesi (API yanıtı)
    taramaId: null,
    onem: 'hepsi',
    iocTur: 'hepsi',
    tema: 'gece',
    yuzey: null,           // harita motoru
    dunya: null,
    olayAdim: [],
    olayKayit: [],
    /* gerçek Java köprüsü bağlı mı (APK) — yoksa Python sunucusu kullanılır */
    kopruVar: false
  };

  /* ------------------------------- yardımcılar ------------------------------- */
  function $(id) { return document.getElementById(id); }
  function $$(sec, kok) { return Array.prototype.slice.call((kok || document).querySelectorAll(sec)); }
  function sayi(n) { return (n === null || n === undefined) ? '0' : String(n).replace(/\B(?=(\d{3})+(?!\d))/g, '.'); }
  function saat() { var d = new Date(); return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2) + ':' + ('0' + d.getSeconds()).slice(-2); }
  function kac(s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function balon(metin, tur) {
    var d = document.createElement('div');
    d.className = 'balon ' + (tur || '');
    d.innerHTML = metin;
    $('balonlar').appendChild(d);
    setTimeout(function () { d.style.opacity = '0'; d.style.transform = 'translateY(6px)'; }, 4200);
    setTimeout(function () { if (d.parentNode) d.parentNode.removeChild(d); }, 5200);
  }

  /* Yerleşik (Java/APK) motor yalnız köprü GERÇEKTEN bağlıysa kullanılır.
     Masaüstünde window.KOPRU de yüklüdür ama arkasında Java yoktur → o zaman
     istekler Python sunucusuna (fetch) gitmelidir. */
  function kopruAktif() {
    return !!(window.KOPRU && typeof window.KOPRU.javaVarMi === 'function' && window.KOPRU.javaVarMi());
  }

  function api(yol, secenek) {
    secenek = secenek || {};
    if (kopruAktif()) {
      return new Promise(function (cozum, red) {
        try {
          var ham = window.KOPRU.istek(yol, secenek.govde ? JSON.stringify(secenek.govde) : '');
          cozum(JSON.parse(ham || '{}'));
        } catch (e) { red(e); }
      });
    }
    var ayar = { method: secenek.yol || secenek.method || 'GET', headers: { 'Content-Type': 'application/json' } };
    if (secenek.govde) ayar.body = JSON.stringify(secenek.govde);
    return fetch(yol, ayar).then(function (r) {
      return r.json().catch(function () { return { hata: 'yanıt çözümlenemedi (' + r.status + ')' }; });
    });
  }

  /* ------------------------------- tema ------------------------------- */
  var TEMALAR = [
    { id: 'gece', ad: 'Gece', renk: '#0b1622' },
    { id: 'gunduz', ad: 'Gündüz', renk: '#eef3f8' },
    { id: 'orman', ad: 'Orman', renk: '#0c1a14' },
    { id: 'deniz', ad: 'Deniz', renk: '#071a26' },
    { id: 'mor', ad: 'Mor', renk: '#150f24' },
    { id: 'altin', ad: 'Altın', renk: '#1a160c' },
    { id: 'kizil', ad: 'Kızıl', renk: '#1d0f11' },
    { id: 'buz', ad: 'Buz', renk: '#f4f9ff' },
    { id: 'kum', ad: 'Kum', renk: '#f7f2e7' },
    { id: 'kalem', ad: 'Kalem', renk: '#fbfbf6' },
    { id: 'matriks', ad: 'Matris', renk: '#00ff41' },
    { id: 'terminal', ad: 'Terminal', renk: '#ffb000' },
    { id: 'neon', ad: 'Neon Siber', renk: '#00fff7' },
    { id: 'zifiri', ad: 'Zifiri', renk: '#00a3ff' },
    { id: 'qdoled', ad: 'QD-OLED 4K', renk: '#00ff8a' }
  ];
  function temaCiz() {
    var kap = $('temaSec');
    kap.innerHTML = '';
    TEMALAR.forEach(function (t) {
      var b = document.createElement('button');
      b.className = 'temaNokta' + (S.tema === t.id ? ' sec' : '');
      b.title = t.ad + ' teması';
      b.style.background = t.renk;
      b.style.boxShadow = 'inset 0 0 0 2px rgba(255,255,255,.18)';
      b.onclick = function () { tema(t.id); };
      kap.appendChild(b);
    });
  }
  function tema(id) {
    S.tema = id;
    document.documentElement.setAttribute('data-tema', id);
    try { localStorage.setItem('osint_tema', id); } catch (e) {}
    temaCiz();
    if (S.tarama) { gostergeCiz(S.tarama); if (S.yuzey) S.yuzey.ciz(); if (S.dunya) S.dunya.ciz(); }
    balon('🎨 Tema: <b>' + (TEMALAR.filter(function (t) { return t.id === id; })[0] || { ad: id }).ad + '</b>');
  }

  /* ------------------------------- gezinme ------------------------------- */
  function panelAc(id, sessiz) {
    S.panel = id;
    $$('.panel').forEach(function (p) { p.classList.remove('acik'); });
    var hedef = $('p-' + id);
    if (hedef) hedef.classList.add('acik');
    $$('.menuDug').forEach(function (b) { b.classList.toggle('sec', b.getAttribute('data-panel') === id); });
    try { localStorage.setItem('osint_panel', id); } catch (e) {}
    if (window.scrollY > 40) window.scrollTo({ top: 0, behavior: 'smooth' });
    if (id === 'yuzey' && S.yuzey) setTimeout(function () { S.yuzey.boyutla(); S.yuzey.ciz(); }, 40);
    if (id === 'dunya' && S.dunya) setTimeout(function () { S.dunya.boyutla(); S.dunya.ciz(); }, 40);
    if (id === 'gosterge') gostergeCiz(S.tarama);
    if (!sessiz) {
      var ad = { gosterge: 'Gösterge paneli', yuzey: 'Saldırı yüzeyi haritası', tarama: 'Tarama merkezi', alarm: 'Alarm & triyaj', ioc: 'IOC kasası', dunya: 'Dünya haritası', log: 'Log / SIEM analizi', olay: 'Olay müdahalesi', zafiyet: 'Zafiyet & öneri', rapor: 'Rapor & kanıt', ayar: 'Ayarlar' }[id] || id;
      balon('🧭 <b>' + kac(ad) + '</b> paneline geçildi');
    }
  }

  /* ------------------------------- amblem ------------------------------- */
  function amblemCiz() {
    var t = $('amblemTuval'); if (!t) return;
    var g = t.getContext('2d'), G = t.width, Y = t.height, m = G / 2;
    g.clearRect(0, 0, G, Y);
    var st = getComputedStyle(document.documentElement);
    var r1 = st.getPropertyValue('--renk1').trim() || '#2ee6a8';
    var r2 = st.getPropertyValue('--renk2').trim() || '#37e0ff';
    var yz = st.getPropertyValue('--yazi').trim() || '#e8f2fb';
    // zemin
    var gr = g.createRadialGradient(m, m * .8, 4, m, m, m);
    gr.addColorStop(0, 'rgba(255,255,255,.10)');
    gr.addColorStop(1, 'rgba(255,255,255,0)');
    g.fillStyle = gr; g.fillRect(0, 0, G, Y);
    // kalkan
    g.beginPath();
    g.moveTo(m, 8);
    g.lineTo(G - 12, 22);
    g.lineTo(G - 16, m + 4);
    g.quadraticCurveTo(m, Y - 6, 16, m + 4);
    g.lineTo(12, 22);
    g.closePath();
    var kg = g.createLinearGradient(0, 0, G, Y);
    kg.addColorStop(0, r1); kg.addColorStop(1, r2);
    g.fillStyle = kg; g.globalAlpha = .22; g.fill(); g.globalAlpha = 1;
    g.strokeStyle = r1; g.lineWidth = 2.4; g.stroke();
    // radar ışığı
    g.save(); g.beginPath(); g.arc(m, m, m - 14, 0, Math.PI * 2); g.clip();
    var t2 = Date.now() / 900 % (Math.PI * 2);
    var tg = g.createLinearGradient(m, m, m + Math.cos(t2) * m, m + Math.sin(t2) * m);
    tg.addColorStop(0, 'rgba(255,255,255,0)'); tg.addColorStop(1, r2);
    g.strokeStyle = tg; g.lineWidth = 3;
    g.beginPath(); g.moveTo(m, m); g.lineTo(m + Math.cos(t2) * m, m + Math.sin(t2) * m); g.stroke();
    g.restore();
    // merkez nokta + halkalar
    g.strokeStyle = r1; g.globalAlpha = .45; g.lineWidth = 1.2;
    [18, 28].forEach(function (r) { g.beginPath(); g.arc(m, m, r, 0, Math.PI * 2); g.stroke(); });
    g.globalAlpha = 1;
    g.fillStyle = yz; g.beginPath(); g.arc(m, m, 5, 0, Math.PI * 2); g.fill();
    // >_ imzası
    g.font = 'bold 17px Consolas, monospace'; g.fillStyle = r1; g.textAlign = 'center';
    g.fillText('>_', m, Y - 20);
    requestAnimationFrame(function () { setTimeout(amblemCiz, 60); });
  }

  /* ------------------------------- gösterge ------------------------------- */
  function olcu(kap, baslik, deger, sinif, altYazi) {
    var d = document.createElement('div');
    d.className = 'olcu ' + (sinif || '');
    d.innerHTML = '<span>' + kac(baslik) + '</span><b>' + deger + '</b>' +
      (altYazi ? '<span>' + kac(altYazi) + '</span>' : '');
    kap.appendChild(d);
  }

  function gostergeCiz(t) {
    var kap = $('gostergeKartlar');
    if (!kap) return;
    kap.innerHTML = '';
    if (!t) {
      olcu(kap, 'DURUM', 'tarama yok', '', 'tarama merkezinden başlat');
      olcu(kap, 'CİHAZ', '0', '', '');
      olcu(kap, 'AÇIK PORT', '0', '', '');
      olcu(kap, 'ALARM', '0', '', '');
      riskHalka(0, 'tarama yok');
      onemCubuk({});
      return;
    }
    var s = t.sayilar || {};
    olcu(kap, 'CİHAZ', sayi(s.cihaz), '', 'canlı bulunan');
    olcu(kap, 'AÇIK PORT', sayi(s.acikPort), s.acikPort > 20 ? 'uyari' : '', 'servis sayısı');
    olcu(kap, 'ALARM', sayi(s.alarm), s.alarm ? 'kritik' : 'iyi', sayi(s.kritik) + ' kritik');
    olcu(kap, 'IOC', sayi(s.ioc), '', 'iz göstergesi');
    olcu(kap, 'KONUM', sayi(s.konum), '', 'haritada işaretli');
    olcu(kap, 'MOTOR', kac(t.motor || '-'), '', 'soket / nmap');
    riskHalka(t.risk || 0, riskEtiket(t.risk || 0));
    onemCubuk(onemSay(t));
    // risk nedenleri
    var rn = $('riskNedenler');
    rn.innerHTML = '';
    (t.riskNedenleri || []).forEach(function (n) {
      var li = document.createElement('li'); li.textContent = n; rn.appendChild(li);
    });
    if (!rn.children.length) rn.innerHTML = '<li>Riskli servis bulunmadı.</li>';
    // akış
    var lg = $('gostergeLog');
    lg.textContent = (t.loglar || []).map(function (x) { return '[' + x.zaman + '] ' + x.metin; }).join('\n') || 'kayıt yok';
    lg.scrollTop = lg.scrollHeight;
    // menü sayaçları
    menüSayac(S.tarama);
  }

  function onemSay(t) {
    var s = { kritik: 0, yuksek: 0, orta: 0, dusuk: 0, bilgi: 0 };
    ((t && t.alarmlar) || []).forEach(function (a) { s[a.onem] = (s[a.onem] || 0) + 1; });
    return s;
  }
  function riskEtiket(p) {
    if (!p) return 'düşük yüzey';
    if (p >= 70) return 'çok yüksek risk';
    if (p >= 45) return 'yüksek risk';
    if (p >= 20) return 'orta risk';
    return 'düşük risk';
  }

  function riskHalka(puan, etiket) {
    var t = $('riskHalka'); if (!t) return;
    var g = t.getContext('2d'), m = t.width / 2;
    var st = getComputedStyle(document.documentElement);
    var k1 = st.getPropertyValue('--kart').trim(), cz = st.getPropertyValue('--cizgi').trim();
    g.clearRect(0, 0, t.width, t.height);
    g.lineWidth = 20; g.lineCap = 'round';
    g.strokeStyle = cz;
    g.beginPath(); g.arc(m, m, m - 22, 0, Math.PI * 2); g.stroke();
    var renk = puan >= 70 ? '#ff5470' : puan >= 45 ? '#ff8f00' : puan >= 20 ? '#ffc107' : '#2ee6a8';
    g.strokeStyle = renk;
    g.beginPath(); g.arc(m, m, m - 22, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * (puan / 100)); g.stroke();
    $('riskPuan').textContent = puan;
    $('riskEtiket').textContent = etiket || '';
  }

  function onemCubuk(s) {
    var t = $('onemCubuk'); if (!t) return;
    var g = t.getContext('2d'), G = t.width, Y = t.height;
    var st = getComputedStyle(document.documentElement);
    g.clearRect(0, 0, G, Y);
    var sira = [['kritik', '#ff5470'], ['yuksek', '#ff8f00'], ['orta', '#ffc107'], ['dusuk', '#7cffb2'], ['bilgi', '#37e0ff']];
    var enB = Math.max(1, Math.max.apply(null, sira.map(function (x) { return s[x[0]] || 0; })));
    var y = 18, h = (Y - 40) / sira.length - 8;
    sira.forEach(function (x) {
      var deger = s[x[0]] || 0;
      g.fillStyle = st.getPropertyValue('--kart2').trim() || '#17293b';
      g.fillRect(96, y, G - 150, h);
      g.fillStyle = x[1];
      g.fillRect(96, y, (G - 150) * (deger / enB), h);
      g.fillStyle = st.getPropertyValue('--yazi').trim() || '#fff';
      g.font = '12px Consolas, monospace'; g.textAlign = 'right';
      g.fillText(x[0].toUpperCase(), 88, y + h * .72);
      g.textAlign = 'left';
      g.fillText(String(deger), G - 44, y + h * .72);
      y += h + 8;
    });
  }

  function menüSayac(t) {
    var s = (t && t.sayilar) || {};
    $('sayGosterge').textContent = s.alarm ? s.alarm : '';
    $('sayYuzey').textContent = s.cihaz || '';
    $('sayTarama').textContent = s.acikPort || '';
    $('sayAlarm').textContent = s.kritik ? '⚠' + s.kritik : '';
    $('sayIoc').textContent = s.ioc || '';
    $('sayDunya').textContent = s.konum || '';
  }

  /* ------------------------------- durum ------------------------------- */
  function durumYenile(sessiz) {
    return api('/api/durum').then(function (d) {
      S.durum = d;
      if (d.hata) { balon('⚠ arka uç yanıtı: ' + kac(d.hata), 'kotu'); return d; }
      var nm = $('rozetNmap');
      if (d.kopru) {
        nm.textContent = 'mod: telefonda yerleşik';
        nm.className = 'rozet iyi';
      } else {
        nm.textContent = 'nmap: ' + (d.nmap ? 'var' : 'yok (soket motoru)');
        nm.className = 'rozet ' + (d.nmap ? 'iyi' : '');
      }
      $('rozetAg').textContent = 'ağ: ' + (d.altAg || d.yerelIp || '-');
      var mo = $('rozetMotor');
      mo.textContent = 'motor: ' + (d.motor || (d.nmap ? 'nmap + soket' : 'soket'));
      $('surumYazi').textContent = d.surum || S.surum;
      if (!sessiz) ayarDurumCiz(d);
      return d;
    }).catch(function (e) {
      balon('⚠ Arka uca ulaşılamadı: ' + kac(e.message) + '<br><span class="soluk">APK sürümünde köprü kullanılır.</span>', 'kotu');
      return null;
    });
  }

  function ayarDurumCiz(d) {
    var kap = $('ayarDurum'); if (!kap) return;
    kap.innerHTML = '';
    var satirlar = [
      ['SÜRÜM', d.surum], ['YEREL IP', d.yerelIp], ['AĞ', d.altAg],
      ['nmap', d.nmap ? (d.nmapYolu || 'var') : 'YOK — yerleşik soket motoru'],
      ['İŞLETİM SİSTEMİ', d.isletim], ['PYTHON', d.python],
      ['TARAMA SAYISI', (d.taramaSayisi || 0) + ' (bu oturum)'],
      ['DIŞ IP KONUMU', d.disIp ? (d.disIp.ulke + ' · ' + (d.disIp.sehir || '-')) : 'yerel ağ (özel adres)']
    ];
    satirlar.forEach(function (x) {
      var s = document.createElement('div');
      s.className = 'satir';
      s.innerHTML = '<span class="etiket">' + kac(x[0]) + '</span><span class="anahtar">' + kac(x[1]) + '</span>';
      kap.appendChild(s);
    });
  }

  /* ------------------------------- başlat ------------------------------- */
  function basla() {
    var kt = null, kp = null;
    try { kt = localStorage.getItem('osint_tema'); kp = localStorage.getItem('osint_panel'); } catch (e) {}
    S.tema = kt || 'gece';
    document.documentElement.setAttribute('data-tema', S.tema);
    temaCiz();
    amblemCiz();
    $$('.menuDug').forEach(function (b) {
      b.onclick = function () { panelAc(b.getAttribute('data-panel')); };
    });
    setInterval(function () { $('rozetSaat').textContent = saat(); }, 1000);
    $('rozetSaat').textContent = saat();

    // panel modülleri
    if (window.Tarama) Tarama.kur();
    if (window.Yuzey) S.yuzey = Yuzey.kur();
    if (window.Dunya) S.dunya = Dunya.kur();
    if (window.Alarm) Alarm.kur();
    if (window.Log) Log.kur();
    if (window.Olay) Olay.kur();
    if (window.Rapor) Rapor.kur();
    if (window.Ayar) Ayar.kur();

    OS.S.kopruVar = kopruAktif();
    durumYenile().then(function () { Ayar.onayGeriYukle(); });
    var baslangic = kp || 'gosterge';
    if (location.hash && location.hash.length > 1) {
      var h = location.hash.slice(1);
      if (document.getElementById('p-' + h)) baslangic = h;
    }
    panelAc(baslangic, true);
    balon('🛰️ <b>ÜSTAD OSINT</b> hazır · panel sayısı: 11');
  }

  return {
    S: S, $: $, $$: $$, api: api, sayi: sayi, kac: kac, saat: saat, balon: balon,
    tema: tema, temaCiz: temaCiz, panelAc: panelAc, gostergeCiz: gostergeCiz,
    durumYenile: durumYenile, riskHalka: riskHalka, onemCubuk: onemCubuk,
    menüSayac: menüSayac, olcu: olcu, amblemCiz: amblemCiz, basla: basla
  };
})();

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', OS.basla);
else OS.basla();
