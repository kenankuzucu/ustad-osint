/* ==========================================================================
   ÜSTAD OSINT — KÖPRÜ KATMANI (Android APK)
   Java köprüsü (window.Kopru) varsa /api istekleri yerelde karşılanır:
   tarama Java soketleriyle yapılır, analiz MOTOR (motor.js) ile üretilir.
   Köprü yoksa (PC/Kali sunucusu) hiçbir şey değişmez, fetch yolu kullanılır.
   ========================================================================== */
var KOPRU = (function () {

  var javaVar = (typeof window.Kopru !== 'undefined' && window.Kopru !== null);
  /* köprü sonradan da bağlanabilir (WebView hazır olma sırası) → dinamik bak */
  function jv() { return typeof window.Kopru !== 'undefined' && window.Kopru !== null; }
  var geoOnbellek = {};      /* ip → konum nesnesi */
  var disIpKonum = null;     /* kendi çıkış IP'mizin konumu */
  var onay = { verildi: false, metin: '', zaman: '', kapsam: [] };
  var isler = {};            /* id → iş durumu */
  var sayac = 0;
  var yerel = { ip: '127.0.0.1', altAg: '127.0.0.0/24' };
  var surum = '1.0';

  function uid() { sayac++; return 'apk' + Date.now().toString(36).slice(-5) + sayac; }

  function yerelBilgiAl() {
    try {
      if (jv() && window.Kopru.yerelBilgi) {
        var d = JSON.parse(window.Kopru.yerelBilgi() || '{}');
        if (d.ip) yerel = d;
        if (d.surum) surum = d.surum;
      }
    } catch (e) { }
  }

  /* --------------------------- konum (ipwho.is) --------------------------- */
  function geoCek(ip, bitti) {
    var adres = ip ? ('https://ipwho.is/' + encodeURIComponent(ip)) : 'https://ipwho.is/';
    function isle(d) {
      if (!d || d.success === false || !d.ip) { bitti(null); return; }
      var k = {
        ip: d.ip, tur: MOTOR.ozelIp(d.ip) ? 'ozel' : 'genel',
        enlem: (typeof d.latitude === 'number') ? d.latitude : null,
        boylam: (typeof d.longitude === 'number') ? d.longitude : null,
        ulke: d.country || '', ulkeKod: d.country_code || '', sehir: d.city || '',
        iss: (d.connection && d.connection.isp) || '', kaynak: 'ipwho.is', kendi: !ip
      };
      geoOnbellek[k.ip] = k;
      bitti(k);
    }
    /* Android: köprü üzerinden (CORS yok, WebView ayarlarından bağımsız) */
    if (jv() && window.Kopru.veriCek) {
      try {
        window.Kopru.veriCek(adres, registerCb(function (govde) {
          var d = null;
          try { d = JSON.parse(govde || 'null'); } catch (e) { d = null; }
          isle(d);
        }));
        return;
      } catch (e) { /* köprü düşerse fetch yoluna devam */ }
    }
    fetch(adres, { cache: 'no-store' }).then(function (r) { return r.json(); }).then(isle)
      .catch(function () { bitti(null); });
  }

  function disIpAl() {
    if (disIpKonum && disIpKonum.enlem !== null) return;
    geoCek(null, function (k) {
      if (k) disIpKonum = k;
      try { window.dispatchEvent(new CustomEvent('osint-geo-guncel')); } catch (e) { }
    });
  }

  /* ------------------------------ tarama işi ------------------------------ */
  function isOlustur(hedefler, mod, ekPortlar) {
    var id = uid();
    isler[id] = {
      id: id, durum: 'calisiyor', asama: 'hedefler çözümleniyor', yuzde: 2,
      baslangic: MOTOR.simdi(), bitis: null, motor: 'yerleşik',
      hedefler: hedefler, portMod: mod, loglar: [], hata: null,
      hostlar: [], alarmlar: [], iocler: [], geo: [], graf: { dugumler: [], kenarlar: [] },
      risk: 0, riskNedenleri: []
    };
    return isler[id];
  }

  function log(is, metin) {
    is.loglar.push({ zaman: MOTOR.simdi(), metin: metin });
    if (is.loglar.length > 400) is.loglar = is.loglar.slice(-400);
  }

  function taramaBaslat(govde) {
    var hedefler = govde.hedefler || '';
    var mod = govde.portlarMod || govde.mod || 'hizli';
    var ek = govde.ekPortlar || '';
    var is = isOlustur(hedefler, mod, ek);
    var portlar = MOTOR.portListesi(mod, ek);
    var hedefListesi = String(hedefler).split(/[,\s]+/).filter(function (x) { return x.trim(); });

    is.zaman_asimi = govde.zamanAsimi || 900;
    is.banner = (mod !== 'tam');

    /* 1. adım: hedef çözümleme (alan adları Java DNS ile) */
    var ipListesi = [], bekleyenAdlar = [];
    hedefListesi.forEach(function (h) {
      var r = MOTOR.hedefCoz(h);
      if (r.length) ipListesi = ipListesi.concat(r);
      else bekleyenAdlar.push(h);
    });

    function adlariCoz(geriDon) {
      if (!bekleyenAdlar.length || !jv() || !window.Kopru.adCoz) { geriDon(); return; }
      var kalan = bekleyenAdlar.length;
      bekleyenAdlar.forEach(function (ad) {
        try {
          window.Kopru.adCoz(ad, registerCb(function (ip) {
            if (ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
              ipListesi.push(ip);
              log(is, ad + ' → ' + ip);
            } else {
              log(is, 'atlandı: ' + ad + ' (çözümlenemedi)');
            }
            if (--kalan === 0) geriDon();
          }));
        } catch (e) { if (--kalan === 0) geriDon(); }
      });
    }

    function tekille() {
      var g = {}, t = [];
      ipListesi.forEach(function (ip) { if (!g[ip]) { g[ip] = 1; t.push(ip); } });
      ipListesi = t.sort(function (a, b) {
        var A = a.split('.').map(Number), B = b.split('.').map(Number);
        for (var i = 0; i < 4; i++) if (A[i] !== B[i]) return A[i] - B[i];
        return 0;
      });
    }

    adlariCoz(function () {
      tekille();
      if (!ipListesi.length) {
        is.durum = 'hata'; is.hata = 'Geçerli hedef bulunamadı'; is.yuzde = 0;
        return;
      }
      log(is, ipListesi.length + ' hedef çözümlendi');
      is.asama = 'canlı cihazlar aranıyor'; is.yuzde = 5;
      kesif(ipListesi, function (canli) {
        if (!canli.length && ipListesi.length <= 4) {
          canli = ipListesi;
          log(is, 'canlı tespiti boş döndü; verilen hedefler yine de taranıyor');
        }
        log(is, canli.length + ' canlı cihaz');
        if (!canli.length) {
          is.durum = 'bitti'; is.asama = 'tamamlandı (canlı cihaz yok)'; is.yuzde = 100;
          is.bitis = MOTOR.simdi();
          return;
        }
        is.asama = 'portlar taranıyor'; is.yuzde = 12;
        portTaraHepsi(canli, portlar, is, function (hamHostlar) {
          is.asama = 'risk ve alarm motoru çalışıyor'; is.yuzde = 82;
          var a = MOTOR.analiz(hamHostlar, is.id, yerel.ip);
          is.hostlar = a.hostlar; is.alarmlar = a.alarmlar; is.iocler = a.iocler;
          is.risk = a.risk; is.riskNedenleri = a.riskNedenleri; is.graf = a.graf;
          is.asama = 'IP konumları çözümleniyor'; is.yuzde = 92;
          konumlariTopla(is, function () {
            is.durum = 'bitti'; is.asama = 'tamamlandı'; is.yuzde = 100; is.bitis = MOTOR.simdi();
            log(is, 'tarama tamamlandı: ' + is.hostlar.length + ' cihaz, ' + is.alarmlar.length + ' alarm');
            try { window.dispatchEvent(new CustomEvent('osint-geo-guncel')); } catch (e) { }
          });
        });
      });
    }, registerCb);

    return is;
  }

  var geriSayac = 0;
  function registerCb(fn) {
    geriSayac++;
    var ad = '__uosint_cb_' + geriSayac;
    window[ad] = function (x) {
      try { delete window[ad]; } catch (e) { window[ad] = null; }
      try { fn(x); } catch (e) { if (window.console) console.log('köprü geri çağrı hatası', e); }
    };
    return ad;
  }

  /* canlı cihaz keşfi */
  function kesif(ipListesi, bitti) {
    var canli = [], islemde = 0, sira = 0;
    var kesifPortlari = '80,443,22,445,3389,8080,53,8008,5000';
    function yeni() {
      if (sira >= ipListesi.length) {
        if (islemde === 0) bitti(canli);
        return;
      }
      var ip = ipListesi[sira++];
      islemde++;
      try {
        window.Kopru.portTara(ip, kesifPortlari, registerCb(function (liste) {
          try {
            var arr = JSON.parse(liste || '[]');
            if (arr.length) canli.push(ip);
          } catch (e) { }
          islemde--;
          yeni();
        }));
      } catch (e) { islemde--; yeni(); }
    }
    for (var i = 0; i < 24; i++) yeni();
    if (!ipListesi.length) bitti([]);
  }

  /* port taraması: cihaz başına Java çağrısı, iki cihaz paralel */
  function portTaraHepsi(canli, portlar, is, bitti) {
    var ham = [], sira = 0, islemde = 0, tamam = 0;
    var csv = portlar.join(',');
    function yeni() {
      if (sira >= canli.length) {
        if (islemde === 0) bitti(ham);
        return;
      }
      var ip = canli[sira++];
      islemde++;
      try {
        window.Kopru.taramaYap(ip, csv, is.zaman_asimi, is.banner ? '1' : '0', registerCb(function (json) {
          try {
            var liste = JSON.parse(json || '[]');
            if (liste.length) {
              ham.push({ ip: ip, ad: '', isletim: '', portlar: liste });
              log(is, ip + ': ' + liste.length + ' açık port');
            } else {
              log(is, ip + ': açık port yok');
            }
          } catch (e) { log(is, ip + ': yanıt çözümlenemedi'); }
          tamam++;
          is.yuzde = Math.min(80, 12 + Math.floor(68 * tamam / Math.max(1, canli.length)));
          islemde--;
          yeni();
        }));
      } catch (e) { islemde--; tamam++; yeni(); }
    }
    for (var i = 0; i < 2; i++) yeni();
    if (!canli.length) bitti([]);
  }

  /* konumları topla (genel adresler + kendi çıkış IP'miz) */
  function konumlariTopla(is, bitti) {
    var liste = [];
    is.hostlar.forEach(function (h) {
      if (MOTOR.ozelIp(h.ip)) {
        liste.push({ ip: h.ip, tur: 'ozel', ulke: 'Yerel ağ (özel adres)', sehir: '', enlem: null, boylam: null, iss: '', kaynak: 'yerel' });
      } else {
        liste.push(null);
      }
    });
    is.geo = liste.filter(function (x) { return x; });
    var genel = is.hostlar.filter(function (h) { return !MOTOR.ozelIp(h.ip); });
    var kalan = genel.length + 1;
    function son() {
      if (--kalan > 0) return;
      if (disIpKonum) is.geo.push(disIpKonum);
      else if (MOTOR.ozelIp(yerel.ip)) {
        is.geo.push({ ip: yerel.ip, tur: 'ozel', ulke: 'Yerel ağ (özel adres)', sehir: '', enlem: null, boylam: null, iss: '', kaynak: 'yerel' });
      }
      bitti();
    }
    genel.forEach(function (h) {
      geoCek(h.ip, function (k) {
        if (k) is.geo.push(k);
        son();
      });
    });
    geoCek(null, function (k) {
      if (k) disIpKonum = k;
      son();
    });
  }

  /* ======================================================================
     OSINT ÇEKİRDEĞİ YÖNLENDİRMESİ — /api/arac/*
     Python (osint-araclar.py) uçlarının telefonda karşılığı: motor-osint.js
     Ağ işleri eşzamanlı (async) olduğu için:
       • OS.api('/api/arac/...') çağrıları Promise dönecek şekilde sarılır,
       • KOPRU.istek() eşzamanlı sözleşmesi için sonuç önbelleği tutulur.
     ====================================================================== */
  var ARAC_YOL = '/api/arac/';
  var ARAC_ONBELLEK = {};
  var motorYukleniyor = false, motorBekleyen = [];

  function motorAl(cb) {
    if (typeof window !== 'undefined' && window.OSINT_MOTOR) { cb(window.OSINT_MOTOR); return; }
    motorBekleyen.push(cb);
    if (motorYukleniyor) return;
    motorYukleniyor = true;
    /* index.html değiştirilmeden yüklenir (APK assets klasöründe dosya mevcut) */
    try {
      var s = document.createElement('script');
      s.src = 'motor-osint.js';
      s.async = true;
      s.onload = motorDagit;
      s.onerror = motorDagit;
      (document.head || document.documentElement).appendChild(s);
    } catch (e) { }
    /* yüklenemezse (dosya yok) bekleyenlere boş dön */
    setTimeout(function () { motorDagit(true); }, 2500);
  }

  function motorDagit(zorla) {
    var M = (typeof window !== 'undefined') ? window.OSINT_MOTOR : null;
    if (!M && !zorla) return;
    var kuyruk = motorBekleyen;
    motorBekleyen = [];
    kuyruk.forEach(function (cb) { try { cb(M); } catch (e) { } });
  }

  function sorguCoz(yol) {
    var s = {};
    var i = String(yol || '').indexOf('?');
    if (i < 0) return s;
    String(yol).slice(i + 1).split('&').forEach(function (par) {
      if (!par) return;
      var p = par.split('=');
      try { s[decodeURIComponent(p[0])] = decodeURIComponent(p.slice(1).join('=') || ''); }
      catch (e) { s[p[0]] = p.slice(1).join('=') || ''; }
    });
    return s;
  }

  function ayarlarAl() {
    var a = {};
    try {
      a.github_anahtar = localStorage.getItem('osint_github_anahtar') || '';
      a.hibp_anahtar = localStorage.getItem('osint_hibp_anahtar') || '';
    } catch (e) { }
    return a;
  }

  /* /api/arac/* → Promise<veri>. Köprü yoksa da motor.js çalışır (fetch yolu). */
  function aracIstek(yol, govdeMetni) {
    var hamYol = String(yol || '');
    var anahtar = hamYol + (govdeMetni || '');   /* KOPRU.istek önbelleğiyle aynı anahtar */
    var govde = {};
    try { govde = govdeMetni ? JSON.parse(govdeMetni) : {}; } catch (e) { govde = {}; }
    var sorgu = sorguCoz(hamYol);
    var temizYol = hamYol.split('?')[0];
    return new Promise(function (coz) {
      motorAl(function (M) {
        if (!M || typeof M.uclariIsle !== 'function') {
          coz({ hata: 'OSINT çekirdeği (motor-osint.js) yüklenemedi — Python sunucusu yoksa /api/arac uçları telefonda bu dosyaya bağlıdır.' });
          return;
        }
        M.uclariIsle(temizYol, sorgu, govde, ayarlarAl()).then(function (v) {
          ARAC_ONBELLEK[anahtar] = v || {};
          coz(v || {});
        }, function (e) {
          coz({ hata: String((e && e.message) || e) });
        });
      });
    });
  }

  /* OS.api'yi sar: Java köprüsü varken /api/arac istekleri motora gider */
  function apiSar(deneme) {
    deneme = deneme || 0;
    if (typeof window === 'undefined') return;
    if (typeof window.OS === 'undefined' || typeof window.OS.api !== 'function') {
      if (deneme < 6) setTimeout(function () { apiSar(deneme + 1); }, 400);
      return;
    }
    if (window.OS.__aracSarildi) return;
    var eski = window.OS.api;
    window.OS.api = function (yol, secenek) {
      secenek = secenek || {};
      if (jv() && typeof yol === 'string' && yol.indexOf(ARAC_YOL) === 0) {
        return aracIstek(yol, secenek.govde ? JSON.stringify(secenek.govde) : '');
      }
      return eski.call(window.OS, yol, secenek);
    };
    window.OS.__aracSarildi = true;
  }
  apiSar();

  /* ------------------------------ /api yönlendirme ------------------------------ */
  function durum() {
    return {
      surum: surum, yerelIp: yerel.ip, altAg: yerel.altAg, isletim: 'Android',
      python: '-', nmap: null, motor: 'yerleşik',
      onay: onay, taramaSayisi: Object.keys(isler).length,
      taramaMotorlari: ['telefon soket motoru'], disIp: disIpKonum,
      kopru: true
    };
  }

  function istek(yol, govdeMetni) {
    var govde = {};
    try { govde = govdeMetni ? JSON.parse(govdeMetni) : {}; } catch (e) { }

    if (yol === '/api/durum') { disIpAl(); return JSON.stringify(durum()); }

    if (yol === '/api/onay') {
      onay = {
        verildi: !!(govde.onay), metin: govde.metin || '',
        zaman: MOTOR.simdi(), kapsam: (govde.metin || '').split(/[,\s]+/).filter(Boolean)
      };
      return JSON.stringify({ tamam: true, onay: onay });
    }

    if (yol === '/api/tarama') {
      if (!onay.verildi) return JSON.stringify({ hata: 'Kapsam onayı verilmedi.' });
      var is = taramaBaslat(govde);
      return JSON.stringify({ id: is.id });
    }

    if (yol.indexOf('/api/tarama/') === 0) {
      var parcalar = yol.split('/');
      var id = parcalar[3] || '';
      var kayit = isler[id];
      if (parcalar[4] === 'dur') {
        if (kayit) { kayit.durum = 'iptal'; kayit.asama = 'kullanıcı iptal etti'; }
        return JSON.stringify({ tamam: true });
      }
      if (!kayit) return JSON.stringify({ hata: 'tarama bulunamadı' });
      var kopya = JSON.parse(JSON.stringify(kayit));
      kopya.sayilar = {
        cihaz: kayit.hostlar.length,
        acikPort: kayit.hostlar.reduce(function (t, h) { return t + h.portlar.length; }, 0),
        alarm: kayit.alarmlar.length,
        kritik: kayit.alarmlar.filter(function (a) { return a.onem === 'kritik'; }).length,
        ioc: kayit.iocler.length,
        konum: kayit.geo.filter(function (g) { return g.enlem !== null && g.enlem !== undefined; }).length
      };
      kopya.loglar = kayit.loglar.slice(-40);
      return JSON.stringify(kopya);
    }

    if (yol.indexOf('/api/geo/') === 0) {
      var ip = yol.split('/')[3];
      if (geoOnbellek[ip]) return JSON.stringify(geoOnbellek[ip]);
      geoCek(ip, function () { });
      return JSON.stringify({ ip: ip, bekliyor: true, ulke: 'sorgulanıyor…', enlem: null, boylam: null });
    }

    if (yol === '/api/logcoz') {
      return JSON.stringify(MOTOR.logCoz(govde.metin || '', govde.kaynak || ''));
    }

    /* --- OSINT araçları (/api/arac/*) — Python uçlarının telefon karşılığı --- */
    if (yol.indexOf(ARAC_YOL) === 0) {
      var anahtar = yol + (govdeMetni || '');
      if (ARAC_ONBELLEK[anahtar]) return JSON.stringify(ARAC_ONBELLEK[anahtar]);
      /* ağ işi eşzamanlı: işi başlat, sonucu önbelleğe al; ilk çağrıda durum döner */
      aracIstek(yol, govdeMetni);
      return JSON.stringify({
        bekliyor: true, yol: yol,
        mesaj: 'OSINT çekirdeği çalışıyor… sonuç hazır olunca yeniden sorgulanır (OS.api bu yolu Promise ile bekler).'
      });
    }

    return JSON.stringify({ hata: 'bilinmeyen istek: ' + yol });
  }

  return {
    javaVar: javaVar, jv: jv,
    istek: istek,
    javaVarMi: jv,
    aracIstek: aracIstek,
    motorAl: motorAl,
    aracOnbellek: ARAC_ONBELLEK,
    modulListesi: function () {
      return (typeof window !== 'undefined' && window.OSINT_MOTOR)
        ? window.OSINT_MOTOR.MODUL_LISTESI : [];
    },
    basla: function () {
      if (!jv()) return;
      yerelBilgiAl();
      disIpAl();
      /* üst bilgi çubuğu köprü hazır olunca tazelensin */
      try { if (window.OS && OS.durumYenile) OS.durumYenile(true); } catch (e) { }
    },
    durum: durum,
    isler: isler
  };
})();
if (typeof window !== 'undefined') {
  window.KOPRU = KOPRU;
  /* köprü geç bağlanırsa (WebView) iki kez yeniden dene */
  try {
    KOPRU.basla();
    setTimeout(function () { KOPRU.basla(); }, 900);
    setTimeout(function () { KOPRU.basla(); }, 2500);
  } catch (e) { }
}
