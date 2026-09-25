/* ==========================================================================
   ÜSTAD OSINT — OSINT ÇEKİRDEĞİ (JS) : motor-osint.js
   osint-araclar.py (SÜRÜM 1.2) dosyasının birebir JS uyarlaması.
   Telefonda (APK) Python yoktur; bu dosya aynı toplayıcıları aynı şemayla üretir.

   Taşıma katmanı:
     • Java köprüsü varsa (window.Kopru) → veriCekTam (kod + başlıklar + gövde),
       yoksa veriCek (yalnız gövde), POST için veriGonder. CORS yok.
     • Köprü yoksa → fetch (tarayıcı). Bazı kaynaklar CORS başlığı göndermediği
       için boş döner; sonuç şeması yine aynıdır (alanlar boş kalır).

   Python ile birebir eşleşen dönüş şemaları:
     dnsToplu, whoisRdap, ipAnaliz, subdomainTara, webTek, cloudAra,
     epostaIstihbarat, kullaniciAra, githubIstihbarat, sizintiTara,
     darkwebAra, tehditVerisi, profilCikar, uclariIsle,
     EK (v1.5): pasifRadar, cveEsle, arsivWayback, urlscanAra, takeoverTara,
     savunmaKurallari, topluTarama, kanitEkle,
     EK2 (v1.6 · osint-ek2a/b/c.py): istismarSorgu, postaGuvenlik, baslikAnaliz,
     sertifikaAltAlanlar, webZafiyet, fidyeIzleme, saldiriAkisi, sirAvcisi,
     yerelAg, sifreKontrol, raporPaket, bildirimIsle → ek2Isle
   ========================================================================== */
var OSINT_MOTOR = (function () {
  'use strict';

  var SURUM = '1.2';
  var UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) USTAD-OSINT/1.2';

  /* ------------------------------------------------------------------ */
  /*  yardımcılar (Python: _kok, _alan_bul, ozel_ip, _cek, _json)        */
  /* ------------------------------------------------------------------ */
  function simdi() {
    var d = new Date();
    function p(n) { return (n < 10 ? '0' : '') + n; }
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
      p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  function yuvarlak(x, hane) {
    var f = Math.pow(10, hane === undefined ? 2 : hane);
    return Math.round(x * f) / f;
  }

  function simdiMs() { return (typeof Date !== 'undefined' ? Date.now() : 0); }

  function kok(hedef) {
    /* 'https://www.ornek.com/yol' → ('ornek.com', 'https://www.ornek.com/yol') */
    var h = String(hedef == null ? '' : hedef).trim();
    if (!h) return ['', ''];
    if (h.indexOf('://') < 0) h = 'http://' + h;
    var ad = '';
    try {
      var m = h.match(/^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\/([^\/?#]*)/);
      var otorite = m ? m[1] : '';
      if (otorite.indexOf('@') >= 0) otorite = otorite.split('@').pop();
      otorite = otorite.replace(/^\[/, '').replace(/\].*$/, '');
      ad = otorite.split(':')[0];
    } catch (e) { ad = ''; }
    return [String(ad).toLowerCase(), h];
  }

  function alanBul(hedef) {
    var r = kok(hedef), ad = r[0];
    if (!ad && String(hedef || '').indexOf('@') >= 0) {
      ad = String(hedef).split('@').pop().trim().toLowerCase();
    }
    return String(ad).replace(/^\.+/, '').replace(/\.+$/, '');
  }

  function ozelIp(ip) {
    var s = String(ip == null ? '' : ip).trim();
    if (!s) return true;
    if (s.indexOf(':') >= 0) {
      var k = s.toLowerCase();
      if (k === '::1' || k === '::') return true;
      if (k.indexOf('fc') === 0 || k.indexOf('fd') === 0) return true;   /* ULA */
      if (k.indexOf('fe80') === 0) return true;                          /* bağlantı yerel */
      if (k.indexOf('ff') === 0) return true;                            /* çok yayın */
      return false;
    }
    var p = s.split('.');
    if (p.length !== 4) return true;
    var a = [], i;
    for (i = 0; i < 4; i++) {
      var n = parseInt(p[i], 10);
      if (isNaN(n) || n < 0 || n > 255 || String(n) !== p[i].replace(/^0+(?=\d)/, '')) return true;
      a.push(n);
    }
    if (a[0] === 0 || a[0] === 10 || a[0] === 127) return true;
    if (a[0] === 100 && a[1] >= 64 && a[1] <= 127) return true;
    if (a[0] === 169 && a[1] === 254) return true;
    if (a[0] === 172 && a[1] >= 16 && a[1] <= 31) return true;
    if (a[0] === 192 && a[1] === 168) return true;
    if (a[0] === 192 && a[1] === 0 && a[2] === 0) return true;
    if (a[0] === 192 && a[1] === 0 && a[2] === 2) return true;
    if (a[0] === 198 && (a[1] === 18 || a[1] === 19)) return true;
    if (a[0] === 198 && a[1] === 51 && a[2] === 100) return true;
    if (a[0] === 203 && a[1] === 0 && a[2] === 113) return true;
    if (a[0] >= 224) return true;                                       /* çok yayın + ayrılmış */
    return false;
  }

  function ipMi(s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(s || '').trim()); }

  /* --------------------------- taşıma katmanı --------------------------- */
  var cbSayac = 0;
  function cbKaydet(fn) {
    cbSayac++;
    var ad = '__uosintm_' + cbSayac + '_' + Math.floor(Math.random() * 1000);
    var K = (typeof window !== 'undefined') ? window : (typeof global !== 'undefined' ? global : null);
    if (!K) return null;
    K[ad] = function (x) {
      try { delete K[ad]; } catch (e) { K[ad] = null; }
      try { fn(x); } catch (e) { if (K.console) K.console.log('motor-osint geri çağrı hatası', e); }
    };
    return ad;
  }

  function kopruVarMi() {
    if (typeof window === 'undefined') return false;
    var K = window.Kopru;
    if (!K) return false;
    return typeof K.veriCekTam === 'function' || typeof K.veriCek === 'function' ||
      typeof K.veriGonder === 'function';
  }

  function yontemVar(ad) {
    if (typeof window === 'undefined') return false;
    return !!(window.Kopru && typeof window.Kopru[ad] === 'function');
  }

  function zamanAsimi(p, ms) {
    return new Promise(function (coz) {
      var bitti = false;
      var z = setTimeout(function () {
        if (bitti) return;
        bitti = true;
        coz({ kod: 0, govde: '', basliklar: {}, hata: 'zaman aşımı' });
      }, ms);
      p.then(function (d) {
        if (bitti) return;
        bitti = true; clearTimeout(z); coz(d);
      }, function (e) {
        if (bitti) return;
        bitti = true; clearTimeout(z);
        coz({ kod: 0, govde: '', basliklar: {}, hata: String((e && e.message) || e) });
      });
    });
  }

  function norm(d) {
    /* köprü/fetch yanıtını {kod, govde, basliklar} biçimine getirir */
    var o = { kod: 0, govde: '', basliklar: {} };
    if (d == null) return o;
    if (typeof d === 'string') {
      var t = d;
      try { t = JSON.parse(d); } catch (e) { t = d; }
      if (typeof t === 'string') { o.govde = t; o.kod = t ? 200 : 0; return o; }
      return norm(t);
    }
    if (typeof d === 'object') {
      if (typeof d.kod !== 'undefined') o.kod = parseInt(d.kod, 10) || 0;
      else if (d.status !== undefined) o.kod = parseInt(d.status, 10) || 0;
      o.govde = (typeof d.govde === 'string') ? d.govde : (d.body !== undefined ? String(d.body) : '');
      if (d.basliklar && typeof d.basliklar === 'object') {
        Object.keys(d.basliklar).forEach(function (k) {
          o.basliklar[String(k).toLowerCase()] = d.basliklar[k];
        });
      }
      if (d.hata) o.hata = String(d.hata);
      if (d.sure !== undefined) o.sure = d.sure;
    }
    return o;
  }

  function kopruCek(url, veri, tip) {
    return new Promise(function (coz) {
      var K = window.Kopru;
      try {
        if (veri && typeof K.veriGonder === 'function') {
          K.veriGonder(url, veri, tip || 'application/json', cbKaydet(function (y) { coz(norm(y)); }));
          return;
        }
        if (typeof K.veriCekTam === 'function') {
          K.veriCekTam(url, cbKaydet(function (y) { coz(norm(y)); }));
          return;
        }
        if (typeof K.veriCek === 'function') {
          /* yalnız gövde döner: durum kodu ve başlık yoktur */
          K.veriCek(url, cbKaydet(function (y) {
            var o = norm(y);
            if (!o.kod) o.kod = o.govde ? 200 : 0;
            o.baslik_yok = true;
            coz(o);
          }));
          return;
        }
        coz({ kod: 0, govde: '', basliklar: {}, hata: 'köprü ağ metodu yok' });
      } catch (e) {
        coz({ kod: 0, govde: '', basliklar: {}, hata: String((e && e.message) || e) });
      }
    });
  }

  function fetchCek(url, veri, tip, secenek) {
    secenek = secenek || {};
    if (typeof fetch !== 'function') {
      return Promise.resolve({ kod: 0, govde: '', basliklar: {}, hata: 'fetch yok' });
    }
    var yontem = veri ? 'POST' : (secenek.tip ? String(secenek.tip).toUpperCase() : 'GET');
    var ayar = { method: yontem, cache: 'no-store', headers: {} };
    /* Python _cek() her istekte UA gönderir; bazı kaynaklar (rdap.org) UA'sızı 403'ler.
       Tarayıcı fetch'i User-Agent'ı yok sayar (yasak başlık), zararsızdır. */
    ayar.headers['User-Agent'] = UA;
    ayar.headers['Accept'] = '*/*';
    if (secenek.basliklar) {
      Object.keys(secenek.basliklar).forEach(function (k) { ayar.headers[k] = secenek.basliklar[k]; });
    }
    if (veri) {
      ayar.body = veri;
      ayar.headers['Content-Type'] = tip || 'application/x-www-form-urlencoded';
    }
    var t0 = simdiMs();
    return fetch(url, ayar).then(function (r) {
      var bas = {};
      try {
        if (r.headers && r.headers.forEach) {
          r.headers.forEach(function (v, k) { bas[String(k).toLowerCase()] = v; });
        }
      } catch (e) { }
      return r.text().then(function (t) {
        return { kod: r.status, govde: t, basliklar: bas, sure: yuvarlak((simdiMs() - t0) / 1000) };
      });
    }).catch(function (e) {
      return { kod: 0, govde: '', basliklar: {}, hata: String((e && e.message) || e), sure: yuvarlak((simdiMs() - t0) / 1000) };
    });
  }

  /* Python _cek(): → Promise({kod, govde, basliklar, sure})  (hata: kod 0) */
  function _cek(url, secenek) {
    secenek = secenek || {};
    var t0 = simdiMs();
    var zaman = (secenek.zaman || 12) * 1000;
    var veri = (secenek.veri === undefined) ? null : secenek.veri;
    var tip = secenek.tip || (veri != null ? 'application/x-www-form-urlencoded' : null);
    var is;
    if (kopruVarMi()) is = kopruCek(url, veri, tip);
    else is = fetchCek(url, veri, tip, secenek);
    return zamanAsimi(is, zaman + 5000).then(function (d) {
      if (d.sure === undefined) d.sure = yuvarlak((simdiMs() - t0) / 1000);
      if (!d.basliklar) d.basliklar = {};
      if (typeof d.govde !== 'string') d.govde = d.govde == null ? '' : String(d.govde);
      /* Python _cek(): y.read(2000000) — gövde 2 MB'ta kesilir */
      if (d.govde.length > 2000000) d.govde = d.govde.slice(0, 2000000);
      return d;
    });
  }

  function _json(url, secenek) {
    return _cek(url, secenek).then(function (d) {
      var j = null;
      try { j = JSON.parse(d.govde); } catch (e) { j = null; }
      return { kod: d.kod, j: j, sure: d.sure, basliklar: d.basliklar, govde: d.govde };
    });
  }

  /* Python: socket.gethostbyname — köprüde adCoz, yoksa DoH A kaydı */
  function adCoz(ad) {
    return new Promise(function (coz) {
      if (yontemVar('adCoz')) {
        try {
          window.Kopru.adCoz(ad, cbKaydet(function (ip) {
            coz(String(ip == null ? '' : ip).trim());
          }));
          return;
        } catch (e) { }
      }
      coz('');
    });
  }

  function hedefIpCoz(ad) {
    return adCoz(ad).then(function (ip) {
      if (ip && /\d+\.\d+\.\d+\.\d+/.test(ip)) return ip.match(/\d+\.\d+\.\d+\.\d+/)[0];
      return dnsSorgu(ad, 'A').then(function (r) {
        return (r.kayitlar[0] || {}).deger || '';
      });
    });
  }

  /* ThreadPoolExecutor karşılığı: eş zamanlı havuz */
  function havuz(liste, isci, esZamanli) {
    esZamanli = esZamanli || 8;
    return new Promise(function (coz) {
      var n = liste.length;
      if (!n) { coz([]); return; }
      var sonuc = new Array(n), i = 0, acik = 0, biten = 0, kapandi = false;
      function sonraki() {
        while (acik < esZamanli && i < n) {
          (function (ix) {
            acik++;
            Promise.resolve()
              .then(function () { return isci(liste[ix], ix); })
              .then(function (r) { sonuc[ix] = r; }, function () { sonuc[ix] = null; })
              .then(function () {
                acik--; biten++;
                if (biten === n) { if (!kapandi) { kapandi = true; coz(sonuc); } return; }
                sonraki();
              });
          })(i++);
        }
      }
      sonraki();
    });
  }

  /* ------------------------------- MD5 ------------------------------- */
  /* Gravatar izi için (Python: hashlib.md5). WebCrypto MD5 desteklemez. */
  function md5(metin) {
    var T = [];
    for (var i = 0; i < 64; i++) T.push(Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296));
    function rl(x, c) { return (x << c) | (x >>> (32 - c)); }
    function ad(x, y) { return (x + y) | 0; }
    function cmn(q, a, b, x, s, t) { return ad(rl(ad(ad(a, q), ad(x, t)), s), b); }
    function ff(a, b, c, d, x, s, t) { return cmn((b & c) | (~b & d), a, b, x, s, t); }
    function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & ~d), a, b, x, s, t); }
    function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
    function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | ~d), a, b, x, s, t); }

    var bayt = [], s8 = unescape(encodeURIComponent(String(metin)));
    for (var i = 0; i < s8.length; i++) bayt.push(s8.charCodeAt(i) & 0xFF);
    var bitUzunluk = bayt.length * 8;
    bayt.push(0x80);
    while (bayt.length % 64 !== 56) bayt.push(0);
    var dusuk = bitUzunluk >>> 0, yuksek = Math.floor(bitUzunluk / 4294967296) >>> 0;
    for (var i = 0; i < 4; i++) bayt.push((dusuk >>> (8 * i)) & 0xFF);
    for (var i = 0; i < 4; i++) bayt.push((yuksek >>> (8 * i)) & 0xFF);

    var A = 0x67452301, B = 0xefcdab89 | 0, C = 0x98badcfe | 0, D = 0x10325476;
    var S1 = [7, 12, 17, 22], S2 = [5, 9, 14, 20], S3 = [4, 11, 16, 23], S4 = [6, 10, 15, 21];
    for (var blok = 0; blok < bayt.length / 64; blok++) {
      var x = [];
      for (var j = 0; j < 16; j++) {
        var o = blok * 64 + j * 4;
        x.push(bayt[o] | (bayt[o + 1] << 8) | (bayt[o + 2] << 16) | (bayt[o + 3] << 24));
      }
      var a = A, b = B, c = C, d = D, k, kk;
      for (k = 0; k < 16; k++) {
        if (k % 4 === 0) a = ff(a, b, c, d, x[k], S1[0], T[k]);
        else if (k % 4 === 1) d = ff(d, a, b, c, x[k], S1[1], T[k]);
        else if (k % 4 === 2) c = ff(c, d, a, b, x[k], S1[2], T[k]);
        else b = ff(b, c, d, a, x[k], S1[3], T[k]);
      }
      for (k = 0; k < 16; k++) {
        kk = (1 + 5 * k) % 16;
        if (k % 4 === 0) a = gg(a, b, c, d, x[kk], S2[0], T[16 + k]);
        else if (k % 4 === 1) d = gg(d, a, b, c, x[kk], S2[1], T[16 + k]);
        else if (k % 4 === 2) c = gg(c, d, a, b, x[kk], S2[2], T[16 + k]);
        else b = gg(b, c, d, a, x[kk], S2[3], T[16 + k]);
      }
      for (k = 0; k < 16; k++) {
        kk = (5 + 3 * k) % 16;
        if (k % 4 === 0) a = hh(a, b, c, d, x[kk], S3[0], T[32 + k]);
        else if (k % 4 === 1) d = hh(d, a, b, c, x[kk], S3[1], T[32 + k]);
        else if (k % 4 === 2) c = hh(c, d, a, b, x[kk], S3[2], T[32 + k]);
        else b = hh(b, c, d, a, x[kk], S3[3], T[32 + k]);
      }
      for (k = 0; k < 16; k++) {
        kk = (7 * k) % 16;
        if (k % 4 === 0) a = ii(a, b, c, d, x[kk], S4[0], T[48 + k]);
        else if (k % 4 === 1) d = ii(d, a, b, c, x[kk], S4[1], T[48 + k]);
        else if (k % 4 === 2) c = ii(c, d, a, b, x[kk], S4[2], T[48 + k]);
        else b = ii(b, c, d, a, x[kk], S4[3], T[48 + k]);
      }
      A = ad(A, a); B = ad(B, b); C = ad(C, c); D = ad(D, d);
    }
    function hex(x) {
      var s = '';
      for (var i = 0; i < 4; i++) s += ('0' + ((x >>> (8 * i)) & 0xFF).toString(16)).slice(-2);
      return s;
    }
    return hex(A) + hex(B) + hex(C) + hex(D);
  }

  /* ------------------------------------------------------------------ */
  /*  1) DNS (DoH)                                                       */
  /* ------------------------------------------------------------------ */
  var DNS_TIPLERI = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'SRV'];

  function dnsSorgu(ad, tip) {
    tip = tip || 'A';
    var url = 'https://dns.google/resolve?name=' + encodeURIComponent(ad) + '&type=' + tip;
    return _json(url, { zaman: 10 }).then(function (r) {
      var j = r.j, kayitlar = [];
      if (j && typeof j === 'object') {
        var cevaplar = j.Answer || [];
        for (var i = 0; i < cevaplar.length; i++) {
          var c = cevaplar[i] || {};
          var deger = c.data === undefined ? '' : c.data;
          if (tip === 'TXT' && typeof deger === 'string') deger = deger.replace(/^"/, '').replace(/"$/, '');
          if (tip === 'MX' && typeof deger === 'string') deger = deger.split(' ').slice(1).join(' ').replace(/\.+$/, '');
          if (tip === 'SOA' && typeof deger === 'string') deger = deger.split(' ')[0];
          kayitlar.push({ ad: c.name || '', tip: c.type, deger: deger, ttl: c.TTL });
        }
      }
      return {
        tip: tip, kayitlar: kayitlar,
        durum: (j && typeof j === 'object') ? j.Status : null,
        sure: r.sure
      };
    });
  }

  function dnsToplu(ad) {
    return havuz(DNS_TIPLERI, function (t) { return dnsSorgu(ad, t); }, 9).then(function (liste) {
      var sonuc = {};
      DNS_TIPLERI.forEach(function (t, i) { sonuc[t] = liste[i] || { tip: t, kayitlar: [], durum: null, sure: 0 }; });
      function degerler(t, enFazla) {
        var d = [];
        (sonuc[t].kayitlar || []).forEach(function (k) { d.push(k.deger); });
        return d.slice(0, enFazla);
      }
      var ozet = {
        a: degerler('A', 12), aaaa: degerler('AAAA', 8), mx: degerler('MX', 12),
        ns: degerler('NS', 12), txt: degerler('TXT', 20), cname: degerler('CNAME', 6)
      };
      var uyari = [];
      var txtBirlesik = ozet.txt.join(' ').toLowerCase();
      if (txtBirlesik.indexOf('v=spf1') < 0) {
        uyari.push({ onem: 'yuksek', baslik: 'SPF kaydı yok', aciklama: 'E-posta sahteciliğine açık (spoofing).' });
      }
      if (txtBirlesik.indexOf('v=dmarc') < 0) {
        uyari.push({ onem: 'orta', baslik: 'DMARC kaydı yok', aciklama: 'Alan adı adına sahte e-posta gönderilebilir.' });
      }
      if (!ozet.mx.length) {
        uyari.push({ onem: 'bilgi', baslik: 'MX kaydı yok', aciklama: 'Bu alan adı e-posta kabul etmiyor.' });
      }
      return {
        ad: ad, kayitlar: sonuc, ozet: ozet, uyarilar: uyari,
        kaynak: 'dns.google DoH', zaman: simdi()
      };
    });
  }

  /* ------------------------------------------------------------------ */
  /*  2) WHOIS / RDAP                                                    */
  /* ------------------------------------------------------------------ */
  function whoisRdap(hedef) {
    var ad = alanBul(hedef);
    if (!ad) return Promise.resolve({ hata: 'hedef çözümlenemedi' });
    if (ipMi(ad)) return ipAnaliz(ad);
    var url = 'https://rdap.org/domain/' + encodeURIComponent(ad);
    return _json(url, { zaman: 15 }).then(function (r) {
      var j = r.j, sure = r.sure, kod = r.kod;
      if (!j || typeof j !== 'object') {
        return _json(url + '?format=json', { zaman: 15 }).then(function (r2) {
          return bitir(r2.j, r2.sure, r2.kod);
        });
      }
      return bitir(j, sure, kod);
    });

    function bitir(j, sure, kod) {
      if (!j || typeof j !== 'object') {
        return { ad: ad, hata: 'RDAP yanıtı alınamadı (kod ' + kod + ')', kaynak: 'rdap.org' };
      }
      var olay = {};
      var olaylar = j.events || [];
      for (var i = 0; i < olaylar.length; i++) {
        var o = olaylar[i] || {};
        olay[o.eventAction === undefined ? '?' : o.eventAction] = o.eventDate === undefined ? '' : o.eventDate;
      }
      var ns = [];
      var sunucular = j.nameservers || [];
      for (var i = 0; i < sunucular.length; i++) {
        ns.push(String((sunucular[i] || {}).ldhName || '').toLowerCase());
      }
      var kayitci = '', kisiler = [];
      var varliklar = j.entities || [];
      for (var i = 0; i < varliklar.length; i++) {
        var v = varliklar[i] || {};
        var roller = v.roles || [];
        var adV = '';
        if (v.vcardArray && v.vcardArray[1]) {
          var satirlar = v.vcardArray[1] || [];
          for (var q = 0; q < satirlar.length; q++) {
            if (satirlar[q] && satirlar[q][0] === 'fn') adV = satirlar[q][3];
          }
        }
        if (roller.indexOf('registrar') >= 0) kayitci = adV || v.handle || '';
        else if (roller.length) kisiler.push({ rol: roller.join(','), ad: adV || v.handle || '' });
      }
      var durum = j.status || [];
      var uyari = [];
      var askida = durum.some(function (s) {
        return s === 'client hold' || s === 'server hold' || s === 'suspended';
      });
      if (askida) uyari.push({ onem: 'kritik', baslik: 'Alan adı askıda', aciklama: durum.join(' ') });
      var bitis = olay.expiration || '';
      if (bitis) {
        var t = Date.parse(String(bitis).slice(0, 10) + 'T00:00:00');
        if (!isNaN(t)) {
          var kalan = (t - simdiMs()) / 86400000;
          if (kalan < 30) {
            uyari.push({
              onem: 'orta', baslik: 'Süre yakında bitiyor',
              aciklama: Math.floor(kalan) + ' gün kaldı (' + String(bitis).slice(0, 10) + ')'
            });
          }
        }
      }
      return {
        ad: ad, kaynak: 'rdap.org', olusturma: olay.registration || '',
        guncelleme: olay['last changed'] || '', bitis: bitis, kayitci: kayitci,
        ns: ns, durum: durum, kisiler: kisiler.slice(0, 8), uyarilar: uyari,
        rdap_url: 'https://rdap.org/domain/' + ad, sure: sure
      };
    }
  }

  /* ------------------------------------------------------------------ */
  /*  3) IP / ASN analizi                                                */
  /* ------------------------------------------------------------------ */
  var IP_API_ALANLAR = 'status,message,continent,country,countryCode,regionName,city,zip,lat,lon,timezone,' +
    'isp,org,as,asname,reverse,mobile,proxy,hosting,query';

  function ipAnaliz(ip) {
    ip = String(ip == null ? '' : ip).trim();
    if (!ip) return Promise.resolve({ hata: 'IP gerekli' });
    var url = 'http://ip-api.com/json/' + encodeURIComponent(ip) + '?fields=' + IP_API_ALANLAR;
    return _json(url, { zaman: 12 }).then(function (r) {
      var j = r.j;
      if (!j || typeof j !== 'object' || j.status !== 'success') {
        return _json('https://ipwho.is/' + encodeURIComponent(ip), { zaman: 12 }).then(function (r2) {
          var j2 = r2.j;
          if (j2 && typeof j2 === 'object' && j2.success) {
            var bag = j2.connection || {};
            return {
              ip: ip, kaynak: 'ipwho.is', ulke: j2.country, ulke_kodu: j2.country_code,
              sehir: j2.city, bolge: j2.region, enlem: j2.latitude,
              boylam: j2.longitude, iss: bag.isp, org: bag.org, asn: bag.asn,
              ozel: ozelIp(ip), sure: r2.sure
            };
          }
          return {
            ip: ip, hata: (j && j.message) || 'IP bilgisi alınamadı', ozel: ozelIp(ip)
          };
        });
      }
      var asn = String(j.as || '').split(' ')[0];
      var rdapAg = {};
      var sonuc = {
        ip: ip, kaynak: 'ip-api.com', ulke: j.country, ulke_kodu: j.countryCode,
        sehir: j.city, bolge: j.regionName, posta: j.zip,
        enlem: j.lat, boylam: j.lon, iss: j.isp, org: j.org,
        asn: asn, as_ad: j.asname, ters_dns: j.reverse, mobil: j.mobile,
        proxy: j.proxy, hosting: j.hosting, ag: rdapAg, ozel: ozelIp(ip),
        sure: r.sure
      };
      if (ozelIp(ip)) return sonuc;
      return _json('https://rdap.org/ip/' + encodeURIComponent(ip), { zaman: 15 }).then(function (rr) {
        var jr = rr.j;
        if (jr && typeof jr === 'object') {
          sonuc.ag = {
            ag: jr.name || jr.handle, baslangic: jr.startAddress,
            bitis: jr.endAddress, ulke: jr.country,
            tip: jr.type, kurum: jr.port43 || ''
          };
        }
        return sonuc;
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /*  4) Subdomain tarama                                                */
  /* ------------------------------------------------------------------ */
  function crtSh(ad) {
    return _cek('https://crt.sh/?q=%25.' + encodeURIComponent(ad) + '&output=json', { zaman: 20 })
      .then(function (d) {
        if (d.kod !== 200) return [];
        var j = null;
        try { j = JSON.parse(d.govde); } catch (e) { return []; }
        if (!j || !j.length) return [];
        var adlar = {};
        for (var i = 0; i < j.length; i++) {
          var parcalar = String((j[i] || {}).name_value || '').split('\n');
          for (var q = 0; q < parcalar.length; q++) {
            var x = parcalar[q].trim().toLowerCase().replace(/^\*\./, '').replace(/^\./, '');
            if (x && x.length - ad.length >= 0 && x.slice(-ad.length) === ad &&
              x.indexOf('@') < 0 && x.indexOf(' ') < 0) adlar[x] = 1;
          }
        }
        return Object.keys(adlar).sort();
      });
  }

  function subdomainTara(ad, enFazla) {
    enFazla = enFazla || 400;
    ad = alanBul(ad);
    if (!ad) return Promise.resolve({ hata: 'alan adı gerekli' });
    var bulunan = {}, kaynak = {};

    function ekle(liste, kaynakAd) {
      var yeni = 0;
      (liste || []).forEach(function (ham) {
        var x = String(ham == null ? '' : ham).trim().toLowerCase()
          .replace(/^\*\./, '').replace(/^\./, '').replace(/\.+$/, '');
        if (x && x.slice(-ad.length) === ad && x.indexOf('@') < 0 &&
          x.indexOf(' ') < 0 && x.length < 200) {
          if (!bulunan[x]) { bulunan[x] = { ad: x, kaynak: kaynakAd, ip: '' }; yeni++; }
        }
      });
      kaynak[kaynakAd] = yeni;
    }

    return _cek('https://api.subdomain.center/?domain=' + encodeURIComponent(ad), { zaman: 25 })
      .then(function (d) {
        if (d.kod === 200) {
          try { ekle(JSON.parse(d.govde), 'subdomain.center'); } catch (e) { }
        }
        return _cek('https://api.hackertarget.com/hostsearch/?q=' + encodeURIComponent(ad), { zaman: 20 });
      })
      .then(function (d) {
        var ilk = String(d.govde || '').slice(0, 60).toLowerCase();
        if (d.kod === 200 && ilk.indexOf('error') < 0 && ilk.indexOf('<html') < 0) {
          var liste = [];
          String(d.govde).split(/\r?\n/).forEach(function (satir) {
            if (satir.indexOf(',') >= 0) liste.push(satir.split(',')[0]);
          });
          ekle(liste, 'hackertarget');
        }
        return crtSh(ad);
      })
      .then(function (crts) {
        ekle(crts, 'crt.sh');
        var liste = Object.keys(bulunan).map(function (k) { return bulunan[k]; })
          .sort(function (a, b) { return a.ad < b.ad ? -1 : (a.ad > b.ad ? 1 : 0); })
          .slice(0, enFazla);
        var ilk60 = liste.slice(0, 60);
        return havuz(ilk60, function (k) {
          return adCoz(k.ad).then(function (ip) {
            if (!ip) return k;
            var m = String(ip).match(/\d+\.\d+\.\d+\.\d+/);
            k.ip = m ? m[0] : '';
            return k;
          });
        }, 20).then(function () {
          var canli = liste.filter(function (x) { return x.ip; });
          return {
            ad: ad, toplam: Object.keys(bulunan).length, kaynaklar: kaynak, canli: canli.length,
            alt_alanlar: liste, kaynak: 'subdomain.center + hackertarget + crt.sh',
            zaman: simdi()
          };
        });
      });
  }

  /* ------------------------------------------------------------------ */
  /*  5) Web teknolojileri                                               */
  /* ------------------------------------------------------------------ */
  var TEK_IMZALARI = [
    ['nginx', 'sunucu', 'nginx'], ['Apache', 'sunucu', 'apache'], ['IIS', 'sunucu', 'microsoft-iis'],
    ['Cloudflare', 'cdn', 'cloudflare|cf-ray'], ['LiteSpeed', 'sunucu', 'litespeed'], ['OpenResty', 'sunucu', 'openresty'],
    ['Express', 'cerceve', '^express'], ['PHP', 'dil', 'php'], ['ASP.NET', 'dil', 'asp\\.net'],
    ['WordPress', 'cms', 'wp-content|wp-includes|wordpress'], ['Drupal', 'cms', 'drupal'],
    ['Joomla', 'cms', 'joomla'], ['Shopify', 'e-ticaret', 'shopify'], ['WooCommerce', 'e-ticaret', 'woocommerce'],
    ['Magento', 'e-ticaret', 'magento|mage/'], ['Next.js', 'cerceve', '__next|next/static'],
    ['Nuxt', 'cerceve', '__nuxt'], ['React', 'kutuphane', 'react(?:-dom)?[.\\-/]'],
    ['Vue.js', 'kutuphane', 'vue(?:\\.min)?\\.js|__vue__'],
    ['Angular', 'cerceve', 'ng-version|angular'], ['jQuery', 'kutuphane', 'jquery'], ['Bootstrap', 'css', 'bootstrap'],
    ['Tailwind', 'css', 'tailwind'], ['Google Analytics', 'analitik', 'google-analytics|gtag\\('],
    ['Google Tag Manager', 'analitik', 'googletagmanager'], ['Facebook Pixel', 'analitik', 'connect\\.facebook\\.net|fbq\\('],
    ['Hotjar', 'analitik', 'hotjar'], ['Cloudflare Turnstile', 'guvenlik', 'turnstile'], ['reCAPTCHA', 'guvenlik', 'recaptcha'],
    ['Sentry', 'izleme', 'sentry'], ['Stripe', 'odeme', 'js\\.stripe\\.com|stripe\\.com/v3'],
    ['PayPal', 'odeme', 'paypal\\.com/sdk'], ['Font Awesome', 'ikon', 'font-awesome|fontawesome'],
    ['Google Fonts', 'ikon', 'fonts\\.googleapis\\.com'], ['Open Graph', 'seo', 'property="og:'],
    ['Sitemap', 'seo', 'sitemap\\.xml'], ['Plesk', 'panel', 'plesk'], ['cPanel', 'panel', 'cpanel']
  ];
  var GUVENLIK_BASLIKLARI = ['strict-transport-security', 'content-security-policy', 'x-frame-options',
    'x-content-type-options', 'referrer-policy', 'permissions-policy',
    'cross-origin-opener-policy', 'x-xss-protection'];

  function webTek(hedef) {
    var kr = kok(hedef), ad = kr[0], url = kr[1];
    if (!url) return Promise.resolve({ hata: 'hedef gerekli' });
    if (url.indexOf('://') < 0) url = 'https://' + ad;
    var t0 = simdiMs();
    var denemeler = url.indexOf('https') === 0 ? [url] : [url, 'https://' + ad];

    function dene(ix) {
      if (ix >= denemeler.length) {
        return Promise.resolve(null);
      }
      return _cek(denemeler[ix], { zaman: 15 }).then(function (d) {
        if (d.basliklar && Object.keys(d.basliklar).length) return d;
        if (d.govde) return d;                     /* köprü yalnız gövde verdiyse */
        if (d.kod) return d;
        return dene(ix + 1);
      });
    }

    return dene(0).then(function (d) {
      if (!d) {
        return { url: url, ad: ad, hata: 'bağlantı kurulamadı', sure: yuvarlak((simdiMs() - t0) / 1000) };
      }
      var kod = d.kod || 0, basliklar = d.basliklar || {}, govde = (d.govde || '').slice(0, 400000);
      var sert = {};                               /* JS tarafında TLS sertifikası okunamaz */
      var birlesik = (govde.slice(0, 120000) + ' ' + Object.keys(basliklar).map(function (k) {
        return k + '=' + basliklar[k];
      }).join(' ')).toLowerCase();
      var teknolojiler = [], gorulen = {};
      TEK_IMZALARI.forEach(function (t) {
        if (gorulen[t[0]]) return;
        var uydu = false;
        try { uydu = new RegExp(t[2]).test(birlesik); } catch (e) { uydu = false; }
        if (uydu) { teknolojiler.push({ ad: t[0], kategori: t[1] }); gorulen[t[0]] = 1; }
      });
      var gEksik = GUVENLIK_BASLIKLARI.slice(0, 6).filter(function (b) {
        return !Object.prototype.hasOwnProperty.call(basliklar, b);
      });
      var uyari = [];
      if (govde.indexOf('<html') === 0 && url.slice(0, 8).indexOf('https://') < 0) {
        uyari.push({ onem: 'yuksek', baslik: 'HTTPS yok', aciklama: 'Trafik şifresiz taşınıyor.' });
      }
      gEksik.slice(0, 3).forEach(function (b) {
        uyari.push({ onem: 'dusuk', baslik: b + ' başlığı yok', aciklama: 'Tarayıcı koruması zayıflıyor.' });
      });
      if (basliklar['set-cookie'] && String(basliklar['set-cookie']).toLowerCase().indexOf('secure') < 0) {
        uyari.push({ onem: 'orta', baslik: 'Çerez Secure bayrağı yok', aciklama: 'Çerez HTTP üzerinden sızabilir.' });
      }
      if (!Object.keys(basliklar).length) {
        uyari.push({
          onem: 'bilgi', baslik: 'Yanıt başlıkları okunamadı',
          aciklama: 'Bu taşıma yalnız gövde döndürüyor (köprü veriCek); sunucu ve güvenlik başlıkları denetlenemedi.'
        });
      }
      var basKisalt = {};
      Object.keys(basliklar).slice(0, 40).forEach(function (k) {
        basKisalt[k] = String(basliklar[k]).slice(0, 300);
      });
      var gBas = {};
      GUVENLIK_BASLIKLARI.forEach(function (b) {
        gBas[b] = Object.prototype.hasOwnProperty.call(basliklar, b);
      });
      return {
        ad: ad, url: url, durum_kodu: kod, sunucu: basliklar['server'] || '',
        basliklar: basKisalt,
        teknolojiler: teknolojiler, guvenlik_basliklari: gBas,
        eksik_guvenlik: gEksik, sertifika: sert, uyarilar: uyari,
        icerik_uzunlugu: govde.length, kaynak: 'canlı HTTP + TLS',
        sure: yuvarlak((simdiMs() - t0) / 1000)
      };
    });
  }

  /* ------------------------------------------------------------------ */
  /*  6) Cloud keşfi (S3 / GCS / Azure kova kontrolü)                    */
  /* ------------------------------------------------------------------ */
  var CLOUD_ONEKLER = ['', 'www', 'mail', 'dev', 'test', 'staging', 'prod', 'backup', 'yedek', 'assets', 'media',
    'static', 'files', 'data', 'logs', 'cdn', 'img', 'video', 'docs', 'db', 'api', 'app',
    'public', 'private', 'storage', 'download', 'uploads'];

  function kovaDene(ad, saglayici) {
    var url;
    if (saglayici === 'aws') url = 'https://' + ad + '.s3.amazonaws.com/';
    else if (saglayici === 'gcp') url = 'https://storage.googleapis.com/' + ad;
    else url = 'https://' + ad + '.blob.core.windows.net/?comp=list';
    return _cek(url, { zaman: 10 }).then(function (d) {
      var kod = d.kod, govde = d.govde || '';
      var durum = 'yok', aciklama = '', risk = 'bilgi';
      if (kod === 200 && (govde.indexOf('<ListBucketResult') >= 0 || govde.indexOf('<EnumerationResults') >= 0)) {
        durum = 'acik'; aciklama = 'Kova listelenebiliyor — dosyalar herkese açık.'; risk = 'kritik';
      } else if (kod === 403) {
        durum = 'var'; aciklama = 'Kova mevcut ama liste erişimi kapalı.'; risk = 'dusuk';
      } else if (kod === 404 || govde.indexOf('NoSuchBucket') >= 0 ||
        govde.indexOf('The specified bucket does not exist') >= 0) {
        durum = 'yok'; aciklama = '';
      } else if (kod === 400 && govde.indexOf('ContainerNotFound') >= 0) {
        durum = 'yok'; aciklama = '';
      } else {
        durum = 'bilinmiyor'; aciklama = 'kod ' + kod;
      }
      return {
        ad: ad, saglayici: saglayici, url: url, durum: durum,
        aciklama: aciklama, risk: risk, kod: kod, sure: d.sure
      };
    });
  }

  function cloudAra(hedef) {
    var ad = alanBul(hedef);
    if (!ad) return Promise.resolve({ hata: 'alan adı gerekli' });
    var taban = ad.replace(/\./g, '-');
    var adaylar = [], gorulen = {};
    CLOUD_ONEKLER.forEach(function (onek) {
      var ciftler = onek ? [[onek + taban, 'aws'], [taban + '-' + onek, 'aws']] : [[taban, 'aws']];
      ciftler.forEach(function (c) {
        var anahtar = c[0] + '|' + c[1];
        if (!gorulen[anahtar]) { gorulen[anahtar] = 1; adaylar.push(c); }
      });
    });
    adaylar = adaylar.slice(0, 70);
    return havuz(adaylar, function (x) { return kovaDene(x[0], x[1]); }, 16).then(function (sonuc) {
      var varOlan = sonuc.filter(function (s) { return s.durum === 'var' || s.durum === 'acik'; });
      return {
        hedef: ad, denenen: sonuc.length, bulunan: varOlan.length,
        acik: varOlan.filter(function (s) { return s.durum === 'acik'; }).length,
        sonuclar: varOlan, tumu: sonuc.slice(0, 40),
        kaynak: 'S3 / Google Cloud Storage / Azure Blob',
        zaman: simdi()
      };
    });
  }

  /* ------------------------------------------------------------------ */
  /*  7) E-posta istihbaratı                                             */
  /* ------------------------------------------------------------------ */
  var TEK_KULLANIMLIK = ['mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 'temp-mail.org',
    'yopmail.com', 'trashmail.com', 'sharklasers.com', 'getnada.com', 'dispostable.com',
    'maildrop.cc', 'throwawaymail.com', 'fakeinbox.com', 'mailnesia.com', 'tempr.email',
    'discard.email', 'mohmal.com', 'emailondeck.com'];
  var ROL_HESAPLARI = ['info', 'admin', 'support', 'sales', 'contact', 'help', 'billing', 'office', 'noreply',
    'no-reply', 'postmaster', 'webmaster', 'abuse', 'security', 'hr', 'jobs', 'press', 'marketing'];
  var EPOSTA_NOT = "SMTP RCPT doğrulaması yapılmadı: Türkiye'de birçok ISS 25 numaralı portu kapatıyor. " +
    "Bu yüzden varlık kontrolü MX + servis izleriyle yapılır.";

  function epostaIstihbarat(adres) {
    adres = String(adres == null ? '' : adres).trim().toLowerCase();
    if (!/^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/.test(adres)) {
      return Promise.resolve({
        adres: adres, gecerli: false,
        uyarilar: [{ onem: 'orta', baslik: 'Sözdizimi hatalı', aciklama: 'Adres biçimi geçersiz.' }]
      });
    }
    var p = adres.split('@'), kullanici = p[0], alan = p[1];
    var mxListe = [], txt = '';
    return dnsSorgu(alan, 'MX').then(function (r) {
      mxListe = r.kayitlar || [];
      return dnsSorgu(alan, 'TXT');
    }).then(function (r) {
      txt = (r.kayitlar || []).map(function (k) { return k.deger; }).join(' ').toLowerCase();
      var uyari = [];
      var tek = TEK_KULLANIMLIK.indexOf(alan) >= 0;
      var rol = ROL_HESAPLARI.indexOf(kullanici) >= 0;
      if (!mxListe.length) {
        uyari.push({
          onem: 'yuksek', baslik: 'MX kaydı yok',
          aciklama: alan + ' alan adı e-posta kabul etmiyor — adres çalışmaz.'
        });
      }
      if (tek) {
        uyari.push({ onem: 'orta', baslik: 'Tek kullanımlık servis', aciklama: alan + ' geçici e-posta sağlayıcısı.' });
      }
      if (rol) {
        uyari.push({ onem: 'bilgi', baslik: 'Rol hesabı', aciklama: 'Kişiye değil birime ait adres görünümünde.' });
      }
      if (txt.indexOf('v=spf1') < 0) {
        uyari.push({ onem: 'orta', baslik: 'SPF yok', aciklama: 'Alan adı sahtelenebilir.' });
      }
      var eps = md5(adres);
      return _cek('https://www.gravatar.com/avatar/' + eps + '.json', { zaman: 10 }).then(function (g) {
        var gravatar = g.kod === 200 && String(g.govde || '').indexOf('entry') >= 0;
        return kovaDene(alan.replace(/\./g, '-'), 'aws').then(function (kova) {
          return {
            adres: adres, gecerli: true, kullanici: kullanici, alan: alan,
            mx: mxListe.map(function (k) { return k.deger; }).slice(0, 8),
            spf_var: txt.indexOf('v=spf1') >= 0, dmarc_var: txt.indexOf('v=dmarc') >= 0,
            tek_kullanimlik: tek, rol_hesabi: rol, gravatar: gravatar,
            gravatar_url: gravatar ? ('https://www.gravatar.com/avatar/' + eps) : '',
            kurumsal_kova: (kova.durum === 'var' || kova.durum === 'acik') ? kova : null,
            uyarilar: uyari, kaynak: 'DoH MX/TXT + Gravatar + kova kontrolü',
            not: EPOSTA_NOT
          };
        });
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /*  8) Kullanıcı adı arama (platform varlık kuralları)                 */
  /* ------------------------------------------------------------------ */
  /* veri/kullanici-siteleri.json içeriği (Python _siteler() dosyayı önceler) */
  var SITE_DOSYA = [
    { ad: 'GitHub', url: 'https://github.com/{k}', durum_yok: [404], guvenilir: true, kanit: 'torvalds 200 · zzqqxx99887766aa 404' },
    { ad: 'GitLab', url: 'https://gitlab.com/{k}', durum_yok: [404], guvenilir: false, not: 'Cloudflare bot duvarı: olmayan kullanıcıda 404 yerine 403 döner' },
    { ad: 'YouTube', url: 'https://www.youtube.com/@{k}', durum_yok: [404], guvenilir: true, kanit: 'MrBeast 200 · rastgele 404' },
    { ad: 'Telegram', url: 'https://t.me/{k}', yok_marker: 'noindex, nofollow', guvenilir: true, kanit: 'telegram 200 (og:title dolu) · rastgele 200 (noindex + boş og:description)' },
    { ad: 'Pinterest', url: 'https://www.pinterest.com/{k}/', yok_marker: 'User not found', guvenilir: true, kanit: "pinterest 200 · rastgele 200 + 'User not found.'" },
    { ad: 'Steam', url: 'https://steamcommunity.com/id/{k}', yok_marker: 'The specified profile could not be found', guvenilir: true, kanit: 'gabelogannewell 200 · rastgele 200 (Steam Community :: Error)' },
    { ad: 'Twitch', url: 'https://www.twitch.tv/{k}', yok_marker: 'og:title', guvenilir: true, not: "ters kural: var ise og:title bulunur — kodda 'var_marker' gibi çalışır", kanit: 'shroud 200 + og:title · rastgele 200 og:title yok' },
    { ad: 'Vimeo', url: 'https://vimeo.com/{k}', durum_yok: [404, 410], guvenilir: true, kanit: 'kevin 200 · rastgele 404' },
    { ad: 'SoundCloud', url: 'https://soundcloud.com/{k}', durum_yok: [404], guvenilir: true, kanit: 'forss 200 · rastgele 404' },
    { ad: 'Flickr', url: 'https://www.flickr.com/photos/{k}/', durum_yok: [404], guvenilir: true, not: '/people/ yolu artık 404 döner, /photos/ kullanılmalı', kanit: 'thomashawk 200 · rastgele 404' },
    { ad: 'HackerNews', url: 'https://news.ycombinator.com/user?id={k}', yok_marker: 'No such user.', guvenilir: true, kanit: 'pg 200 (2 KB) · rastgele 200 (13 B \'No such user.\')' },
    { ad: 'Keybase', url: 'https://keybase.io/{k}', durum_yok: [404], guvenilir: true, kanit: 'chris 200 · rastgele 404' },
    { ad: 'Medium', url: 'https://medium.com/@{k}?format=json', durum_yok: [404], guvenilir: true, kanit: 'ev 200 (success:true) · rastgele 404 (No user found)' },
    { ad: 'Disqus', url: 'https://disqus.com/by/{k}/', durum_yok: [404], guvenilir: true, kanit: 'disqus 200 · rastgele 404' },
    { ad: 'Patreon', url: 'https://www.patreon.com/{k}', durum_yok: [404], guvenilir: true, kanit: 'patreon 200 · rastgele 404' },
    { ad: 'Behance', url: 'https://www.behance.net/{k}', durum_yok: [404], guvenilir: true, kanit: 'adobe 200 · rastgele 404' },
    { ad: 'Dribbble', url: 'https://dribbble.com/{k}', durum_yok: [404], guvenilir: true, kanit: 'dribbble 200 · rastgele 404' },
    { ad: 'about.me', url: 'https://about.me/{k}', durum_yok: [404], guvenilir: true, kanit: 'john 200 · rastgele 404' },
    { ad: 'Mastodon', url: 'https://mastodon.social/@{k}', durum_yok: [404], guvenilir: true, kanit: '@Gargron 200 · rastgele 404' },
    { ad: 'StackOverflow', url: 'https://stackoverflow.com/users/{k}', durum_yok: [404], guvenilir: false, not: 'Yalnız sayısal kullanıcı kimliği kabul eder, kullanıcı adıyla arama yapılamaz' },
    { ad: 'TikTok', url: 'https://www.tiktok.com/oembed?url=https://www.tiktok.com/@{k}', durum_yok: [400, 404], guvenilir: true, not: 'oembed uç noktası kullanılır; profil sayfası WAF yüzünden ayırt etmez', kanit: 'tiktok/nasa 200 · rastgele 400' },
    { ad: 'NPM', url: 'https://www.npmjs.com/~{k}', durum_yok: [404], guvenilir: false, not: 'Spa kabuğu — içerik denetimi gerekli' },
    { ad: 'PyPI', url: 'https://pypi.org/user/{k}/', durum_yok: [404], guvenilir: false, not: 'doğrulanmadı' },
    { ad: 'Docker Hub', url: 'https://hub.docker.com/u/{k}', durum_yok: [404], guvenilir: false, not: 'doğrulanmadı' },
    { ad: 'Instagram', url: 'https://www.instagram.com/{k}/', guvenilir: false, not: 'Giriş duvarı: gerçek ve sahte hesap aynı sayfayı döndürüyor' },
    { ad: 'Reddit', url: 'https://www.reddit.com/user/{k}/about.json', durum_yok: [404], guvenilir: false, not: 'Bot duvarı (403)' },
    { ad: 'Twitter/X', url: 'https://x.com/{k}', durum_yok: [404], guvenilir: true, kanit: 'elonmusk 200 · rastgele 404' },
    { ad: 'Facebook', url: 'https://www.facebook.com/{k}', guvenilir: false, not: 'Yalnız facebookexternalhit bot aracısıyla ayırt eder; normal tarayıcıda ikisi de 400' },
    /* Python {k} dışındaki yer tutucuları değiştirmez → bu satır kullanıcı adıyla hep 'yok' döner (davranış birebir korunur) */
    { ad: 'Gravatar', url: 'https://www.gravatar.com/avatar/{md5}?d=404', durum_yok: [404], guvenilir: true, not: "Kullanıcı adı değil e-posta md5'i ile sorgulanır; d=404 parametresi şart" }
  ];

  /* Python SITE_VARSAYILAN: yalnız dosya okunamazsa devreye giren yedek liste */
  var SITE_VARSAYILAN = [
    { ad: 'GitHub', url: 'https://github.com/{k}', durum_yok: [404], guvenilir: true },
    { ad: 'GitLab', url: 'https://gitlab.com/{k}', durum_yok: [404], guvenilir: true },
    { ad: 'Telegram', url: 'https://t.me/{k}', yok_marker: 'tgme_page_icon', guvenilir: true },
    { ad: 'YouTube', url: 'https://www.youtube.com/@{k}', durum_yok: [404], guvenilir: true },
    { ad: 'Steam', url: 'https://steamcommunity.com/id/{k}', yok_marker: 'The specified profile could not be found', guvenilir: true },
    { ad: 'Keybase', url: 'https://keybase.io/{k}', durum_yok: [404], guvenilir: true },
    { ad: 'NPM', url: 'https://www.npmjs.com/~{k}', durum_yok: [404], guvenilir: true },
    { ad: 'PyPI', url: 'https://pypi.org/user/{k}/', durum_yok: [404], guvenilir: true },
    { ad: 'Docker Hub', url: 'https://hub.docker.com/u/{k}', durum_yok: [404], guvenilir: true },
    { ad: 'HackerNews', url: 'https://news.ycombinator.com/user?id={k}', yok_marker: 'No such user.', guvenilir: true },
    { ad: 'Twitch', url: 'https://www.twitch.tv/{k}', durum_yok: [404], guvenilir: true },
    { ad: 'SoundCloud', url: 'https://soundcloud.com/{k}', durum_yok: [404], guvenilir: true },
    { ad: 'Vimeo', url: 'https://vimeo.com/{k}', durum_yok: [404], guvenilir: true },
    { ad: 'Flickr', url: 'https://www.flickr.com/people/{k}', durum_yok: [404], guvenilir: true },
    { ad: 'About.me', url: 'https://about.me/{k}', durum_yok: [404], guvenilir: true },
    { ad: 'Behance', url: 'https://www.behance.net/{k}', durum_yok: [404], guvenilir: true },
    { ad: 'Dribbble', url: 'https://dribbble.com/{k}', durum_yok: [404], guvenilir: true },
    { ad: 'Patreon', url: 'https://www.patreon.com/{k}', durum_yok: [404], guvenilir: true },
    { ad: 'Mastodon', url: 'https://mastodon.social/@{k}', durum_yok: [404], guvenilir: true },
    { ad: 'Pinterest', url: 'https://www.pinterest.com/{k}/', durum_yok: [404], guvenilir: false, not: 'içerik denetimi gerekli' },
    { ad: 'Instagram', url: 'https://www.instagram.com/{k}/', yok_marker: "Sorry, this page isn't available", guvenilir: true },
    { ad: 'TikTok', url: 'https://www.tiktok.com/@{k}', yok_marker: "Couldn't find this account", guvenilir: true },
    { ad: 'Twitter/X', url: 'https://x.com/{k}', guvenilir: false, not: 'Giriş duvarı — doğrulanamıyor' },
    { ad: 'Facebook', url: 'https://www.facebook.com/{k}', guvenilir: false, not: 'Giriş duvarı' },
    { ad: 'Reddit', url: 'https://www.reddit.com/user/{k}/about.json', durum_yok: [404], guvenilir: false, not: 'Reddit bot engeli (403)' }
  ];

  /* Python _siteler(): dosya varsa onu, yoksa SITE_VARSAYILAN'ı kullanır.
     APK'da dosya sistemi yok → dosya içeriği JS'e gömülü (SITE_DOSYA). */
  function siteler() { return SITE_DOSYA; }

  function kullaniciAra(kullanici) {
    kullanici = String(kullanici == null ? '' : kullanici).trim().replace(/^@/, '');
    if (!kullanici || kullanici.length < 2) return Promise.resolve({ hata: 'kullanıcı adı gerekli' });

    function kontrol(s) {
      var url = s.url.replace('{k}', encodeURIComponent(kullanici));
      return _cek(url, { zaman: 12 }).then(function (d) {
        var kod = d.kod, govde = d.govde || '', varMi = null;
        if (s.durum_yok && kod) varMi = s.durum_yok.indexOf(kod) < 0;
        if (s.yok_marker && kod) {
          varMi = String(govde).toLowerCase().indexOf(String(s.yok_marker).toLowerCase()) < 0;
          if (kod === 404 || kod === 410) varMi = false;
        }
        if (s.guvenilir === false) varMi = null;
        return {
          ad: s.ad, url: url, kod: kod, var: varMi,
          guvenilir: (s.guvenilir !== false) && varMi !== null,
          not: s.not || '', sure: d.sure
        };
      });
    }

    var liste = siteler();
    return havuz(liste, kontrol, 12).then(function (sonuc) {
      var temiz = sonuc.filter(function (x) { return x; });
      var bulunan = temiz.filter(function (s) { return s.var === true; });
      temiz.sort(function (a, b) {
        var ea = a.var === true ? 0 : 1, eb = b.var === true ? 0 : 1;
        if (ea !== eb) return ea - eb;
        return a.ad < b.ad ? -1 : (a.ad > b.ad ? 1 : 0);
      });
      return {
        kullanici: kullanici, denenen: temiz.length, bulunan: bulunan.length,
        platformlar: temiz,
        kaynak: 'platform varlık kuralları (durum kodu + içerik işareti)',
        zaman: simdi()
      };
    });
  }

  /* ------------------------------------------------------------------ */
  /*  9) GitHub istihbaratı                                              */
  /* ------------------------------------------------------------------ */
  function gh(yol, anahtar) {
    var baslik = { Accept: 'application/vnd.github+json' };
    if (anahtar) baslik.Authorization = 'Bearer ' + anahtar;
    return _json('https://api.github.com' + yol, { zaman: 15, basliklar: baslik });
  }

  function githubIstihbarat(kullanici, anahtar) {
    kullanici = String(kullanici == null ? '' : kullanici).trim().replace(/^@/, '');
    if (!kullanici) return Promise.resolve({ hata: 'kullanıcı adı gerekli' });
    var q = encodeURIComponent(kullanici);
    return gh('/users/' + q, anahtar).then(function (r) {
      var u = r.j;
      if (!u || typeof u !== 'object' || r.kod !== 200) {
        return {
          kullanici: kullanici,
          hata: (u && u.message) || ('kullanıcı bulunamadı (kod ' + r.kod + ')')
        };
      }
      return Promise.all([
        gh('/users/' + q + '/repos?per_page=100&sort=updated', anahtar),
        gh('/users/' + q + '/orgs', anahtar),
        gh('/users/' + q + '/events/public?per_page=30', anahtar)
      ]).then(function (kalan) {
        var depolar = (kalan[0].j && kalan[0].j.length !== undefined) ? kalan[0].j : [];
        var org = (kalan[1].j && kalan[1].j.length !== undefined) ? kalan[1].j : [];
        var olay = (kalan[2].j && kalan[2].j.length !== undefined) ? kalan[2].j : [];
        var diller = {}, yildiz = 0;
        depolar.forEach(function (d) {
          if (!d) return;
          var dil = d.language || 'belirsiz';
          diller[dil] = (diller[dil] || 0) + 1;
          yildiz += d.stargazers_count || 0;
        });
        var sizinti = [];
        for (var i = 0; i < olay.length; i++) {
          var e = olay[i] || {};
          var commitler = e.commits || [];
          for (var j = 0; j < commitler.length; j++) {
            var em = ((commitler[j] || {}).author || {}).email || '';
            var zaten = sizinti.some(function (s) { return s.eposta === em; });
            if (em && em.indexOf('noreply') < 0 && !zaten) {
              sizinti.push({
                eposta: em, depo: ((e.repo || {}).name) || '',
                tarih: String(e.created_at || '').slice(0, 10)
              });
            }
          }
          if (sizinti.length >= 6) break;
        }
        var uyari = [];
        if (sizinti.length) {
          uyari.push({
            onem: 'orta', baslik: 'E-posta adresi açığa çıktı',
            aciklama: "Herkese açık commit'lerde " + sizinti.length + ' adres görüldü.'
          });
        }
        var sirali = depolar.slice().sort(function (a, b) {
          return (b.stargazers_count || 0) - (a.stargazers_count || 0);
        }).slice(0, 25).map(function (d) {
          return {
            ad: d.name, aciklama: d.description, dil: d.language,
            yildiz: d.stargazers_count, fork: d.forks_count,
            guncelleme: String(d.updated_at || '').slice(0, 10), url: d.html_url,
            arsiv: d.archived, lisans: (d.license || {}).spdx_id
          };
        });
        return {
          kullanici: kullanici, kaynak: 'api.github.com',
          profil: {
            ad: u.name, bio: u.bio, sirket: u.company,
            blog: u.blog, konum: u.location, eposta: u.email,
            twitter: u.twitter_username, avatar: u.avatar_url,
            takipci: u.followers, takip: u.following,
            depo_sayisi: u.public_repos, gist: u.public_gists,
            olusturma: String(u.created_at || '').slice(0, 10),
            guncelleme: String(u.updated_at || '').slice(0, 10),
            site: u.html_url
          },
          toplam_yildiz: yildiz, diller: diller,
          kurumlar: org.slice(0, 10).map(function (o) { return (o || {}).login; }),
          depolar: sirali, sizinti_notlari: sizinti, uyarilar: uyari, sure: r.sure
        };
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* 10) Veri sızıntısı tespiti (açık dosya / konfig probu)              */
  /* ------------------------------------------------------------------ */
  var PROBLAR = [
    { yol: '/.env', ris: 'kritik', imza: ['DB_', 'APP_KEY', 'SECRET', 'PASSWORD', 'API_KEY', '='], aciklama: 'Ortam değişkenleri (veritabanı/API anahtarları) herkese açık.' },
    { yol: '/.env.local', ris: 'kritik', imza: ['DB_', 'APP_KEY', 'SECRET', 'PASSWORD'], aciklama: 'Yerel ortam dosyası açık.' },
    { yol: '/.env.production', ris: 'kritik', imza: ['DB_', 'APP_KEY', 'SECRET', 'PASSWORD'], aciklama: 'Üretim ortam dosyası açık.' },
    { yol: '/.git/config', ris: 'kritik', imza: ['[core]', 'repositoryformatversion', 'url ='], aciklama: 'Git deposu dizini açık — tüm kaynak kod indirilebilir.' },
    { yol: '/.git/HEAD', ris: 'yuksek', imza: ['ref: refs/'], aciklama: 'Git baş dosyası açık.' },
    { yol: '/.svn/entries', ris: 'yuksek', imza: ['dir', 'svn'], aciklama: 'SVN dizini açık.' },
    { yol: '/.DS_Store', ris: 'dusuk', imza: ['Mac OS X'], aciklama: 'macOS dosya listesi sızıntısı.' },
    { yol: '/backup.zip', ris: 'yuksek', imza: [], tip: 'pk', aciklama: 'Yedek arşivi indirilebilir.' },
    { yol: '/backup.sql', ris: 'kritik', imza: ['INSERT INTO', 'CREATE TABLE', '-- MySQL'], aciklama: 'Veritabanı yedeği açık.' },
    { yol: '/db.sql', ris: 'kritik', imza: ['INSERT INTO', 'CREATE TABLE'], aciklama: 'Veritabanı dökümü açık.' },
    { yol: '/dump.sql', ris: 'kritik', imza: ['INSERT INTO', 'CREATE TABLE'], aciklama: 'Veritabanı dökümü açık.' },
    { yol: '/wp-config.php.bak', ris: 'kritik', imza: ['DB_PASSWORD', 'DB_NAME', 'define('], aciklama: 'WordPress yapılandırma yedeği açık.' },
    { yol: '/wp-config.php~', ris: 'kritik', imza: ['DB_PASSWORD', 'DB_NAME'], aciklama: 'WordPress yapılandırma kopyası açık.' },
    { yol: '/config.php.bak', ris: 'kritik', imza: ['password', 'db_', '<?php'], aciklama: 'Yapılandırma yedeği açık.' },
    { yol: '/phpinfo.php', ris: 'yuksek', imza: ['phpinfo()', 'PHP Version'], aciklama: 'phpinfo çıktısı açık — sistem bilgisi sızıyor.' },
    { yol: '/server-status', ris: 'orta', imza: ['Apache Server Status', 'Server Version'], aciklama: 'Apache durum sayfası açık.' },
    { yol: '/swagger.json', ris: 'orta', imza: ['swagger', 'openapi'], aciklama: 'API dokümantasyonu açık.' },
    { yol: '/openapi.json', ris: 'orta', imza: ['openapi', 'paths'], aciklama: 'API şeması açık.' },
    { yol: '/actuator/env', ris: 'kritik', imza: ['activeProfiles', 'propertySources'], aciklama: 'Spring Boot ortam uç noktası açık.' },
    { yol: '/.aws/credentials', ris: 'kritik', imza: ['aws_access_key_id'], aciklama: 'AWS kimlik dosyası açık.' },
    { yol: '/id_rsa', ris: 'kritik', imza: ['PRIVATE KEY'], aciklama: 'Özel SSH anahtarı açık.' },
    { yol: '/logs/error.log', ris: 'orta', imza: ['PHP', 'error', 'Traceback', 'at java'], aciklama: 'Hata günlüğü herkese açık.' },
    { yol: '/.well-known/security.txt', ris: 'bilgi', imza: ['Contact:'], aciklama: 'Güvenlik iletişim dosyası var (olumlu).' },
    { yol: '/robots.txt', ris: 'bilgi', imza: ['User-agent', 'Disallow'], aciklama: 'robots.txt — gizlenmeye çalışılan yolları gösterir.' }
  ];

  function sizintiTara(hedef) {
    var kr = kok(hedef), ad = kr[0], url = kr[1];
    if (!url) return Promise.resolve({ hata: 'hedef gerekli' });
    if (url.indexOf('://') < 0) url = 'https://' + ad;
    var taban = url.replace(/\/+$/, '');
    var uyarilar = [];

    function tek(p) {
      var u = taban + p.yol;
      return _cek(u, { zaman: 10 }).then(function (d) {
        var kod = d.kod, govde = d.govde || '';
        if (kod !== 200 && kod !== 206) {
          return { yol: p.yol, url: u, kod: kod, bulundu: false, durum: 'yok' };
        }
        var kesit = govde.slice(0, 60000).toLowerCase();
        var imzaVar;
        if (p.imza && p.imza.length) {
          imzaVar = p.imza.some(function (i) { return kesit.indexOf(String(i).toLowerCase()) >= 0; });
        } else {
          var pk = (p.tip === 'pk' && govde.indexOf('PK') === 0);
          var htmlDegil = !(govde.replace(/^\s+/, '').toLowerCase().indexOf('<!doctype html') === 0);
          imzaVar = pk || htmlDegil;
        }
        if (!imzaVar) {
          return {
            yol: p.yol, url: u, kod: kod, bulundu: false, durum: 'yanlis_pozitif',
            aciklama: '200 döndü ama içerik probla uyuşmuyor (yumuşak 404).'
          };
        }
        return {
          yol: p.yol, url: u, kod: kod, bulundu: true, risk: p.ris,
          aciklama: p.aciklama, boyut: govde.length, sure: d.sure,
          ornek: govde.slice(0, 220).replace(/\s+/g, ' ')
        };
      });
    }

    return havuz(PROBLAR, tek, 10).then(function (sonuc) {
      var temiz = sonuc.filter(function (x) { return x; });
      var bulunan = temiz.filter(function (s) { return s.bulundu; });
      bulunan.forEach(function (b) {
        if (b.risk === 'kritik' || b.risk === 'yuksek') {
          uyarilar.push({ onem: b.risk, baslik: b.yol + ' açık', aciklama: b.aciklama || '' });
        }
      });
      var sirali = { kritik: 0, yuksek: 1, orta: 2, dusuk: 3, bilgi: 4 };
      bulunan.sort(function (a, b) {
        var x = sirali[a.risk] === undefined ? 9 : sirali[a.risk];
        var y = sirali[b.risk] === undefined ? 9 : sirali[b.risk];
        return x - y;
      });
      return {
        hedef: ad, url: taban, denenen: temiz.length, bulunan: bulunan.length,
        kritik: bulunan.filter(function (b) { return b.risk === 'kritik'; }).length,
        bulgular: bulunan, tum_problar: temiz, uyarilar: uyarilar,
        kaynak: 'canlı HTTP probu (yumuşak 404 ayıklamalı)',
        zaman: simdi()
      };
    });
  }

  /* ------------------------------------------------------------------ */
  /* 11) Dark web / sızıntı kaydı (HIBP anahtarı gerekir)                */
  /* ------------------------------------------------------------------ */
  function darkwebAra(sorgu, anahtar) {
    sorgu = String(sorgu == null ? '' : sorgu).trim();
    if (!sorgu) return Promise.resolve({ hata: 'e-posta veya alan adı gerekli' });
    if (!anahtar) {
      return Promise.resolve({
        sorgu: sorgu, anahtar_gerekli: true,
        mesaj: 'Sızıntı kaydı için Have I Been Pwned API anahtarı gerekir. ' +
          'Ayarlar → API Anahtarları bölümüne ekleyin; anahtar olmadan sorgu çalışmaz.',
        ucretsiz_alternatifler: [
          { ad: 'Google dork — sızmış dosyalar', url: 'https://www.google.com/search?q=%22' + encodeURIComponent(sorgu) + '%22+filetype%3Asql' },
          { ad: 'Arama — yapıştırma siteleri', url: 'https://www.google.com/search?q=%22' + encodeURIComponent(sorgu) + '%22+site%3Apastebin.com' },
          { ad: 'Have I Been Pwned', url: 'https://haveibeenpwned.com/account/' + encodeURIComponent(sorgu) },
          { ad: 'DeHashed (kayıt gerekir)', url: 'https://dehashed.com/search?query=' + encodeURIComponent(sorgu) }
        ],
        kaynak: 'HIBP v3'
      });
    }
    var baslik = { 'hibp-api-key': anahtar, 'User-Agent': 'USTAD-OSINT' };
    var yol = sorgu.indexOf('@') >= 0
      ? '/breachedaccount/' + encodeURIComponent(sorgu) + '?truncateResponse=false'
      : '/breacheddomain/' + encodeURIComponent(sorgu);
    return _json('https://haveibeenpwned.com/api/v3' + yol, { basliklar: baslik, zaman: 20 })
      .then(function (r) {
        if (r.kod === 404) {
          return {
            sorgu: sorgu, temiz: true, sizinti_sayisi: 0,
            mesaj: 'Bu sorgu bilinen sızıntılarda bulunamadı (temiz görünüyor).', kaynak: 'HIBP v3'
          };
        }
        if (r.kod !== 200) {
          return { sorgu: sorgu, hata: 'HIBP yanıtı: ' + r.kod + ' (anahtar geçersiz olabilir)' };
        }
        var kayitlar = (r.j && r.j.length !== undefined) ? r.j : [];
        return {
          sorgu: sorgu, temiz: !kayitlar.length, sizinti_sayisi: kayitlar.length,
          kayitlar: kayitlar.slice(0, 20).map(function (k) {
            return {
              ad: k.Name, baslik: k.Title, tarih: k.BreachDate,
              etkilenen: k.PwnCount, veriler: k.DataClasses,
              dogrulanmis: k.IsVerified,
              aciklama: String(k.Description || '').replace(/<[^>]+>/g, '').slice(0, 300)
            };
          }),
          kaynak: 'HIBP v3', sure: r.sure
        };
      });
  }

  /* ------------------------------------------------------------------ */
  /* 12) Tehdit haritası (gerçek beslemeler + konum)                     */
  /* ------------------------------------------------------------------ */
  var TEHDIT_ONBELLEK_ANAHTAR = 'osint_tehdit_onbellek_js';
  var tehditSozu = null;

  function onbellekOku() {
    try {
      if (typeof localStorage === 'undefined') return null;
      var d = JSON.parse(localStorage.getItem(TEHDIT_ONBELLEK_ANAHTAR) || 'null');
      if (d && d._zaman && d.c2) return d;
    } catch (e) { }
    return null;
  }

  function onbellekYaz(d) {
    try {
      if (typeof localStorage === 'undefined') return;
      localStorage.setItem(TEHDIT_ONBELLEK_ANAHTAR, JSON.stringify(d));
    } catch (e) { }
  }

  function besleme(url, zaman) {
    return _cek(url, { zaman: zaman || 25 }).then(function (d) {
      return d.kod === 200 ? d.govde : '';
    });
  }

  /* Python _cvss(): sürüm farkını gözeterek CVSS puanı */
  function cvss(cve) {
    var m = cve.metrics || {};
    var anahtarlar = ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'];
    for (var i = 0; i < anahtarlar.length; i++) {
      var d = m[anahtarlar[i]];
      if (d && d.length) {
        try { return (d[0].cvssData || {}).baseScore; } catch (e) { }
      }
    }
    return null;
  }

  /* Python time.strftime("%Y-%m-%dT00:00:00.000") — yerel gün başlangıcı */
  function isoGun(t) {
    var d = new Date(t);
    function p(n) { return (n < 10 ? '0' : '') + n; }
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T00:00:00.000';
  }

  function tehditVerisi(zorla) {
    if (tehditSozu && !zorla) return tehditSozu;
    tehditSozu = tehditHesapla(zorla).then(function (d) {
      if (!d) tehditSozu = null;
      return d;
    }, function (e) {
      tehditSozu = null;
      throw e;
    });
    return tehditSozu;
  }

  function tehditHesapla(zorla) {
    var onbellek = onbellekOku();
    if (!zorla && onbellek && (simdiMs() / 1000 - onbellek._zaman) < 900) {
      var kopya = JSON.parse(JSON.stringify(onbellek));
      kopya.onbellek = true;
      return Promise.resolve(kopya);
    }
    var c2 = [], phishing = [], ioc = [];
    return _json('https://feodotracker.abuse.ch/downloads/ipblocklist.json', { zaman: 25 })
      .then(function (r) {
        var j = r.j;
        if (j && j.length !== undefined && !Array.isArray(j)) j = [];
        if (Array.isArray(j)) {
          j.forEach(function (k) {
            var ip = k.ip_address;
            if (ip && ipMi(ip)) {
              c2.push({
                ilk_gorulme: k.first_seen || '', ip: ip, port: k.port,
                durum: k.status, son_cevrimici: k.last_online,
                zararli: k.malware, asn: k.as_number, as_ad: k.as_name,
                ulke: k.country, kaynak: 'Feodo Tracker'
              });
            }
          });
        }
        if (c2.length >= 5) return '';
        return besleme('https://feodotracker.abuse.ch/downloads/ipblocklist.csv');
      })
      .then(function (csv) {
        if (csv) {
          csv.split(/\r?\n/).forEach(function (satir) {
            if (!satir || satir.charAt(0) === '#' || satir.indexOf('first_seen') >= 0) return;
            var p = satir.split(',').map(function (x) { return x.trim().replace(/^"/, '').replace(/"$/, ''); });
            if (p.length >= 6 && ipMi(p[1])) {
              c2.push({
                ilk_gorulme: p[0], ip: p[1], port: p[2], durum: p[3],
                son_cevrimici: p[4], zararli: p[5], kaynak: 'Feodo Tracker'
              });
            }
          });
        }
        return besleme('https://openphish.com/feed.txt');
      })
      .then(function (govde) {
        String(govde || '').split(/\r?\n/).slice(0, 400).forEach(function (satir) {
          var s2 = satir.trim();
          if (s2.indexOf('http') === 0) phishing.push({ url: s2, kaynak: 'OpenPhish' });
        });
        return besleme('https://rules.emergingthreats.net/blockrules/compromised-ips.txt');
      })
      .then(function (govde) {
        String(govde || '').split(/\r?\n/).forEach(function (satir) {
          var s2 = satir.trim();
          if (s2 && s2.charAt(0) !== '#' && /^\d{1,3}(\.\d{1,3}){3}/.test(s2)) {
            ioc.push({ ip: s2.split(/\s+/)[0], kaynak: 'EmergingThreats' });
          }
        });
        /* konum: ilk 60 C2 + ilk 60 IOC, toplu sorgu */
        var ornek = [], gorulen = {};
        c2.slice(0, 60).map(function (c) { return c.ip; })
          .concat(ioc.slice(0, 60).map(function (x) { return x.ip; }))
          .forEach(function (ip) { if (!gorulen[ip]) { gorulen[ip] = 1; ornek.push(ip); } });
        ornek = ornek.slice(0, 80);
        var konumlar = [], ulkeler = {};
        if (!ornek.length) return { konumlar: konumlar, ulkeler: ulkeler };
        var govde = JSON.stringify(ornek.map(function (ip) {
          return { query: ip, fields: 'status,country,countryCode,city,lat,lon,as,query' };
        }));
        return _json('http://ip-api.com/batch', { veri: govde, tip: 'application/json', zaman: 25 })
          .then(function (rr) {
            var j = rr.j;
            if (j && j.length !== undefined) {
              j.forEach(function (k) {
                if (k && k.status === 'success') {
                  var ulke = k.country === undefined ? '?' : k.country;
                  ulkeler[ulke] = (ulkeler[ulke] || 0) + 1;
                  konumlar.push({
                    ip: k.query, ulke: k.country, ulke_kodu: k.countryCode,
                    sehir: k.city, enlem: k.lat, boylam: k.lon, asn: k.as, tur: 'c2'
                  });
                }
              });
            }
            return { konumlar: konumlar, ulkeler: ulkeler };
          });
      })
      .then(function (k) {
        /* ---- ek doğrulanmış beslemeler: sayı + örnek ---- */
        var ekIsler = [
          ['Spamhaus DROP', 'CIDR bloğu', 'https://www.spamhaus.org/drop/drop.txt'],
          ['ipsum (yapıştırma/karaliste skoru)', 'skorlu IP', 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'],
          ['URLhaus (son zararlı URL)', 'URL', 'https://urlhaus.abuse.ch/downloads/text_recent/'],
          ['Phishing Army', 'phishing alan adı', 'https://phishing.army/download/phishing_army_blocklist_extended.txt']
        ];
        return havuz(ekIsler, function (b) {
          return besleme(b[2]).then(function (govde) {
            var ornek = [];
            if (b[0] === 'Spamhaus DROP') {
              govde.split(/\r?\n/).forEach(function (x) {
                if (x && x.charAt(0) !== ';' && x.indexOf('/') >= 0) ornek.push(x.split(';')[0].trim());
              });
            } else if (b[0].indexOf('ipsum') === 0) {
              var ipList = [];
              govde.split(/\r?\n/).forEach(function (satir) {
                if (!satir || satir.charAt(0) === '#') return;
                var par = satir.split(/\s+/);
                if (par.length >= 2 && ipMi(par[0])) ipList.push([par[1], par[0]]);
              });
              if (ipList.length) {
                /* Python: ip_list.sort(reverse=True) — önce skor, sonra IP (azalan, metin) */
                ipList.sort(function (a, b2) {
                  if (a[0] !== b2[0]) return a[0] < b2[0] ? 1 : -1;
                  return a[1] < b2[1] ? 1 : (a[1] > b2[1] ? -1 : 0);
                });
                ornek = ipList.slice(0, 5).map(function (x) { return x[1] + ' (skor ' + x[0] + ')'; });
                return { ad: b[0], tip: b[1], sayi: ipList.length, ornek: ornek, url: b[2] };
              }
            } else if (b[0].indexOf('URLhaus') === 0) {
              govde.split(/\r?\n/).forEach(function (x) {
                var s2 = x.trim();
                if (s2.indexOf('http') === 0) ornek.push(s2);
              });
            } else {
              govde.split(/\r?\n/).forEach(function (x) {
                var s2 = x.trim();
                if (s2 && s2.charAt(0) !== '#') ornek.push(s2);
              });
            }
            if (!ornek.length) return null;
            return { ad: b[0], tip: b[1], sayi: ornek.length, ornek: ornek.slice(0, 5), url: b[2] };
          });
        }, 4).then(function (ekler) {
          return { konumlar: k.konumlar, ulkeler: k.ulkeler, ek: ekler.filter(function (x) { return x; }) };
        });
      })
      .then(function (k) {
        /* son 1 haftanın CVE sayısı (NVD, gerçek) */
        var son = isoGun(simdiMs());
        var bas = isoGun(simdiMs() - 7 * 86400000);
        var nvd = 'https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=' + bas +
          '&pubEndDate=' + son + '&resultsPerPage=6';
        return _json(nvd, { zaman: 25 }).then(function (rr) {
          var cve = {};
          var j = rr.j;
          if (j && typeof j === 'object' && j.length === undefined) {
            cve = {
              son_hafta: j.totalResults,
              pencere: bas.slice(0, 10) + ' → ' + son.slice(0, 10),
              yeni: (j.vulnerabilities || []).slice(0, 6).map(function (v) {
                var c = (v || {}).cve || {};
                return {
                  id: c.id,
                  aciklama: String(((c.descriptions || [{}])[0] || {}).value || '').slice(0, 180),
                  skor: cvss(c)
                };
              })
            };
          }
          return { konumlar: k.konumlar, ulkeler: k.ulkeler, ek: k.ek, cve: cve };
        }, function () {
          return { konumlar: k.konumlar, ulkeler: k.ulkeler, ek: k.ek, cve: {} };
        });
      })
      .then(function (k) {
        var sonuc = {
          c2: c2.slice(0, 300), c2_toplam: c2.length,
          phishing: phishing.slice(0, 200), phishing_toplam: phishing.length,
          ioc: ioc.slice(0, 300), ioc_toplam: ioc.length,
          konumlar: k.konumlar, ulkeler: k.ulkeler,
          ek_beslemeler: k.ek, cve: k.cve || {},
          kaynaklar: ['abuse.ch Feodo Tracker', 'OpenPhish', 'EmergingThreats', 'Spamhaus DROP',
            'ipsum', 'URLhaus', 'Phishing Army', 'NVD CVE API'],
          guncelleme: simdi(), _zaman: simdiMs() / 1000, onbellek: false
        };
        onbellekYaz(sonuc);
        return sonuc;
      });
  }

  /* ------------------------------------------------------------------ */
  /* 13) TAM PROFİL                                                      */
  /* ------------------------------------------------------------------ */
  function riskPuani(bulgular) {
    var agirlik = { kritik: 25, yuksek: 12, orta: 5, dusuk: 2, bilgi: 0 };
    var puan = 0;
    bulgular.forEach(function (b) {
      var a = agirlik[b.risk] === undefined ? 0 : agirlik[b.risk];
      puan += a;
    });
    return Math.min(100, puan);
  }

  var VARSAYILAN_MODULLER = ['dns', 'whois', 'subdomain', 'webtek', 'cloud', 'sizinti', 'tehdit'];

  function profilCikar(hedef, moduller, ayarlar) {
    ayarlar = ayarlar || {};
    var kr = kok(hedef), ad = kr[0], url = kr[1];
    if (!ad) return Promise.resolve({ hata: 'hedef gerekli (alan adı, IP veya URL)' });
    if (typeof moduller === 'string') {
      moduller = moduller.split(/[,\s]+/).filter(function (x) { return x; });
    }
    moduller = moduller && moduller.length ? moduller : VARSAYILAN_MODULLER.slice();
    var t0 = simdiMs();
    var ipMi_ = ipMi(ad);
    var isler = [], isimler = [];
    function ekle(ad_, fn) { isimler.push(ad_); isler.push(fn); }
    if (moduller.indexOf('dns') >= 0 && !ipMi_) ekle('dns', function () { return dnsToplu(ad); });
    if (moduller.indexOf('whois') >= 0) {
      ekle('whois', function () { return ipMi_ ? ipAnaliz(ad) : whoisRdap(ad); });
    }
    if (ipMi_) ekle('ip', function () { return ipAnaliz(ad); });
    if (moduller.indexOf('subdomain') >= 0 && !ipMi_) ekle('subdomain', function () { return subdomainTara(ad); });
    if (moduller.indexOf('webtek') >= 0) ekle('webtek', function () { return webTek(url); });
    if (moduller.indexOf('cloud') >= 0 && !ipMi_) ekle('cloud', function () { return cloudAra(ad); });
    if (moduller.indexOf('sizinti') >= 0) ekle('sizinti', function () { return sizintiTara(url); });
    if (moduller.indexOf('tehdit') >= 0) {
      ekle('tehdit', function () {
        return tehditEsles(ad).then(function (e) { return { hedef_eslesme: e }; });
      });
    }

    return Promise.all(isler.map(function (f) {
      return Promise.resolve().then(f).then(function (v) { return v; }, function (e) {
        return { hata: String((e && e.message) || e).slice(0, 120) };
      });
    })).then(function (degerler) {
      var sonuc = {};
      isimler.forEach(function (n, i) { sonuc[n] = degerler[i]; });
      return bitirProfil(sonuc, ad, url, moduller, t0, ipMi_);
    });

    function bitirProfil(sonuc, ad, url, moduller, t0, ipMi_) {
      var bulgular = [];
      var say = { subdomain: 0, ip: 0, acik_servis: 0, eposta: 0, sizinti: 0, cloud: 0 };
      var sz = sonuc.sizinti || {};
      (sz.bulgular || []).forEach(function (u) {
        bulgular.push({
          tur: 'Veri Sızıntısı', hedef: u.url || '', aciklama: u.aciklama || '',
          risk: u.risk || 'dusuk', kaynak: 'açık dosya probu'
        });
      });
      say.sizinti = bulgular.length;
      (sz.uyarilar || []).forEach(function (b) {
        if ((b.onem === 'kritik' || b.onem === 'yuksek') &&
          !bulgular.some(function (x) { return x.aciklama === b.aciklama; })) {
          bulgular.push({
            tur: 'Veri Sızıntısı', hedef: ad, aciklama: b.aciklama || '',
            risk: b.onem, kaynak: 'probu'
          });
        }
      });
      var d = sonuc.dns || {};
      (d.uyarilar || []).forEach(function (u) {
        bulgular.push({
          tur: 'DNS', hedef: ad, aciklama: (u.baslik || '') + ' — ' + (u.aciklama || ''),
          risk: u.onem || 'orta', kaynak: 'dns.google'
        });
      });
      var w = sonuc.whois || {};
      (w.uyarilar || []).forEach(function (u) {
        bulgular.push({
          tur: 'WHOIS', hedef: ad, aciklama: (u.baslik || '') + ' — ' + (u.aciklama || ''),
          risk: u.onem || 'orta', kaynak: 'RDAP'
        });
      });
      var s = sonuc.subdomain || {};
      say.subdomain = s.toplam || 0;
      say.ip = (s.alt_alanlar || []).filter(function (x) { return x.ip; }).length ||
        (((d.ozet || {}).a) || []).length;
      var wt = sonuc.webtek || {};
      (wt.uyarilar || []).forEach(function (u) {
        bulgular.push({
          tur: 'Web Teknolojisi', hedef: wt.url || ad,
          aciklama: (u.baslik || '') + ' — ' + (u.aciklama || ''),
          risk: u.onem || 'dusuk', kaynak: 'canlı HTTP'
        });
      });
      say.acik_servis = wt.durum_kodu ? 1 : 0;
      var c = sonuc.cloud || {};
      say.cloud = c.bulunan || 0;
      (c.sonuclar || []).forEach(function (k) {
        bulgular.push({
          tur: 'Cloud', hedef: k.url || '', aciklama: k.aciklama || '',
          risk: k.risk || 'dusuk', kaynak: 'kova kontrolü'
        });
      });
      var t = sonuc.tehdit || {};
      ((t.hedef_eslesme) || []).slice(0, 5).forEach(function (e) {
        bulgular.push({
          tur: 'Tehdit', hedef: e.ip || '', aciklama: e.aciklama || '',
          risk: 'kritik', kaynak: e.kaynak || ''
        });
      });

      /* saldırı yüzeyi grafiği */
      var dugumler = [{ id: 'kok', ad: ad, tur: 'kok' }];
      var kenarlar = [];
      (s.alt_alanlar || []).slice(0, 40).forEach(function (x) {
        dugumler.push({ id: 'sd:' + x.ad, ad: x.ad, tur: 'subdomain' });
        kenarlar.push({ kaynak: 'kok', hedef: 'sd:' + x.ad });
      });
      (((d.ozet || {}).mx) || []).slice(0, 6).forEach(function (x) {
        dugumler.push({ id: 'mx:' + x, ad: x, tur: 'eposta' });
        kenarlar.push({ kaynak: 'kok', hedef: 'mx:' + x });
      });
      (((d.ozet || {}).ns) || []).slice(0, 6).forEach(function (x) {
        dugumler.push({ id: 'ns:' + x, ad: x, tur: 'dns' });
        kenarlar.push({ kaynak: 'kok', hedef: 'ns:' + x });
      });
      (wt.teknolojiler || []).slice(0, 14).forEach(function (x) {
        dugumler.push({ id: 'tk:' + x.ad, ad: x.ad, tur: 'teknoloji' });
        kenarlar.push({ kaynak: 'kok', hedef: 'tk:' + x.ad });
      });
      (c.sonuclar || []).slice(0, 8).forEach(function (x) {
        dugumler.push({ id: 'cl:' + x.ad, ad: x.ad, tur: 'cloud' });
        kenarlar.push({ kaynak: 'kok', hedef: 'cl:' + x.ad });
      });
      bulgular.slice(0, 10).forEach(function (x) {
        dugumler.push({ id: 'bz:' + String(x.aciklama).slice(0, 20), ad: x.tur, tur: 'risk' });
        kenarlar.push({ kaynak: 'kok', hedef: 'bz:' + String(x.aciklama).slice(0, 20) });
      });

      var sirali = { kritik: 0, yuksek: 1, orta: 2, dusuk: 3, bilgi: 4 };
      bulgular.sort(function (a, b) {
        var x = sirali[a.risk] === undefined ? 9 : sirali[a.risk];
        var y = sirali[b.risk] === undefined ? 9 : sirali[b.risk];
        return x - y;
      });

      var konum = [];
      var ipBilgi = sonuc.ip || (ipMi_ ? sonuc.whois : null);

      function konumEkle(ib, ipAdi) {
        if (ib && ib.enlem) {
          konum.push({
            ip: ib.ip || ipAdi, ulke: ib.ulke, sehir: ib.sehir,
            enlem: ib.enlem, boylam: ib.boylam, iss: ib.iss, tur: 'hedef'
          });
        }
      }

      var hedefKonumIsi;
      if (ipBilgi && ipBilgi.enlem) {
        konumEkle(ipBilgi, ad);
        hedefKonumIsi = Promise.resolve();
      } else if (!ipMi_) {
        var aKayit = (((d.ozet || {}).a) || [])[0];
        hedefKonumIsi = hedefIpCoz(ad).then(function (ip) {
          if (!ip && aKayit) ip = aKayit;
          if (!ip || ozelIp(ip)) return;
          return ipAnaliz(ip).then(function (ib) {
            if (ib && ib.enlem) {
              konumEkle({
                ip: ip, ulke: ib.ulke, sehir: ib.sehir, enlem: ib.enlem,
                boylam: ib.boylam, iss: ib.iss
              }, ip);
              say.ip = Math.max(say.ip || 0, 1);
            }
          });
        });
      } else {
        hedefKonumIsi = Promise.resolve();
      }

      var tehditKonum = [], tehditUlke = {};
      var tehditIsi = Promise.resolve();
      if (moduller.indexOf('tehdit') >= 0) {
        tehditIsi = tehditVerisi().then(function (tv) {
          tehditKonum = (tv && tv.konumlar) || [];
          tehditUlke = (tv && tv.ulkeler) || {};
        }, function () { });
      }
      return Promise.all([hedefKonumIsi, tehditIsi]).then(function () {
        return {
          hedef: ad, url: url, moduller: moduller, sonuclar: sonuc, bulgular: bulgular.slice(0, 80),
          sayilar: say, risk: riskPuani(bulgular),
          graf: { dugumler: dugumler.slice(0, 120), kenarlar: kenarlar.slice(0, 200) },
          konumlar: konum, tehdit_konumlar: tehditKonum, tehdit_ulkeler: tehditUlke,
          sure: yuvarlak((simdiMs() - t0) / 1000), zaman: simdi()
        };
      });
    }
  }

  function tehditEsles(ad) {
    return tehditVerisi().then(function (t) {
      return hedefIpCoz(ad).then(function (ip) {
        var esles = [];
        ((t && t.c2) || []).forEach(function (k) {
          if (k.ip === ip) {
            esles.push({
              ip: ip, kaynak: k.kaynak || '',
              aciklama: ip + ' zararlı yazılım C2 adresi olarak listelenmiş (' + (k.zararli || '') + ')'
            });
          }
        });
        ((t && t.ioc) || []).forEach(function (k) {
          if (k.ip === ip) {
            esles.push({ ip: ip, kaynak: k.kaynak || '', aciklama: ip + ' ele geçirilmiş sistem listesinde.' });
          }
        });
        return esles;
      });
    }, function () { return []; });
  }

  /* ================================================================== */
  /* 13-bis) EK MODÜLLER (osint-ek.py v1.5'in birebir JS karşılığı)      */
  /*   pasif_radar · cve_detay · cve_esle · arsiv_wayback · urlscan_ara  */
  /*   takeover_tara · savunma_kurallari · toplu_tarama · kanit zinciri  */
  /* ================================================================== */
  var EK_SURUM = '1.5';

  /* Python _kok(): şemayı/yolu/portu at, yalnız alan adını (küçük harf) bırak */
  function ekKok(hedef) {
    var h = String(hedef == null ? '' : hedef).trim().toLowerCase();
    h = h.replace(/^[a-z]+:\/\//, '').split('/')[0].split('@').pop().split(':')[0];
    return h;
  }

  function bekle(ms) {
    return new Promise(function (coz) { setTimeout(coz, ms); });
  }

  function tekrar(metin, adet) {
    var s = '';
    for (var i = 0; i < adet; i++) s += metin;
    return s;
  }

  /* ---------------------------------------------------------- ÖNBELLEK
     Python _onbellekli() karşılığı: basit bellek içi (Map) TTL önbelleği.
     Sayfa yenilenince sıfırlanır (APK'da dosya yazımı yok).               */
  var EK_ONBELLEK = {};

  function ekOnbellekli(anahtar, saniye, zorla, uret) {
    var kayit = EK_ONBELLEK[anahtar];
    if (kayit && !zorla && (simdiMs() / 1000 - (kayit._zaman || 0)) < saniye) {
      var kopya = JSON.parse(JSON.stringify(kayit));
      kopya.onbellek = true;
      return Promise.resolve(kopya);
    }
    return Promise.resolve().then(function () { return uret(); }).then(function (v) {
      if (v && typeof v === 'object') {
        v._zaman = simdiMs() / 1000;
        try { EK_ONBELLEK[anahtar] = JSON.parse(JSON.stringify(v)); }
        catch (e) { EK_ONBELLEK[anahtar] = v; }
      }
      return v;
    });
  }

  /* Python ip_coz(): dns.google DoH (A + AAAA), boşsa köprünün adCoz'u */
  function ekIpCoz(hedef) {
    var ad = ekKok(hedef);
    if (!ad) return Promise.resolve([]);
    if (ipMi(ad)) return Promise.resolve([ad]);
    var liste = [];

    function temizle() {
      var gorulen = {}, cikti = [];
      liste.forEach(function (x) {
        var s = String(x == null ? '' : x).trim();
        if (!s || gorulen[s]) return;
        gorulen[s] = 1;
        if (!ozelIp(s)) cikti.push(s);
      });
      return cikti;
    }

    function tipSorgu(tip) {
      var url = 'https://dns.google/resolve?name=' + encodeURIComponent(ad) + '&type=' + tip;
      return _json(url, { zaman: 12 }).then(function (r) {
        var j = r.j;
        if (j && typeof j === 'object') {
          (j.Answer || []).forEach(function (c) {
            if (c && (c.type === 1 || c.type === 28) && c.data) liste.push(c.data);
          });
        }
      }, function () { });
    }

    return tipSorgu('A').then(function () { return tipSorgu('AAAA'); }).then(function () {
      if (liste.length) return temizle();
      /* Python: socket.getaddrinfo yedeği — köprüde adCoz varsa o kullanılır */
      return adCoz(ad).then(function (ip) {
        var m = String(ip || '').match(/\d+\.\d+\.\d+\.\d+/);
        if (m) liste.push(m[0]);
        return temizle();
      });
    });
  }

  /* --------------------------------------------------------- SHA-256
     Öncelik: Web Crypto (crypto.subtle). Yoksa saf JS yedeği (WebView'de
     güvenli bağlam şartı yüzünden subtle bulunmayabilir).                 */
  var SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function shaRr(x, c) { return (x >>> c) | (x << (32 - c)); }

  function utf8Bayt(metin) {
    var s = String(metin == null ? '' : metin);
    var bayt = [];
    try {
      if (typeof TextEncoder !== 'undefined') {
        var u = new TextEncoder().encode(s);
        for (var i = 0; i < u.length; i++) bayt.push(u[i]);
        return bayt;
      }
    } catch (e) { }
    var s8 = unescape(encodeURIComponent(s));
    for (var j = 0; j < s8.length; j++) bayt.push(s8.charCodeAt(j) & 0xFF);
    return bayt;
  }

  function utf8Uzunluk(metin) { return utf8Bayt(metin).length; }

  function sha256JS(baytGirdi) {
    var liste = baytGirdi.slice();
    var bitUzunluk = liste.length * 8;
    liste.push(0x80);
    while (liste.length % 64 !== 56) liste.push(0);
    var yuksek = Math.floor(bitUzunluk / 4294967296);
    var dusuk = bitUzunluk >>> 0;
    liste.push((yuksek >>> 24) & 255, (yuksek >>> 16) & 255, (yuksek >>> 8) & 255, yuksek & 255);
    liste.push((dusuk >>> 24) & 255, (dusuk >>> 16) & 255, (dusuk >>> 8) & 255, dusuk & 255);

    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var w = new Array(64);
    for (var blok = 0; blok < liste.length; blok += 64) {
      var t;
      for (t = 0; t < 16; t++) {
        var o = blok + t * 4;
        w[t] = ((liste[o] << 24) | (liste[o + 1] << 16) | (liste[o + 2] << 8) | liste[o + 3]) | 0;
      }
      for (t = 16; t < 64; t++) {
        var s0 = shaRr(w[t - 15], 7) ^ shaRr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        var s1 = shaRr(w[t - 2], 17) ^ shaRr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (t = 0; t < 64; t++) {
        var S1 = shaRr(e, 6) ^ shaRr(e, 11) ^ shaRr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + SHA256_K[t] + w[t]) | 0;
        var S0 = shaRr(a, 2) ^ shaRr(a, 13) ^ shaRr(a, 22);
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    var cikti = '';
    for (var q = 0; q < 8; q++) cikti += ('0000000' + (H[q] >>> 0).toString(16)).slice(-8);
    return cikti;
  }

  function sha256Hex(metin) {
    var bayt = utf8Bayt(metin);
    try {
      if (typeof crypto !== 'undefined' && crypto && crypto.subtle && crypto.subtle.digest) {
        return crypto.subtle.digest('SHA-256', new Uint8Array(bayt)).then(function (ozet) {
          var u = new Uint8Array(ozet), s = '';
          for (var i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
          return s;
        }, function () { return sha256JS(bayt); });
      }
    } catch (e) { }
    return Promise.resolve(sha256JS(bayt));
  }

  /* Python json.dumps(..., ensure_ascii=False, sort_keys=True) karşılığı:
     kanıt özeti Python ile birebir aynı çıksın diye ayırıcılar ", " / ": ". */
  function pyStr(s) {
    var cikti = '"';
    for (var i = 0; i < s.length; i++) {
      var kod = s.charCodeAt(i), c = s.charAt(i);
      if (c === '"') cikti += '\\"';
      else if (c === '\\') cikti += '\\\\';
      else if (c === '\n') cikti += '\\n';
      else if (c === '\r') cikti += '\\r';
      else if (c === '\t') cikti += '\\t';
      else if (kod === 8) cikti += '\\b';
      else if (kod === 12) cikti += '\\f';
      else if (kod < 32) cikti += '\\u' + ('000' + kod.toString(16)).slice(-4);
      else cikti += c;
    }
    return cikti + '"';
  }

  function pyJson(deger) {
    if (deger === null || deger === undefined) return 'null';
    var t = typeof deger;
    if (t === 'string') return pyStr(deger);
    if (t === 'boolean') return deger ? 'true' : 'false';
    if (t === 'number') return isFinite(deger) ? String(deger) : 'null';
    if (Object.prototype.toString.call(deger) === '[object Array]') {
      var p = [];
      for (var i = 0; i < deger.length; i++) p.push(pyJson(deger[i]));
      return '[' + p.join(', ') + ']';
    }
    if (t === 'object') {
      var anahtarlar = Object.keys(deger).sort();
      var ciftler = [];
      for (var k = 0; k < anahtarlar.length; k++) {
        ciftler.push(pyStr(anahtarlar[k]) + ': ' + pyJson(deger[anahtarlar[k]]));
      }
      return '{' + ciftler.join(', ') + '}';
    }
    return pyStr(String(deger));
  }

  /* ------------------------------------------------- 1) PASİF RADAR */
  function pasifRadar(hedef, zorla) {
    var anahtar = 'pasif::' + ekKok(hedef);
    return ekOnbellekli(anahtar, 1800, zorla, function () {
      var hedef2 = ekKok(hedef);
      return ekIpCoz(hedef2).then(function (ipler) {
        var kayitlar = [], cveAnahtar = [], tumCve = {}, tumPort = {}, tumCpe = {}, tumHost = {};

        function hostSirala(i) {
          if (i >= Math.min(ipler.length, 3)) return Promise.resolve();
          var ip = ipler[i];
          return _json('https://internetdb.shodan.io/' + ip, { zaman: 15 }).then(function (r) {
            var j = r.j;
            if (r.kod !== 200 || !j || typeof j !== 'object') {
              /* Veri yoksa uydurma YOK: yalnız not düşülür */
              kayitlar.push({ ip: ip, durum: r.kod, not: 'InternetDB kaydı yok (IP taranmamış olabilir)' });
              return;
            }
            var portlar = [];
            (j.ports || []).forEach(function (x) {
              if (/^\d+$/.test(String(x))) portlar.push(parseInt(x, 10));
            });
            var cveIdler = (j.vulns || []).map(function (x) { return String(x); });
            kayitlar.push({
              ip: ip, portlar: portlar, hostname: j.hostnames || [], cpe: j.cpes || [],
              etiket: j.tags || [], cve: cveIdler
            });
            portlar.forEach(function (p) { tumPort[p] = 1; });
            (j.cpes || []).forEach(function (c) { tumCpe[c] = 1; });
            (j.hostnames || []).forEach(function (h) { tumHost[h] = 1; });
            cveIdler.slice(0, 12).forEach(function (c) {
              if (!tumCve[c]) { tumCve[c] = { id: c }; cveAnahtar.push(c); }
            });
          }).then(function () { return hostSirala(i + 1); });
        }

        return hostSirala(0).then(function () {
          /* CVE ayrıntıları: MITRE CVE AWG, ilk 10 kayıt, aralarda 350 ms */
          var cveKuyruk = cveAnahtar.slice(0, 10);
          function cveSirala(i) {
            if (i >= cveKuyruk.length) return Promise.resolve();
            return Promise.resolve().then(function () {
              return i ? bekle(350) : null;
            }).then(function () {
              return cveDetay(cveKuyruk[i]);
            }).then(function (det) {
              if (det) tumCve[cveKuyruk[i]] = det;
              return cveSirala(i + 1);
            });
          }
          return cveSirala(0).then(function () {
            var sirali = cveAnahtar.map(function (k) { return tumCve[k]; });
            sirali.sort(function (a, b) { return (b.skor || 0) - (a.skor || 0); });
            var portlar = Object.keys(tumPort).map(function (x) { return parseInt(x, 10); });
            portlar.sort(function (a, b) { return a - b; });
            return {
              hedef: hedef2, ip: ipler, kayitlar: kayitlar,
              portlar: portlar, port_sayisi: portlar.length,
              cpe: Object.keys(tumCpe).sort(), hostname: Object.keys(tumHost).sort(),
              cveler: sirali, cve_sayisi: sirali.length,
              kritik: sirali.filter(function (c) { return (c.skor || 0) >= 9; }).length,
              kaynak: 'Shodan InternetDB + MITRE CVE',
              uyari: 'Pasif tarama: hedef sistem bu sorguyu görmez. ' +
                'Yalnız sahibi olduğun/izin aldığın sistemler için kullan.',
              guncelleme: simdi()
            };
          });
        });
      });
    });
  }

  /* Tek CVE için başlık/özet/CVSS (Python cve_detay — MITRE CVE AWG) */
  function cveDetay(cid) {
    cid = String(cid == null ? '' : cid).trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,7}$/.test(cid)) return Promise.resolve(null);
    return _json('https://cveawg.mitre.org/api/cve/' + cid, { zaman: 15 }).then(function (r) {
      var j = r.j;
      if (r.kod !== 200 || !j || typeof j !== 'object') {
        return { id: cid, baslik: '', ozet: '', skor: null, kaynak: 'MITRE' };
      }
      var kaplar = j.containers || {};
      var cna = kaplar.cna || {};
      var adp = kaplar.adp || [];
      var skor = null, siddet = '', vektor = '';
      var v3 = ['cvssV3_1', 'cvssV3_0', 'cvssV4_0', 'cvssV2_0'];
      var metrikler = cna.metrics || [];
      for (var i = 0; i < metrikler.length && skor === null; i++) {
        var m = metrikler[i] || {};
        for (var k = 0; k < v3.length; k++) {
          if (Object.prototype.hasOwnProperty.call(m, v3[k])) {
            var mm = m[v3[k]] || {};
            skor = (typeof mm.baseScore === 'undefined') ? null : mm.baseScore;
            siddet = mm.baseSeverity || '';
            vektor = mm.vectorString || '';
            break;
          }
        }
      }
      if (skor === null) {
        var v3adp = ['cvssV3_1', 'cvssV3_0', 'cvssV4_0'];
        for (var b = 0; b < adp.length && skor === null; b++) {
          var blok = adp[b] || {};
          var bm = blok.metrics || [];
          for (var q = 0; q < bm.length; q++) {
            var m2 = bm[q] || {};
            for (var k2 = 0; k2 < v3adp.length; k2++) {
              if (Object.prototype.hasOwnProperty.call(m2, v3adp[k2])) {
                var mm2 = m2[v3adp[k2]] || {};
                skor = (typeof mm2.baseScore === 'undefined') ? null : mm2.baseScore;
                siddet = mm2.baseSeverity || '';
                break;
              }
            }
            if (skor) break;
          }
        }
      }
      var ozet = '';
      var tanimlar = cna.descriptions || [];
      for (var d = 0; d < tanimlar.length; d++) {
        var td = tanimlar[d] || {};
        if (String(td.lang || '').toLowerCase().indexOf('en') === 0) {
          ozet = td.value || '';
          break;
        }
      }
      return {
        id: cid, baslik: String(cna.title || '').trim(), ozet: ozet.slice(0, 300),
        skor: skor, siddet: siddet, vektor: vektor,
        tarih: String((j.cveMetadata || {}).datePublished || '').slice(0, 10),
        url: 'https://www.cve.org/CVERecord?id=' + cid, kaynak: 'MITRE CVE AWG'
      };
    });
  }

  /* ------------------------------------------- 2) TEKNOLOJİ → CVE EŞLEME */
  function cveEsle(tek, surum, enFazla) {
    tek = String(tek == null ? '' : tek).trim().toLowerCase();
    if (!tek) {
      return Promise.resolve({ hata: 'teknoloji adı gerekli', ornek: 'nginx, apache, wordpress, openssh' });
    }
    surum = String(surum == null ? '' : surum).trim();
    enFazla = enFazla || 8;
    var anahtar = 'cve::' + tek + '::' + surum;

    return ekOnbellekli(anahtar, 21600, false, function () {
      /* NVD anahtar kelime araması çok kelimede boş dönüyor: yalnız ürün adıyla
         ara, sürüm izini açıklama metninde kendimiz arayalım. */
      var url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=' +
        encodeURIComponent(tek) + '&resultsPerPage=120';
      return _json(url, { zaman: 30 }).then(function (r) {
        var kayitlar = [];
        var j = r.j;
        if (r.kod === 200 && j && typeof j === 'object') {
          (j.vulnerabilities || []).forEach(function (v) {
            var c = (v || {}).cve || {};
            var metin = '';
            var ds = c.descriptions || [];
            for (var i = 0; i < ds.length; i++) {
              var dd = ds[i] || {};
              if (String(dd.lang || '').toLowerCase().indexOf('en') === 0 && dd.value) {
                metin = dd.value;
                break;
              }
            }
            if (metin.toLowerCase().indexOf(tek) < 0) return;
            var skor = null, siddet = '';
            var metrikler = c.metrics || {};
            var mAnahtarlar = Object.keys(metrikler);
            for (var q = 0; q < mAnahtarlar.length && !skor; q++) {
              var m = metrikler[mAnahtarlar[q]] || [];
              try {
                var cv = (m[0] || {}).cvssData || {};
                skor = (typeof cv.baseScore === 'undefined') ? null : cv.baseScore;
                siddet = cv.baseSeverity || (m[0] || {}).baseSeverity || '';
              } catch (e) { }
            }
            /* sürüm izi: tam sürüm ya da ilk iki hane (1.24.0 → 1.24) */
            var ipuclari = [];
            if (surum) {
              ipuclari = [surum, surum.split('.').slice(0, 2).join('.')];
              if (surum.split('.').length - 1 === 1) ipuclari.push(surum + '.0');
            }
            var ipucleri = ipuclari.filter(function (x) { return x.length >= 3; });
            var eslesti = false;
            for (var z = 0; z < ipucleri.length; z++) {
              if (metin.indexOf(ipucleri[z]) >= 0) { eslesti = true; break; }
            }
            kayitlar.push({
              id: c.id, ozet: metin.slice(0, 260), skor: skor, siddet: siddet,
              yayin: String(c.published || '').slice(0, 10), surum_geciyor: eslesti,
              url: 'https://www.cve.org/CVERecord?id=' + String(c.id)
            });
          });
        }
        var eslesen = kayitlar.filter(function (k) { return k.surum_geciyor; });
        var kalan = kayitlar.filter(function (k) { return !k.surum_geciyor; });
        eslesen.sort(function (a, b) { return (b.skor || 0) - (a.skor || 0); });
        if (surum && !eslesen.length) {
          /* sürüm verilmiş ve hiç eşleşme yoksa: tarihe göre yeniden eskiye */
          kalan.sort(function (a, b) {
            var ya = a.yayin || '', yb = b.yayin || '';
            if (ya !== yb) return ya < yb ? 1 : -1;
            return (b.skor || 0) - (a.skor || 0);
          });
        } else {
          kalan.sort(function (a, b) { return (b.skor || 0) - (a.skor || 0); });
        }
        var secili = surum ? eslesen.concat(kalan).slice(0, enFazla) : kalan.slice(0, enFazla);
        return {
          teknoloji: tek, surum: surum, toplam_bulunan: kayitlar.length,
          surum_eslesen: eslesen.length, kayitlar: secili,
          kaynak: 'NVD CVE API 2.0 (anahtar kelime + sürüm izi)',
          uyari: "Olası eşleşme: NVD açıklamasında '" + tek + "' geçen kayıtlar listelendi. " +
            (surum ? 'Sürüm izi bulunanlar ("' + surum + '") başta. ' : '') +
            'Kesin zafiyet tespiti için ürün sürüm aralığı doğrulanmalı.',
          ornek: "nginx + 1.24.0 → açıklamasında 1.24 geçen CVE'ler ilk sırada",
          guncelleme: simdi()
        };
      });
    });
  }

  /* ------------------------------------------------ 3) ARŞİV (WAYBACK CDX) */
  function arsivWayback(hedef, enFazla) {
    enFazla = enFazla || 200;
    var anahtar = 'arsiv::' + ekKok(hedef);
    return ekOnbellekli(anahtar, 86400, false, function () {
      var d = ekKok(hedef);
      var limit = Math.min(Math.max(enFazla, 20), 800);
      var url = 'http://web.archive.org/cdx/search/cdx?url=' + encodeURIComponent(d) +
        '&matchType=domain&output=json&fl=timestamp,original,statuscode&collapse=urlkey&limit=' +
        limit + '&filter=statuscode:200';
      return _cek(url, { zaman: 35 }).then(function (r) {
        var satirlar = [];
        try {
          var govde = String(r.govde || '');
          var ham = govde.trim().charAt(0) === '[' ? JSON.parse(govde) : [];
          satirlar = (ham && ham.length && ham[0] && ham[0][0] === 'timestamp') ? ham.slice(1) : (ham || []);
        } catch (e) { satirlar = []; }
        var eskiHost = {}, eskiYol = {}, yillar = {};
        satirlar.forEach(function (s) {
          if (!s || s[0] === undefined || s[1] === undefined) return;
          var ts = String(s[0]), org = String(s[1]);
          var yil = ts.slice(0, 4);
          yillar[yil] = (yillar[yil] || 0) + 1;
          try {
            var t = org.indexOf('http') === 0 ? org : 'http://' + org;
            var kalan = t.replace(/^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//, '');
            var parc = kalan.split('#')[0];
            var netloc = parc.split('?')[0].split('/')[0];
            if (netloc) eskiHost[netloc] = (eskiHost[netloc] || 0) + 1;
            var kuyruk = parc.slice(netloc.length);
            if (kuyruk.charAt(0) === '?') kuyruk = '';
            var yol = kuyruk.split('?')[0];
            /* '%' içeren ve 60 karakterden uzun yollar elenir */
            if (yol && yol !== '/' && yol.indexOf('%') < 0 && yol.length <= 60) {
              eskiYol[yol] = (eskiYol[yol] || 0) + 1;
            }
          } catch (e) { }
        });
        /* hedef dışı / vahşi alan adı varsa dikkat çek */
        var disari = Object.keys(eskiHost).filter(function (h) { return h.indexOf(d) < 0; }).sort();
        var yilSiral = {};
        Object.keys(yillar).sort().forEach(function (y) { yilSiral[y] = yillar[y]; });
        return {
          hedef: d, toplam_kayit: satirlar.length,
          ilk_kayit: satirlar.length ? String(satirlar[0][0]) : '',
          son_kayit: satirlar.length ? String(satirlar[satirlar.length - 1][0]) : '',
          yillar: yilSiral,
          eski_hostlar: Object.keys(eskiHost).map(function (h) { return [h, eskiHost[h]]; })
            .sort(function (a, b) { return b[1] - a[1]; }).slice(0, 12),
          dis_hostlar: disari.slice(0, 12),
          eski_yollar: Object.keys(eskiYol).map(function (y) { return [y, eskiYol[y]]; })
            .sort(function (a, b) { return b[1] - a[1]; }).slice(0, 15),
          kaynak: 'Wayback Machine CDX (archive.org)',
          ornek: 'Silinmiş sayfalar ve eski parametreler burada görünür — ' +
            'ör. /admin, /eski-site, test.php gibi yollar hâlâ sunucuda olabilir.',
          guncelleme: simdi()
        };
      });
    });
  }

  /* --------------------------------------------------------- 4) URLSCAN.IO */
  function urlscanAra(hedef, enFazla) {
    enFazla = enFazla || 10;
    var anahtar = 'urlscan::' + ekKok(hedef);
    return ekOnbellekli(anahtar, 3600, false, function () {
      var d = ekKok(hedef);
      var boyut = Math.min(Math.max(enFazla, 1), 50);
      var url = 'https://urlscan.io/api/v1/search/?q=' +
        encodeURIComponent('page.domain:' + d) + '&size=' + boyut;
      return _json(url, { zaman: 25 }).then(function (r) {
        var kayitlar = [];
        var j = r.j;
        if (j && typeof j === 'object') {
          (j.results || []).forEach(function (x) {
            var gorev = x.task || {}, sayfa = x.page || {};
            var uuid = x._id || gorev.uuid || '';
            kayitlar.push({
              url: sayfa.url || gorev.url,
              zaman: String(gorev.time || '').slice(0, 19).replace('T', ' '),
              ip: sayfa.ip, sunucu: sayfa.server, ulke: sayfa.country,
              durum: sayfa.status,
              sonuc: uuid ? ('https://urlscan.io/result/' + uuid + '/') : '',
              ekran: uuid ? ('https://urlscan.io/screenshots/' + uuid + '.png') : '',
              malzeme: uuid ? ('https://urlscan.io/dom/' + uuid + '/') : ''
            });
          });
        }
        return {
          hedef: d, kayitlar: kayitlar, toplam: kayitlar.length,
          kaynak: 'urlscan.io genel API (anahtarsız)',
          ornek: 'Başkasının yaptığı gerçek taramadan ekran görüntüsü/DOM çekilir: ' +
            'ör. eski bir phishing sayfasının kopyası veya sitenin 2019 hâli.',
          guncelleme: simdi()
        };
      });
    });
  }

  /* ------------------------------------- 5) SUBDOMAIN TAKEOVER TARAMASI */
  var TAKEOVER_IMIZALARI = [
    ['github.io', "There isn't a GitHub Pages site here", 'GitHub Pages'],
    ['herokuapp.com', 'No such app', 'Heroku'],
    ['s3.amazonaws.com', 'NoSuchBucket', 'AWS S3'],
    ['cloudfront.net', 'Bad request', 'CloudFront'],
    ['azureedge.net', '', 'Azure CDN'],
    ['blob.core.windows.net', 'BlobNotFound', 'Azure Blob'],
    ['fastly.net', 'Fastly error: unknown domain', 'Fastly'],
    ['pantheonsite.io', 'The gods are wise, but do not know of the site', 'Pantheon'],
    ['myshopify.com', 'Sorry, this shop is currently unavailable', 'Shopify'],
    ['wordpress.com', 'Do you want to register', 'WordPress.com'],
    ['tumblr.com', "There's nothing here.", 'Tumblr'],
    ['readthedocs.io', 'unknown to Read the Docs', 'Read the Docs'],
    ['surge.sh', 'project not found', 'Surge.sh'],
    ['netlify.app', 'Not Found - Request ID', 'Netlify'],
    ['vercel.app', 'The deployment could not be found', 'Vercel'],
    ['webflow.io', "The page you are looking for doesn't exist", 'Webflow'],
    ['zendesk.com', 'Help Center Closed', 'Zendesk'],
    ['statuspage.io', 'Status page not found', 'Statuspage'],
    ['freshdesk.com', 'May be this is still fresh', 'Freshdesk'],
    ['cargo.site', '404 Not Found', 'Cargo']
  ];

  var TAKEOVER_CHAIN = [
    ['CNAME', 'CNAME'], ['A', 'A'], ['AAAA', 'AAAA'], ['NS', 'NS']
  ];

  /* Python cname_zinciri(): dns.google üzerinden CNAME zinciri */
  function cnameZinciri(ad, derinlik) {
    derinlik = derinlik || 6;
    var zincir = [], mevcut = ad, gorulen = {};

    function adim(i) {
      if (i >= derinlik || !mevcut || gorulen[mevcut]) {
        return Promise.resolve([mevcut, zincir]);
      }
      gorulen[mevcut] = 1;
      var url = 'https://dns.google/resolve?name=' + encodeURIComponent(mevcut) + '&type=CNAME';
      return _json(url, { zaman: 12 }).then(function (r) {
        var hedef = '';
        var j = r.j;
        if (j && typeof j === 'object') {
          (j.Answer || []).forEach(function (c) {
            if (!hedef && c && c.type === 5 && c.data) hedef = String(c.data).replace(/\.+$/, '');
          });
        }
        if (!hedef) return [mevcut, zincir];
        zincir.push({ kaynak: mevcut, hedef: hedef });
        mevcut = hedef;
        return adim(i + 1);
      });
    }
    return adim(0);
  }

  function takeoverTara(hedef, altAlanlar, enFazla) {
    enFazla = enFazla || 60;
    var anahtar = 'takeover::' + ekKok(hedef);
    return ekOnbellekli(anahtar, 3600, false, function () {
      var d = ekKok(hedef);
      /* Alt alan kaynağı: motor-osint.js'teki mevcut subdomain tarayıcısı */
      var altIsi;
      if (altAlanlar && altAlanlar.length) {
        altIsi = Promise.resolve(altAlanlar.map(function (x) { return String(x); }));
      } else {
        altIsi = Promise.resolve().then(function () {
          return subdomainTara(d, 400);
        }).then(function (s) {
          var liste = [];
          var kayitlar = (s && (s.alt_alanlar || s.kayitlar)) || [];
          kayitlar.forEach(function (k) {
            var ad = (k && typeof k === 'object') ? k.ad : k;
            if (ad) liste.push(String(ad));
          });
          return liste;
        }, function () { return []; });
      }

      return altIsi.then(function (ham) {
        var gorulen = {}, altlar = [];
        (ham || []).forEach(function (a) {
          var s = String(a == null ? '' : a);
          if (s && s.indexOf(d) >= 0 && !gorulen[s]) { gorulen[s] = 1; altlar.push(s); }
        });
        /* Python: alt alan hiç bulunamazsa hackertarget yedeği */
        if (!altlar.length && !(altAlanlar && altAlanlar.length)) {
          return _cek('https://api.hackertarget.com/hostsearch/?q=' + encodeURIComponent(d), { zaman: 30 })
            .then(function (r) {
              var govde = String(r.govde || '').toLowerCase();
              if (r.kod === 200 && r.govde && govde.indexOf('<html') < 0 && govde.indexOf('exceeded') < 0) {
                String(r.govde).split(/\r?\n/).forEach(function (satir) {
                  var par = satir.split(',');
                  if (par[0] && par[0].indexOf(d) >= 0 && !gorulen[par[0].trim()]) {
                    gorulen[par[0].trim()] = 1;
                    altlar.push(par[0].trim());
                  }
                });
              }
              return devam();
            });
        }
        return devam();

        function devam() {
          altlar = altlar.slice(0, enFazla);
          var supheli = [], zincirler = [];

          function zincirSirala(i) {
            if (i >= altlar.length) return Promise.resolve();
            return cnameZinciri(altlar[i]).then(function (z) {
              var zincir = z[1];
              if (zincir.length) {
                var nihai = zincir[zincir.length - 1].hedef;
                zincirler.push({ ad: altlar[i], cname: nihai, zincir: zincir, servis: '—' });
                for (var k = 0; k < TAKEOVER_IMIZALARI.length; k++) {
                  if (nihai.indexOf(TAKEOVER_IMIZALARI[k][0]) >= 0) {
                    supheli.push({ ad: altlar[i], cname: nihai, servis: TAKEOVER_IMIZALARI[k][2] });
                    break;
                  }
                }
              }
              return zincirSirala(i + 1);
            });
          }

          return zincirSirala(0).then(function () {
            var bulgular = [];

            /* şüphelileri HTTP ile doğrula (kendi ağından DEĞİL, sadece okuma) */
            function dogrula(i) {
              if (i >= Math.min(supheli.length, 12)) return Promise.resolve();
              var s = supheli[i];
              return _cek('http://' + s.ad, { zaman: 10 }).then(function (r) {
                var kod = r.kod, govde = r.govde || '';
                if (kod === 0 || kod === 404) {
                  return _cek('https://' + s.ad, { zaman: 10 }).then(function (r2) {
                    if (r2.kod) { kod = r2.kod; govde = r2.govde || ''; }
                    return { kod: kod, govde: govde };
                  });
                }
                return { kod: kod, govde: govde };
              }).then(function (v) {
                var imza = '';
                for (var k = 0; k < TAKEOVER_IMIZALARI.length; k++) {
                  var im = TAKEOVER_IMIZALARI[k][1];
                  if (im && String(v.govde).toLowerCase().indexOf(String(im).toLowerCase()) >= 0) {
                    imza = im;
                    break;
                  }
                }
                s.durum_kodu = v.kod;
                s.imza_bulundu = !!imza;
                s.imza = imza;
                s.risk = (imza || v.kod === 404) ? 'yüksek' : 'orta';
                bulgular.push(s);
                return dogrula(i + 1);
              });
            }

            return dogrula(0).then(function () {
              return {
                hedef: d, denenen: altlar.length, supheli: supheli.length,
                kayitlar: bulgular, cname_zincirleri: zincirler.slice(0, 20),
                subdomain_sayisi: altlar.length,
                kaynak: 'dns.google (CNAME) + servis imzaları',
                ornek: 'Sahipsiz kalan subdomain (ör. eski.magaza.com → silinmiş Shopify mağazası) ' +
                  "başkası tarafından ele geçirilebilir; imza bulunursa risk 'yüksek' yazılır.",
                guncelleme: simdi()
              };
            });
          });
        }
      });
    });
  }

  /* --------------------------- 6) SAVUNMA: IOC → WINDOWS GÜVENLİK DUVARI */
  function ps1Zamani() {
    var d = new Date();
    function p(n) { return (n < 10 ? '0' : '') + n; }
    return p(d.getDate()) + '.' + p(d.getMonth() + 1) + '.' + d.getFullYear() + ' ' +
      p(d.getHours()) + ':' + p(d.getMinutes());
  }

  function dosyaZamani() {
    var d = new Date();
    function p(n) { return (n < 10 ? '0' : '') + n; }
    return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' +
      p(d.getHours()) + p(d.getMinutes());
  }

  /* Python _ps1_uret — metin birebir aynı olmalı */
  function _ps1Uret(ipler) {
    var satir = ipler.map(function (ip) { return '  "' + ip + '"'; }).join('\n');
    return '# ÜSTAD OSINT — Windows Güvenlik Duvarı engel listesi\n' +
      '# ' + ps1Zamani() + ' · ' + String(ipler.length) + ' IP\n' +
      '# YÖNETİCİ olarak çalıştır:  powershell -ExecutionPolicy Bypass -File <bu-dosya>\n' +
      '$liste = @(\n' + satir + '\n)\n' +
      'if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()' +
      ').IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {\n' +
      "  Write-Host 'HATA: Bu betiği yönetici olarak çalıştırmalısın.' -ForegroundColor Red; exit 1\n" +
      '}\n' +
      '# eski kuralı temizle\n' +
      "Get-NetFirewallRule -DisplayName 'USTAD-OSINT-Engel-*' -ErrorAction SilentlyContinue | " +
      'Remove-NetFirewallRule -ErrorAction SilentlyContinue\n' +
      '$i = 0\n' +
      'foreach ($ip in $liste) {\n' +
      '  $i++\n' +
      '  try {\n' +
      '    New-NetFirewallRule -DisplayName ("USTAD-OSINT-Engel-$i") -Direction Outbound ' +
      '-Action Block -RemoteAddress $ip -Profile Any -ErrorAction Stop | Out-Null\n' +
      '    New-NetFirewallRule -DisplayName ("USTAD-OSINT-Engel-Gelen-$i") -Direction Inbound ' +
      '-Action Block -RemoteAddress $ip -Profile Any -ErrorAction Stop | Out-Null\n' +
      '  } catch { Write-Host "atlandı: $ip" }\n' +
      '}\n' +
      'Write-Host "TAMAM: $($liste.Count) zararlı IP engellendi." -ForegroundColor Green\n' +
      "Write-Host 'Kaldırmak için: ustad-osint-duvar-geri.ps1' -ForegroundColor Yellow\n";
  }

  /* Python _ps1_geri — metin birebir aynı olmalı */
  function _ps1Geri(ipler) {
    return '# ÜSTAD OSINT — engel listesini KALDIRIR\n' +
      "Get-NetFirewallRule -DisplayName 'USTAD-OSINT-Engel-*' -ErrorAction SilentlyContinue | " +
      'Remove-NetFirewallRule\n' +
      "Write-Host 'TAMAM: ÜSTAD OSINT engel kuralları kaldırıldı.' -ForegroundColor Green\n";
  }

  function savunmaKurallari() {
    return ekOnbellekli('savunma', 3600, false, function () {
      var ipler = [], kaynaklar = [];
      var beslemeler = [
        ['https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'EmergingThreats'],
        ['https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt', 'ET Block IPs'],
        ['https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 'Feodo Tracker']
      ];

      function sirada(i) {
        if (i >= beslemeler.length) return Promise.resolve();
        var url = beslemeler[i][0], ad = beslemeler[i][1];
        return _cek(url, { zaman: 25 }).then(function (r) {
          var sayi = 0;
          if (r.kod === 200 && r.govde) {
            String(r.govde).split(/\r?\n/).forEach(function (satir) {
              satir = satir.trim();
              if (!satir || satir.charAt(0) === '#') return;
              var parcalar = satir.split(/\s+/);
              var ip = parcalar.length ? satir.split(';')[0].split(/\s+/)[0] : '';
              ip = ip.replace('http://', '').replace('https://', '').split('/')[0];
              if (ipMi(ip) && !ozelIp(ip)) { ipler.push(ip); sayi++; }
            });
          }
          kaynaklar.push({ ad: ad, sayi: sayi, url: url });
          return sirada(i + 1);
        });
      }

      return sirada(0).then(function () {
        var gorulen = {}, benzersiz = [];
        ipler.forEach(function (x) { if (!gorulen[x]) { gorulen[x] = 1; benzersiz.push(x); } });
        benzersiz.sort();
        return {
          ip_sayisi: benzersiz.length, ipler: benzersiz.slice(0, 400), kaynaklar: kaynaklar,
          ps1: _ps1Uret(benzersiz), geri_alma: _ps1Geri(benzersiz),
          dosya_adi: 'ustad-osint-guvenlik-duvari-' + dosyaZamani() + '.ps1',
          kaynak: 'EmergingThreats + Feodo Tracker + ET Block IPs',
          ornek: "Bu betiği yönetici olarak çalıştırınca listelenen zararlı IP'ler Windows'a " +
            "engellenir; 'geri_alma' betiği temizler. Kendi ağını korumak için.",
          guncelleme: simdi()
        };
      });
    });
  }

  /* ------------------------------------------------------- 7) TOPLU TARAMA */
  function topluTarama(hedefler, moduller, enFazla) {
    enFazla = enFazla || 25;
    if (typeof hedefler === 'string') {
      hedefler = hedefler.split(/[\s,;]+/).map(function (x) { return x.trim(); })
        .filter(function (x) { return x; });
    }
    hedefler = (hedefler || []).filter(function (x) { return x; })
      .slice(0, Math.min(Math.max(enFazla, 1), 100));
    if (typeof moduller === 'string') {
      moduller = moduller.split(/[,\s]+/).filter(function (x) { return x; });
    }
    moduller = (moduller && moduller.length) ? moduller : ['dns', 'whois', 'ip', 'subdomain', 'webtek'];
    var sonuclar = [];

    function sirada(i) {
      if (i >= hedefler.length) return Promise.resolve();
      var h = hedefler[i];
      return Promise.resolve().then(function () {
        return profilCikar(h, moduller);
      }).then(function (r) {
        sonuclar.push({
          hedef: h, risk: r.risk, sayilar: r.sayilar,
          bulgu: (r.bulgular || []).length,
          ilk_bulgular: (r.bulgular || []).slice(0, 3).map(function (b) {
            /* Python: (baslik or aciklama or tur or "")[:90] */
            var d = b ? (b.baslik || b.aciklama || b.tur || '') : '';
            return String(d).slice(0, 90);
          })
        });
      }, function (e) {
        sonuclar.push({ hedef: h, risk: -1, hata: String((e && e.message) || e).slice(0, 120) });
      }).then(function () { return sirada(i + 1); });
    }

    return sirada(0).then(function () {
      sonuclar.sort(function (a, b) { return (b.risk || 0) - (a.risk || 0); });
      return {
        adet: sonuclar.length, kayitlar: sonuclar,
        kaynak: 'ÜSTAD OSINT profil çekirdeği',
        ornek: 'Elindeki 50 alan adını tek seferde tarar, riski yüksekten aşağıya sıralar — ' +
          'ör. hangi sitende eski bir panel var?',
        guncelleme: simdi()
      };
    });
  }

  /* ------------------------------------------------------ 8) KANIT ZİNCİRİ
     Dosya yazımı yoksa zincir bellekte tutulur, localStorage'a da yedeklenir. */
  var KANIT_ANAHTAR = 'ustad_kanit_zinciri';
  var kanitBellek = null;

  function kanitOku() {
    try {
      if (typeof localStorage !== 'undefined') {
        var ham = localStorage.getItem(KANIT_ANAHTAR);
        if (ham) {
          var z = JSON.parse(ham);
          if (z && z.length !== undefined) { kanitBellek = z; return kanitBellek; }
        }
      }
    } catch (e) { }
    return kanitBellek || [];
  }

  function kanitYaz(zincir) {
    kanitBellek = zincir;
    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(KANIT_ANAHTAR, JSON.stringify(zincir));
      }
    } catch (e) { }
  }

  function kanitEkle(rapor) {
    var sozluk = rapor && typeof rapor === 'object' &&
      Object.prototype.toString.call(rapor) !== '[object Array]';
    var ham = (typeof rapor === 'string') ? rapor : pyJson(rapor);
    return sha256Hex(ham).then(function (ozet) {
      var kayit = {
        sha256: ozet, zaman: simdi(), boyut: utf8Uzunluk(ham),
        hedef: sozluk ? (rapor.hedef === undefined ? null : rapor.hedef) : ''
      };
      var zincir = kanitOku();
      var onceki = zincir.length ? zincir[zincir.length - 1].sha256 : tekrar('0', 64);
      kayit.onceki = onceki;
      kayit.zincir_no = zincir.length + 1;
      /* zincir kaydı: önceki özeti de içine kat → sonradan değiştirilirse zincir bozulur */
      return sha256Hex(ozet + onceki).then(function (muhur) {
        kayit.muhur = muhur;
        zincir.push(kayit);
        kanitYaz(zincir.slice(-200));
        return {
          kayit: kayit, zincir_uzunluk: zincir.length,
          kaynak: 'SHA-256 + yerel zincir (veri/kanit-zinciri.json)',
          ornek: 'Raporu sonradan değiştirirsen mühür tutmaz; mahkemeye/karşı tarafa ' +
            "'bu rapor değiştirilmedi' kanıtı olur.",
          guncelleme: kayit.zaman
        };
      });
    });
  }

  function kanitListesi(enFazla) {
    enFazla = enFazla || 20;
    var z = kanitOku();
    return Promise.resolve({
      zincir: z.slice(-enFazla).reverse(), toplam: z.length,
      dosya: 'ustad_kanit_zinciri (bellek + localStorage)'
    });
  }

  /* ================================================================== */
  /* 13-ter) YENİ NESİL ARAÇLAR (v1.6)                                   */
  /*   osint-ek2a.py · osint-ek2b.py · osint-ek2c.py dosyalarının        */
  /*   birebir JS karşılığı. Alan adları Python sürümüyle AYNIDIR.       */
  /*                                                                     */
  /*   istismar · postaguvenlik · baslikanaliz · sertifika ·             */
  /*   webzafiyet · fidye · saldiriakisi · siravc · yerelag ·            */
  /*   sifrekontrol · raporpaket · bildirim                              */
  /*                                                                     */
  /*   APK gerçekleri (dürüstçe ele alınır, uydurma veri üretilmez):     */
  /*     • Dosya sistemi yok → siravc yalnız GitHub yolu (?github=1).    */
  /*     • `arp -a` / UDP SSDP yok → yerelag dürüst hata döner.          */
  /*     • python-docx yok → raporpaket HTML içeriğini döndürür.         */
  /*     • Şifre asla yanıt gövdesine/log'a yazılmaz.                    */
  /* ================================================================== */
  var EK2_SURUM = '1.6';
  var EK2_MAX_CVE = 20;
  var EK2_KEV_TTL = 86400, EK2_EPSS_TTL = 3600, EK2_DNS_TTL = 1800, EK2_POSTA_TTL = 3600;
  var EK2_TTL_SERTIFIKA = 6 * 3600, EK2_TTL_WEBZAFIYET = 30 * 60, EK2_TTL_FIDYE = 3600;
  var EK2_ISTEK_ARASI = 250;           /* ms — Python: 0.25 sn bekleme */
  var EK2_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/' +
    'known_exploited_vulnerabilities.json';
  var EK2_EPSS_URL = 'https://api.first.org/data/v1/epss';
  var EK2_DOH_URL = 'https://dns.google/resolve';
  var EK2_DKIM_SECICILERI = ['default', 'google', 'k1', 'mail', 'dkim',
    'selector1', 'selector2', 's1', 's2', 'smtp'];

  /* APK tarafında dosya yok: önbellek ve "önceki tarama" kayıtları bellek +
     localStorage'da tutulur (masaüstü sürümünde veri/ek2-onbellek.json).    */
  var EK2_ONBELLEK = {};
  var EK2_LS_BILDIRIM = 'osint_ek2_bildirim';
  var EK2_LS_SERTIFIKA = 'osint_ek2_sertifika_gecmis';
  var EK2_LS_IZLEME = 'osint_ek2_izleme';
  var EK2_GITHUB_ANAHTAR = '';

  function ek2LsOku(anahtar) {
    try {
      if (typeof localStorage === 'undefined') return null;
      var ham = localStorage.getItem(anahtar);
      return ham ? JSON.parse(ham) : null;
    } catch (e) { return null; }
  }

  function ek2LsYaz(anahtar, deger) {
    try {
      if (typeof localStorage === 'undefined') return false;
      localStorage.setItem(anahtar, JSON.stringify(deger));
      return true;
    } catch (e) { return false; }
  }

  /* Python _onbellekli(): taze kayıt varsa onu döner; "hata" taşıyan ve
     "_onbellekleme" işaretli (eksik veri) sonuçlar önbelleğe YAZILMAZ.     */
  function ek2Onbellekli(anahtar, saniye, zorla, uret) {
    if (zorla) { try { delete EK2_ONBELLEK[anahtar]; } catch (e) { } }
    var kayit = EK2_ONBELLEK[anahtar];
    if (kayit && (simdiMs() / 1000 - (kayit._zaman || 0)) < saniye) {
      var kopya = JSON.parse(JSON.stringify(kayit));
      delete kopya._zaman;
      kopya.onbellek = true;
      return Promise.resolve(kopya);
    }
    return Promise.resolve().then(function () { return uret(); }).then(function (v) {
      if (v && typeof v === 'object' && !v.hata) {
        if (v._onbellekleme) { try { delete v._onbellekleme; } catch (e) { } return v; }
        try {
          var kayda = JSON.parse(JSON.stringify(v));
          kayda._zaman = simdiMs() / 1000;
          EK2_ONBELLEK[anahtar] = kayda;
        } catch (e) { }
      }
      return v;
    });
  }

  function ek2ZorlaMi(sorgu, govde) {
    var kaynaklar = [sorgu || {}, govde || {}];
    for (var i = 0; i < kaynaklar.length; i++) {
      var v = kaynaklar[i].zorla;
      if (String(v === undefined || v === null ? '' : v).toLowerCase() === '1' ||
        ['true', 'evet', 'yes', 'var'].indexOf(String(v === undefined || v === null ? '' : v).toLowerCase()) >= 0) {
        return true;
      }
    }
    return false;
  }

  function ek2Kirp(s, karakterler) {
    s = String(s == null ? '' : s);
    while (s.length && karakterler.indexOf(s.charAt(0)) >= 0) s = s.slice(1);
    while (s.length && karakterler.indexOf(s.charAt(s.length - 1)) >= 0) s = s.slice(0, -1);
    return s;
  }

  /* Python _kok(): şema/yol/kullanıcı/port atılır, sondaki nokta temizlenir */
  function ek2Kok(hedef) {
    var h = String(hedef == null ? '' : hedef).trim().toLowerCase();
    h = h.replace(/^[a-z]+:\/\//, '').split('/')[0].split('@').pop().split(':')[0];
    return ek2Kirp(h, '.');
  }

  /* Python _ad_temizle() */
  function ek2AdTemizle(hedef) {
    var h = String(hedef == null ? '' : hedef).trim().toLowerCase();
    h = h.replace(/^[a-z][a-z0-9+.\-]*:\/\//, '');
    h = h.split('/')[0];
    if (h.indexOf('@') >= 0) h = h.split('@').pop();
    h = h.split(':')[0].trim();
    return ek2Kirp(h, '.');
  }

  /* Python _ad_gecerli() */
  function ek2AdGecerli(ad) {
    return /^(?!-)[a-z0-9_][a-z0-9_-]{0,62}(\.[a-z0-9_][a-z0-9_-]{0,62})+$/.test(String(ad || '').toLowerCase());
  }

  /* Python _ozel_ip(): yalnız yönlendirilemeyen aralıklar (203.0.113.x gibi
     belge/test adresleri özel SAYILMAZ — JS ozelIp'ten farkı budur).        */
  var EK2_OZEL_AGLAR = [
    ['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['127.0.0.0', 8],
    ['169.254.0.0', 16], ['100.64.0.0', 10], ['0.0.0.0', 8], ['240.0.0.0', 4]
  ];

  function ek2IpBaytlari(ip) {
    var p = String(ip || '').split('.');
    if (p.length !== 4) return null;
    var a = [];
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(p[i])) return null;
      var n = parseInt(p[i], 10);
      if (n > 255) return null;
      a.push(n);
    }
    return a;
  }

  function ek2OzelIp(ip) {
    var s = String(ip == null ? '' : ip).trim();
    if (!s) return false;
    if (s.indexOf(':') >= 0) {
      var k = s.toLowerCase();
      if (k === '::1' || k === '::') return true;
      var ilk = k.split(':')[0];
      if (!ilk) return false;
      if (ilk.charAt(0) === 'f') {
        var c1 = ilk.charAt(1);
        if (c1 === 'c' || c1 === 'd') return true;              /* fc00::/7 */
        if (c1 === 'e') {                                       /* fe80::/10 */
          var uc = parseInt(ilk.slice(0, 3), 16);
          if (!isNaN(uc) && uc >= 0xfe8 && uc <= 0xfeb) return true;
        }
        if (c1 === 'f') return true;                            /* ff00::/8 */
      }
      return false;
    }
    var a = ek2IpBaytlari(s);
    if (!a) return false;
    for (var j = 0; j < EK2_OZEL_AGLAR.length; j++) {
      var ag = EK2_OZEL_AGLAR[j], bayt = ek2IpBaytlari(ag[0]), kalan = ag[1], es = true;
      for (var o = 0; o < 4 && kalan > 0; o++) {
        var bit = kalan >= 8 ? 8 : kalan;
        var maske = bit === 8 ? 255 : (256 - Math.pow(2, 8 - bit));
        if ((a[o] & maske) !== (bayt[o] & maske)) { es = false; break; }
        kalan -= 8;
      }
      if (es) return true;
    }
    return a[0] >= 224;                                         /* çoklu yayın */
  }

  function ek2GecerliIp(s) {
    s = String(s || '').trim();
    if (!s) return false;
    if (s.indexOf(':') >= 0) return /^[0-9a-fA-F:]{2,45}$/.test(s) && s.split(':').length >= 3;
    return !!ek2IpBaytlari(s);
  }

  /* ---------------------------------------------------------------- SHA-1
     yalnız şifre kontrolünde (HIBP k-anonymity) kullanılır; şifre cihazdan
     ÇIKMAZ, yalnız SHA-1'in ilk 5 karakteri gönderilir.                    */
  function sha1JS(baytGirdi) {
    var liste = baytGirdi.slice();
    var bitUzunluk = liste.length * 8;
    liste.push(0x80);
    while (liste.length % 64 !== 56) liste.push(0);
    var yuksek = Math.floor(bitUzunluk / 4294967296);
    var dusuk = bitUzunluk >>> 0;
    liste.push((yuksek >>> 24) & 255, (yuksek >>> 16) & 255, (yuksek >>> 8) & 255, yuksek & 255);
    liste.push((dusuk >>> 24) & 255, (dusuk >>> 16) & 255, (dusuk >>> 8) & 255, dusuk & 255);
    var H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    var w = new Array(80);
    for (var blok = 0; blok < liste.length; blok += 64) {
      var i;
      for (i = 0; i < 16; i++) {
        var o = blok + i * 4;
        w[i] = (liste[o] << 24) | (liste[o + 1] << 16) | (liste[o + 2] << 8) | liste[o + 3];
      }
      for (i = 16; i < 80; i++) {
        var x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (x << 1) | (x >>> 31);
      }
      var a = H[0] | 0, b = H[1] | 0, c = H[2] | 0, d = H[3] | 0, e = H[4] | 0;
      for (i = 0; i < 80; i++) {
        var f, kk;
        if (i < 20) { f = (b & c) | (~b & d); kk = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; kk = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); kk = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; kk = 0xCA62C1D6; }
        var tmp = (((a << 5) | (a >>> 27)) + f + e + kk + w[i]) | 0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = tmp;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0;
      H[3] = (H[3] + d) | 0; H[4] = (H[4] + e) | 0;
    }
    var cikti = '';
    for (var q = 0; q < 5; q++) cikti += ('0000000' + (H[q] >>> 0).toString(16)).slice(-8);
    return cikti.toUpperCase();
  }

  function sha1Hex(metin) {
    var bayt = utf8Bayt(metin);
    try {
      if (typeof crypto !== 'undefined' && crypto && crypto.subtle && crypto.subtle.digest) {
        return crypto.subtle.digest('SHA-1', new Uint8Array(bayt)).then(function (ozet) {
          var u = new Uint8Array(ozet), s = '';
          for (var i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
          return s.toUpperCase();
        }, function () { return sha1JS(bayt); });
      }
    } catch (e) { }
    return Promise.resolve(sha1JS(bayt));
  }

  /* Python _entropi(): Shannon entropisi (bit/karakter) */
  function ek2Entropi(s) {
    s = String(s == null ? '' : s);
    if (!s) return 0.0;
    var sayac = {}, i;
    for (i = 0; i < s.length; i++) {
      var c = s.charAt(i);
      sayac[c] = (sayac[c] || 0) + 1;
    }
    var n = s.length, h = 0.0;
    Object.keys(sayac).forEach(function (c) {
      var p = sayac[c] / n;
      h -= p * (Math.log(p) / Math.LN2);
    });
    return h;
  }

  /* Python _kisalt(): sırrı maskeler (ilk 4 + '…' + son 4) */
  function ek2Kisalt(m, bas, son) {
    bas = (bas === undefined) ? 4 : bas;
    son = (son === undefined) ? 4 : son;
    var s = String(m == null ? '' : m);
    if (s.length <= bas + son) {
      if (s.length <= 4) return '…';
      return s.slice(0, 2) + '…' + s.slice(-2);
    }
    return s.slice(0, bas) + '…' + s.slice(-son);
  }

  /* --------------------------------------------------- DoH (Google DNS) */
  /* Python _doh(): (yanit, hata) — sonuç önbellekli, ağ hatasında 1 kez yeniden */
  function ek2Doh(ad, tip, zorla) {
    var temiz = ek2AdTemizle(ad);
    if (!ek2AdGecerli(temiz)) {
      return Promise.resolve({ j: null, hata: 'geçersiz alan adı: ' + (temiz || '-') });
    }
    var anahtar = 'doh::' + temiz + '::' + tip;

    function uret() {
      var url = EK2_DOH_URL + '?name=' + encodeURIComponent(temiz) + '&type=' + tip;
      return _json(url, { zaman: 20 }).then(function (r) {
        if (r.kod === 0) {
          /* ağ hatası (Kaspersky/geçici kopma) → 0.6 sn sonra bir kez daha */
          return bekle(600).then(function () { return _json(url, { zaman: 20 }); });
        }
        return r;
      }).then(function (r) {
        var j = r.j;
        var diziMi = Object.prototype.toString.call(j) === '[object Array]';
        if (r.kod !== 200 || !j || typeof j !== 'object' || diziMi) {
          return { hata: 'DoH yanıtı alınamadı (HTTP ' + r.kod + ')' };
        }
        return j;
      });
    }

    return ek2Onbellekli(anahtar, EK2_DNS_TTL, !!zorla, uret).then(function (j) {
      if (j && typeof j === 'object' && j.hata) return { j: null, hata: j.hata };
      return { j: j, hata: null };
    });
  }

  /* Python _txt_deger(): parçalı tırnaklı TXT kaydını birleştirir */
  function ek2TxtDeger(hamVeri) {
    var s = String(hamVeri == null ? '' : hamVeri);
    var m = s.match(/"((?:[^"\\]|\\.)*)"/g);
    if (m && m.length) {
      var birlesik = m.map(function (x) { return x.slice(1, -1); }).join('');
      return birlesik.trim();
    }
    return ek2Kirp(s.trim(), '"');
  }

  function ek2DnsTxt(ad, zorla) {
    return ek2Doh(ad, 'TXT', zorla).then(function (r) {
      if (r.j === null) return { liste: [], hata: r.hata };
      var liste = [];
      (r.j.Answer || []).forEach(function (c) {
        if (c && c.type === 16 && c.data) liste.push(ek2TxtDeger(c.data));
      });
      return { liste: liste, hata: null };
    });
  }

  /* Python _dns_mx(): öncelik sırasına göre; RFC 7505 null MX ayrı işaretlenir */
  function ek2DnsMx(ad, zorla) {
    return ek2Doh(ad, 'MX', zorla).then(function (r) {
      if (r.j === null) return { kayitlar: [], hata: r.hata };
      var kayitlar = [];
      (r.j.Answer || []).forEach(function (c) {
        if (!c || c.type !== 15 || !c.data) return;
        var d = String(c.data).trim();
        var p = d.split(/\s+/).slice(0, 1).concat([d.split(/\s+/).slice(1).join(' ')]);
        if (p.length === 2 && p[1] !== '' && /^\d+$/.test(p[0])) {
          var sunucu = ek2Kirp(p[1].trim(), '.');
          var kayit = { oncelik: parseInt(p[0], 10) };
          if (sunucu === '' || sunucu === '.') {
            kayit.sunucu = '.';
            kayit.not = 'null MX (RFC 7505): alan adı posta kabul etmiyor';
          } else {
            kayit.sunucu = sunucu;
          }
          kayitlar.push(kayit);
        } else {
          kayitlar.push({ oncelik: null, sunucu: ek2Kirp(d.trim(), '.') });
        }
      });
      kayitlar.sort(function (a, b) {
        var an = a.oncelik === null, bn = b.oncelik === null;
        if (an !== bn) return an ? 1 : -1;
        var ao = a.oncelik || 0, bo = b.oncelik || 0;
        if (ao !== bo) return ao - bo;
        return a.sunucu < b.sunucu ? -1 : (a.sunucu > b.sunucu ? 1 : 0);
      });
      return { kayitlar: kayitlar, hata: null };
    });
  }

  /* Python ip_coz(): DoH A + AAAA, boşsa köprü adCoz */
  function ek2IpCoz(ad, zorla) {
    var d = ek2AdTemizle(ad);
    if (!d) return Promise.resolve([]);
    if (ek2IpBaytlari(d) || ek2GecerliIp(d)) return Promise.resolve([d]);
    var ipler = [];
    function topla(tip) {
      return ek2Doh(d, tip, zorla).then(function (r) {
        if (r.j && typeof r.j === 'object') {
          (r.j.Answer || []).forEach(function (c) {
            if (c && (c.type === 1 || c.type === 28) && c.data) ipler.push(String(c.data).trim());
          });
        }
      });
    }
    return topla('A').then(function () { return topla('AAAA'); }).then(function () {
      if (ipler.length) return ek2Tekiller(ipler);
      return adCoz(d).then(function (ip) {
        var m = String(ip || '').match(/\d+\.\d+\.\d+\.\d+/);
        if (m) ipler.push(m[0]);
        return ek2Tekiller(ipler);
      });
    });
  }

  function ek2Tekiller(liste) {
    var gorulen = {}, cikti = [];
    (liste || []).forEach(function (x) {
      var s = String(x == null ? '' : x).trim();
      if (!s || gorulen[s]) return;
      gorulen[s] = 1;
      cikti.push(s);
    });
    return cikti;
  }

  /* ============================================ 1) İSTİSMAR (KEV + EPSS) */
  function ek2KevListesi(zorla) {
    var anahtar = 'kev::katalog';

    function uret() {
      return _json(EK2_KEV_URL, { zaman: 45 }).then(function (r) {
        var j = r.j;
        if (r.kod !== 200 || !j || typeof j !== 'object' ||
          !j.vulnerabilities || !j.vulnerabilities.length) {
          return { hata: 'CISA KEV listesi alınamadı (HTTP ' + r.kod + ')' };
        }
        var idx = {};
        j.vulnerabilities.forEach(function (k) {
          if (!k || typeof k !== 'object') return;
          var cid = String(k.cveID || '').trim().toUpperCase();
          if (cid) idx[cid] = k;
        });
        return {
          kayitlar: idx, sayi: Object.keys(idx).length,
          surum: j.catalogVersion === undefined ? null : j.catalogVersion,
          yayin: j.dateReleased === undefined ? null : j.dateReleased
        };
      });
    }

    return ek2Onbellekli(anahtar, EK2_KEV_TTL, !!zorla, uret);
  }

  function ek2Epss(cveIdler, zorla) {
    var sirali = cveIdler.slice().sort();
    var anahtar = 'epss::' + sirali.join(',');

    function uret() {
      var url = EK2_EPSS_URL + '?cve=' + encodeURIComponent(sirali.join(',')).replace(/%2C/g, ',');
      return _json(url, { zaman: 25 }).then(function (r) {
        var j = r.j;
        if (r.kod !== 200 || !j || typeof j !== 'object') {
          return { hata: 'FIRST EPSS yanıtı alınamadı (HTTP ' + r.kod + ')' };
        }
        var sozluk = {};
        (j.data || []).forEach(function (d) {
          if (!d || typeof d !== 'object') return;
          var cid = String(d.cve || '').trim().toUpperCase();
          if (!cid) return;
          var puan = null, yuzde = null;
          if (d.epss !== null && d.epss !== undefined && isFinite(Number(d.epss))) puan = Number(d.epss);
          if (d.percentile !== null && d.percentile !== undefined && isFinite(Number(d.percentile))) {
            yuzde = Number(d.percentile);
          }
          sozluk[cid] = { epss: puan, yuzdelik: yuzde, tarih: d.date === undefined ? null : d.date };
        });
        return { puanlar: sozluk, sayi: Object.keys(sozluk).length };
      });
    }

    return ek2Onbellekli(anahtar, EK2_EPSS_TTL, !!zorla, uret);
  }

  function ek2KararVer(kevVar, puan) {
    if (kevVar === true) return 'ACİL — aktif istismar ediliyor';
    if (puan === null || puan === undefined) return 'bilinmiyor — EPSS verisi yok';
    if (puan >= 0.5) return 'YÜKSEK — istismar olasılığı yüksek';
    if (puan >= 0.1) return 'orta';
    return 'düşük';
  }

  /* Python istismar_sorgu(): CISA KEV + FIRST EPSS birleşik sorgu (en fazla 20 CVE) */
  function istismarSorgu(cveIdler, zorla) {
    var temiz = [];
    (cveIdler || []).forEach(function (c) {
      c = String(c == null ? '' : c).trim().toUpperCase();
      if (!c) return;
      if (!/^CVE-\d{4}-\d{4,}$/.test(c)) {
        return; /* hata aşağıda toplanır */
      }
      if (temiz.indexOf(c) < 0) temiz.push(c);
    });
    var hamListe = (cveIdler || []).map(function (c) { return String(c == null ? '' : c).trim().toUpperCase(); })
      .filter(function (c) { return c && !/^CVE-\d{4}-\d{4,}$/.test(c); });
    if (hamListe.length) {
      return Promise.resolve({
        hata: 'geçersiz CVE kimliği: ' + hamListe[0] + ' (beklenen biçim: CVE-2024-3094)'
      });
    }
    if (!temiz.length) {
      return Promise.resolve({ hata: 'CVE kimliği verilmedi (örn: ?cve=CVE-2024-3094)' });
    }
    if (temiz.length > EK2_MAX_CVE) {
      return Promise.resolve({
        hata: 'en fazla ' + EK2_MAX_CVE + ' CVE sorgulanabilir (' + temiz.length + ' verildi)'
      });
    }

    return ek2KevListesi(zorla).then(function (kev) {
      var kevIdx = (kev && typeof kev === 'object') ? kev.kayitlar : null;
      var kevHata = (kev && typeof kev === 'object') ? kev.hata : null;
      return ek2Epss(temiz, zorla).then(function (epss) {
        var epssIdx = (epss && typeof epss === 'object') ? epss.puanlar : null;
        var epssHata = (epss && typeof epss === 'object') ? epss.hata : null;

        /* İki kaynak da düştüyse dürüst hata — uydurma veri üretilmez. */
        if (!kevIdx && !epssIdx) {
          return {
            hata: 'kaynaklara ulaşılamadı — ' + (kevHata || 'KEV yok') + ' / ' + (epssHata || 'EPSS yok')
          };
        }

        var kayitlar = [];
        temiz.forEach(function (c) {
          var k = (kevIdx || {})[c] || null;
          var e = (epssIdx || {})[c] || {};
          var puan = (e.epss === undefined) ? null : e.epss;
          var kayit = {
            cve: c,
            kev: !!k,
            kev_eklenme: k ? (k.dateAdded === undefined ? null : k.dateAdded) : null,
            fidye_kampanyasi: !!(k && String(k.knownRansomwareCampaignUse || '').toLowerCase() === 'known'),
            urun: (k ? ((String(k.vendorProject || '') + ' ' + String(k.product || '')).trim() || null) : null),
            epss: (typeof puan === 'number' && isFinite(puan)) ? yuvarlak(puan, 4) : null,
            epss_yuzdelik: (typeof e.yuzdelik === 'number' && isFinite(e.yuzdelik)) ? yuvarlak(e.yuzdelik * 100, 2) : null,
            epss_tarih: (e.tarih === undefined) ? null : e.tarih,
            karar: ek2KararVer(!!k, (typeof puan === 'number' && isFinite(puan)) ? puan : null),
            aciklama: k ? (k.shortDescription === undefined ? null : k.shortDescription) : null,
            kaynak: 'CISA KEV + FIRST EPSS'
          };
          var notlar = [];
          if (!kevIdx) notlar.push('CISA KEV listesi alınamadı: ' + (kevHata || 'bilinmiyor'));
          else if (!k) notlar.push('CISA KEV kataloğunda yok');
          if (!epssIdx) notlar.push('EPSS servisi yanıt vermedi: ' + (epssHata || 'bilinmiyor'));
          else if (!e || e.epss === undefined) notlar.push('EPSS bu CVE için kayıt döndürmedi');
          if (notlar.length) kayit.not = notlar.join(' · ');
          if (!kayit.aciklama) kayit.aciklama = null;
          kayitlar.push(kayit);
        });

        kayitlar.sort(function (a, b) {
          if (a.kev !== b.kev) return a.kev ? -1 : 1;
          return (b.epss || 0) - (a.epss || 0);
        });

        if (kayitlar.length === 1) return kayitlar[0];
        return {
          kayitlar: kayitlar, toplam: kayitlar.length,
          kev_toplam: kayitlar.filter(function (x) { return x.kev; }).length,
          kaynak: 'CISA KEV + FIRST EPSS',
          guncelleme: simdi()
        };
      });
    });
  }

  /* ================================================= 2) POSTA GÜVENLİĞİ */
  function ek2SpfPolitika(spfKayit) {
    var m = String(spfKayit || '').match(/([~\-+?])all\b/i);
    return m ? m[0].toLowerCase() : null;
  }

  function ek2DkimKullanilabilir(kayit) {
    var s = String(kayit || '');
    if (!/\b(v\s*=\s*DKIM1|k\s*=\s*rsa|p\s*=)/i.test(s)) return { uygun: false, neden: 'DKIM alanları yok' };
    var m = s.match(/(?:^|;)\s*p\s*=\s*([A-Za-z0-9+/=]*)/);
    if (!m) return { uygun: false, neden: 'p= alanı yok' };
    if (m[1].trim().length < 32) {
      return { uygun: false, neden: 'p= boş veya çok kısa (anahtar iptal edilmiş olabilir)' };
    }
    return { uygun: true, neden: null };
  }

  function ek2DmarcPolitika(kayit) {
    var s = String(kayit || '');
    var p = s.match(/(?:^|;)\s*p\s*=\s*([a-z]+)/i);
    var pct = s.match(/(?:^|;)\s*pct\s*=\s*(\d{1,3})/i);
    return {
      politika: p ? p[1].toLowerCase() : null,
      pct: pct ? parseInt(pct[1], 10) : null
    };
  }

  /* Python posta_guvenlik(): SPF/DKIM/DMARC/MX + 0-100 direnç puanı */
  function postaGuvenlik(ad, mxIp, zorla) {
    var d = ek2AdTemizle(ad);
    if (!d || !ek2AdGecerli(d)) {
      return Promise.resolve({ hata: 'geçerli bir alan adı verilmedi (örn: ?ad=example.com)' });
    }
    var anahtar = 'posta::' + d;

    function uret() {
      var kaynakNotlari = [];
      var spf = { 'var': false, kayit: null, politika: null, uyari: null };
      var dmarc = {
        'var': false, kayit: null, politika: null, pct: null, uyari: null,
        onerilen: 'v=DMARC1; p=quarantine; pct=100; rua=mailto:rapor@' + d
      };
      var dkim = { bulunan: [], denenen: [] };
      var eksikler = [], oneriler = [];
      var dnsHata = 0;

      /* ---- SPF */
      return ek2DnsTxt(d, zorla).then(function (r) {
        if (r.hata) {
          dnsHata++;
          kaynakNotlari.push('SPF/DMARC TXT sorgusu: ' + r.hata);
        }
        for (var i = 0; i < r.liste.length; i++) {
          if (String(r.liste[i]).toLowerCase().indexOf('v=spf1') === 0) {
            spf['var'] = true;
            spf.kayit = r.liste[i];
            spf.politika = ek2SpfPolitika(r.liste[i]);
            break;
          }
        }
        /* ---- DMARC */
        return ek2DnsTxt('_dmarc.' + d, zorla).then(function (dr) {
          if (dr.hata) {
            dnsHata++;
            kaynakNotlari.push('DMARC (_dmarc.' + d + ') sorgusu: ' + dr.hata);
          }
          for (var j = 0; j < dr.liste.length; j++) {
            if (String(dr.liste[j]).toLowerCase().indexOf('v=dmarc1') === 0) {
              dmarc['var'] = true;
              dmarc.kayit = dr.liste[j];
              var pol = ek2DmarcPolitika(dr.liste[j]);
              dmarc.politika = pol.politika;
              dmarc.pct = pol.pct;
              break;
            }
          }
          /* ---- DKIM: yaygın seçiciler (paralel, sıra korunur) */
          return havuz(EK2_DKIM_SECICILERI, function (sec) {
            return ek2DnsTxt(sec + '._domainkey.' + d, zorla).then(function (sr) {
              if (sr.hata) return { secici: sec, var: false, not: sr.hata, hataSay: 1 };
              var bulundu = null, gecersiz = null;
              for (var t = 0; t < sr.liste.length; t++) {
                var uy = ek2DkimKullanilabilir(sr.liste[t]);
                if (uy.uygun) { bulundu = sr.liste[t]; break; }
                if (!gecersiz) gecersiz = uy.neden;
              }
              var kayit = { secici: sec, var: !!bulundu };
              if (bulundu) kayit.kayit = bulundu.slice(0, 200);
              else if (gecersiz) kayit.not = gecersiz;
              return { secici: sec, var: !!bulundu, kayit: kayit, bulundu: bulundu, hataSay: 0 };
            });
          }, 4).then(function (sonuclar) {
            sonuclar.forEach(function (s) {
              if (s.hataSay) {
                dnsHata++;
                dkim.denenen.push({ secici: s.secici, 'var': false, not: s.not });
                return;
              }
              if (s.bulundu) dkim.bulunan.push(s.secici);
              dkim.denenen.push(s.kayit);
            });
            /* ---- MX */
            return ek2DnsMx(d, zorla).then(function (mr) {
              if (mr.hata) {
                dnsHata++;
                kaynakNotlari.push('MX sorgusu: ' + mr.hata);
              }
              var mx = mr.kayitlar;
              var ipZinciri = Promise.resolve();
              if (mxIp && mx.length) {
                ipZinciri = havuz(mx, function (m) {
                  return ek2IpCoz(m.sunucu, zorla).then(function (ipler) { m.ip = ipler; });
                }, 4);
              }
              return ipZinciri.then(function () {
                /* ---- PUANLAMA (üst sınır 100) */
                var puan = 0;
                if (spf['var']) {
                  puan += 25;
                  if (spf.politika === '-all') puan += 10;
                } else {
                  eksikler.push('SPF kaydı yok: gönderen sunucular doğrulanamıyor');
                  oneriler.push('SPF ekleyin, örn: v=spf1 include:_spf.<sağlayıcı>.com -all');
                }
                if (dmarc['var']) {
                  puan += 20;
                  if (dmarc.politika === 'quarantine') puan += 10;
                  else if (dmarc.politika === 'reject') puan += 20;
                } else {
                  eksikler.push('DMARC kaydı yok: başarısız doğrulamada ne yapılacağı tanımsız');
                  oneriler.push('DMARC ekleyin: ' + dmarc.onerilen);
                }
                if (dkim.bulunan.length) {
                  puan += 20;
                } else {
                  eksikler.push('DKIM kaydı bulunamadı (denenen seçiciler: ' + EK2_DKIM_SECICILERI.join(', ') + ')');
                  oneriler.push('Posta sağlayıcınızın DKIM imzalamasını açın ve seçici adını doğrulayın');
                }
                if (mx.length) {
                  puan += 5;
                } else {
                  eksikler.push('MX kaydı yok: alan adı posta kabul etmiyor olabilir');
                }
                puan = Math.max(0, Math.min(100, puan));
                var seviye = puan >= 75 ? 'iyi' : (puan >= 40 ? 'orta' : 'zayıf');

                /* ---- Uyarılar */
                if (spf['var']) {
                  if (spf.politika === null) {
                    spf.uyari = "'all' mekanizması yok: politika belirsiz (varsayılan ~all gibi davranır)";
                    oneriler.push('SPF kaydının sonuna -all ekleyin (yetkisiz sunucuları reddet)');
                  } else if (spf.politika === '+all' || spf.politika === '?all') {
                    spf.uyari = 'gevşek SPF politikası (' + spf.politika + '): her sunucu gönderici gibi davranabilir';
                    oneriler.push("SPF 'all' mekanizmasını -all (sert) yapın");
                  } else if (spf.politika === '~all') {
                    spf.uyari = 'yumuşak SPF politikası (~all): başarısız postalar yine de kabul edilebilir';
                    oneriler.push("SPF politikasını -all'e yükseltmeyi değerlendirin");
                  }
                }
                if (dmarc['var']) {
                  if (dmarc.politika === 'none') {
                    dmarc.uyari = 'politika none: sahte mailler karantinaya alınmıyor';
                    oneriler.push('DMARC politikasını p=quarantine, ardından p=reject\'e yükseltin');
                  } else if (dmarc.politika === null) {
                    dmarc.uyari = 'p= etiketi yok: politika okunamadı';
                  }
                  if (dmarc.pct !== null && dmarc.pct < 100) {
                    dmarc.uyari = (dmarc.uyari ? dmarc.uyari + ' · ' : '') +
                      'pct=' + dmarc.pct + ': postanın yalnız %' + dmarc.pct + "'ine politika uygulanıyor";
                    oneriler.push('pct değerini 100 yapın');
                  }
                  if (!/\brua\s*=/i.test(String(dmarc.kayit || ''))) {
                    oneriler.push('DMARC kaydına rua=mailto:... ekleyin (rapor toplama)');
                  }
                }

                var uyariMetni = 'Yalnız sahibi olduğun/izin aldığın alan adlarını sorgula.';
                if (dnsHata) {
                  uyariMetni = 'DNS sorgularının ' + dnsHata + ' tanesi başarısız oldu (ağ hatası); ' +
                    'puan EKSİK VERİYE dayanıyor — tekrar deneyin. ' + uyariMetni;
                }

                /* oneriler: Python list(dict.fromkeys(...)) — sıra korunur, tekilleşir */
                var tekil = [];
                oneriler.forEach(function (x) { if (tekil.indexOf(x) < 0) tekil.push(x); });

                return {
                  ad: d,
                  spf: spf,
                  dmarc: dmarc,
                  dkim: dkim,
                  mx: mx,
                  puan: puan,
                  seviye: seviye,
                  eksikler: eksikler,
                  oneriler: tekil,
                  kaynak: 'Google DoH (dns.google) + DKIM seçici taraması',
                  not: kaynakNotlari.length ? kaynakNotlari.join(' · ') : null,
                  uyari: uyariMetni,
                  guncelleme: simdi(),
                  _onbellekleme: !!dnsHata
                };
              });
            });
          });
        });
      });
    }

    return ek2Onbellekli(anahtar, EK2_POSTA_TTL, !!zorla, uret);
  }

  /* ================================================ 3) BAŞLIK ANALİZİ */
  var EK2_MARKALAR = [
    'microsoft', 'apple', 'google', 'paypal', 'amazon', 'netflix', 'dhl', 'ups',
    'fedex', 'instagram', 'facebook', 'meta', 'whatsapp', 'telegram', 'binance',
    'linkedin', 'dropbox', 'adobe', 'steam', 'spotify', 'twitter', 'outlook',
    'office365', 'icloud', 'gmail', 'turkcell', 'vodafone', 'garanti', 'ziraat',
    'akbank', 'vakifbank', 'halkbank', 'denizbank', 'isbank', 'yapikredi'
  ];
  var EK2_TR_HARF = {
    'ı': 'i', 'İ': 'i', 'ş': 's', 'Ş': 's', 'ğ': 'g', 'Ğ': 'g',
    'ü': 'u', 'Ü': 'u', 'ö': 'o', 'Ö': 'o', 'ç': 'c', 'Ç': 'c'
  };

  function ek2Sade(metin) {
    var s = String(metin == null ? '' : metin), ara = '';
    for (var i = 0; i < s.length; i++) {
      var c = s.charAt(i);
      ara += (EK2_TR_HARF[c] !== undefined) ? EK2_TR_HARF[c] : c;
    }
    ara = ara.toLowerCase();
    var cikti = '';
    for (var j = 0; j < ara.length; j++) {
      var k = ara.charAt(j);
      if (/[a-z0-9]/.test(k)) cikti += k;
    }
    return cikti;
  }

  function ek2AlanlariAyristir(ham) {
    var s = String(ham == null ? '' : ham).replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    var satirlar = s.split('\n'), alanlar = [];
    for (var i = 0; i < satirlar.length; i++) {
      var satir = satirlar[i];
      if (satir.replace(/\s+/g, '') === '') break;
      var ilk = satir.charAt(0);
      if ((ilk === ' ' || ilk === '\t') && alanlar.length) {
        alanlar[alanlar.length - 1][1] += ' ' + ek2Kirp(satir, ' \t');
        continue;
      }
      var ix = satir.indexOf(':');
      if (ix >= 0) {
        alanlar.push([satir.slice(0, ix).trim(), satir.slice(ix + 1).trim()]);
      }
    }
    return alanlar;
  }

  function ek2Alan(alanlar, ad) {
    var cikti = [];
    (alanlar || []).forEach(function (c) {
      if (String(c[0]).toLowerCase() === String(ad).toLowerCase()) cikti.push(c[1]);
    });
    return cikti;
  }

  function ek2AdresAyristir(deger) {
    var d = String(deger == null ? '' : deger).trim();
    var m = d.match(/<([^>]+)>/);
    if (m) {
      var adres = m[1].trim();
      var ad = ek2Kirp(ek2Kirp(d.slice(0, m.index).trim(), '"'), "'").trim();
      return { ad: ad, adres: adres };
    }
    return { ad: '', adres: d };
  }

  function ek2AlanAdi(adres) {
    var a = ek2Kirp(String(adres == null ? '' : adres).trim(), '<>').toLowerCase();
    if (a.indexOf('@') >= 0) a = a.split('@').pop();
    return ek2Kirp(a.trim(), '.');
  }

  /* Python parsedate_to_datetime() karşılığı — tz yoksa "naif" işaretlenir
     (Python'da naif tarihlerle fark alma TypeError verir → gecikme None). */
  var EK2_AYLAR = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
  var EK2_BOLGELER = {
    ut: 0, utc: 0, gmt: 0, z: 0, est: -300, edt: -240, cst: -360, cdt: -300,
    mst: -420, mdt: -360, pst: -480, pdt: -420
  };

  function ek2TarihCoz(metin) {
    var s = String(metin == null ? '' : metin).trim();
    if (!s) return null;
    var m = s.match(/^(?:[A-Za-z]{3},\s*)?(\d{1,2})\s+([A-Za-z]{3})\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(.*)$/);
    if (!m) return null;
    var ay = EK2_AYLAR[m[2].toLowerCase()];
    if (ay === undefined) return null;
    var yil = parseInt(m[3], 10);
    if (m[3].length <= 2) yil += (yil < 69) ? 2000 : 1900;   /* Python parsedate kuralı */
    var sa = parseInt(m[4], 10), dk = parseInt(m[5], 10), sn = m[6] ? parseInt(m[6], 10) : 0;
    var kalan = (m[7] || '').trim();
    var naif = true, dakikaOfset = 0;
    if (kalan) {
      var z = kalan.match(/^([+-])(\d{2})(\d{2})$/);
      if (z) {
        naif = false;
        dakikaOfset = (z[1] === '-' ? -1 : 1) * (parseInt(z[2], 10) * 60 + parseInt(z[3], 10));
      } else if (EK2_BOLGELER[kalan.toLowerCase()] !== undefined) {
        naif = false;
        dakikaOfset = EK2_BOLGELER[kalan.toLowerCase()];
      }
    }
    var ms = Date.UTC(yil, ay, parseInt(m[1], 10), sa, dk, sn) - dakikaOfset * 60000;
    if (!isFinite(ms)) return null;
    return { ms: ms, naif: naif };
  }

  function ek2TarihFark(ilk, son) {
    /* Python: aware - naive → TypeError → None */
    if (!ilk || !son) return null;
    if (ilk.naif !== son.naif) return null;
    return Math.floor((son.ms - ilk.ms) / 1000);
  }

  function ek2ReceivedAyristir(satirlar) {
    var zincir = [];
    (satirlar || []).forEach(function (s) {
      s = String(s == null ? '' : s);
      var m = s.match(/\bfrom\s+([^\s(;]+)/i);
      var sunucu = (m ? m[1].trim() : '') || '';
      var ip = '';
      var bulunan = s.match(/[\[(]([0-9a-fA-F:.]+)[\])]/g) || [];
      for (var i = 0; i < bulunan.length; i++) {
        var parca = bulunan[i].slice(1, -1);
        if (ek2GecerliIp(parca)) { ip = parca; break; }
      }
      if (!sunucu && ip) sunucu = ip;
      if (sunucu.charAt(0) === '[') sunucu = ip || '';
      var ix = s.lastIndexOf(';');
      var tarih = ix >= 0 ? s.slice(ix + 1).trim() : '';
      zincir.push({ sunucu: sunucu || null, ip: ip || null, tarih: tarih || null });
    });
    zincir.reverse();                       /* göndericiden alıcıya */
    var onceki = null;
    zincir.forEach(function (h, i) {
      h.sira = i + 1;
      var dt = ek2TarihCoz(h.tarih);
      var gecikme = null;
      if (dt !== null && onceki !== null) {
        var g = ek2TarihFark(onceki, dt);
        if (g !== null && g >= 0) gecikme = g;
      }
      h.gecikme_sn = gecikme;
      if (dt !== null) onceki = dt;
    });
    return zincir;
  }

  function ek2KimlikSonuclari(alanlar) {
    var ar = ek2Alan(alanlar, 'authentication-results').join(' ; ');
    var rspf = ek2Alan(alanlar, 'received-spf').join(' ; ');
    var sonuc = { spf: null, dkim: null, dmarc: null, ar_var: !!ar.trim() };
    ['spf', 'dkim', 'dmarc'].forEach(function (anahtar) {
      var m = ar.match(new RegExp('\\b' + anahtar + '\\s*=\\s*([a-z]+)', 'i'));
      if (m) sonuc[anahtar] = m[1].toLowerCase();
    });
    if (sonuc.spf === null && rspf) {
      var m2 = rspf.match(/^\s*(pass|fail|softfail|neutral|none|temperror|permerror)/i);
      if (m2) sonuc.spf = m2[1].toLowerCase();
    }
    return sonuc;
  }

  function ek2TaklitMi(gorunenAd, adres) {
    var adHam = String(gorunenAd == null ? '' : gorunenAd).trim();
    if (!adHam) return null;
    var alan = ek2AlanAdi(adres);
    if (!alan) return null;
    var alanSade = ek2Sade(alan);

    var m = adHam.match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/i);
    if (m && ek2AlanAdi(m[0]) !== alan) {
      return 'görünen ad içinde farklı bir e-posta adresi var (' + m[0] + ')';
    }
    var alanlar = adHam.match(/\b([a-z0-9-]+(?:\.[a-z0-9-]+){1,3}\.(?:com|net|org|tr|co|io|info|biz))\b/ig) || [];
    for (var i = 0; i < alanlar.length; i++) {
      var sade = ek2Sade(alanlar[i]);
      if (sade && alanSade.indexOf(sade) < 0 && sade.indexOf(alanSade) < 0) {
        return 'görünen ad farklı bir alan adı içeriyor (' + alanlar[i] + '), gerçek adres: ' + alan;
      }
    }
    var adSade = ek2Sade(adHam);
    for (var j = 0; j < EK2_MARKALAR.length; j++) {
      var marka = EK2_MARKALAR[j];
      if (adSade.indexOf(marka) >= 0) {
        if (alanSade.indexOf(marka.slice(0, 4)) < 0) {
          return "görünen ad '" + marka + "' markasına benziyor, adres alan adı: " + alan;
        }
        break;
      }
    }
    return null;
  }

  /* Python baslik_analiz(): yerel ayrıştırma, ağ sorgusu YOK */
  function baslikAnaliz(ham) {
    if (ham && typeof ham === 'object') ham = ham.ham || ham.basliklar || ham.raw || '';
    ham = String(ham == null ? '' : ham);
    if (!ham.trim()) {
      return { hata: 'ham başlık boş (POST gövdesi: {"ham": "..."} olmalı)' };
    }
    var alanlar = ek2AlanlariAyristir(ham);
    if (!alanlar.length) {
      return { hata: "başlık ayrıştırılamadı (her satır 'Ad: değer' biçiminde olmalı)" };
    }

    var fromHam = (ek2Alan(alanlar, 'from') || [''])[0];
    var fromAyr = ek2AdresAyristir(fromHam);
    var gorunenAd = fromAyr.ad, fromAdres = fromAyr.adres;
    var fromAlan = ek2AlanAdi(fromAdres);
    var returnPath = (ek2Alan(alanlar, 'return-path') || [''])[0];
    var yanit = (ek2Alan(alanlar, 'reply-to') || [''])[0];
    var yanitAdres = ek2AdresAyristir(yanit).adres;
    var yanitAlan = ek2AlanAdi(yanitAdres);
    var kime = (ek2Alan(alanlar, 'to') || [''])[0];
    var konu = (ek2Alan(alanlar, 'subject') || [''])[0];
    var mesajId = (ek2Alan(alanlar, 'message-id') || [''])[0];
    var tarih = (ek2Alan(alanlar, 'date') || [''])[0];

    var received = ek2Alan(alanlar, 'received');
    var zincir = ek2ReceivedAyristir(received);
    var kimlik = ek2KimlikSonuclari(alanlar);

    var ilkDisIp = null, icIpVar = false;
    zincir.forEach(function (h) {
      var ip = h.ip;
      if (!ip) return;
      if (ek2OzelIp(ip)) icIpVar = true;
      else if (ilkDisIp === null) ilkDisIp = ip;
    });

    var isaretler = [];
    function ekle(baslik, agirlik, kanit) {
      var kayit = { baslik: baslik, agirlik: agirlik };
      if (kanit) kayit.kanit = kanit;
      isaretler.push(kayit);
    }

    if (kimlik.spf === 'fail' || kimlik.spf === 'softfail') {
      ekle('SPF doğrulaması başarısız (gönderen sunucu yetkisiz)', 30, 'spf=' + kimlik.spf);
    }
    if (kimlik.dkim === 'fail' || kimlik.dkim === 'permerror') {
      ekle('DKIM imzası geçersiz (içerik/imza uyuşmuyor)', 25, 'dkim=' + kimlik.dkim);
    }
    if (kimlik.dmarc === 'fail') ekle('DMARC doğrulaması başarısız', 30, 'dmarc=fail');
    if (!kimlik.ar_var && !ek2Alan(alanlar, 'received-spf').length) {
      ekle('Authentication-Results başlığı yok (doğrulama kaydı bırakılmamış)', 10);
    }
    if (yanitAlan && fromAlan && yanitAlan !== fromAlan) {
      ekle('Reply-To farklı alan adı', 20, yanitAlan + ' ≠ ' + fromAlan);
    }
    var taklit = ek2TaklitMi(gorunenAd, fromAdres);
    if (taklit) ekle('Görünen ad ile adres alan adı uyuşmuyor', 20, taklit);
    if (icIpVar) ekle('Received zincirinde özel/iç ağ IP\'si var', 10);
    if (received.length <= 1) {
      ekle("Tek Received hop'u (normal posta zinciri beklenenden kısa)", 10,
        received.length + ' adet Received başlığı');
    }
    var dtBaslik = ek2TarihCoz(tarih);
    var dtHop = zincir.length ? ek2TarihCoz(zincir[zincir.length - 1].tarih) : null;
    var fark = ek2TarihFark(dtBaslik, dtHop);
    if (fark !== null && Math.abs(fark) > 86400) {
      ekle('Date başlığı ile Received tarihi tutarsız', 10,
        (Math.abs(fark) / 3600.0).toFixed(1) + ' saat fark');
    }
    if (!mesajId) ekle('Message-ID başlığı yok', 8);

    var toplam = 0;
    isaretler.forEach(function (i) { toplam += i.agirlik; });
    var risk = Math.max(0, Math.min(100, toplam));
    var karar = risk >= 60 ? 'YÜKSEK — sahte olabilir'
      : (risk >= 30 ? 'ORTA — dikkatli incele' : 'düşük risk');

    var parcalar = [];
    if (fromAlan) parcalar.push('Kimden: ' + fromAlan);
    if (ilkDisIp) parcalar.push('ilk dış IP: ' + ilkDisIp);
    parcalar.push('kimlik: SPF=' + (kimlik.spf || '-') + '/DKIM=' + (kimlik.dkim || '-') +
      '/DMARC=' + (kimlik.dmarc || '-'));
    parcalar.push(received.length + ' hop');
    if (isaretler.length) {
      parcalar.push('işaretler: ' + isaretler.slice(0, 4).map(function (i) { return i.baslik; }).join(', '));
    } else {
      parcalar.push('belirgin sahtecilik işareti bulunmadı');
    }

    return {
      kimden: fromAdres || null,
      ad: gorunenAd || null,
      yanit_adresi: yanitAdres || null,
      return_path: returnPath || null,
      kime: kime || null,
      konu: konu || null,
      mesaj_id: mesajId || null,
      tarih: tarih || null,
      ilk_dis_ip: ilkDisIp,
      received_sayisi: received.length,
      zincir: zincir,
      zincir_yonu: 'gönderici → alıcı (en eski hop = 1)',
      kimlik: { spf: kimlik.spf, dkim: kimlik.dkim, dmarc: kimlik.dmarc },
      isaretler: isaretler,
      risk: risk,
      karar: karar,
      ozet: parcalar.join(' · '),
      kaynak: 'yerel başlık ayrıştırma (ağ sorgusu yapılmaz)',
      guncelleme: simdi()
    };
  }

  /* ============================================ 4) SERTİFİKA (CT log) */
  function ek2YeniMi(tarihMetni) {
    var m = String(tarihMetni == null ? '' : tarihMetni).match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (!m) return false;
    var t = Date.UTC(parseInt(m[1], 10), parseInt(m[2], 10) - 1, parseInt(m[3], 10));
    if (!isFinite(t)) return false;
    return (simdiMs() - t) < 30 * 86400000;
  }

  function ek2SertifikaCertspotter(ad) {
    var temel = 'https://api.certspotter.com/v1/issuances?domain=' +
      encodeURIComponent(ad) + '&include_subdomains=true';
    return _json(temel + '&expand=dns_names', { zaman: 30 }).then(function (r) {
      if (r.kod !== 200 || Object.prototype.toString.call(r.j) !== '[object Array]') {
        if (r.kod === 404) {
          return { kayitlar: [], verenler: [], hata: 'certspotter: bu alan adı için CT kaydı bulunamadı', notlar: [] };
        }
        if (r.kod === 429) {
          return {
            kayitlar: [], verenler: [], notlar: [],
            hata: 'certspotter ücretsiz kota sınırı (HTTP 429) — birkaç dakika sonra tekrar deneyin'
          };
        }
        return { kayitlar: [], verenler: [], notlar: [], hata: 'certspotter yanıtı alınamadı (HTTP ' + r.kod + ')' };
      }
      var kayitlar = [];
      r.j.forEach(function (x) {
        if (!x || typeof x !== 'object') return;
        var adlar = [];
        (x.dns_names || []).forEach(function (a) { if (a) adlar.push(String(a)); });
        kayitlar.push({
          id: String(x.id || ''),
          veren: '',
          yayin: String(x.not_before || '').slice(0, 10),
          bitis: String(x.not_after || '').slice(0, 10),
          yeni: ek2YeniMi(x.not_before),
          _adlar: adlar
        });
      });
      var notlar = [];
      return bekle(EK2_ISTEK_ARASI).then(function () {
        return _json(temel + '&expand=issuer', { zaman: 25 });
      }).then(function (r2) {
        var verenler = [];
        if (r2.kod === 200 && Object.prototype.toString.call(r2.j) === '[object Array]') {
          r2.j.forEach(function (x, i) {
            if (!x || typeof x !== 'object') return;
            var v = x.issuer || {}, adVeren = '';
            if (v && typeof v === 'object') adVeren = v.friendly_name || v.name || '';
            else if (typeof v === 'string') adVeren = v;
            adVeren = String(adVeren).trim();
            if (adVeren && i < kayitlar.length) kayitlar[i].veren = adVeren;
          });
          var set = {};
          kayitlar.forEach(function (k) { if (k.veren) set[k.veren] = 1; });
          verenler = Object.keys(set).sort();
          if (!verenler.length) notlar.push('certspotter veren (issuer) alanını boş döndürdü');
        } else {
          notlar.push('veren bilgisi alınamadı (certspotter HTTP ' + r2.kod +
            (r2.kod === 429 ? ', ücretsiz kota sınırı' : '') + ') — alt alan adları yine de tam');
        }
        return { kayitlar: kayitlar, verenler: verenler, hata: '', notlar: notlar };
      }, function () {
        return {
          kayitlar: kayitlar, verenler: [], hata: '',
          notlar: ['veren bilgisi alınamadı (beklenmeyen yanıt)']
        };
      });
    });
  }

  function ek2SertifikaCrtsh(ad) {
    var url = 'https://crt.sh/?q=' + encodeURIComponent('%25.' + ad) + '&output=json';
    return _json(url, { zaman: 40 }).then(function (r) {
      if (r.kod !== 200 || Object.prototype.toString.call(r.j) !== '[object Array]') {
        var ek = [502, 503, 504, 0].indexOf(r.kod) >= 0 ? ', sık görülen 502 hatası' : '';
        return { kayitlar: [], verenler: [], hata: 'crt.sh yanıt vermedi (HTTP ' + r.kod + ek + ')' };
      }
      var kayitlar = [], verenSet = {};
      r.j.forEach(function (x) {
        if (!x || typeof x !== 'object') return;
        var adlar = [];
        String(x.name_value || '').split('\n').forEach(function (parca) {
          parca = parca.trim().toLowerCase();
          parca = parca.replace(/^[*]+\.?/, '').replace(/^\.+/, '');
          if (parca) adlar.push(parca);
        });
        if (!adlar.length) return;
        var veren = String(x.issuer_name || '').trim();
        if (veren) {
          var m = veren.match(/O=([^,]+)/);
          veren = (m ? m[1].trim() : veren).slice(0, 80);
          verenSet[veren] = 1;
        }
        kayitlar.push({
          id: String(x.id || ''), veren: veren,
          yayin: String(x.not_before || '').slice(0, 10),
          bitis: String(x.not_after || '').slice(0, 10),
          yeni: ek2YeniMi(x.not_before),
          _adlar: adlar
        });
      });
      return { kayitlar: kayitlar, verenler: Object.keys(verenSet).sort(), hata: '' };
    });
  }

  /* Python sertifika_alt_alanlar(): CT loglarından alt alan adları */
  function sertifikaAltAlanlar(hedef, crtsh, zorla) {
    var d = ek2Kok(hedef);
    if (!d || d.indexOf('.') < 0 || /^\d+\.\d+\.\d+\.\d+$/.test(d)) {
      return Promise.resolve({ hata: 'geçerli bir alan adı girin (ör. ornek.com)' });
    }
    var anahtar = 'ek2-sertifika::' + d + (crtsh ? '::crtsh' : '');

    function uret() {
      var kayitlar = [], verenler = [], notlar = [], kaynak = '';
      var zincir = Promise.resolve();

      if (crtsh) {
        zincir = ek2SertifikaCrtsh(d).then(function (r) {
          if (r.kayitlar.length) {
            kayitlar = r.kayitlar; verenler = r.verenler; kaynak = 'crt.sh (CT log)';
          } else {
            notlar.push(r.hata || 'crt.sh sonuç döndürmedi');
          }
        });
      }

      return zincir.then(function () {
        if (kayitlar.length) return null;
        return bekle(EK2_ISTEK_ARASI).then(function () {
          return ek2SertifikaCertspotter(d);
        }).then(function (r) {
          if (r.notlar && r.notlar.length) notlar = notlar.concat(r.notlar);
          if (r.kayitlar.length) {
            kayitlar = r.kayitlar; verenler = r.verenler; kaynak = 'certspotter (CT log)';
            if (crtsh) notlar.push('crt.sh 502 verdiğinde yedek kaynak: certspotter');
          } else if (!notlar.length) {
            notlar.push(r.hata || 'CT loglarına ulaşılamadı');
          }
        });
      }).then(function () {
        if (!kayitlar.length) {
          return {
            hata: 'sertifika kaydı bulunamadı — ' + (notlar.join('; ') || 'CT loglarına ulaşılamadı'),
            ad: d, kaynak: 'certspotter / crt.sh'
          };
        }
        /* --- alt alan adlarını topla (joker yıldızı atılır, hedef dışı süzülür) */
        var altSet = {};
        kayitlar.forEach(function (k) {
          var adlar = k._adlar || [];
          try { delete k._adlar; } catch (e) { k._adlar = undefined; }
          adlar.forEach(function (a) {
            a = String(a).trim().toLowerCase();
            a = a.replace(/^[*]+\.?/, '').replace(/^\.+/, '');
            if (a && (a === d || a.slice(-(d.length + 1)) === '.' + d)) altSet[a] = 1;
          });
        });
        altSet[d] = 1;
        var altAlanlar = Object.keys(altSet).sort();

        /* --- önceki taramayla karşılaştır (APK: localStorage, masaüstü: JSON) */
        var gecmis = ek2LsOku(EK2_LS_SERTIFIKA);
        if (!gecmis || typeof gecmis !== 'object') gecmis = {};
        var oncekiSet = {};
        (gecmis[d] || []).forEach(function (a) { oncekiSet[a] = 1; });
        var yeniAlt = altAlanlar.filter(function (a) { return !oncekiSet[a]; });
        gecmis[d] = altAlanlar;
        gecmis['_guncelleme::' + d] = simdi();
        ek2LsYaz(EK2_LS_SERTIFIKA, gecmis);

        kayitlar.sort(function (a, b) {
          var x = a.yayin || '', y = b.yayin || '';
          if (x === y) return 0;
          return x < y ? 1 : -1;
        });
        var yeniler = kayitlar.filter(function (k) { return k.yeni; });
        return {
          ad: d,
          sertifika_sayisi: kayitlar.length,
          alt_alan_sayisi: altAlanlar.length,
          alt_alanlar: altAlanlar,
          verenler: verenler,
          kayitlar: kayitlar.slice(0, 60),
          yeni_sertifikalar: yeniler.length,
          yeni_alt_alanlar: yeniAlt,
          ilk_tarama: Object.keys(oncekiSet).length === 0,
          kaynak: kaynak || 'certspotter (CT log)',
          not: (notlar.join(' ') || 'crt.sh 502 verdiğinde yedek kaynak: certspotter'),
          ornek: 'CT logları herkese açıktır: bir alan adı için alınan TÜM sertifikalar ' +
            'burada görünür — yeni bir joker sertifika (ör. *.site.com) çıkmışsa ' +
            'yeni bir alt alan adı yayına alınmış demektir.',
          guncelleme: simdi()
        };
      });
    }

    return ek2Onbellekli(anahtar, EK2_TTL_SERTIFIKA, !!zorla, uret);
  }

  /* ================================ 5) WEB ZAFİYET (yalnız izinli adlar) */
  var EK2_HASSAS_YOLLAR = [
    ['/.env', 'kritik', 'Ortam değişkenleri: veritabanı şifresi, API anahtarı'],
    ['/.git/config', 'kritik', 'Git deposu: tüm kaynak kod geçmişi indirilebilir'],
    ['/.svn/entries', 'kritik', 'SVN çalışma kopyası kalıntısı'],
    ['/backup.zip', 'kritik', 'Yedek arşivi'],
    ['/db.sql', 'kritik', 'Veritabanı dökümü'],
    ['/.htaccess', 'yüksek', 'Sunucu yapılandırması (yönlendirme kuralları sızar)'],
    ['/wp-config.php.bak', 'kritik', 'WordPress yapılandırma yedeği: DB şifresi'],
    ['/.DS_Store', 'orta', 'Dizin içeriği listesi sızar'],
    ['/config.php~', 'kritik', 'Editör yedeği: yapılandırma dosyası'],
    ['/server-status', 'orta', 'Apache durum sayfası: ziyaretçi yolları sızar']
  ];

  var EK2_GUVENLIK_BASLIKLARI = [
    ['strict-transport-security', 'HSTS', "Kullanıcıyı HTTPS'e zorlar", 'kritik'],
    ['content-security-policy', 'CSP', 'XSS ve enjeksiyon kaynaklarını kısıtlar', 'yüksek'],
    ['x-frame-options', 'X-Frame-Options', 'Clickjacking (iframe ile tıklama hırsızlığı)', 'orta'],
    ['x-content-type-options', 'X-Content-Type-Options', 'MIME tipi karışıklığı', 'orta'],
    ['referrer-policy', 'Referrer-Policy', 'Dış sitelere URL sızması', 'düşük'],
    ['permissions-policy', 'Permissions-Policy', 'Kamera/mikrofon/konum izinleri', 'düşük']
  ];

  var EK2_ONERI_NGINX = [
    '# --- NGINX (cPanel: Ek Yapılandırma / nginx.conf include) ---',
    'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
    'add_header X-Content-Type-Options "nosniff" always;',
    'add_header X-Frame-Options "SAMEORIGIN" always;',
    'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
    'add_header Content-Security-Policy "default-src \'self\'; img-src \'self\' data:; ' +
    'style-src \'self\' \'unsafe-inline\'; script-src \'self\'" always;',
    'location ~ /\\.(env|git|svn|htaccess|DS_Store) { deny all; return 403; }',
    'location ~* \\.(zip|sql|bak|old|swp|tar|gz)$ { deny all; return 403; }',
    'location = /server-status { deny all; return 403; }'
  ];

  var EK2_ONERI_APACHE = [
    '# --- Apache / .htaccess (public_html içine) ---',
    'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
    'Header always set X-Content-Type-Options "nosniff"',
    'Header always set X-Frame-Options "SAMEORIGIN"',
    'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"',
    'Header always set Content-Security-Policy "default-src \'self\'; img-src \'self\' data:; ' +
    'style-src \'self\' \'unsafe-inline\'; script-src \'self\'"',
    'RedirectMatch 403 ^/\\.(env|git|svn|htaccess|DS_Store)',
    'RedirectMatch 403 (?i)\\.(zip|sql|bak|old|swp|tar|gz)$',
    'TraceEnable off',
    'Options -Indexes',
    '# Not: Header/RedirectMatch için mod_headers ve mod_alias açık olmalı ' +
    "(cPanel'de genelde açıktır)."
  ];

  /* APK'da veri/izleme.json yoktur → kapsam listesi derleme gömülü +
     localStorage (osint_ek2_izleme) + istek parametresinden okunur.        */
  var EK2_IZLEME_VARSAYILAN = ['ustadkenankuzucu.com.tr', 'ustadcyber.com.tr'];

  function ek2IzlemeListesi(ekGirdi) {
    var set = {};
    function ekle(x) {
      var ad = ek2Kok((x && typeof x === 'object') ? x.ad : x);
      if (ad) set[ad] = 1;
    }
    EK2_IZLEME_VARSAYILAN.forEach(ekle);
    var ls = ek2LsOku(EK2_LS_IZLEME);
    if (ls) {
      if (Object.prototype.toString.call(ls) === '[object Array]') ls.forEach(ekle);
      else if (typeof ls === 'object') {
        (ls.hedefler || ls.siteler || ls.alan_adlari || []).forEach(ekle);
      }
    }
    if (ekGirdi) String(ekGirdi).split(/[,\s]+/).forEach(function (x) { if (x) ekle(x); });
    return Object.keys(set).sort();
  }

  function ek2BaslikDegeri(bas, ad) {
    if (!bas) return '';
    var v = bas[String(ad).toLowerCase()];
    if (v === undefined || v === null) return '';
    if (Object.prototype.toString.call(v) === '[object Array]') return v.length ? String(v[0]) : '';
    return String(v);
  }

  function ek2CerezHam(bas) {
    if (!bas) return [];
    var liste = [];
    var dizi = bas['_set_cookie'];
    if (Object.prototype.toString.call(dizi) === '[object Array]') {
      dizi.forEach(function (x) { liste.push(String(x)); });
    }
    ['set-cookie', 'set-cookie2'].forEach(function (k) {
      var v = bas[k];
      if (v === undefined || v === null) return;
      if (Object.prototype.toString.call(v) === '[object Array]') {
        v.forEach(function (x) { liste.push(String(x)); });
      } else {
        String(v).split(/,(?=\s*[A-Za-z0-9_\-]+=)/).forEach(function (x) {
          if (x.trim()) liste.push(x.trim());
        });
      }
    });
    return liste;
  }

  function ek2CerezleriCoz(hamListe) {
    var out = [];
    (hamListe || []).slice(0, 20).forEach(function (c) {
      var parcalar = String(c).split(';').map(function (p) { return p.trim(); });
      if (!parcalar.length || parcalar[0].indexOf('=') < 0) return;
      var kucuk = parcalar.slice(1).map(function (p) { return p.toLowerCase(); });
      var ad = parcalar[0].split('=')[0].trim().slice(0, 60);
      var samesite = null;
      parcalar.slice(1).forEach(function (p) {
        if (p.toLowerCase().indexOf('samesite=') === 0) {
          var v = p.split('=').slice(1).join('=').trim();
          samesite = v.charAt(0).toUpperCase() + v.slice(1).toLowerCase();
        }
      });
      out.push({
        ad: ad,
        httponly: kucuk.indexOf('httponly') >= 0,
        secure: kucuk.indexOf('secure') >= 0,
        samesite: samesite
      });
    });
    return out;
  }

  function ek2DosyaDurumu(kod) {
    if (kod === 200) return { durum: 'AÇIK', derece: 'kritik' };
    if (kod === 401 || kod === 403) return { durum: 'kapalı', derece: '' };
    if (kod === 404 || kod === 410) return { durum: 'yok', derece: '' };
    if (kod === 0) return { durum: 'erişilemedi', derece: '' };
    return { durum: 'belirsiz', derece: 'düşük' };
  }

  /* Python web_zafiyet(): pasif/zararsız yapılandırma kontrolü.
     KAPSAM: yalnız izleme listesindeki kendi alan adları.                  */
  function webZafiyet(hedef, izlemeEk, zorla) {
    var d = ek2Kok(hedef);
    if (!d || d.indexOf('.') < 0) {
      return Promise.resolve({ hata: 'geçerli bir alan adı girin (ör. ornek.com)' });
    }
    var izinli = ek2IzlemeListesi(izlemeEk);
    if (!izinli.length) {
      return Promise.resolve({
        hata: 'izleme listesi boş — veri/izleme.json içine kendi alan adlarınızı ekleyin'
      });
    }
    if (izinli.indexOf(d) < 0) {
      return Promise.resolve({
        hata: 'kapsam dışı — yalnız kendi alan adlarınız taranır',
        ad: d, izinli: izinli
      });
    }
    var anahtar = 'ek2-webzafiyet::' + d;

    function uret() {
      var temel = 'https://' + d;
      return _cek(temel + '/', { zaman: 20, tip: 'HEAD' }).then(function (r0) {
        var kod0 = r0.kod, bas0 = r0.basliklar || {};
        var temelSec = temel;
        if (kod0 === 0) {
          temelSec = 'http://' + d;
          return _cek(temelSec + '/', { zaman: 20, tip: 'HEAD' }).then(function (r1) {
            return { kod0: r1.kod, bas0: r1.basliklar || {}, temel: temelSec };
          });
        }
        return { kod0: kod0, bas0: bas0, temel: temelSec };
      }).then(function (ilk) {
        if (ilk.kod0 === 0) {
          return {
            hata: 'siteye ulaşılamadı (sunucu kapalı ya da ağ engelli)',
            ad: d, url: ilk.temel
          };
        }
        var devam = Promise.resolve(ilk);
        if (!Object.keys(ilk.bas0).length) {
          devam = _cek(ilk.temel + '/', { zaman: 20, tip: 'GET' }).then(function (r) {
            ilk.bas0 = r.basliklar || {};
            if (r.kod) ilk.kod0 = r.kod;
            return ilk;
          });
        }
        return devam.then(function (x) { return tarama(x.kod0, x.bas0, x.temel); });
      });
    }

    function tarama(kod0, bas0, temel) {
      var bulgular = [], oneriler = [];
      var acikSayisi = 0;

      /* ---------- (a) hassas dosyalar (HEAD; 405 ise GET) */
      var hassas = [];
      return havuz(EK2_HASSAS_YOLLAR, function (y) {
        var yol = y[0], onem = y[1], aciklama = y[2];
        function tek(tip) {
          return _cek(temel + yol, { zaman: 15, tip: tip }).then(function (r) {
            if (tip === 'HEAD' && r.kod === 405) {
              return bekle(EK2_ISTEK_ARASI).then(function () {
                return _cek(temel + yol, { zaman: 15, tip: 'GET' });
              });
            }
            return r;
          });
        }
        return bekle(EK2_ISTEK_ARASI).then(function () { return tek('HEAD'); }).then(function (r) {
          var dd = ek2DosyaDurumu(r.kod);
          var kayit = {
            yol: yol, kod: r.kod, durum: dd.durum,
            onem: dd.derece || onem, aciklama: aciklama
          };
          hassas.push(kayit);
          if (dd.durum === 'AÇIK') {
            bulgular.push({
              tur: 'hassas_dosya', onem: 'kritik',
              aciklama: yol + ' adresi HTTP ' + r.kod + ' döndü — dosya dışarıdan okunabilir (' + aciklama + ')'
            });
          } else if (dd.durum === 'belirsiz') {
            bulgular.push({
              tur: 'hassas_dosya', onem: 'düşük',
              aciklama: yol + ' için beklenmedik kod: HTTP ' + r.kod
            });
          }
        });
      }, 2).then(function () {
        hassas.sort(function (a, b) {
          var ia = EK2_HASSAS_YOLLAR.map(function (y) { return y[0]; }).indexOf(a.yol);
          var ib = EK2_HASSAS_YOLLAR.map(function (y) { return y[0]; }).indexOf(b.yol);
          return ia - ib;
        });
        acikSayisi = hassas.filter(function (h) { return h.durum === 'AÇIK'; }).length;
        if (!acikSayisi) {
          bulgular.push({
            tur: 'hassas_dosya', onem: 'bilgi',
            aciklama: 'Test edilen ' + hassas.filter(function (h) { return h.kod !== 0; }).length +
              ' hassas yol açık değil (403/404 döndü).'
          });
        }

        /* ---------- (b) HTTP metotları */
        return bekle(EK2_ISTEK_ARASI).then(function () {
          return _cek(temel + '/', { zaman: 15, tip: 'OPTIONS' });
        }).then(function (ro) {
          var allow = ek2BaslikDegeri(ro.basliklar, 'allow');
          return bekle(EK2_ISTEK_ARASI).then(function () {
            return _cek(temel + '/', { zaman: 15, tip: 'TRACE' });
          }).then(function (rt) {
            var traceAcik = rt.kod === 200;
            var metotlar = {
              OPTIONS: ro.kod || 'kapalı',
              TRACE: traceAcik ? 'AÇIK' : 'kapalı',
              allow: allow
            };
            if (traceAcik) {
              bulgular.push({
                tur: 'metot', onem: 'kritik',
                aciklama: 'TRACE metodu açık (HTTP 200) — Cross-Site Tracing (XST) riski. ' +
                  "Apache'de 'TraceEnable off' ekleyin."
              });
            } else {
              bulgular.push({
                tur: 'metot', onem: 'bilgi',
                aciklama: 'TRACE metodu kapalı (HTTP ' + (rt.kod || 'yanıt yok') + ').'
              });
            }

            /* ---------- (c) CORS */
            return bekle(EK2_ISTEK_ARASI).then(function () {
              var kotuKok = 'https://kotu-site.example';
              return _cek(temel + '/', { zaman: 15, tip: 'GET', basliklar: { Origin: kotuKok } })
                .then(function (rc) {
                  var acao = ek2BaslikDegeri(rc.basliklar, 'access-control-allow-origin').trim();
                  var corsUyari = null;
                  if (acao === '*') {
                    corsUyari = 'Access-Control-Allow-Origin: * — kimlik doğrulamalı sayfalarda ' +
                      'başka siteler veri okuyabilir';
                  } else if (acao && (acao.indexOf(kotuKok) >= 0 || acao.indexOf('kotu-site.example') >= 0)) {
                    corsUyari = 'Sunucu isteğin Origin başlığını yansıtıyor (' + acao + ') — ' +
                      'yansıtma (reflected CORS) riski';
                  }
                  if (corsUyari) {
                    bulgular.push({ tur: 'cors', onem: 'yüksek', aciklama: corsUyari });
                  }
                  var cors = {
                    uyari: corsUyari, test_origin: kotuKok,
                    access_control_allow_origin: acao
                  };
                  if (kopruVarMi()) {
                    cors.not = 'Telefonda (köprü) isteğe Origin başlığı konulamaz — CORS ' +
                      'yansıtma testi yalnız masaüstü sürümünde kesin sonuç verir.';
                  }

                  /* ---------- (d) güvenlik başlıkları */
                  var eksik = [], mevcut = [];
                  EK2_GUVENLIK_BASLIKLARI.forEach(function (b) {
                    var var_ = !!ek2BaslikDegeri(bas0, b[0]);
                    (var_ ? mevcut : eksik).push(b[1]);
                    if (!var_) {
                      bulgular.push({
                        tur: 'baslik', onem: b[3],
                        aciklama: b[1] + ' başlığı yok — ' + b[2]
                      });
                    }
                  });
                  var baslikPuan = Math.round(100.0 * mevcut.length / EK2_GUVENLIK_BASLIKLARI.length);

                  /* ---------- (e) çerezler */
                  var cerezler = ek2CerezleriCoz(ek2CerezHam(bas0));
                  var eksikBayrak = 0;
                  cerezler.forEach(function (c) {
                    var sorun = [];
                    if (!c.httponly) sorun.push('HttpOnly');
                    if (!c.secure) sorun.push('Secure');
                    if (!c.samesite) sorun.push('SameSite');
                    c.sorun = sorun;
                    eksikBayrak += sorun.length;
                    if (sorun.length) {
                      bulgular.push({
                        tur: 'cerez', onem: 'yüksek',
                        aciklama: "'" + c.ad + "' çerezinde eksik bayrak: " + sorun.join(', ')
                      });
                    }
                  });

                  /* ---------- puanlama */
                  var puan = 100;
                  puan -= 5 * eksik.length;
                  puan -= 20 * acikSayisi;
                  puan -= 5 * hassas.filter(function (h) { return h.durum === 'belirsiz'; }).length;
                  if (traceAcik) puan -= 10;
                  if (corsUyari) puan -= 10;
                  puan -= 3 * eksikBayrak;
                  puan = Math.max(0, Math.min(100, puan));
                  var seviye = puan >= 85 ? 'iyi' : (puan >= 60 ? 'orta' : 'zayıf');

                  /* ---------- öneriler */
                  oneriler = oneriler.concat(EK2_ONERI_NGINX, EK2_ONERI_APACHE);
                  if (acikSayisi) {
                    oneriler.unshift('ÖNCE ŞUNU YAPIN: ' + acikSayisi + ' hassas yol açık. Bu dosyaları ' +
                      'sunucudan silin/yeniden adlandırın (ör. .env yerine .env-local, web kökü ' +
                      'dışına taşıyın) ve yedekleri public_html dışında tutun.');
                  }
                  if (corsUyari) {
                    oneriler.push('# CORS: yansıtma yerine sabit liste kullanın → ' +
                      'add_header Access-Control-Allow-Origin "https://kendi-siteniz.com" always;');
                  }
                  if (traceAcik) {
                    oneriler.push('# TRACE kapalı değil → Apache .htaccess: TraceEnable off ' +
                      "(NGINX TRACE'i zaten yanıtlamaz)");
                  }
                  if (cerezler.length) {
                    oneriler.push('# Çerez bayrakları (PHP örneği): ' +
                      "setcookie($ad, $deger, ['httponly'=>true,'secure'=>true," +
                      "'samesite'=>'Lax']);");
                  }

                  return {
                    ad: d,
                    url: temel + '/',
                    http_durum: kod0,
                    hassas_dosyalar: hassas,
                    metotlar: metotlar,
                    cors: cors,
                    basliklar: { eksik: eksik, mevcut: mevcut, puan: baslikPuan },
                    cerezler: cerezler,
                    puan: puan,
                    seviye: seviye,
                    bulgular: bulgular,
                    oneriler: oneriler,
                    kaynak: 'kendi sunucunuz (pasif başlık kontrolü)',
                    uyari: 'Bu modül yalnızca izleme listesindeki alan adlarında çalışır. ' +
                      'Yapılan istekler zararsız HEAD/GET çağrılarıdır; istekler arası 250 ms beklenir.',
                    guncelleme: simdi()
                  };
                });
            });
          });
        });
      });
    }

    return ek2Onbellekli(anahtar, EK2_TTL_WEBZAFIYET, !!zorla, uret);
  }

  /* =========================================== 6) FİDYE YAZILIMI İZLEME */
  function ek2TarihKirp(deger) {
    var m = String(deger == null ? '' : deger).match(/^(\d{4}-\d{2}-\d{2})/);
    return m ? m[1] : '';
  }

  function ek2TeslimTarihi(aciklama) {
    var m = String(aciklama == null ? '' : aciklama).match(/deadline\s+(\d{4}-\d{2}-\d{2})/i);
    return m ? m[1] : null;
  }

  function ek2Say(anahtarFn, kayitlar, enFazla) {
    enFazla = enFazla || 15;
    var sayac = {};
    (kayitlar || []).forEach(function (k) {
      var v = anahtarFn(k);
      if (v) sayac[v] = (sayac[v] || 0) + 1;
    });
    return Object.keys(sayac).map(function (k) { return { adet: sayac[k], deger: k }; })
      .sort(function (a, b) { return b.adet - a.adet; })
      .slice(0, enFazla);
  }

  function fidyeIzleme(ulke, sektor, limit, zorla) {
    var lim = parseInt(limit, 10);
    if (isNaN(lim)) lim = 100;
    lim = Math.max(10, Math.min(lim, 100));
    ulke = String(ulke || '').trim().toUpperCase().slice(0, 3);
    sektor = String(sektor || '').trim().toLowerCase();
    var anahtar = 'ek2-fidye::' + ulke + '::' + sektor + '::' + lim;

    function uret() {
      return _json('https://api.ransomware.live/recentvictims', { zaman: 35 }).then(function (r) {
        if ([200, 301, 302].indexOf(r.kod) < 0 || Object.prototype.toString.call(r.j) !== '[object Array]') {
          if (r.kod === 0) return { hata: 'ransomware.live beslemesine ulaşılamadı (ağ/SSL)' };
          return { hata: 'ransomware.live beklenmeyen yanıt (HTTP ' + r.kod + ')' };
        }
        var tumKurumlar = [];
        r.j.filter(function (x) { return x && typeof x === 'object'; }).slice(0, lim).forEach(function (x) {
          var aciklama = String(x.description || '').trim();
          tumKurumlar.push({
            kurum: (String(x.post_title || '').trim() || '—').slice(0, 160),
            ulke: String(x.country || '').trim().toUpperCase() || '—',
            sektor: String(x.activity || '').trim() || '—',
            grup: String(x.group_name || '').trim() || '—',
            tarih: ek2TarihKirp(x.published || x.discovered),
            veri_boyutu: x.data_size === undefined ? null : x.data_size,
            teslim: ek2TeslimTarihi(aciklama),
            aciklama: aciklama.slice(0, 300),
            site: String(x.website || '').trim().slice(0, 120)
          });
        });
        var suzulmus = tumKurumlar.filter(function (k) {
          return (!ulke || k.ulke === ulke) && (!sektor || k.sektor.toLowerCase().indexOf(sektor) >= 0);
        });
        var turkiye = tumKurumlar.filter(function (k) { return k.ulke === 'TR'; });
        return {
          toplam: tumKurumlar.length,
          gosterilen: suzulmus.length,
          kurumlar: suzulmus,
          gruplar: ek2Say(function (k) { return k.grup; }, suzulmus).map(function (x) {
            return { grup: x.deger, adet: x.adet };
          }),
          ulkeler: ek2Say(function (k) { return k.ulke; }, suzulmus).map(function (x) {
            return { ulke: x.deger, adet: x.adet };
          }),
          sektorler: ek2Say(function (k) { return k.sektor; }, suzulmus).map(function (x) {
            return { sektor: x.deger, adet: x.adet };
          }),
          turkiye: turkiye,
          uyari: 'son ' + tumKurumlar.length + ' kayıtta Türkiye\'den ' + turkiye.length + ' kurum',
          kaynak: 'ransomware.live',
          not: '.onion bağlantıları listelenmez',
          suzgec: { ulke: ulke || 'hepsi', sektor: sektor || 'hepsi', limit: lim },
          ornek: 'Yeni bir fidye yazılımı kurbanı kendi sektörünüzde görünüyorsa ' +
            'aynı grup sizi de hedefleyebilir: teslim tarihi ve grup adı ' +
            'üzerinden önlem alın (yedek, EDR, MFA).',
          guncelleme: simdi()
        };
      });
    }

    return ek2Onbellekli(anahtar, EK2_TTL_FIDYE, !!zorla, uret);
  }

  /* ============================================== 7) SALDIRI AKIŞI (ISC) */
  function ek2KonumToplu(ipler) {
    var sonuc = {};
    if (!ipler || !ipler.length) return Promise.resolve(sonuc);
    var govde = JSON.stringify(ipler.slice(0, 100).map(function (ip) { return { query: ip }; }));
    return _cek('http://ip-api.com/batch?fields=status,country,city,lat,lon,query',
      { zaman: 20, veri: govde, tip: 'application/json' }).then(function (r) {
        var j = null;
        try { j = JSON.parse(r.govde); } catch (e) { j = null; }
        if (r.kod === 200 && Object.prototype.toString.call(j) === '[object Array]') {
          j.forEach(function (x) {
            if (!x || typeof x !== 'object' || x.status !== 'success') return;
            sonuc[String(x.query)] = {
              ulke: x.country || '', sehir: x.city || '',
              enlem: x.lat === undefined ? null : x.lat,
              boylam: x.lon === undefined ? null : x.lon
            };
          });
          if (Object.keys(sonuc).length) {
            sonuc._kaynak = 'ip-api.com';
            return sonuc;
          }
        }
        /* ---- yedek: ipwho.is (HTTPS) */
        return havuz(ipler.slice(0, 20), function (ip) {
          return _json('https://ipwho.is/' + encodeURIComponent(ip), { zaman: 12 }).then(function (r2) {
            var j2 = r2.j;
            if (r2.kod === 200 && j2 && typeof j2 === 'object' && j2.success) {
              sonuc[ip] = {
                ulke: j2.country || '', sehir: j2.city || '',
                enlem: j2.latitude === undefined ? null : j2.latitude,
                boylam: j2.longitude === undefined ? null : j2.longitude
              };
            }
          });
        }, 4).then(function () {
          if (Object.keys(sonuc).length) sonuc._kaynak = 'ipwho.is';
          return sonuc;
        });
      });
  }

  function saldiriAkisi(zorla) {
    var anahtar = 'saldiriakisi::topips';

    function uret() {
      return _json('https://isc.sans.edu/api/topips/records/20?json', { zaman: 20 }).then(function (r) {
        if (r.kod !== 200 || Object.prototype.toString.call(r.j) !== '[object Array]') {
          return {
            hata: 'SANS ISC verisi alınamadı (durum ' + r.kod + '). Ağ/engel olabilir.'
          };
        }
        var ham = [];
        r.j.slice(0, 20).forEach(function (x) {
          if (!x || typeof x !== 'object') return;
          ham.push({
            sira: parseInt(x.rank, 10) || (ham.length + 1),
            ip: String(x.source || '').trim(),
            rapor: parseInt(x.reports, 10) || 0,
            hedef: parseInt(x.targets, 10) || 0
          });
        });
        var ipler = ham.filter(function (x) { return x.ip; }).map(function (x) { return x.ip; });
        return ek2KonumToplu(ipler).then(function (konum) {
          var kayitlar = ham.map(function (x) {
            var k = konum[x.ip] || {};
            return {
              sira: x.sira, ip: x.ip, rapor: x.rapor, hedef: x.hedef,
              ulke: k.ulke || '', sehir: k.sehir || '',
              enlem: k.enlem === undefined ? null : k.enlem,
              boylam: k.boylam === undefined ? null : k.boylam
            };
          });
          var toplam = 0;
          kayitlar.forEach(function (x) { toplam += x.rapor; });
          return {
            kaynak: 'SANS ISC DShield',
            kayitlar: kayitlar,
            toplam_rapor: toplam,
            konum_kaynagi: konum._kaynak || '',
            guncelleme: simdi(),
            not: 'İzinli/kendi sistem bağlamında pasif istihbarat kaynağıdır; hedeflere dokunulmaz.'
          };
        });
      });
    }

    return ek2Onbellekli(anahtar, 900, !!zorla, uret);
  }

  /* =================================================== 8) SIR AVCISI
     APK'da dosya sistemi YOKTUR: yerel klasör taraması yapılamaz. Yalnız
     GitHub kod arama yolu (?github=1) çalışır; o da token gerektirir.       */
  function ek2GithubToken(ayarlar) {
    if (EK2_GITHUB_ANAHTAR) return EK2_GITHUB_ANAHTAR;
    var kaynaklar = [ayarlar ? ayarlar.github_anahtar : '', ''];
    for (var i = 0; i < kaynaklar.length; i++) {
      var t = String(kaynaklar[i] || '').trim();
      if (t) { EK2_GITHUB_ANAHTAR = t; return t; }
    }
    try {
      if (typeof localStorage !== 'undefined') {
        var ls = localStorage.getItem('osint_github_anahtar');
        if (ls) { EK2_GITHUB_ANAHTAR = String(ls).trim(); return EK2_GITHUB_ANAHTAR; }
      }
    } catch (e) { }
    return '';
  }

  function ek2GithubKodArama(ayarlar) {
    var tok = ek2GithubToken(ayarlar);
    if (!tok) {
      return Promise.resolve({ durum: 'GitHub token bulunamadı — yalnız yerel tarama yapıldı' });
    }
    var bas = { Authorization: 'token ' + tok, Accept: 'application/vnd.github+json' };
    return _json('https://api.github.com/user', { zaman: 15, basliklar: bas }).then(function (r) {
      var login = (r.j && typeof r.j === 'object') ? r.j.login : '';
      if (r.kod !== 200 || !login) {
        return { durum: 'GitHub token doğrulanamadı (durum ' + r.kod + ') — yalnız yerel tarama yapıldı' };
      }
      var sonuclar = [], reddedildi = false;
      var desenler = ['AKIA', 'ghp_', 'sk_live_', 'xoxb-'];
      var zincir = Promise.resolve();
      desenler.forEach(function (desen) {
        zincir = zincir.then(function () {
          if (reddedildi) return null;
          var q = encodeURIComponent(desen + ' user:' + login);
          return _json('https://api.github.com/search/code?q=' + q, { zaman: 20, basliklar: bas })
            .then(function (r2) {
              if (r2.kod !== 200 || !r2.j || typeof r2.j !== 'object') { reddedildi = true; return null; }
              (r2.j.items || []).slice(0, 5).forEach(function (o) {
                sonuclar.push({
                  desen: desen,
                  depo: o && o.repository ? o.repository.full_name : null,
                  yol: o ? o.path : null,
                  url: o ? o.html_url : null
                });
              });
            });
        });
      });
      return zincir.then(function () {
        if (reddedildi) {
          return { durum: "kod arama API'si bu token ile reddedildi — yalnız yerel tarama yapıldı" };
        }
        return { durum: 'tamam', kullanici: login, bulunan: sonuclar.length, kayitlar: sonuclar };
      });
    });
  }

  function sirAvcisi(yol, limit, github, ayarlar) {
    var hedefYol = String(yol || '').trim();
    if (!github) {
      /* APK'da dosya sistemi yok → gerçek veri üretilemez, uydurma yapılmaz */
      return Promise.resolve({
        hata: 'yerel klasör taraması yalnız masaüstü sürümünde çalışır (APK\'da dosya sistemi yok)',
        yol: hedefYol || null,
        cozum: 'GitHub kod araması için "github" seçeneğini açın (?github=1)'
      });
    }
    return ek2GithubToken(ayarlar)
      ? ek2GithubKodArama(ayarlar).then(function (gh) {
        if (gh.durum !== 'tamam') {
          return {
            hata: 'yerel klasör taraması yalnız masaüstü sürümünde çalışır — ' + gh.durum,
            github: gh
          };
        }
        return {
          kok: null, taranan_dosya: 0, atlanan: 0, sure_sn: 0,
          bulgular: [], kritik: 0, yuksek: 0, toplam_bulgu: gh.bulunan || 0,
          ozet: 'APK\'da yerel dosya taraması yapılamaz (dosya sistemi yok) — ' +
            'GitHub kod araması yapıldı: ' + (gh.bulunan || 0) + ' sonuç',
          kaynak: 'GitHub kod arama API (APK)',
          not: 'Bulgularda sır değerleri maskelenmiştir (yalnız ilk 4 + son 4 karakter).',
          github: gh
        };
      })
      : Promise.resolve({
        hata: 'yerel klasör taraması yalnız masaüstü sürümünde çalışır; ' +
          'GitHub kod araması için token gerekli (Ayarlar → GitHub anahtarı)',
        yol: hedefYol || null
      });
  }

  /* ====================================================== 9) YEREL AĞ
     `arp -a` ve UDP SSDP yoktur (APK'da ağ komutları kullanılamaz):
     uydurma cihaz listesi üretilmez, dürüst hata döner.                     */
  function yerelAg() {
    return {
      hata: 'yerel ağ taraması yalnız masaüstü sürümünde çalışır (APK\'da ağ komutları kullanılamıyor)',
      kaynak: 'kendi bilgisayarınız (masaüstü sürümü)'
    };
  }

  /* ============================================ 10) ŞİFRE KONTROL (HIBP) */
  function sifreKontrol(sifre) {
    sifre = String(sifre == null ? '' : sifre);
    if (!sifre) {
      return Promise.resolve({ hata: "şifre boş olamaz (gövdede {'sifre':'...'} gönderin)" });
    }
    /* 1) SHA-1 SADECE YERELDE hesaplanır; şifre hiçbir yere yazılmaz. */
    return sha1Hex(sifre).then(function (sha1) {
      var ilk5 = sha1.slice(0, 5), kalan = sha1.slice(5);
      return _cek('https://api.pwnedpasswords.com/range/' + ilk5,
        { zaman: 20, basliklar: { 'Add-Padding': 'true' } }).then(function (r) {
          var sizinti = 0, bulundu = false;
          if (r.kod === 200 && r.govde) {
            var satirlar = r.govde.split(/\r?\n/);
            for (var i = 0; i < satirlar.length; i++) {
              var p = satirlar[i].trim().split(':');
              if (p.length === 2 && p[0].toUpperCase() === kalan) {
                var n = parseInt(p[1], 10);
                sizinti = isNaN(n) ? 0 : n;
                bulundu = sizinti > 0;
                break;
              }
            }
          } else {
            return { hata: 'HIBP sorgusu başarısız (durum ' + r.kod + '). Ağ/engel olabilir.' };
          }

          /* 2) Güç analizi (tamamen yerel) */
          var uzunluk = sifre.length, kumeler = 0;
          if (/[a-z]/.test(sifre)) kumeler += 26;
          if (/[A-Z]/.test(sifre)) kumeler += 26;
          if (/\d/.test(sifre)) kumeler += 10;
          if (/[^A-Za-z0-9]/.test(sifre)) kumeler += 33;
          var entropiKar = ek2Entropi(sifre);
          var entropiBit = kumeler ? yuvarlak(uzunluk * (Math.log(kumeler) / Math.LN2), 1) : 0.0;
          var puan = entropiBit;
          if (bulundu) puan = Math.min(puan, 20);
          var seviye = puan < 40 ? 'zayıf' : (puan < 60 ? 'orta' : (puan < 80 ? 'güçlü' : 'çok güçlü'));
          var oneriler = [];
          if (bulundu) oneriler.push('Bu şifre ' + sizinti + ' kez sızmış — DERHAL değiştirin.');
          if (uzunluk < 12) oneriler.push('En az 12 karakter kullanın (16+ ideal).');
          if (kumeler <= 26) oneriler.push('Büyük/küçük harf, rakam ve simge çeşitliliği ekleyin.');
          if (entropiKar < 3.0) oneriler.push('Tekrar eden/öngörülebilir kalıplardan kaçının.');
          if (!oneriler.length) {
            oneriler.push('Şifre güçlü görünüyor; her sitede farklı şifre kullanın ve 2FA açın.');
          }
          return {
            sizinti_sayisi: sizinti,
            bulundu: bulundu,
            gucluluk: {
              uzunluk: uzunluk, entropi_bit: entropiBit,
              entropi_karekter: yuvarlak(entropiKar, 2),
              karakter_havuzu: kumeler, seviye: seviye
            },
            oneriler: oneriler,
            kaynak: 'HIBP Pwned Passwords (k-anonymity)',
            not: 'şifreniz cihazdan çıkmadı; yalnız SHA-1\'in ilk 5 karakteri gönderildi'
          };
        });
    });
  }

  /* =================================================== 11) RAPOR PAKETİ
     python-docx yoktur: word ve html için aynı yazdırılabilir HTML üretilir;
     `dosya` yolu yerine içerik (`html`) döner ve `not` ile açıklanır.       */
  function ek2HtmlKac(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
  }

  function ek2HtmlRapor(baslik, ozet, bolumler, kanitHash, zaman) {
    var o = ['<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8">',
      '<title>' + ek2HtmlKac(baslik) + '</title>',
      '<style>body{font-family:Segoe UI,Arial,sans-serif;margin:28px;color:#1b1b1b}',
      'h1{background:#E87722;color:#fff;padding:12px 16px;border-radius:6px;font-size:22px}',
      'h2{background:#E87722;color:#fff;padding:8px 12px;border-radius:5px;font-size:16px;margin-top:22px}',
      'h3{background:#1F3864;color:#fff;padding:8px 12px;border-radius:5px;font-size:14px}',
      'table{border-collapse:collapse;width:100%;margin:8px 0 16px}',
      'th{background:#E87722;color:#fff;text-align:left;padding:6px 8px;font-size:13px}',
      'td{border:1px solid #ccc;padding:6px 8px;font-size:12px;vertical-align:top}',
      '.meta{color:#555;font-style:italic;font-size:12px}',
      '.kanit{background:#f2f5fb;border:1px solid #1F3864;padding:10px;border-radius:5px;font-size:12px;word-break:break-all}',
      'footer{text-align:center;color:#666;font-size:11px;margin-top:26px;border-top:1px solid #ddd;padding-top:8px}',
      '@media print{h1,h2,h3{-webkit-print-color-adjust:exact;print-color-adjust:exact}}',
      '</style></head><body>'];
    o.push('<h1>' + ek2HtmlKac(baslik) + '</h1>');
    o.push('<p class="meta">ÜSTAD OSINT · adli bilişim raporu · ' + ek2HtmlKac(zaman) + '</p>');
    if (ozet && Object.keys(ozet).length) {
      o.push('<h2>ÖZET</h2><table><tr><th>Alan</th><th>Değer</th></tr>');
      Object.keys(ozet).forEach(function (k) {
        o.push('<tr><td>' + ek2HtmlKac(k) + '</td><td>' + ek2HtmlKac(ozet[k]) + '</td></tr>');
      });
      o.push('</table>');
    }
    (bolumler || []).forEach(function (bol) {
      if (!bol || typeof bol !== 'object') return;
      o.push("<h2>" + ek2HtmlKac(bol.ad || 'Bölüm') +
        "</h2><table><tr><th style='width:52px'>#</th><th>Kayıt</th></tr>");
      (bol.satirlar || []).forEach(function (s, i) {
        o.push('<tr><td>' + (i + 1) + '</td><td>' + ek2HtmlKac(String(s).slice(0, 1200)) + '</td></tr>');
      });
      o.push('</table>');
    });
    o.push('<h3>ADLİ KANIT</h3>');
    o.push('<div class="kanit"><b>İçerik SHA-256:</b> ' + ek2HtmlKac(kanitHash) +
      '<br><b>Zaman damgası:</b> ' + ek2HtmlKac(zaman) + '</div>');
    o.push('<footer>ÜSTAD OSINT · Kenan Kuzucu</footer></body></html>');
    return o.join('\n');
  }

  function raporPaket(girdi) {
    girdi = (girdi && typeof girdi === 'object') ? girdi : {};
    var tur = String(girdi.tur || 'word').toLowerCase();
    tur = (tur === 'html') ? 'html' : 'word';
    var baslik = String(girdi.baslik || 'ÜSTAD OSINT Raporu');
    var ozet = (girdi.ozet && typeof girdi.ozet === 'object' &&
      Object.prototype.toString.call(girdi.ozet) !== '[object Array]') ? girdi.ozet : {};
    var bolumler = (Object.prototype.toString.call(girdi.bolumler) === '[object Array]') ? girdi.bolumler : [];
    var zaman = simdi();

    /* Adli kanıt özeti: Python json.dumps(..., ensure_ascii=False, sort_keys=True) */
    var kanitMetni = pyJson({ baslik: baslik, ozet: ozet, bolumler: bolumler, zaman: zaman });
    return sha256Hex(kanitMetni).then(function (kanitHash) {
      var html = ek2HtmlRapor(baslik, ozet, bolumler, kanitHash, zaman);
      return sha256Hex(html).then(function (dosyaHash) {
        var sonuc = {
          html: html,
          tur: tur,
          boyut: utf8Uzunluk(html),
          sha256: dosyaHash,
          kanit_sha256: kanitHash,
          qr: null,
          bolum: bolumler.length,
          baslik: baslik,
          zaman: zaman,
          kaynak: 'APK içi HTML üretimi',
          not: 'Dosya masaüstünde kaydedilir; telefonda içerik gösterilir'
        };
        if (tur === 'word') {
          sonuc.not = 'Telefonda Word (.docx) üretilemez (python-docx yok) — içerik HTML ' +
            'olarak üretildi, "html" alanından alınabilir. Dosya masaüstünde kaydedilir; ' +
            'telefonda içerik gösterilir';
        }
        return sonuc;
      });
    });
  }

  /* ==================================================== 12) BİLDİRİM */
  var EK2_BILDIRIM_VARSAYILAN = {
    yeni_port: true, yeni_cve: true, kritik: true, whatsapp: true, eposta: false
  };

  function ek2BildirimOku() {
    var d = ek2LsOku(EK2_LS_BILDIRIM);
    if (!d || typeof d !== 'object' || Object.prototype.toString.call(d) === '[object Array]') {
      d = {};
    }
    if (!d.ayar || typeof d.ayar !== 'object') d.ayar = {};
    Object.keys(EK2_BILDIRIM_VARSAYILAN).forEach(function (k) {
      if (d.ayar[k] === undefined) d.ayar[k] = EK2_BILDIRIM_VARSAYILAN[k];
    });
    if (Object.prototype.toString.call(d.olaylar) !== '[object Array]') d.olaylar = [];
    return d;
  }

  function ek2BildirimYaz(d) { return ek2LsYaz(EK2_LS_BILDIRIM, d); }

  function bildirimIsle(govde) {
    govde = (govde && typeof govde === 'object') ? govde : {};
    var d = ek2BildirimOku();
    if (govde.ayar && typeof govde.ayar === 'object') {
      Object.keys(govde.ayar).forEach(function (k) { d.ayar[String(k)] = !!govde.ayar[k]; });
      ek2BildirimYaz(d);
    }
    if (govde.olay && typeof govde.olay === 'object') {
      var o = govde.olay;
      d.olaylar.unshift({
        tip: String(o.tip || 'genel'),
        baslik: String(o.baslik || '').slice(0, 300),
        onem: String(o.onem || 'bilgi'),
        zaman: simdi(),
        okundu: false
      });
      d.olaylar = d.olaylar.slice(0, 200);
      ek2BildirimYaz(d);
    }
    var olaylar = d.olaylar || [];
    return {
      ayar: d.ayar,
      olaylar: olaylar.slice(0, 20),
      olay_sayisi: olaylar.length,
      okunmamis: olaylar.filter(function (o) { return !o.okundu; }).length,
      kaynak: 'yerel olay günlüğü'
    };
  }

  function bildirimOlayEkle(olay) {
    var d = ek2BildirimOku();
    var o = (olay && typeof olay === 'object') ? olay : {};
    d.olaylar.unshift({
      tip: String(o.tip || 'genel'), baslik: String(o.baslik || '').slice(0, 300),
      onem: String(o.onem || 'bilgi'), zaman: simdi(), okundu: false
    });
    d.olaylar = d.olaylar.slice(0, 200);
    ek2BildirimYaz(d);
    return { tamam: true, olay_sayisi: d.olaylar.length };
  }

  /* ------------------------------- v1.6 modül listesi + uç dağıtıcısı */
  var EK2_MODUL_LISTESI = [
    { kod: 'istismar', ad: 'İstismar Radarı (KEV+EPSS)', aciklama: 'CISA KEV + FIRST EPSS: aktif istismar ve olasılık puanı', ornek: '/api/arac/istismar?cve=CVE-2024-3094' },
    { kod: 'postaguvenlik', ad: 'Posta Güvenliği', aciklama: 'SPF / DMARC / DKIM / MX denetimi ve direnç puanı', ornek: '/api/arac/postaguvenlik?ad=example.com' },
    { kod: 'baslikanaliz', ad: 'Başlık Analizi', aciklama: 'Ham mail başlıklarından sahtecilik risk puanı (POST)', ornek: 'POST /api/arac/baslikanaliz {"ham": "..."}' },
    { kod: 'sertifika', ad: 'Sertifika Şeffaflığı (CT)', aciklama: 'CT loglarından alt alan adları + yeni sertifikalar', ornek: '/api/arac/sertifika?ad=ornek.com' },
    { kod: 'webzafiyet', ad: 'Web Zafiyet Ön Kontrolü', aciklama: 'Hassas yol, metot, CORS, başlık, çerez kontrolü (yalnız izleme listesi)', ornek: '/api/arac/webzafiyet?ad=ornek.com' },
    { kod: 'fidye', ad: 'Fidye Yazılımı İzleme', aciklama: 'ransomware.live son kurbanlar, ülke/sektör süzgeci', ornek: '/api/arac/fidye?ulke=TR&limit=100' },
    { kod: 'saldiriakisi', ad: 'Saldırı Akışı', aciklama: 'SANS ISC en çok saldıran IP\'ler + konum' },
    { kod: 'siravc', ad: 'Sır Avcısı', aciklama: 'Yerel dosyalarda maskeli sır/anahtar taraması' },
    { kod: 'yerelag', ad: 'Yerel Ağ', aciklama: 'ARP tablosu + UPnP keşfi + MAC üretici' },
    { kod: 'sifrekontrol', ad: 'Şifre Kontrol', aciklama: 'HIBP k-anonymity sızıntı + güç analizi' },
    { kod: 'raporpaket', ad: 'Rapor Paketi', aciklama: 'Word/HTML adli bilişim raporu' },
    { kod: 'bildirim', ad: 'Bildirim Merkezi', aciklama: 'Uyarı ayarları + olay günlüğü' }
  ];

  var EK2_YOLLARI = [
    '/api/arac/istismar', '/api/arac/postaguvenlik', '/api/arac/baslikanaliz',
    '/api/arac/sertifika', '/api/arac/webzafiyet', '/api/arac/fidye',
    '/api/arac/saldiriakisi', '/api/arac/siravc', '/api/arac/yerelag',
    '/api/arac/sifrekontrol', '/api/arac/raporpaket', '/api/arac/bildirim',
    '/api/arac/ek2'
  ];

  /* Python ek2a_isle + ek2b_isle + ek2c_isle zincirinin JS karşılığı */
  function ek2Isle(yol, sorgu, govde, ayarlar) {
    var ad = String(yol || '').replace(/\/+$/, '').split('/').pop().split('?')[0].toLowerCase();
    sorgu = (sorgu && typeof sorgu === 'object') ? sorgu : {};
    govde = (govde && typeof govde === 'object') ? govde : {};

    function deger() {
      for (var i = 0; i < arguments.length; i++) {
        var a = arguments[i];
        var v = sorgu[a];
        if (v === undefined || v === null || v === '') v = govde[a];
        if (v !== undefined && v !== null && v !== '') return v;
      }
      return '';
    }
    function evet(v) {
      return ['1', 'true', 'evet', 'yes'].indexOf(String(v == null ? '' : v).toLowerCase()) >= 0;
    }
    var zorla = ek2ZorlaMi(sorgu, govde);

    if (ad === 'moduller' || ad === 'modul' || ad === 'ek2' || ad === 'ek2a' ||
      ad === 'ek2b' || ad === 'ek2c') {
      return Promise.resolve({
        surum: EK2_SURUM,
        dosya: 'osint-ek2a.py · osint-ek2b.py · osint-ek2c.py (JS: motor-osint.js)',
        ekler: EK2_MODUL_LISTESI
      });
    }
    if (ad === 'istismar') {
      var ham = deger('cveler');
      var idler;
      if (ham) idler = String(ham).split(/[,;\s]+/).filter(function (x) { return !!x; });
      else {
        var tek = deger('cve', 'id');
        idler = tek ? [tek] : [];
      }
      return istismarSorgu(idler, zorla);
    }
    if (ad === 'postaguvenlik') {
      return postaGuvenlik(deger('ad', 'hedef', 'domain'), evet(deger('mxip')), zorla);
    }
    if (ad === 'baslikanaliz') {
      var h2 = govde.ham || govde.basliklar || govde.raw;
      if (!h2) {
        ['veri', 'metin', 'text'].forEach(function (k) { if (!h2 && govde[k]) h2 = govde[k]; });
      }
      if (!h2 && typeof sorgu.ham === 'string') h2 = sorgu.ham;
      return Promise.resolve(baslikAnaliz(h2));
    }
    if (ad === 'sertifika') {
      return sertifikaAltAlanlar(deger('ad', 'hedef', 'domain', 'alan'), evet(deger('crtsh')), zorla);
    }
    if (ad === 'webzafiyet') {
      return webZafiyet(deger('ad', 'hedef', 'domain', 'alan'), deger('izinli', 'kapsam'), zorla);
    }
    if (ad === 'fidye') {
      return fidyeIzleme(deger('ulke'), deger('sektor'), deger('limit') || 100, zorla);
    }
    if (ad === 'saldiriakisi') return saldiriAkisi(zorla);
    if (ad === 'siravc') {
      return sirAvcisi(deger('yol'), deger('limit') || 400, evet(deger('github')), ayarlar);
    }
    if (ad === 'yerelag') return Promise.resolve(yerelAg());
    if (ad === 'sifrekontrol') return sifreKontrol(deger('sifre'));
    if (ad === 'raporpaket') {
      var girdi = (govde && Object.keys(govde).length) ? govde : sorgu;
      return raporPaket(girdi);
    }
    if (ad === 'bildirim') {
      if (govde.olay && typeof govde.olay === 'object' && !govde.ayar) {
        return Promise.resolve(bildirimOlayEkle(govde.olay));
      }
      return Promise.resolve(bildirimIsle(govde));
    }
    return Promise.resolve({
      hata: 'bilinmeyen ek2 uç nokta: ' + ad,
      mevcut: ['istismar', 'postaguvenlik', 'baslikanaliz', 'sertifika', 'webzafiyet',
        'fidye', 'saldiriakisi', 'siravc', 'yerelag', 'sifrekontrol', 'raporpaket',
        'bildirim', 'moduller']
    });
  }

  function EK2_MODUL_LISTESI_duzelt_kaldirildi() { return null; }

  /* ------------------------------------------------------------ EK LİSTESİ */
  var EK_MODUL_LISTESI = [
    { kod: 'pasif', ad: 'Pasif Radar', aciklama: 'InternetDB ile dokunmadan port + CVE' },
    { kod: 'cve', ad: 'CVE Eşleştirme', aciklama: 'Teknoloji/sürüm → olası CVE listesi' },
    { kod: 'arsiv', ad: 'Arşiv (Wayback)', aciklama: 'Eski sürümler, silinmiş yollar' },
    { kod: 'urlscan', ad: 'URLScan', aciklama: 'Dünyada yapılmış taramalar + ekran' },
    { kod: 'takeover', ad: 'Takeover Taraması', aciklama: 'Sahipsiz subdomain (CNAME)' },
    { kod: 'savunma', ad: 'Savunma Duvarı', aciklama: 'IOC → Windows Güvenlik Duvarı .ps1' },
    { kod: 'toplu', ad: 'Toplu Tarama', aciklama: 'Çoklu hedef, risk sıralı tablo' },
    { kod: 'kanit', ad: 'Kanıt Zinciri', aciklama: 'Rapor SHA-256 + zaman damgası' }
  ];

  var EK_YOLLARI = [
    '/api/arac/pasif', '/api/arac/cve', '/api/arac/arsiv', '/api/arac/urlscan',
    '/api/arac/takeover', '/api/arac/savunma', '/api/arac/toplu', '/api/arac/kanit'
  ];

  /* Python ek_isle(): "/api/arac/<ad>" ek yollarını işler */
  function ekIsle(yol, sorgu, govde) {
    var ad = String(yol || '').replace(/\/+$/, '').split('/').pop().toLowerCase();
    sorgu = sorgu || {};
    govde = (govde && typeof govde === 'object') ? govde : {};
    function sg(k) {
      var v = sorgu[k];
      return (v === undefined || v === null) ? '' : String(v);
    }
    function bg(k) {
      var v = govde[k];
      return (v === undefined || v === null) ? '' : v;
    }
    var hedef = sg('ad') || sg('hedef') || bg('hedef') || bg('ad') || '';
    var zorla = ['1', 'true', 'evet'].indexOf(String(sg('zorla') || bg('zorla') || '').toLowerCase()) >= 0;

    if (ad === 'moduller') return Promise.resolve({ ekler: EK_MODUL_LISTESI });
    if (ad === 'pasif') return pasifRadar(hedef, zorla);
    if (ad === 'cve') return cveEsle(sg('tek') || hedef, sg('surum'));
    if (ad === 'arsiv') return arsivWayback(hedef);
    if (ad === 'urlscan') return urlscanAra(hedef);
    if (ad === 'takeover') return takeoverTara(hedef);
    if (ad === 'savunma') return savunmaKurallari();
    if (ad === 'toplu') return topluTarama(bg('hedefler') || sg('hedefler'), bg('moduller'));
    if (ad === 'kanit') {
      if (bg('rapor')) return kanitEkle(bg('rapor'));
      return kanitListesi();
    }
    return Promise.resolve({
      hata: 'bilinmeyen ek uç nokta: ' + ad,
      mevcut: ['pasif', 'cve', 'arsiv', 'urlscan', 'takeover', 'savunma', 'toplu', 'kanit', 'moduller']
    });
  }

  /* ------------------------------------------------------------------ */
  /* 14) UÇ NOKTA YÖNLENDİRİCİ (Python: uclari_isle)                     */
  /* ------------------------------------------------------------------ */
  var MODUL_LISTESI = [
    { kod: 'dns', ad: 'DNS Analizi', aciklama: 'A, AAAA, MX, TXT, NS, SOA, CAA kayıtları + SPF/DMARC denetimi' },
    { kod: 'whois', ad: 'WHOIS / RDAP', aciklama: 'Alan adı tescil bilgileri, kayıtçı, süre, askı durumu' },
    { kod: 'ip', ad: 'IP / ASN Analizi', aciklama: 'Konum, ISS, ASN, ağ bloğu, proxy/hosting göstergesi' },
    { kod: 'subdomain', ad: 'Subdomain Tarama', aciklama: 'Sertifika şeffaflığı + pasif DNS kaynakları' },
    { kod: 'webtek', ad: 'Web Teknolojileri', aciklama: 'Sunucu, CMS, dil, analitik, güvenlik başlıkları, TLS sertifikası' },
    { kod: 'cloud', ad: 'Cloud Keşfi', aciklama: 'S3 / GCS / Azure kova varlık ve açıklık kontrolü' },
    { kod: 'eposta', ad: 'E-posta İstihbaratı', aciklama: 'MX, SPF, tek kullanımlık, rol hesabı, Gravatar izi' },
    { kod: 'kullanici', ad: 'Kullanıcı Adı Arama', aciklama: '25+ platformda hesap varlığı' },
    { kod: 'github', ad: 'GitHub İstihbaratı', aciklama: 'Profil, depolar, diller, commit e-posta sızıntısı' },
    { kod: 'sizinti', ad: 'Veri Sızıntısı Tespiti', aciklama: 'Açık .env/.git/yedek/konfig probu (yumuşak 404 ayıklamalı)' },
    { kod: 'darkweb', ad: 'Dark Web / Sızıntı Kaydı', aciklama: 'HIBP anahtarı ile sızıntı kaydı sorgusu' },
    { kod: 'tehdit', ad: 'Tehdit Haritası', aciklama: 'Botnet C2, phishing ve ele geçirilmiş sistem beslemeleri + konum' }
  ];

  function ayarOku(ayarlar, adlar) {
    var d = {};
    (adlar || []).forEach(function (a) {
      var v = ayarlar ? ayarlar[a] : '';
      if (!v && typeof localStorage !== 'undefined') {
        try { v = localStorage.getItem('osint_' + a) || ''; } catch (e) { v = ''; }
      }
      d[a] = v || null;
    });
    return d;
  }

  /* kopru.js: OSINT_MOTOR.uclariIsle(yol, sorgu, govde, ayarlar) → Promise<veri> */
  function uclariIsle(yol, sorgu, govde, ayarlar) {
    sorgu = sorgu || {};
    govde = govde || {};
    var ay = ayarOku(ayarlar, ['github_anahtar', 'hibp_anahtar']);
    yol = '/' + String(yol || '').replace(/^\/+/, '').replace(/\/+$/, '');

    function g(k, d) {
      var v = sorgu[k];
      if (v === undefined || v === null) v = d === undefined ? '' : d;
      return typeof v === 'string' ? v.trim() : v;
    }
    function bg(k, d) {
      var v = (govde && typeof govde === 'object') ? govde[k] : undefined;
      return (v === undefined || v === null || v === '') ? (d === undefined ? '' : d) : v;
    }

    if (yol === '/api/arac/moduller' || yol === '/api/arac') {
      /* ekler: osint-ek.py modül listesi (Python ek_isle ile aynı alan adı),
         ek2ler: v1.6 araç listesi (osint-ek2a/b/c.py) */
      return Promise.resolve({
        moduller: MODUL_LISTESI, ekler: EK_MODUL_LISTESI,
        ek2ler: EK2_MODUL_LISTESI, surum: SURUM
      });
    }
    /* osint-ek.py ek uç noktaları (pasif, cve, arsiv, urlscan, takeover,
       savunma, toplu, kanit) — Python'da olduğu gibi buraya devredilir */
    if (EK_YOLLARI.indexOf(yol) >= 0) return ekIsle(yol, sorgu, govde);
    /* osint-ek2a/b/c.py (v1.6) uç noktaları: istismar, postaguvenlik,
       baslikanaliz, sertifika, webzafiyet, fidye, saldiriakisi, siravc,
       yerelag, sifrekontrol, raporpaket, bildirim */
    if (EK2_YOLLARI.indexOf(yol) >= 0) return ek2Isle(yol, sorgu, govde, ay);
    if (yol === '/api/arac/dns') {
      var ad1 = alanBul(g('ad') || g('hedef'));
      return ad1 ? dnsToplu(ad1) : Promise.resolve({ hata: 'ad gerekli' });
    }
    if (yol === '/api/arac/whois') return whoisRdap(g('ad') || g('hedef'));
    if (yol === '/api/arac/asn') {
      var hedef = g('ip') || g('ad') || g('hedef');
      var ip = hedef;
      if (ip && !ipMi(ip)) {
        return hedefIpCoz(alanBul(ip)).then(function (cozulen) { return ipAnaliz(cozulen || ip); });
      }
      return ipAnaliz(ip);
    }
    if (yol === '/api/arac/ip') return ipAnaliz(g('ip') || g('ad'));
    if (yol === '/api/arac/subdomain') {
      var ad2 = alanBul(g('ad') || g('hedef'));
      return ad2 ? subdomainTara(ad2) : Promise.resolve({ hata: 'ad gerekli' });
    }
    if (yol === '/api/arac/webtek') return webTek(g('ad') || g('url') || g('hedef'));
    if (yol === '/api/arac/cloud') {
      var ad3 = alanBul(g('ad') || g('hedef'));
      return ad3 ? cloudAra(ad3) : Promise.resolve({ hata: 'ad gerekli' });
    }
    if (yol === '/api/arac/eposta') return epostaIstihbarat(g('ad') || g('adres') || g('hedef'));
    if (yol === '/api/arac/kullanici') return kullaniciAra(g('ad') || g('kullanici'));
    if (yol === '/api/arac/github') return githubIstihbarat(g('ad') || g('kullanici'), ay.github_anahtar);
    if (yol === '/api/arac/sizinti') {
      var hedef2 = g('ad') || g('hedef') || g('url');
      return hedef2 ? sizintiTara(hedef2) : Promise.resolve({ hata: 'hedef gerekli' });
    }
    if (yol === '/api/arac/darkweb') return darkwebAra(g('ad') || g('sorgu'), ay.hibp_anahtar);
    if (yol === '/api/arac/tehdit') return tehditVerisi(!!g('zorla'));
    if (yol === '/api/arac/profil') {
      var hedef3 = bg('hedef') || g('hedef') || g('ad');
      var moduller = bg('moduller') || null;
      if (typeof moduller === 'string') moduller = moduller.split(/[,\s]+/).filter(Boolean);
      return hedef3 ? profilCikar(hedef3, moduller, ay) : Promise.resolve({ hata: 'hedef gerekli' });
    }
    if (yol === '/api/arac/ozet') {
      return tehditVerisi().then(function (t) {
        return {
          modul_sayisi: MODUL_LISTESI.length,
          tehdit: {
            c2: (t && t.c2_toplam) || 0,
            phishing: (t && t.phishing_toplam) || 0,
            ioc: (t && t.ioc_toplam) || 0,
            guncelleme: (t && t.guncelleme) || ''
          },
          siteler: siteler().length
        };
      }, function () {
        return {
          modul_sayisi: MODUL_LISTESI.length,
          tehdit: { c2: 0, phishing: 0, ioc: 0, guncelleme: '' },
          siteler: siteler().length
        };
      });
    }
    return Promise.resolve({ hata: 'bilinmeyen araç uç noktası: ' + yol });
  }

  return {
    SURUM: SURUM,
    /* yardımcılar */
    simdi: simdi, kok: kok, alanBul: alanBul, ozelIp: ozelIp, ipMi: ipMi, md5: md5,
    adCoz: adCoz, hedefIpCoz: hedefIpCoz, _cek: _cek, _json: _json, havuz: havuz,
    kopruVarMi: kopruVarMi, yontemVar: yontemVar,
    /* tablolar (Python ile birebir) */
    DNS_TIPLERI: DNS_TIPLERI, TEK_IMZALARI: TEK_IMZALARI, GUVENLIK_BASLIKLARI: GUVENLIK_BASLIKLARI,
    CLOUD_ONEKLER: CLOUD_ONEKLER, TEK_KULLANIMLIK: TEK_KULLANIMLIK, ROL_HESAPLARI: ROL_HESAPLARI,
    SITE_VARSAYILAN: SITE_VARSAYILAN, SITE_DOSYA: SITE_DOSYA, PROBLAR: PROBLAR, MODUL_LISTESI: MODUL_LISTESI,
    /* modüller */
    dnsSorgu: dnsSorgu, dnsToplu: dnsToplu,
    whoisRdap: whoisRdap, ipAnaliz: ipAnaliz,
    subdomainTara: subdomainTara, webTek: webTek, cloudAra: cloudAra, kovaDene: kovaDene,
    epostaIstihbarat: epostaIstihbarat, kullaniciAra: kullaniciAra,
    githubIstihbarat: githubIstihbarat, sizintiTara: sizintiTara,
    darkwebAra: darkwebAra, tehditVerisi: tehditVerisi, tehditEsles: tehditEsles,
    profilCikar: profilCikar, uclariIsle: uclariIsle, riskPuani: riskPuani,
    /* EK MODÜLLER (osint-ek.py v1.5 karşılığı) */
    pasifRadar: pasifRadar, cveDetay: cveDetay, cveEsle: cveEsle,
    arsivWayback: arsivWayback, urlscanAra: urlscanAra, takeoverTara: takeoverTara,
    cnameZinciri: cnameZinciri, savunmaKurallari: savunmaKurallari,
    topluTarama: topluTarama, kanitEkle: kanitEkle, kanitListesi: kanitListesi,
    ekIsle: ekIsle, ekKok: ekKok, ekIpCoz: ekIpCoz,
    EK_MODUL_LISTESI: EK_MODUL_LISTESI, EK_SURUM: EK_SURUM,
    /* v1.6 YENİ NESİL ARAÇLAR (osint-ek2a/b/c.py karşılığı) */
    istismarSorgu: istismarSorgu, postaGuvenlik: postaGuvenlik, baslikAnaliz: baslikAnaliz,
    sertifikaAltAlanlar: sertifikaAltAlanlar, webZafiyet: webZafiyet, fidyeIzleme: fidyeIzleme,
    saldiriAkisi: saldiriAkisi, sirAvcisi: sirAvcisi, yerelAg: yerelAg,
    sifreKontrol: sifreKontrol, raporPaket: raporPaket, bildirimIsle: bildirimIsle,
    bildirimOlayEkle: bildirimOlayEkle, ek2Isle: ek2Isle,
    EK2_MODUL_LISTESI: EK2_MODUL_LISTESI, EK2_YOLLARI: EK2_YOLLARI, EK2_SURUM: EK2_SURUM,
    ek2Onbellekli: ek2Onbellekli, ek2Doh: ek2Doh, ek2OzelIp: ek2OzelIp,
    sha1Hex: sha1Hex, ek2Sade: ek2Sade, ek2IzlemeListesi: ek2IzlemeListesi,
    /* python adlarıyla birebir takma adlar (v1.6) */
    istismar_sorgu: istismarSorgu, posta_guvenlik: postaGuvenlik, baslik_analiz: baslikAnaliz,
    sertifika_alt_alanlar: sertifikaAltAlanlar, web_zafiyet: webZafiyet, fidye_izleme: fidyeIzleme,
    saldiriakisi: saldiriAkisi, siravc: sirAvcisi, yerelag: yerelAg,
    sifrekontrol: sifreKontrol, raporpaket: raporPaket, bildirim: bildirimIsle,
    ek2_isle: ek2Isle, ek2a_isle: ek2Isle, ek2b_isle: ek2Isle, ek2c_isle: ek2Isle,
    TAKEOVER_IMIZALARI: TAKEOVER_IMIZALARI, TAKEOVER_CHAIN: TAKEOVER_CHAIN,
    EK_ONBELLEK: EK_ONBELLEK, pyJson: pyJson, sha256Hex: sha256Hex,
    _ps1Uret: _ps1Uret, _ps1Geri: _ps1Geri,
    /* Python adlarıyla birebir takma adlar */
    dns_sorgu: dnsSorgu, dns_toplu: dnsToplu, whois_rdap: whoisRdap, ip_analiz: ipAnaliz,
    subdomain_tara: subdomainTara, web_tek: webTek, cloud_ara: cloudAra,
    eposta_istihbarat: epostaIstihbarat, kullanici_ara: kullaniciAra,
    github_istihbarat: githubIstihbarat, sizinti_tara: sizintiTara,
    darkweb_ara: darkwebAra, tehdit_verisi: tehditVerisi, profil_cikar: profilCikar,
    uclari_isle: uclariIsle,
    /* osint-ek.py fonksiyon adlarıyla birebir takma adlar */
    pasif_radar: pasifRadar, cve_detay: cveDetay, cve_esle: cveEsle,
    arsiv_wayback: arsivWayback, urlscan_ara: urlscanAra, takeover_tara: takeoverTara,
    cname_zinciri: cnameZinciri, savunma_kurallari: savunmaKurallari,
    toplu_tarama: topluTarama, kanit_ekle: kanitEkle, kanit_listesi: kanitListesi,
    ek_isle: ekIsle
  };
})();

if (typeof window !== 'undefined') window.OSINT_MOTOR = OSINT_MOTOR;
if (typeof module !== 'undefined' && module.exports) module.exports = OSINT_MOTOR;
