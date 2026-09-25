/* ==========================================================================
   ÜSTAD OSINT v1.5 — EK ARAÇLAR
   Pasif Radar · CVE Eşleştirme · Arşiv/URLScan · Subdomain Takeover ·
   Savunma Duvarı · Toplu Tarama · Mini Terminal · Kanıt Zinciri · Sesli özet
   Aynı arayüz PC (Python köprüsü) ve APK (JS motoru) üzerinde çalışır.
   ========================================================================== */
var Ek = (function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var sonSavunma = null, sonOzet = '', gecmis = [], gecmisNo = -1;

  function kac(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function sayi(n) { return (n == null ? 0 : n).toLocaleString('tr-TR'); }
  function api(yol, secenek) { return OS.api(yol, secenek); }
  function yaz(kapId, html) { var k = $(kapId); if (k) k.innerHTML = html; }
  function durum(id, m) { var k = $(id); if (k) k.textContent = m || ''; }
  function iskelet(kapId, y) { yaz(kapId, '<div class="osIskelet">' + kac(y || 'çalışıyor…') + '</div>'); }
  function hata(kapId, m) { yaz(kapId, '<div class="osIskelet" style="color:#ff5470">⚠ ' + kac(m) + '</div>'); }
  function balon(m, t) { if (OS.balon) OS.balon(m, t); }

  function indir(ad, icerik, tip) {
    try {
      var b = new Blob([icerik], { type: tip || 'text/plain;charset=utf-8' });
      var u = URL.createObjectURL(b);
      var a = document.createElement('a');
      a.href = u; a.download = ad; document.body.appendChild(a); a.click();
      setTimeout(function () { document.body.removeChild(a); URL.revokeObjectURL(u); }, 900);
      balon('⬇ <b>' + kac(ad) + '</b> indirildi', 'iyi');
    } catch (e) { balon('⚠ indirme hatası: ' + kac(e.message), 'kotu'); }
  }

  var TEHLIKE_PORT = [21, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017];

  /* ============================== SÖZLÜK ============================== */
  var PORT_ADI = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
    135: 'MS-RPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 587: 'SMTP-Sub',
    993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
    5432: 'Postgres', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    9200: 'Elastic', 11211: 'Memcached', 27017: 'MongoDB', 21: 'FTP'
  };

  /* ============================== 1) PASİF RADAR ============================== */
  function pasifTara(zorla) {
    var h = ($('pasifGirdi') || {}).value;
    h = (h || '').trim();
    if (!h) { balon('⚠ Hedef yaz (ör. ornek.com · 1.1.1.1)', 'kotu'); return; }
    iskelet('pasifSonuc', 'pasif taranıyor… (hedefe istek gitmez)');
    durum('pasifDurum', 'sorgulanıyor…');
    api('/api/arac/pasif?ad=' + encodeURIComponent(h) + (zorla ? '&zorla=1' : '')).then(function (d) {
      durum('pasifDurum', d && d.onbellek ? 'önbellekten geldi' : 'tamamlandı');
      if (!d || d.hata) { hata('pasifSonuc', (d && d.hata) || 'yanıt yok'); return; }
      cizPasif(d);
      sonOzet = 'Pasif radar: ' + d.hedef + ' · ' + (d.ip || []).join(', ') + ' · ' + sayi(d.port_sayisi) +
        ' port · ' + sayi(d.cve_sayisi) + ' zafiyet kaydı' + (d.kritik ? ' (' + d.kritik + ' kritik)' : '');
      balon('🛰️ <b>' + kac(d.hedef) + '</b>: ' + sayi(d.port_sayisi) + ' port · ' + sayi(d.cve_sayisi) + ' CVE', d.kritik ? 'kotu' : 'iyi');
    }).catch(function (e) { durum('pasifDurum', 'hata'); hata('pasifSonuc', e.message); });
  }

  function cizPasif(d) {
    var h = '';
    h += '<div class="ekAnahtar"><b>Hedef</b><span>' + kac(d.hedef) + '</span></div>';
    h += '<div class="ekAnahtar"><b>IP adresleri</b><span>' + ((d.ip || []).map(kac).join(' · ') || '—') + '</span></div>';
    if (d.hostname && d.hostname.length) h += '<div class="ekAnahtar"><b>InternetDB host adı</b><span>' + d.hostname.map(kac).join(' · ') + '</span></div>';
    h += '<div class="ekAnahtar"><b>Dışarıdan görünen port sayısı</b><span>' + sayi(d.port_sayisi) + '</span></div>';
    h += '<div style="margin:8px 0 12px">' + ((d.portlar || []).map(function (p) {
      var t = TEHLIKE_PORT.indexOf(Number(p)) >= 0;
      return '<span class="ekPort' + (t ? ' tehlike' : '') + '" title="' + kac(PORT_ADI[Number(p)] || 'bilinmiyor') + '">' + kac(p) + '</span>';
    }).join('') || '<span class="osIskelet">port kaydı yok</span>') + '</div>';
    if ((d.cpe || []).length) {
      h += '<div class="ekAnahtar"><b>Teknolojiler (CPE)</b><span>' + d.cpe.slice(0, 12).map(kac).join(' · ') + '</span></div>';
    }
    h += '<div style="margin-top:12px"><b style="color:#ff8f8f">Bilinen zafiyetler (' + sayi(d.cve_sayisi) + ')</b></div>';
    if (!(d.cveler || []).length) {
      h += '<div class="osIskelet" style="margin-top:6px">Bu IP için kayıtlı CVE yok (iyi haber).</div>';
    } else {
      h += (d.cveler || []).slice(0, 12).map(function (c) {
        var s = c.skor;
        var sinif = (s >= 9) ? 'kritik' : (s >= 7 ? 'yuksek' : 'orta');
        return '<div class="ekCve" style="border-left-color:' + (s >= 9 ? '#ff5d5d' : s >= 7 ? '#ffb400' : '#4da3ff') + '">' +
          (s != null ? '<span class="ekRisk ' + sinif + ' skor">CVSS ' + s + '</span>' : '') +
          '<span class="id">' + kac(c.id) + '</span>' +
          '<span class="ozet">' + kac(c.ozet || c.baslik || '') + '</span>' +
          '<span class="ozet" style="opacity:.65;font-size:.78rem">kaynak: ' + kac(c.kaynak || 'MITRE') + (c.tarih ? ' · ' + kac(c.tarih) : '') + '</span>' +
          '</div>';
      }).join('');
    }
    if ((d.kayitlar || []).some(function (k) { return k.not; })) {
      h += '<div class="osIskelet" style="margin-top:8px">Not: ' + (d.kayitlar.filter(function (k) { return k.not; })[0].not) + '</div>';
    }
    h += '<div class="ekAnahtar" style="margin-top:10px"><b>Kaynak</b><span>' + kac(d.kaynak) + '</span></div>';
    h += '<div class="osIskelet" style="margin-top:6px">' + kac(d.uyari || '') + ' · ' + kac(d.guncelleme || '') + '</div>';
    yaz('pasifSonuc', h);
    durum('pasifOzet', sayi(d.port_sayisi) + ' port · ' + sayi(d.cve_sayisi) + ' CVE');
  }

  /* ============================== 2) CVE EŞLEŞTİRME ============================== */
  function cveEsle() {
    var t = (($('cveGirdi') || {}).value || '').trim();
    var s = (($('cveSurum') || {}).value || '').trim();
    if (!t) { balon('⚠ Ürün adı yaz (ör. nginx)', 'kotu'); return; }
    iskelet('cveSonuc', 'NVD sorgulanıyor…');
    durum('cveDurum', 'sorgulanıyor…');
    api('/api/arac/cve?tek=' + encodeURIComponent(t) + '&surum=' + encodeURIComponent(s)).then(function (d) {
      durum('cveDurum', 'tamamlandı');
      if (!d || d.hata) { hata('cveSonuc', (d && d.hata) || 'yanıt yok'); return; }
      cizCve(d); sonOzet = 'CVE eşleştirme ' + d.teknoloji + ' ' + (d.surum || '') + ': ' + sayi(d.toplam_bulunan) + ' kayıt';
      balon('🧨 <b>' + kac(d.teknoloji) + '</b>: ' + sayi(d.toplam_bulunan) + ' kayıt', 'iyi');
    }).catch(function (e) { durum('cveDurum', 'hata'); hata('cveSonuc', e.message); });
  }

  function cizCve(d) {
    var h = '<div class="ekAnahtar"><b>Ürün</b><span>' + kac(d.teknoloji) + (d.surum ? ' ' + kac(d.surum) : '') + '</span></div>';
    h += '<div class="ekAnahtar"><b>NVD toplam kayıt</b><span>' + sayi(d.toplam_bulunan) + '</span></div>';
    h += '<div class="ekAnahtar"><b>Açıklamada sürümü geçen</b><span>' + sayi(d.surum_eslesen) + '</span></div>';
    h += '<div style="margin-top:10px">' + (d.kayitlar || []).map(function (c) {
      var sinif = (c.skor >= 9) ? 'kritik' : (c.skor >= 7 ? 'yuksek' : 'orta');
      return '<div class="ekCve" style="border-left-color:' + (c.surum_geciyor ? '#ff5d5d' : 'rgba(120,200,255,.4)') + '">' +
        (c.skor != null ? '<span class="ekRisk ' + sinif + ' skor">CVSS ' + c.skor + '</span>' : '') +
        '<span class="id">' + kac(c.id) + '</span>' +
        (c.surum_geciyor ? ' <span class="ekRozet yuksek">sürüm geçiyor</span>' : ' <span class="ekRozet bilgi">olası</span>') +
        '<span class="ozet">' + kac(c.ozet || '') + '</span>' +
        '<span class="ozet" style="opacity:.6;font-size:.78rem">' + kac(c.yayin || '') + ' · <a href="' + kac(c.url) + '" target="_blank" rel="noopener" style="color:#4da3ff">CVE kaydı</a></span>' +
        '</div>';
    }).join('') + '</div>';
    h += '<div class="osIskelet" style="margin-top:6px">' + kac(d.uyari || '') + ' · ' + kac(d.ornek || '') + '</div>';
    yaz('cveSonuc', h);
    durum('cveOzet', sayi(d.toplam_bulunan) + ' kayıt · ' + sayi(d.surum_eslesen) + ' sürüm eşleşmesi');
  }

  /* ============================== 3) ARŞİV + URLSCAN ============================== */
  function arsivAc() {
    var h = (($('arsivGirdi') || {}).value || '').trim();
    if (!h) { balon('⚠ Hedef yaz (ör. example.com)', 'kotu'); return; }
    iskelet('arsivSonuc', 'Wayback sorgulanıyor…');
    iskelet('urlscanSonuc', 'urlscan.io sorgulanıyor…');
    durum('arsivDurum', 'sorgulanıyor…');
    api('/api/arac/arsiv?ad=' + encodeURIComponent(h)).then(function (d) {
      if (!d || d.hata) { hata('arsivSonuc', (d && d.hata) || 'yanıt yok'); return; }
      cizArsiv(d);
    }).catch(function (e) { hata('arsivSonuc', e.message); });
    api('/api/arac/urlscan?ad=' + encodeURIComponent(h)).then(function (d) {
      durum('arsivDurum', 'tamamlandı');
      if (!d || d.hata) { hata('urlscanSonuc', (d && d.hata) || 'yanıt yok'); return; }
      cizUrlscan(d);
      sonOzet = 'Arşiv: ' + d.hedef + ' · ' + sayi((d.kayitlar || []).length) + ' urlscan kaydı';
    }).catch(function (e) { hata('urlscanSonuc', e.message); });
  }

  function tarihYaz(t) {
    t = String(t || '');
    if (t.length < 8) return kac(t);
    return t.slice(6, 8) + '.' + t.slice(4, 6) + '.' + t.slice(0, 4);
  }

  function cizArsiv(d) {
    var h = '<div class="ekAnahtar"><b>Toplam arşiv kaydı</b><span>' + sayi(d.toplam_kayit) + '</span></div>';
    h += '<div class="ekAnahtar"><b>İlk kayıt</b><span>' + tarihYaz(d.ilk_kayit) + '</span></div>';
    h += '<div class="ekAnahtar"><b>Son kayıt</b><span>' + tarihYaz(d.son_kayit) + '</span></div>';
    var yil = Object.keys(d.yillar || {});
    if (yil.length) {
      h += '<div style="margin:8px 0"><b style="color:#8fb4d0;font-size:.8rem">YILLARA GÖRE</b><br>' +
        yil.slice(-14).map(function (y) { return '<span class="ekRozet bilgi">' + kac(y) + ': ' + sayi(d.yillar[y]) + '</span>'; }).join('') + '</div>';
    }
    if ((d.eski_yollar || []).length) {
      h += '<div style="margin-top:8px"><b style="color:#8fb4d0;font-size:.8rem">ESKİ / SİLİNMİŞ YOLLAR</b><ul class="ekSirali">' +
        d.eski_yollar.map(function (y) { return '<li><code>' + kac(y[0]) + '</code> <span style="opacity:.6">(' + sayi(y[1]) + ' kayıt)</span></li>'; }).join('') + '</ul></div>';
    }
    if ((d.dis_hostlar || []).length) {
      h += '<div style="margin-top:8px"><b style="color:#8fb4d0;font-size:.8rem">HEDEF DIŞI ESKİ HOSTLAR</b><br>' +
        d.dis_hostlar.map(function (x) { return '<span class="ekRozet orta">' + kac(x) + '</span>'; }).join('') + '</div>';
    }
    if (!d.toplam_kayit) h += '<div class="osIskelet">Bu alan adı için arşiv kaydı bulunamadı.</div>';
    h += '<div class="osIskelet" style="margin-top:8px">' + kac(d.ornek || '') + '</div>';
    yaz('arsivSonuc', h);
    durum('arsivOzet', sayi(d.toplam_kayit) + ' kayıt · ' + tarihYaz(d.ilk_kayit) + ' → ' + tarihYaz(d.son_kayit));
  }

  function cizUrlscan(d) {
    if (!(d.kayitlar || []).length) {
      yaz('urlscanSonuc', '<div class="osIskelet">Bu alan adı için urlscan.io kaydı yok. ' + kac(d.ornek || '') + '</div>');
      durum('urlscanOzet', '0 kayıt'); return;
    }
    var h = '<table class="ekTablo"><thead><tr><th>Zaman</th><th>URL</th><th>IP / Sunucu</th><th>Bağlantı</th></tr></thead><tbody>';
    h += d.kayitlar.map(function (k) {
      return '<tr><td>' + kac(k.zaman || '') + '</td>' +
        '<td><code>' + kac((k.url || '').slice(0, 60)) + '</code></td>' +
        '<td>' + kac(k.ip || '—') + '<br><span style="opacity:.6">' + kac(k.sunucu || '') + ' ' + kac(k.ulke || '') + '</span></td>' +
        '<td>' + (k.sonuc ? '<a class="ekRozet iyi" href="' + kac(k.sonuc) + '" target="_blank" rel="noopener">sonuç</a>' : '') +
        (k.ekran ? '<a class="ekRozet bilgi" href="' + kac(k.ekran) + '" target="_blank" rel="noopener">ekran</a>' : '') +
        (k.malzeme ? '<a class="ekRozet orta" href="' + kac(k.malzeme) + '" target="_blank" rel="noopener">DOM</a>' : '') + '</td></tr>';
    }).join('') + '</tbody></table>';
    h += '<div class="osIskelet" style="margin-top:8px">' + kac(d.ornek || '') + '</div>';
    yaz('urlscanSonuc', h);
    durum('urlscanOzet', sayi((d.kayitlar || []).length) + ' tarama');
  }

  /* ============================== 4) TAKEOVER ============================== */
  function takeoverTara() {
    var h = (($('takeoverGirdi') || {}).value || '').trim();
    if (!h) { balon('⚠ Hedef yaz (ör. ornek.com)', 'kotu'); return; }
    iskelet('takeoverSonuc', 'alt alanlar ve CNAME zincirleri çözülüyor…');
    durum('takeoverDurum', 'taranıyor…');
    api('/api/arac/takeover?ad=' + encodeURIComponent(h)).then(function (d) {
      durum('takeoverDurum', 'tamamlandı');
      if (!d || d.hata) { hata('takeoverSonuc', (d && d.hata) || 'yanıt yok'); return; }
      cizTakeover(d);
      sonOzet = 'Takeover taraması ' + d.hedef + ': ' + sayi(d.denenen) + ' alt alan, ' + sayi(d.supheli) + ' şüpheli';
      balon('🧲 <b>' + kac(d.hedef) + '</b>: ' + sayi(d.denenen) + ' alt alan · ' + sayi(d.supheli) + ' şüpheli', d.supheli ? 'kotu' : 'iyi');
    }).catch(function (e) { durum('takeoverDurum', 'hata'); hata('takeoverSonuc', e.message); });
  }

  function cizTakeover(d) {
    var h = '<div class="ekAnahtar"><b>Bulunan alt alan</b><span>' + sayi(d.subdomain_sayisi || d.denenen) + '</span></div>';
    h += '<div class="ekAnahtar"><b>CNAME çözülen / denenen</b><span>' + sayi(d.denenen) + '</span></div>';
    h += '<div class="ekAnahtar"><b>Şüpheli (sahipsiz servise bakan)</b><span>' + sayi(d.supheli) + '</span></div>';
    if (!(d.kayitlar || []).length) {
      h += '<div class="osIskelet" style="margin-top:8px">Şüpheli CNAME bulunamadı. ' + kac(d.ornek || '') + '</div>';
      h += '<div style="margin-top:8px"><b style="color:#8fb4d0;font-size:.8rem">ÇÖZÜLEN CNAME ZİNCİRLERİ</b><ul class="ekSirali">' +
        (d.cname_zincirleri || []).slice(0, 15).map(function (c) {
          return '<li><code>' + kac(c.ad) + '</code> → ' + kac(c.cname) + ' <span class="ekRozet bilgi">' + kac(c.servis) + '</span></li>';
        }).join('') + '</ul></div>';
    } else {
      h += '<table class="ekTablo" style="margin-top:8px"><thead><tr><th>Alt alan</th><th>CNAME</th><th>Servis</th><th>Durum</th><th>Risk</th></tr></thead><tbody>';
      h += d.kayitlar.map(function (k) {
        return '<tr><td><code>' + kac(k.ad) + '</code></td><td><code>' + kac(k.cname) + '</code></td>' +
          '<td>' + kac(k.servis) + '</td>' +
          '<td>' + kac(k.durum_kodu) + (k.imza_bulundu ? '<br><span style="color:#ff8f8f;font-size:.78rem">' + kac(k.imza) + '</span>' : '') + '</td>' +
          '<td><span class="ekRisk ' + kac(k.risk) + '">' + kac(k.risk) + '</span></td></tr>';
      }).join('') + '</tbody></table>';
    }
    h += '<div class="osIskelet" style="margin-top:8px">' + kac(d.ornek || '') + '</div>';
    yaz('takeoverSonuc', h);
    durum('takeoverOzet', sayi(d.denenen) + ' alt alan · ' + sayi(d.supheli) + ' şüpheli');
  }

  /* ============================== 5) SAVUNMA DUVARI ============================== */
  function savunmaUret() {
    iskelet('savunmaSonuc', 'tehdit beslemeleri toplanıyor…');
    durum('savunmaDurum', 'çalışıyor…');
    api('/api/arac/savunma').then(function (d) {
      durum('savunmaDurum', 'tamamlandı');
      if (!d || d.hata) { hata('savunmaSonuc', (d && d.hata) || 'yanıt yok'); return; }
      sonSavunma = d;
      cizSavunma(d);
      if ($('savunmaIndir')) $('savunmaIndir').disabled = false;
      if ($('savunmaGeri')) $('savunmaGeri').disabled = false;
      sonOzet = 'Savunma duvarı: ' + sayi(d.ip_sayisi) + ' zararlı IP engellenmeye hazır';
      balon('🛡️ <b>' + sayi(d.ip_sayisi) + '</b> zararlı IP listesi hazır', 'iyi');
    }).catch(function (e) { durum('savunmaDurum', 'hata'); hata('savunmaSonuc', e.message); });
  }

  function cizSavunma(d) {
    var h = '<div class="ekAnahtar"><b>Engellenecek zararlı IP</b><span>' + sayi(d.ip_sayisi) + '</span></div>';
    h += '<div class="ekAnahtar"><b>Betik dosyası</b><span>' + kac(d.dosya_adi) + '</span></div>';
    h += '<div style="margin:8px 0"><b style="color:#8fb4d0;font-size:.8rem">KAYNAKLAR</b><br>' +
      (d.kaynaklar || []).map(function (k) { return '<span class="ekRozet bilgi">' + kac(k.ad) + ': ' + sayi(k.sayi) + '</span>'; }).join('') + '</div>';
    h += '<div class="osIskelet">İlk IP\'ler: ' + (d.ipler || []).slice(0, 12).map(kac).join(', ') + ' …</div>';
    h += '<div class="osIskelet" style="margin-top:8px">' + kac(d.ornek || '') + '</div>';
    yaz('savunmaSonuc', h);
    durum('savunmaOzet', sayi(d.ip_sayisi) + ' IP · ' + kac(d.dosya_adi));
  }

  function savunmaIndir() {
    if (!sonSavunma) return;
    indir(sonSavunma.dosya_adi, sonSavunma.ps1);
  }
  function savunmaGeriIndir() {
    if (!sonSavunma) return;
    indir('ustad-osint-duvar-geri.ps1', sonSavunma.geri_alma);
  }

  /* ============================== 6) TOPLU TARAMA ============================== */
  function topluTara() {
    var t = (($('topluGirdi') || {}).value || '').trim();
    if (!t) { balon('⚠ En az bir alan adı yaz', 'kotu'); return; }
    var liste = t.split(/[\s,;]+/).filter(Boolean);
    iskelet('topluSonuc', sayi(liste.length) + ' hedef taranıyor… (sırayla, biraz sürebilir)');
    durum('topluDurum', 'çalışıyor…');
    api('/api/arac/toplu', { yol: 'POST', govde: { hedefler: liste } }).then(function (d) {
      durum('topluDurum', 'tamamlandı');
      if (!d || d.hata) { hata('topluSonuc', (d && d.hata) || 'yanıt yok'); return; }
      cizToplu(d);
      balon('🗃️ <b>' + sayi(d.adet) + '</b> hedef tarandı', 'iyi');
    }).catch(function (e) { durum('topluDurum', 'hata'); hata('topluSonuc', e.message); });
  }

  function cizToplu(d) {
    var h = '<table class="ekTablo"><thead><tr><th>#</th><th>Hedef</th><th>Risk</th><th>Bulgu</th><th>Alt alan</th><th>Cloud</th></tr></thead><tbody>';
    (d.kayitlar || []).forEach(function (k, i) {
      var r = k.risk == null || k.risk < 0 ? '—' : k.risk;
      var sinif = (k.risk >= 60) ? 'kritik' : (k.risk >= 35 ? 'orta' : 'iyi');
      h += '<tr><td>' + (i + 1) + '</td><td><code>' + kac(k.hedef) + '</code></td>' +
        '<td><span class="ekRisk ' + sinif + '">' + kac(r) + '</span>/100</td>' +
        '<td>' + sayi(k.bulgu) + (k.ilk_bulgular && k.ilk_bulgular.length ? '<br><span style="opacity:.65;font-size:.78rem">' + k.ilk_bulgular.map(kac).join(' · ') + '</span>' : '') + '</td>' +
        '<td>' + sayi((k.sayilar || {}).subdomain) + '</td><td>' + sayi((k.sayilar || {}).cloud) + '</td></tr>';
    }).join('') + '</tbody></table>';
    h += '<div class="osIskelet" style="margin-top:8px">' + kac(d.ornek || '') + ' · ' + kac(d.guncelleme || '') + '</div>';
    yaz('topluSonuc', h);
    durum('topluOzet', sayi(d.adet) + ' hedef · en yüksek risk: ' + sayi((d.kayitlar || [])[0] ? (d.kayitlar[0].risk || 0) : 0) + '/100');
    sonOzet = 'Toplu tarama: ' + sayi(d.adet) + ' hedef tamamlandı';
  }

  /* ============================== 7) MİNİ TERMİNAL ============================== */
  function termYaz(metin, sinif) {
    var k = $('termCikti'); if (!k) return;
    var d = document.createElement('div');
    d.className = 'ekTermSatir' + (sinif ? ' ' + sinif : '');
    d.innerHTML = metin;
    k.appendChild(d);
    k.scrollTop = k.scrollHeight;
  }

  function termTemizle() { var k = $('termCikti'); if (k) k.innerHTML = ''; }

  function termCalistir() {
    var g = $('termGirdi'); if (!g) return;
    var satir = (g.value || '').trim();
    if (!satir) return;
    g.value = '';
    gecmis.push(satir); gecmisNo = gecmis.length;
    termYaz('<span class="ekTermImlec">ustad@osint:~$</span> ' + kac(satir), 'ekKomut');
    komut(satir);
  }

  function kisaYaz(baslik, degerler) {
    termYaz('<b>' + kac(baslik) + '</b>', 'ekUyari');
    (degerler || []).forEach(function (d) { termYaz('  • ' + d); });
  }

  function komut(satir) {
    var p = satir.split(/\s+/);
    var c = (p[0] || '').toLowerCase(), a = p[1] || '', b = p[2] || '';
    if (!c) return;

    if (c === 'yardım' || c === 'yardim' || c === 'help' || c === '?') {
      kisaYaz('Komutlar', [
        '<b>scan</b> &lt;hedef&gt; — tam profil (DNS, WHOIS, alt alan, web teknolojisi…)',
        '<b>dns</b> &lt;ad&gt; · <b>whois</b> &lt;ad&gt; · <b>ip</b> &lt;ad|IP&gt; · <b>sub</b> &lt;ad&gt;',
        '<b>kullanici</b> &lt;ad&gt; — platformlarda hesap araması',
        '<b>pasif</b> &lt;hedef&gt; — dokunmadan port + CVE',
        '<b>cve</b> &lt;ürün&gt; [sürüm] — zafiyet eşleştirme',
        '<b>arsiv</b> &lt;ad&gt; · <b>urlscan</b> &lt;ad&gt;',
        '<b>takeover</b> &lt;ad&gt; · <b>savunma</b> · <b>toplu</b> &lt;ad1&gt; &lt;ad2&gt; …',
        '<b>leak</b> &lt;e-posta&gt; · <b>tehdit</b> · <b>kanit</b> · <b>temizle</b> · <b>ses</b>',
        'İpucu: ↑ / ↓ tuşlarıyla geçmiş komutlara dön.'
      ]);
      return;
    }
    if (c === 'temizle' || c === 'cls' || c === 'clear') { termTemizle(); return; }
    if (c === 'ses' || c === 'konus') { sesliOzet(); return; }

    if (c === 'kanit') {
      api('/api/arac/kanit').then(function (d) {
        if (!d || d.hata) { termYaz('hata: ' + kac((d && d.hata) || 'yanıt yok'), 'ekHata'); return; }
        kisaYaz('Kanıt zinciri (' + sayi(d.toplam) + ' kayıt)', (d.zincir || []).slice(0, 8).map(function (z) {
          return '#' + z.zincir_no + ' ' + kac(z.hedef || '—') + ' · ' + kac(z.sha256.slice(0, 16)) + '… · ' + kac(z.zaman);
        }));
      });
      return;
    }
    if (c === 'tehdit') {
      api('/api/arac/tehdit').then(function (d) {
        if (!d || d.hata) { termYaz('hata: ' + kac((d && d.hata) || 'yanıt yok'), 'ekHata'); return; }
        kisaYaz('Tehdit beslemeleri', ['C2: ' + sayi(d.c2_toplam), 'Phishing: ' + sayi(d.phishing_toplam),
          'IOC: ' + sayi(d.ioc_toplam), 'Konum: ' + sayi((d.konumlar || []).length), 'Güncelleme: ' + kac(d.guncelleme || '')]);
      });
      return;
    }
    if (c === 'savunma') { termYaz('savunma betiği hazırlanıyor…', 'ekBilgi'); savunmaUret(); return; }

    if (c === 'toplu') {
      var hedefler = p.slice(1);
      if (!hedefler.length) { termYaz('kullanım: toplu ornek.com site2.com', 'ekUyari'); return; }
      termYaz(sayi(hedefler.length) + ' hedef taranıyor…', 'ekBilgi');
      api('/api/arac/toplu', { yol: 'POST', govde: { hedefler: hedefler } }).then(function (d) {
        if (!d || d.hata) { termYaz('hata: ' + kac((d && d.hata) || 'yanıt yok'), 'ekHata'); return; }
        kisaYaz('Toplu tarama', (d.kayitlar || []).map(function (k) {
          return kac(k.hedef) + ' → risk ' + kac(k.risk) + '/100 · ' + sayi(k.bulgu) + ' bulgu';
        }));
      });
      return;
    }

    if (!a) { termYaz('kullanım: ' + kac(c) + ' <hedef>  ·  "yardım" yaz', 'ekUyari'); return; }

    var yollar = {
      scan: '/api/arac/profil', dns: '/api/arac/dns', whois: '/api/arac/whois',
      ip: '/api/arac/ip', sub: '/api/arac/subdomain', subdomain: '/api/arac/subdomain',
      kullanici: '/api/arac/kullanici', leak: '/api/arac/eposta', eposta: '/api/arac/eposta',
      pasif: '/api/arac/pasif', arsiv: '/api/arac/arsiv', urlscan: '/api/arac/urlscan',
      takeover: '/api/arac/takeover', webtek: '/api/arac/webtek', cloud: '/api/arac/cloud',
      sizinti: '/api/arac/sizinti'
    };
    if (c === 'cve') {
      termYaz('NVD sorgulanıyor…', 'ekBilgi');
      api('/api/arac/cve?tek=' + encodeURIComponent(a) + '&surum=' + encodeURIComponent(b)).then(function (d) {
        if (!d || d.hata) { termYaz('hata: ' + kac((d && d.hata) || 'yanıt yok'), 'ekHata'); return; }
        kisaYaz('CVE: ' + d.teknoloji + ' ' + (d.surum || '') + ' (' + sayi(d.toplam_bulunan) + ' kayıt)',
          (d.kayitlar || []).slice(0, 6).map(function (x) {
            return kac(x.id) + ' · CVSS ' + kac(x.skor == null ? '?' : x.skor) + (x.surum_geciyor ? ' <span class="ekRozet yuksek">sürüm geçiyor</span>' : '') + ' — ' + kac((x.ozet || '').slice(0, 90));
          }));
      });
      return;
    }
    if (!yollar[c]) { termYaz('bilinmeyen komut: ' + kac(c) + ' — "yardım" yaz', 'ekHata'); return; }

    termYaz('çalışıyor: ' + kac(c) + ' ' + kac(a) + ' …', 'ekBilgi');
    var sec = (c === 'scan') ? { yol: 'POST', govde: { hedef: a } } : null;
    var url = sec ? yollar[c] : (yollar[c] + '?ad=' + encodeURIComponent(a) + '&hedef=' + encodeURIComponent(a) + '&ip=' + encodeURIComponent(a));
    api(url, sec).then(function (d) {
      if (!d || d.hata) { termYaz('hata: ' + kac((d && d.hata) || 'yanıt yok'), 'ekHata'); return; }
      if (c === 'scan') {
        kisaYaz('Profil: ' + kac(d.hedef) + ' · risk ' + sayi(d.risk) + '/100', (d.bulgular || []).slice(0, 6).map(function (x) {
          return '[' + kac((x.onem || '').toUpperCase()) + '] ' + kac(x.baslik || '');
        }).concat(['Sayılar: ' + JSON.stringify(d.sayilar || {})]));
        return;
      }
      if (c === 'dns') {
        var kayit = d.kayitlar || d.sonuclar || {};
        kisaYaz('DNS: ' + kac(a), Object.keys(kayit).slice(0, 12).map(function (t) {
          var v = kayit[t], degerler = [];
          if (v && typeof v === 'object' && !Array.isArray(v)) {
            degerler = (v.kayitlar || []).map(function (x) { return x.deger != null ? x.deger : (x.data || ''); });
          } else if (Array.isArray(v)) {
            degerler = v.map(function (x) { return (x && typeof x === 'object') ? (x.deger != null ? x.deger : JSON.stringify(x)) : x; });
          } else { degerler = [v]; }
          degerler = degerler.filter(function (x) { return String(x || '').length; });
          return kac(t) + ': ' + (degerler.slice(0, 4).map(kac).join(', ') || 'kayıt yok');
        }));
        return;
      }
      if (c === 'whois') {
        kisaYaz('WHOIS: ' + kac(a), Object.keys(d).slice(0, 12).map(function (t) {
          var v = d[t]; if (v && typeof v === 'object') v = Array.isArray(v) ? v.join(', ') : JSON.stringify(v);
          return kac(t) + ': ' + kac(String(v).slice(0, 120));
        }));
        return;
      }
      if (c === 'pasif') {
        kisaYaz('Pasif radar: ' + kac(d.hedef) + ' · ' + sayi(d.cve_sayisi) + ' CVE',
          ['IP: ' + (d.ip || []).join(', '), 'Portlar: ' + (d.portlar || []).join(', '),
           'Kritik: ' + sayi(d.kritik)].concat((d.cveler || []).slice(0, 5).map(function (x) {
            return kac(x.id) + ' · CVSS ' + kac(x.skor == null ? '?' : x.skor) + ' — ' + kac((x.ozet || '').slice(0, 80));
          })));
        return;
      }
      if (c === 'arsiv') {
        kisaYaz('Arşiv: ' + kac(d.hedef), ['Toplam kayıt: ' + sayi(d.toplam_kayit),
          'İlk: ' + tarihYaz(d.ilk_kayit), 'Son: ' + tarihYaz(d.son_kayit),
          'Eski yollar: ' + (d.eski_yollar || []).slice(0, 6).map(function (y) { return kac(y[0]); }).join(', ')]);
        return;
      }
      if (c === 'urlscan') {
        kisaYaz('urlscan: ' + sayi((d.kayitlar || []).length) + ' tarama', (d.kayitlar || []).slice(0, 6).map(function (x) {
          return kac(x.zaman) + ' · ' + kac(x.ip || '') + ' · ' + kac(x.sonuc || '');
        }));
        return;
      }
      if (c === 'takeover') {
        kisaYaz('Takeover: ' + kac(d.hedef) + ' · ' + sayi(d.supheli) + ' şüpheli', (d.kayitlar || []).slice(0, 8).map(function (x) {
          return kac(x.ad) + ' → ' + kac(x.cname) + ' · ' + kac(x.risk);
        }));
        return;
      }
      if (c === 'kullanici') {
        kisaYaz('Kullanıcı adı: ' + kac(a), (d.siteler || d.kayitlar || []).slice(0, 12).map(function (x) {
          return kac(x.site || x.ad || '') + ': ' + kac(x.durum || x.sonuc || '');
        }));
        return;
      }
      kisaYaz(kac(c) + ': ' + kac(a), Object.keys(d).slice(0, 12).map(function (t) {
        var v = d[t]; if (v && typeof v === 'object') v = JSON.stringify(v).slice(0, 140);
        return kac(t) + ': ' + kac(String(v));
      }));
    }).catch(function (e) { termYaz('hata: ' + kac(e.message), 'ekHata'); });
  }

  /* ============================== 8) KANIT ZİNCİRİ ============================== */
  function kanitMuhurle() {
    var veri = (window.Osint && Osint.S && Osint.S.sonuc) ? Osint.S.sonuc : null;
    if (!veri) { balon('⚠ Önce OSINT Gösterge panelinden bir tarama yap', 'kotu'); return; }
    iskelet('kanitSonuc', 'mühürleniyor…');
    api('/api/arac/kanit', { yol: 'POST', govde: { rapor: veri } }).then(function (d) {
      if (!d || d.hata) { hata('kanitSonuc', (d && d.hata) || 'yanıt yok'); return; }
      var k = d.kayit || {};
      yaz('kanitSonuc', '<div class="ekAnahtar"><b>Zincir no</b><span>#' + sayi(k.zincir_no) + '</span></div>' +
        '<div class="ekAnahtar"><b>Hedef</b><span>' + kac(k.hedef || '—') + '</span></div>' +
        '<div class="ekAnahtar"><b>Zaman damgası</b><span>' + kac(k.zaman) + '</span></div>' +
        '<div class="ekAnahtar"><b>Boyut</b><span>' + sayi(k.boyut) + ' bayt</span></div>' +
        '<div style="margin-top:8px"><b style="color:#8fb4d0;font-size:.8rem">SHA-256 ÖZETİ</b><br><code class="ekKod" style="font-size:.78rem">' + kac(k.sha256) + '</code></div>' +
        '<div style="margin-top:6px"><b style="color:#8fb4d0;font-size:.8rem">ZİNCİR MÜHRÜ</b><br><code class="ekKod" style="font-size:.78rem">' + kac(k.muhur) + '</code></div>' +
        '<div class="osIskelet" style="margin-top:8px">' + kac(d.ornek || '') + '</div>');
      if ($('kanitYaz')) $('kanitYaz').disabled = false;
      durum('kanitOzet', 'zincir uzunluğu: ' + sayi(d.zincir_uzunluk));
      balon('🔗 Rapor mühürlendi · #' + sayi(k.zincir_no), 'iyi');
      kanitListele();
    }).catch(function (e) { hata('kanitSonuc', e.message); });
  }

  function kanitListele() {
    api('/api/arac/kanit').then(function (d) {
      if (!d || d.hata) return;
      if (!(d.zincir || []).length) { durum('kanitOzet', 'kayıt yok'); return; }
      var h = '<table class="ekTablo"><thead><tr><th>#</th><th>Zaman</th><th>Hedef</th><th>SHA-256</th><th>Mühür</th></tr></thead><tbody>';
      h += d.zincir.map(function (z) {
        return '<tr><td>' + sayi(z.zincir_no) + '</td><td>' + kac(z.zaman) + '</td><td>' + kac(z.hedef || '—') + '</td>' +
          '<td><code style="font-size:.72rem">' + kac(String(z.sha256).slice(0, 24)) + '…</code></td>' +
          '<td><code style="font-size:.72rem">' + kac(String(z.muhur || '').slice(0, 16)) + '…</code></td></tr>';
      }).join('') + '</tbody></table>';
      yaz('kanitSonuc', h);
      durum('kanitOzet', sayi(d.toplam) + ' kayıt');
    });
  }

  function kanitYaz() {
    api('/api/arac/kanit').then(function (d) {
      if (!d) return;
      indir('ustad-osint-kanit-zinciri.json', JSON.stringify(d, null, 1), 'application/json;charset=utf-8');
    });
  }

  /* ============================== SESLİ ÖZET (TTS) ============================== */
  function sesliOzet() {
    try {
      if (!('speechSynthesis' in window)) { balon('⚠ Bu tarayıcı sesli okumayı desteklemiyor', 'kotu'); return; }
      var metin = '';
      var s = (window.Osint && Osint.S && Osint.S.sonuc) ? Osint.S.sonuc : null;
      if (s) {
        metin = 'Üstad OSINT raporu. Hedef ' + s.hedef + '. Risk puanı ' + s.risk + ' bölü yüz. ' +
          (s.bulgular || []).length + ' bulgu var. ' +
          ((s.bulgular || []).length ? 'En önemlisi: ' + ((s.bulgular || [])[0].baslik || '') + '. ' : '') + 'Rapor hazır.';
      } else if (sonOzet) {
        metin = 'Üstad OSINT. ' + sonOzet;
      } else {
        balon('⚠ Söylenecek sonuç yok — önce bir panel çalıştır', 'kotu'); return;
      }
      window.speechSynthesis.cancel();
      var u = new SpeechSynthesisUtterance(metin);
      u.lang = 'tr-TR'; u.rate = 1.02; u.pitch = 1;
      var sesler = window.speechSynthesis.getVoices() || [];
      for (var i = 0; i < sesler.length; i++) {
        if ((sesler[i].lang || '').toLowerCase().indexOf('tr') === 0) { u.voice = sesler[i]; break; }
      }
      window.speechSynthesis.speak(u);
      balon('🔊 Sesli özet okunuyor', 'iyi');
    } catch (e) { balon('⚠ Ses hatası: ' + kac(e.message), 'kotu'); }
  }


  /* ============================== 9) DEĞİŞİM (FARK) ============================== */
  function farkAnahtar(hedef) { return 'ustad_fark_' + String(hedef || '').toLowerCase(); }

  function farkOku(hedef) {
    try { return JSON.parse(localStorage.getItem(farkAnahtar(hedef)) || '[]') || []; }
    catch (e) { return []; }
  }
  function farkYaz(hedef, liste) {
    try { localStorage.setItem(farkAnahtar(hedef), JSON.stringify(liste.slice(-30))); } catch (e) {}
  }

  function anlikGoruntu(hedef, veri) {
    veri = veri || {};
    var portlar = [], altlar = [];
    var w = ((veri.sonuclar || {}).webtek) || {};
    (w.portlar || []).forEach(function (p) {
      var n = (p && typeof p === 'object') ? p.port : p;
      if (n) portlar.push(Number(n));
    });
    var s = (veri.sonuclar || {}).subdomain || {};
    (s.alt_alanlar || s.kayitlar || []).forEach(function (x) {
      var ad = (x && typeof x === 'object') ? x.ad : x;
      if (ad) altlar.push(String(ad));
    });
    var tekil = function (v, i, a) { return a.indexOf(v) === i; };
    return {
      zaman: veri.zaman || (new Date()).toLocaleString('tr-TR'),
      hedef: veri.hedef || hedef,
      risk: veri.risk == null ? 0 : veri.risk,
      portlar: portlar.filter(tekil).sort(function (a, b) { return a - b; }),
      alt_alanlar: altlar.filter(tekil),
      bulgular: (veri.bulgular || []).map(function (b) {
        return (b.tur || '') + ': ' + String(b.aciklama || b.baslik || '').slice(0, 140);
      }),
      cve: (((veri.sonuclar || {}).pasif || {}).cve || []).map(function (c) { return c.id || c; })
    };
  }

  function farkKaydet() {
    var s = (window.Osint && Osint.S && Osint.S.sonuc) ? Osint.S.sonuc : null;
    if (!s) { balon('⚠ Önce OSINT Gösterge panelinden tarama yap', 'kotu'); return; }
    var hedef = s.hedef || (($('farkGirdi') || {}).value || '').trim();
    if (!hedef) { balon('⚠ Hedef bilinmiyor', 'kotu'); return; }
    durum('farkDurum', 'pasif veri alınıyor…');
    iskelet('farkSonuc', 'anlık görüntü hazırlanıyor (port + CVE + alt alan)…');
    // profil portları taşımaz: port ve CVE'yi pasif radardan al, sonra kaydet
    api('/api/arac/pasif?ad=' + encodeURIComponent(hedef)).then(function (p) {
      var g = anlikGoruntu(hedef, s);
      if (p && !p.hata) g = pasifVerisiyle(g, p);
      var liste = farkOku(hedef);
      liste.push(g);
      farkYaz(hedef, liste);
      if ($('farkGirdi')) $('farkGirdi').value = hedef;
      yaz('farkSonuc', '<div class="osIskelet">Kaydedildi: <b>' + sayi((g.portlar || []).length) + '</b> port · ' +
        sayi((g.cve || []).length) + ' CVE · ' + sayi((g.alt_alanlar || []).length) + ' alt alan · risk ' +
        sayi(g.risk) + '/100</div>');
      balon('💾 <b>' + kac(hedef) + '</b> görüntüsü kaydedildi (' + liste.length + '. kayıt)', 'iyi');
      farkGecmisCiz(hedef);
      durum('farkDurum', 'kaydedildi');
    }).catch(function (e) {
      // pasif veri alınamazsa yine de kaydet (eksik veriyle)
      var g = anlikGoruntu(hedef, s);
      var liste = farkOku(hedef);
      liste.push(g);
      farkYaz(hedef, liste);
      farkGecmisCiz(hedef);
      durum('farkDurum', 'pasif veri alınamadı, temel kayıt yapıldı');
      balon('⚠ Pasif veri alınamadı: ' + kac(e.message), 'kotu');
    });
  }

  function pasifVerisiyle(goruntu, p) {
    var portlar = (goruntu.portlar || []).slice();
    (p.portlar || []).forEach(function (x) {
      var n = Number(x);
      if (n && portlar.indexOf(n) < 0) portlar.push(n);
    });
    goruntu.portlar = portlar.sort(function (a, b) { return a - b; });
    goruntu.cve = (p.cveler || []).map(function (c) { return c.id || c; });
    goruntu.kritik = p.kritik || 0;
    goruntu.ip = p.ip || [];
    return goruntu;
  }

  function farkHesapla(eski, yeni) {
    var fark = function (a, b) {
      var A = {}, B = {};
      (a || []).forEach(function (x) { A[String(x)] = 1; });
      (b || []).forEach(function (x) { B[String(x)] = 1; });
      return {
        yeni: (b || []).filter(function (x) { return !A[String(x)]; }),
        giden: (a || []).filter(function (x) { return !B[String(x)]; })
      };
    };
    var p = fark(eski.portlar, yeni.portlar);
    var a = fark(eski.alt_alanlar, yeni.alt_alanlar);
    var b = fark(eski.bulgular, yeni.bulgular);
    var c = fark(eski.cve, yeni.cve);
    return { yeni_portlar: p.yeni, kapanan_portlar: p.giden, yeni_alt_alanlar: a.yeni,
             kaybolan_alt_alanlar: a.giden, yeni_bulgular: b.yeni, duzelen_bulgular: b.giden,
             yeni_cve: c.yeni, kapanan_cve: c.giden, risk_eski: eski.risk, risk_yeni: yeni.risk,
             risk_degisim: (yeni.risk || 0) - (eski.risk || 0), onceki_zaman: eski.zaman, simdi: yeni.zaman };
  }

  function farkGoster() {
    var h = (($('farkGirdi') || {}).value || '').trim();
    var liste = farkOku(h);
    var s = (window.Osint && Osint.S && Osint.S.sonuc) ? Osint.S.sonuc : null;
    var yeni = null, eski = null;
    // Canlı tarama varsa onu kullan ama port/CVE'yi pasif radarla tamamla
    if (s && liste.length >= 1 && (!h || String(s.hedef || '').toLowerCase().indexOf(h.toLowerCase()) >= 0)) {
      eski = liste[liste.length - 1];
      yeni = anlikGoruntu(s.hedef || h, s);
      durum('farkDurum', 'pasif veri ile tamamlanıyor…');
      api('/api/arac/pasif?ad=' + encodeURIComponent(eski.hedef || s.hedef || h)).then(function (p) {
        if (p && !p.hata) yeni = pasifVerisiyle(yeni, p);
        cizFark(farkHesapla(eski, yeni), yeni);
        farkGecmisCiz(eski.hedef || h);
        durum('farkDurum', 'tamamlandı');
      }).catch(function () {
        cizFark(farkHesapla(eski, yeni), yeni);
        farkGecmisCiz(eski.hedef || h);
        durum('farkDurum', 'pasif veri alınamadı');
      });
      return;
    }
    if (false) {
      if (liste.length < 2) {
        yaz('farkSonuc', '<div class="osIskelet">Karşılaştırma için en az 2 kayıt gerekiyor. "TARAMAYI KAYDET" ile birkaç kez kaydet.</div>');
        farkGecmisCiz(h);
        return;
      }
      yeni = liste[liste.length - 1]; eski = liste[liste.length - 2];
    }
    if (!eski) {
      yaz('farkSonuc', '<div class="osIskelet">Önceki kayıt yok: bu ilk anlık görüntü. Sonraki taramada fark çıkacak.<br>Şimdiki durum: <b>' +
        sayi((yeni.portlar || []).length) + '</b> port · risk <b>' + sayi(yeni.risk) + '/100</b></div>');
      farkGecmisCiz(h || yeni.hedef);
      durum('farkDurum', 'ilk kayıt');
      return;
    }
    var f = farkHesapla(eski, yeni);
    cizFark(f, yeni);
    farkGecmisCiz(h || yeni.hedef);
    durum('farkDurum', 'tamamlandı');
  }

  function cizFark(f, yeni) {
    var degisti = f.yeni_portlar.length + f.kapanan_portlar.length + f.yeni_alt_alanlar.length +
      f.kaybolan_alt_alanlar.length + f.yeni_bulgular.length + f.yeni_cve.length;
    var h = '<div class="ekAnahtar"><b>Önceki kayıt</b><span>' + kac(f.onceki_zaman) + '</span></div>';
    h += '<div class="ekAnahtar"><b>Şimdiki kayıt</b><span>' + kac(f.simdi) + '</span></div>';
    var renk = f.risk_degisim > 0 ? 'yuksek' : (f.risk_degisim < 0 ? 'iyi' : 'orta');
    h += '<div class="ekAnahtar"><b>Risk değişimi</b><span class="ekRisk ' + renk + '">' + sayi(f.risk_eski) + ' → ' +
      sayi(f.risk_yeni) + ' (' + (f.risk_degisim > 0 ? '+' : '') + sayi(f.risk_degisim) + ')</span></div>';
    h += '<div class="ekAnahtar"><b>Toplam değişim</b><span>' + (degisti ? sayi(degisti) + ' kalem' : 'Değişim yok') + '</span></div>';
    [['Yeni açılan port', f.yeni_portlar, 'kritik'], ['Kapanan port', f.kapanan_portlar, 'iyi'],
     ['Yeni alt alan', f.yeni_alt_alanlar, 'kritik'], ['Kaybolan alt alan', f.kaybolan_alt_alanlar, 'iyi'],
     ['Yeni CVE', f.yeni_cve, 'kritik'], ['Kapanan CVE', f.kapanan_cve, 'iyi'],
     ['Yeni bulgu', f.yeni_bulgular, 'orta'], ['Düzelen bulgu', f.duzelen_bulgular, 'iyi']].forEach(function (x) {
      if (!x[1].length) return;
      h += '<div style="margin-top:8px"><b class="ekRisk ' + x[2] + '">' + kac(x[0]) + ' (' + x[1].length + ')</b>' +
        '<ul class="ekSirali">' + x[1].slice(0, 25).map(function (y) { return '<li><code>' + kac(y) + '</code></li>'; }).join('') + '</ul></div>';
    });
    if (!degisti) h += '<div class="osIskelet" style="margin-top:8px">Önceki taramaya göre değişiklik yok. Sakin gün.</div>';
    h += '<div class="osIskelet" style="margin-top:8px">Şimdiki durum: ' + sayi((yeni.portlar || []).length) + ' port · ' +
      sayi((yeni.alt_alanlar || []).length) + ' alt alan · ' + sayi((yeni.cve || []).length) + ' CVE kaydı</div>';
    yaz('farkSonuc', h);
    durum('farkOzet', degisti ? sayi(degisti) + ' değişiklik' : 'değişim yok');
    sonOzet = 'Değişim radarı: ' + (yeni.hedef || '') + ' · ' + (degisti ? sayi(degisti) + ' değişiklik' : 'değişim yok');
    balon(degisti ? '⚖️ <b>' + sayi(degisti) + '</b> değişiklik bulundu' : '⚖️ Değişiklik yok', degisti ? 'uyari' : 'iyi');
  }

  function farkGecmisCiz(hedef) {
    var liste = farkOku(hedef);
    if (!liste.length) {
      yaz('farkGecmis', '<div class="osIskelet">Bu hedef için kayıt yok. Tarama yapıp "TARAMAYI KAYDET"e bas.</div>');
      durum('farkGecmisOzet', '0 kayıt');
      return;
    }
    var h = '<table class="ekTablo"><thead><tr><th>#</th><th>Zaman</th><th>Risk</th><th>Port</th><th>Alt alan</th><th>Bulgu</th></tr></thead><tbody>';
    liste.slice().reverse().forEach(function (x, i) {
      h += '<tr><td>' + (liste.length - i) + '</td><td>' + kac(x.zaman) + '</td><td>' + sayi(x.risk) + '/100</td>' +
        '<td>' + sayi((x.portlar || []).length) + '</td><td>' + sayi((x.alt_alanlar || []).length) + '</td>' +
        '<td>' + sayi((x.bulgular || []).length) + '</td></tr>';
    });
    h += '</tbody></table>';
    yaz('farkGecmis', h);
    durum('farkGecmisOzet', sayi(liste.length) + ' kayıt');
  }

  function farkTemizle() {
    var h = (($('farkGirdi') || {}).value || '').trim();
    if (!h) { balon('⚠ Hedef yaz (ör. ornek.com)', 'kotu'); return; }
    if (!window.confirm('"' + h + '" için kayıtlı değişim geçmişi silinsin mi?')) return;
    try { localStorage.removeItem(farkAnahtar(h)); } catch (e) {}
    yaz('farkSonuc', '<div class="osIskelet">Geçmiş silindi.</div>');
    farkGecmisCiz(h);
    balon('🗑️ <b>' + kac(h) + '</b> geçmişi silindi', 'iyi');
  }

  /* ============================== KURULUM ============================== */
  function bagla(id, fn) { var d = $(id); if (d) d.onclick = fn; }
  function gir(id, fn) { var d = $(id); if (d) d.onkeydown = function (e) { if (e.key === 'Enter') fn(); }; }

  function kur() {
    bagla('pasifDug', function () { pasifTara(false); });
    bagla('pasifZorla', function () { pasifTara(true); });
    gir('pasifGirdi', function () { pasifTara(false); });

    bagla('cveDug', cveEsle);
    gir('cveGirdi', cveEsle); gir('cveSurum', cveEsle);

    bagla('arsivDug', arsivAc);
    gir('arsivGirdi', arsivAc);

    bagla('takeoverDug', takeoverTara);
    gir('takeoverGirdi', takeoverTara);

    bagla('savunmaDug', savunmaUret);
    bagla('savunmaIndir', savunmaIndir);
    bagla('savunmaGeri', savunmaGeriIndir);

    bagla('topluDug', topluTara);

    bagla('termDug', termCalistir);
    var tg = $('termGirdi');
    if (tg) {
      tg.onkeydown = function (e) {
        if (e.key === 'Enter') { termCalistir(); return; }
        if (e.key === 'ArrowUp') { if (gecmisNo > 0) { gecmisNo--; tg.value = gecmis[gecmisNo] || ''; } e.preventDefault(); }
        if (e.key === 'ArrowDown') { if (gecmisNo < gecmis.length - 1) { gecmisNo++; tg.value = gecmis[gecmisNo] || ''; } else { gecmisNo = gecmis.length; tg.value = ''; } e.preventDefault(); }
      };
    }

    bagla('farkKaydet', farkKaydet);
    bagla('farkGoster', farkGoster);
    bagla('farkTemizle', farkTemizle);
    var fk = $('farkGirdi');
    if (fk) {
      fk.onchange = function () { farkGecmisCiz(fk.value.trim()); };
      fk.onkeydown = function (e) { if (e.key === 'Enter') farkGoster(); };
    }

    bagla('kanitDug', kanitMuhurle);
    bagla('kanitYaz', kanitYaz);

    // sesli özet düğmelerini rapor şeritlerine ekle
    var seritler = document.querySelectorAll('.raporSerit');
    Array.prototype.forEach.call(seritler, function (serit) {
      if (serit.querySelector('.ekSesDug')) return;
      var b = document.createElement('button');
      b.className = 'ekSesDug'; b.type = 'button';
      b.innerHTML = '🔊 SESLİ ÖZET';
      b.onclick = sesliOzet;
      serit.appendChild(b);
    });

    // panel açılınca kanıt listesini tazele
    if (typeof OS !== 'undefined' && OS.panelAc && !OS.panelAc.__ekSarmal) {
      var eski = OS.panelAc;
      var yeni = function (id, sessiz) {
        eski.call(OS, id, sessiz);
        if (id === 'kanit') setTimeout(kanitListele, 60);
        if (id === 'fark') setTimeout(function () {
          var sv = (window.Osint && Osint.S && Osint.S.sonuc) ? Osint.S.sonuc : null;
          var girdi = $('farkGirdi');
          var h = (girdi && girdi.value ? girdi.value : '').trim() || (sv ? sv.hedef : '');
          if (girdi && !girdi.value && h) girdi.value = h;
          farkGecmisCiz(h);
        }, 90);
        if (id === 'terminal') setTimeout(function () { var g = $('termGirdi'); if (g) g.focus(); }, 120);
      };
      yeni.__ekSarmal = true;
      OS.panelAc = yeni;
    }
    kanitListele();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { setTimeout(kur, 140); });
  else setTimeout(kur, 140);

  return { kur: kur, pasifTara: pasifTara, cveEsle: cveEsle, arsivAc: arsivAc, takeoverTara: takeoverTara,
           savunmaUret: savunmaUret, topluTara: topluTara, komut: komut, kanitMuhurle: kanitMuhurle,
           kanitListele: kanitListele, sesliOzet: sesliOzet, farkKaydet: farkKaydet,
           farkGoster: farkGoster, farkGecmisCiz: farkGecmisCiz, farkTemizle: farkTemizle };
})();
