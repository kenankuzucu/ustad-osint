/* ==========================================================================
   ÜSTAD OSINT v1.6 — YENİ NESİL ARAÇLAR (12 panel)
   1) Aktif istismar radarı (CISA KEV + EPSS)      7) Canlı saldırı akışı (DShield + harita)
   2) E-posta sahtecilik kalkanı (SPF/DKIM/DMARC)  8) Kod sır avcısı (yerel + GitHub)
   3) Mail başlığı adli analizi                    9) Yerel ağ cihazları (ARP + UPnP)
   4) Sertifika logu (CT) alt alanlar             10) Şifre sızıntı kontrolü (HIBP k-anonymity)
   5) Web yapılandırma denetimi                   11) Rapor paketi (Word/HTML + QR)
   6) Fidye yazılımı radarı                       12) Olay & bildirim merkezi
   ========================================================================== */
var Ek2 = (function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var saldiriZaman = null, saldiriHarita = null, otoZaman = null;

  function kac(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function sayi(n) { return (n == null ? 0 : Number(n)).toLocaleString('tr-TR'); }
  function api(yol, secenek) { return OS.api(yol, secenek); }
  function yaz(id, html) { var k = $(id); if (k) k.innerHTML = html; }
  function durum(id, m) { var k = $(id); if (k) k.textContent = m || ''; }
  function calisiyor(id, m) { yaz(id, '<div class="osIskelet">' + kac(m || 'çalışıyor…') + '</div>'); }
  function hataYaz(id, m) { yaz(id, '<div class="osIskelet" style="color:#ff5470">⚠ ' + kac(m || 'hata') + '</div>'); }
  function balon(m, t) { if (OS.balon) OS.balon(m, t); }
  function bagla(id, fn) { var d = $(id); if (d) d.onclick = fn; }
  function deger(id) { var d = $(id); return d ? String(d.value || '').trim() : ''; }

  function metrik(deger, etiket, renk) {
    return '<div class="e2Metrik"' + (renk ? ' style="--ton:' + renk + '"' : '') + '><b>' + deger + '</b><span>' + kac(etiket) + '</span></div>';
  }
  function rozet(m, sinif) { return '<span class="e2Rozet ' + (sinif || 'e2Gri') + '">' + kac(m) + '</span>'; }
  function onemSinif(o) { return o >= 70 ? 'e2Kirmizi' : (o >= 40 ? 'e2Turuncu' : (o > 0 ? 'e2Mavi' : 'e2Yesil')); }
  function tablo(basliklar, satirlar) {
    if (!satirlar || !satirlar.length) return '<div class="e2Alt">kayıt yok</div>';
    return '<table class="e2Tablo"><thead><tr>' + basliklar.map(function (b) { return '<th>' + kac(b) + '</th>'; }).join('') +
      '</tr></thead><tbody>' + satirlar.map(function (s) {
        return '<tr>' + s.map(function (h) { return '<td>' + h + '</td>'; }).join('') + '</tr>';
      }).join('') + '</tbody></table>';
  }

  /* =============================== 1) AKTİF İSTİSMAR RADARI =============================== */
  function istismarTara() {
    var c = deger('e2CveGirdi') || 'CVE-2024-3094';
    calisiyor('e2IstismarSonuc', 'CISA KEV + EPSS sorgulanıyor…');
    var cok = c.indexOf(',') >= 0;
    api('/api/arac/istismar?' + (cok ? 'cveler=' : 'cve=') + encodeURIComponent(c)).then(function (d) {
      if (d.hata) return hataYaz('e2IstismarSonuc', d.hata);
      if (cok) return cizIstismarListe(d);
      cizIstismar(d);
    }).catch(function (e) { hataYaz('e2IstismarSonuc', e); });
  }

  function cizIstismar(d) {
    var k = d.kev ? ['ACİL', 'e2Kirmizi'] : (d.epss >= 0.5 ? ['YÜKSEK', 'e2Turuncu'] : ['İZLE', 'e2Mavi']);
    yaz('e2IstismarSonuc',
      '<div class="e2Kartlar">' +
      metrik(d.kev ? 'EVET' : 'HAYIR', 'CISA KEV listesinde (aktif istismar)', d.kev ? '#ef4444' : '#22c55e') +
      metrik(((d.epss || 0) * 100).toFixed(1) + '%', 'EPSS — 30 günde istismar olasılığı', '#f59e0b') +
      metrik((d.epss_yuzdelik || 0).toFixed(1), 'Yüzdelik dilim', '#37e0ff') +
      metrik(d.fidye_kampanyasi ? 'EVET' : 'HAYIR', 'Fidye yazılımı kampanyasında', d.fidye_kampanyasi ? '#ef4444' : '#22c55e') +
      '</div>' +
      '<div class="e2Kart"><div class="e2Baslik"><i>🚨</i><span>' + kac(d.cve) + ' · ' + rozet(k[0], k[1]) + '</span></div>' +
      '<div class="e2Alt"><b>Ürün:</b> ' + kac(d.urun || '-') + '<br><b>KEV\'e eklenme:</b> ' + kac(d.kev_eklenme || '-') +
      '<br><b>EPSS tarihi:</b> ' + kac(d.epss_tarih || '-') + '<br><b>Karar:</b> ' + kac(d.karar || '-') +
      (d.aciklama ? '<br><br>' + kac(String(d.aciklama).slice(0, 420)) : '') +
      '<br><span class="e2Not">kaynak: ' + kac(d.kaynak || '') + '</span></div></div>');
  }

  function cizIstismarListe(d) {
    var s = (d.kayitlar || []).map(function (x) {
      var k = x.kev ? ['e2Kirmizi', 'ACİL'] : (x.epss >= 0.5 ? ['e2Turuncu', 'YÜKSEK'] : ['e2Mavi', 'İZLE']);
      return [ '<span class="e2Mono">' + kac(x.cve) + '</span>', kac(x.urun || '-'),
        x.kev ? rozet('KEV', 'e2Kirmizi') : rozet('—', 'e2Gri'),
        '<span class="e2Mono">' + ((x.epss || 0) * 100).toFixed(1) + '%</span>', rozet(k[1], k[0]) ];
    });
    yaz('e2IstismarSonuc', tablo(['CVE', 'Ürün', 'KEV', 'EPSS', 'Karar'], s) +
      '<div class="e2Not">' + kac(d.kaynak || '') + '</div>');
  }

  /* ====================== 2) E-POSTA SAHTECİLİK KALKANI ====================== */
  function postaTara() {
    var ad = deger('e2PostaGirdi') || 'ustadkenankuzucu.com.tr';
    calisiyor('e2PostaSonuc', 'SPF · DMARC · DKIM · MX sorgulanıyor…');
    api('/api/arac/postaguvenlik?ad=' + encodeURIComponent(ad)).then(function (d) {
      if (d.hata) return hataYaz('e2PostaSonuc', d.hata);
      var puan = d.puan || 0;
      var spf = d.spf || {}, dm = d.dmarc || {}, dk = d.dkim || {};
      yaz('e2PostaSonuc',
        '<div class="e2Kartlar">' +
        metrik(puan + '/100', 'Posta güvenlik puanı', puan >= 70 ? '#22c55e' : (puan >= 40 ? '#f59e0b' : '#ef4444')) +
        metrik(spf.var ? 'VAR' : 'YOK', 'SPF kaydı', spf.var ? '#22c55e' : '#ef4444') +
        metrik(dm.var ? String(dm.politika || '').toUpperCase() : 'YOK', 'DMARC politikası',
          dm.politika === 'reject' ? '#22c55e' : (dm.politika === 'quarantine' ? '#f59e0b' : (dm.var ? '#ef4444' : '#ef4444'))) +
        metrik((dk.bulunan || []).length, 'Bulunan DKIM seçicisi', (dk.bulunan || []).length ? '#22c55e' : '#f59e0b') +
        metrik((d.mx || []).length, 'MX kaydı', (d.mx || []).length ? '#22c55e' : '#ef4444') +
        '</div>' +
        '<div class="e2Kart"><div class="e2Baslik"><i>📧</i><span>' + kac(d.ad) + '</span></div>' +
        '<div class="e2Alt"><b>SPF:</b> <span class="e2Mono">' + kac(spf.kayit || 'kayıt yok') + '</span>' +
        (spf.politika ? ' · politika <b>' + kac(spf.politika) + '</b>' : '') + '<br>' +
        '<b>DMARC:</b> <span class="e2Mono">' + kac(dm.kayit || 'kayıt yok') + '</span><br>' +
        '<b>DKIM seçicileri:</b> ' + ((dk.bulunan || []).length ? kac((dk.bulunan || []).join(', ')) : 'bulunamadı') + '<br>' +
        '<span class="e2Not">kaynak: ' + kac(d.kaynak || 'Google DoH') + '</span></div></div>' +
        (dm.onerilen ? '<div class="e2Kart"><div class="e2Baslik"><i>🛠️</i><span>ÖNERİLEN DMARC KAYDI</span></div><div class="e2Alt e2Mono">' + kac(dm.onerilen) + '</div></div>' : '') +
        ((d.exikler || d.eksikler || []).length ? '<div class="e2Kart"><div class="e2Baslik"><i>⚠️</i><span>EKSİKLER</span></div><div class="e2Alt">' +
          (d.eksikler || []).map(function (x) { return '• ' + kac(x); }).join('<br>') + '</div></div>' : '') +
        ((d.oneriler || []).length ? '<div class="e2Kart"><div class="e2Baslik"><i>✅</i><span>YAPILACAKLAR</span></div><div class="e2Alt">' +
          d.oneriler.map(function (x) { return '• ' + kac(x); }).join('<br>') + '</div></div>' : ''));
    }).catch(function (e) { hataYaz('e2PostaSonuc', e); });
  }

  /* ====================== 3) MAİL BAŞLIĞI ADLİ ANALİZİ ====================== */
  function baslikAnaliz() {
    var ham = deger('e2BaslikAlan');
    if (ham.length < 20) return hataYaz('e2BaslikSonuc', 'Mail başlıklarını yapıştırın (From, Received vb.)');
    calisiyor('e2BaslikSonuc', 'başlıklar çözümleniyor…');
    api('/api/arac/baslikanaliz', { yol: 'POST', govde: { ham: ham } }).then(function (d) {
      if (d.hata) return hataYaz('e2BaslikSonuc', d.hata);
      var k = d.risk >= 60 ? ['e2Kirmizi', 'YÜKSEK'] : (d.risk >= 30 ? ['e2Turuncu', 'ORTA'] : ['e2Yesil', 'DÜŞÜK']);
      var km = d.kimlik || {};
      yaz('e2BaslikSonuc',
        '<div class="e2Kartlar">' +
        metrik((d.risk || 0) + '/100', 'Risk puanı', d.risk >= 60 ? '#ef4444' : (d.risk >= 30 ? '#f59e0b' : '#22c55e')) +
        metrik(String(km.spf || '-').toUpperCase(), 'SPF sonucu', km.spf === 'pass' ? '#22c55e' : '#ef4444') +
        metrik(String(km.dkim || '-').toUpperCase(), 'DKIM sonucu', km.dkim === 'pass' ? '#22c55e' : '#ef4444') +
        metrik(String(km.dmarc || '-').toUpperCase(), 'DMARC sonucu', km.dmarc === 'pass' ? '#22c55e' : '#ef4444') +
        '</div>' +
        '<div class="e2Kart"><div class="e2Baslik"><i>🔎</i><span>KARAR: ' + rozet(k[1], k[0]) + '</span></div>' +
        '<div class="e2Alt"><b>Gönderen:</b> ' + kac(d.ad || '-') + ' &lt;' + kac(d.kimden || '-') + '&gt;' +
        '<br><b>Reply-To:</b> ' + kac(d.yanit_adresi || '-') +
        '<br><b>Konu:</b> ' + kac(d.konu || '-') +
        '<br><b>Gönderen IP:</b> <span class="e2Mono">' + kac(d.gonderen_ip || '-') + '</span>' +
        '<br><b>Özet:</b> ' + kac(d.ozet || '-') + '</div></div>' +
        tablo(['Zincir', 'Sunucu', 'IP', 'Tarih', 'Gecikme'],
          (d.zincir || []).map(function (z) {
            return [ kac(z.sira), kac(z.sunucu || '-'), '<span class="e2Mono">' + kac(z.ip || '-') + '</span>',
              '<span class="e2Mono">' + kac(String(z.tarih || '').slice(0, 25)) + '</span>',
              z.gecikme_sn == null ? '-' : kac(z.gecikme_sn + ' sn') ];
          })) +
        ((d.isaretler || []).length ? '<div class="e2Kart"><div class="e2Baslik"><i>⚠️</i><span>BULUNAN İŞARETLER</span></div>' +
          '<div class="e2Alt">' + d.isaretler.map(function (x) {
            return '• ' + kac(x.baslik) + ' <span class="e2Not">(+' + kac(x.agirlik) + ')</span>';
          }).join('<br>') + '</div></div>' : ''));
    }).catch(function (e) { hataYaz('e2BaslikSonuc', e); });
  }

  /* ====================== 4) SERTİFİKA LOGU (CT) ====================== */
  function sertifikaTara() {
    var ad = deger('e2SertGirdi') || 'ustadkenankuzucu.com.tr';
    calisiyor('e2SertSonuc', 'sertifika şeffaflık logları taranıyor…');
    api('/api/arac/sertifika?ad=' + encodeURIComponent(ad)).then(function (d) {
      if (d.hata) return hataYaz('e2SertSonuc', d.hata);
      yaz('e2SertSonuc',
        '<div class="e2Kartlar">' +
        metrik(d.sertifika_sayisi || 0, 'Sertifika kaydı', '#37e0ff') +
        metrik((d.alt_alanlar || []).length, 'Benzersiz alan adı', '#00ffa3') +
        metrik((d.yeni_alt_alanlar || []).length, 'YENİ görülen ad', '#f59e0b') +
        metrik((d.verenler || []).length, 'Sertifika veren (CA)', '#c084fc') +
        '</div>' +
        (((d.yeni_alt_alanlar || []).length) ? '<div class="e2Kart"><div class="e2Baslik"><i>🆕</i><span>ÖNCEKİ TARAMADA OLMAYAN ADLAR</span></div>' +
          ((d.yeni_alt_alanlar || []).map(function (x) { return '• <span class="e2Mono">' + kac(x) + '</span>'; }).join('<br>')) + '</div>' : '') +
        '<div class="e2Kart"><div class="e2Baslik"><i>📜</i><span>ALT ALAN ADLARI</span></div>' +
        ((d.alt_alanlar || []).map(function (x) { return '• <span class="e2Mono">' + kac(x) + '</span>'; }).join('<br>') || '<div class="e2Alt">kayıt yok</div>') +
        '<div class="e2Not" style="margin-top:8px">kaynak: ' + kac(d.kaynak || 'certspotter') + (d.not ? ' · ' + kac(d.not) : '') + '</div></div>' +
        tablo(['Sertifika', 'Veren', 'Yayın', 'Yeni'],
          (d.kayitlar || []).map(function (x) {
            return [ '<span class="e2Mono">' + kac(String(x.id || '').slice(0, 16)) + '</span>', kac(x.veren || '-'),
              '<span class="e2Mono">' + kac(x.yayin || '-') + '</span>', x.yeni ? rozet('YENİ', 'e2Turuncu') : rozet('—', 'e2Gri') ];
          })));
    }).catch(function (e) { hataYaz('e2SertSonuc', e); });
  }

  /* ====================== 5) WEB YAPILANDIRMA DENETİMİ ====================== */
  function webZafiyet() {
    var ad = deger('e2WebGirdi') || 'ustadkenankuzucu.com.tr';
    calisiyor('e2WebSonuc', 'kendi sunucunuz denetleniyor (pasif başlık kontrolü)…');
    api('/api/arac/webzafiyet?ad=' + encodeURIComponent(ad)).then(function (d) {
      if (d.hata) return hataYaz('e2WebSonuc', d.hata);
      var acik = (d.hassas_dosyalar || []).filter(function (x) { return x.durum === 'AÇIK'; });
      yaz('e2WebSonuc',
        '<div class="e2Kartlar">' +
        metrik(d.puan + '/100', 'Yapılandırma puanı', d.puan >= 70 ? '#22c55e' : (d.puan >= 40 ? '#f59e0b' : '#ef4444')) +
        metrik(acik.length, 'AÇIK hassas dosya', acik.length ? '#ef4444' : '#22c55e') +
        metrik((d.basliklar && d.basliklar.eksik ? d.basliklar.eksik.length : 0), 'Eksik güvenlik başlığı', '#f59e0b') +
        metrik((d.cerezler || []).length, 'Çerez sayısı', '#37e0ff') +
        '</div>' +
        '<div class="e2Kart"><div class="e2Baslik"><i>🛡️</i><span>' + kac(d.ad) + ' · ' + rozet(String(d.seviye || '').toUpperCase(),
          d.seviye === 'iyi' ? 'e2Yesil' : (d.seviye === 'orta' ? 'e2Turuncu' : 'e2Kirmizi')) + '</span></div>' +
        '<div class="e2Alt"><b>URL:</b> <span class="e2Mono">' + kac(d.url || '') + '</span><br>' +
        '<b>HTTP metotları:</b> OPTIONS ' + kac((d.metotlar || {}).OPTIONS || '-') + ' · TRACE ' + kac((d.metotlar || {}).TRACE || '-') +
        '<br><b>CORS:</b> ' + ((d.cors || {}).uyari ? rozet(d.cors.uyari, 'e2Kirmizi') : rozet('sorun yok', 'e2Yesil')) +
        '<br><span class="e2Not">kaynak: ' + kac(d.kaynak || '') + '</span></div></div>' +
        tablo(['Hassas yol', 'Kod', 'Durum', 'Önem'],
          (d.hassas_dosyalar || []).map(function (x) {
            return [ '<span class="e2Mono">' + kac(x.yol) + '</span>', kac(x.kod),
              x.durum === 'AÇIK' ? rozet('AÇIK', 'e2Kirmizi') : (x.durum === 'kapalı' ? rozet('kapalı', 'e2Yesil') : rozet(x.durum, 'e2Gri')),
              kac(x.onem) ];
          })) +
        '<div class="e2Kart"><div class="e2Baslik"><i>🔧</i><span>EKSİK BAŞLIKLAR</span></div><div class="e2Alt e2Mono">' +
        (((d.basliklar || {}).eksik || []).join('<br>') || 'eksik yok ✔') + '</div></div>' +
        ((d.oneriler || []).length ? '<div class="e2Kart"><div class="e2Baslik"><i>✅</i><span>NASIL DÜZELTİLİR (NGINX / .htaccess)</span></div>' +
          '<div class="e2Alt e2Mono">' + d.oneriler.map(kac).join('<br>') + '</div></div>' : ''));
    }).catch(function (e) { hataYaz('e2WebSonuc', e); });
  }

  /* ====================== 6) FİDYE YAZILIMI RADARI ====================== */
  function fidyeTara() {
    var ulke = deger('e2FidyeUlke');
    calisiyor('e2FidyeSonuc', 'kurba kayıtları çekiliyor…');
    api('/api/arac/fidye?limit=100' + (ulke ? '&ulke=' + encodeURIComponent(ulke) : '')).then(function (d) {
      if (d.hata) return hataYaz('e2FidyeSonuc', d.hata);
      yaz('e2FidyeSonuc',
        '<div class="e2Kartlar">' +
        metrik(d.toplam || 0, 'Son kayıt', '#c084fc') +
        metrik(((d.gruplar || [])[0] || {}).grup || '-', 'En aktif grup', '#ef4444') +
        metrik((d.turkiye || []).length, 'Türkiye kaydı', '#f59e0b') +
        metrik((d.sektorler || []).length, 'Farklı sektör', '#37e0ff') +
        '</div>' +
        (d.uyari ? '<div class="e2Ipucu"><b>Uyarı:</b> ' + kac(d.uyari) + '</div>' : '') +
        tablo(['Kurum', 'Ülke', 'Sektör', 'Grup', 'Tarih', 'Teslim'],
          (d.kurumlar || []).slice(0, 60).map(function (x) {
            return [ '<b>' + kac(x.kurum || '-') + '</b>', kac(x.ulke || '-'), kac(x.sektor || '-'),
              rozet(x.grup || '-', 'e2Kirmizi'), '<span class="e2Mono">' + kac(x.tarih || '-') + '</span>',
              x.teslim ? '<span class="e2Mono">' + kac(x.teslim) + '</span>' : '—' ];
          })) +
        '<div class="e2Kart"><div class="e2Baslik"><i>📊</i><span>EN AKTİF GRUPLAR</span></div>' +
        ((d.gruplar || []).slice(0, 8).map(function (g) {
          return '<div class="e2Anahtar"><span><b>' + kac(g.grup || '-') + '</b></span><span>' + sayi(g.adet) + ' kurban</span></div>';
        }).join('') || '<div class="e2Alt">veri yok</div>') +
        '<div class="e2Not" style="margin-top:6px">kaynak: ' + kac(d.kaynak || 'ransomware.live') + ' · ' + kac(d.not || '') + '</div></div>');
    }).catch(function (e) { hataYaz('e2FidyeSonuc', e); });
  }

  /* ====================== 7) CANLI SALDIRI AKIŞI (haritalı) ====================== */
  function saldiriTara(sessiz) {
    if (!sessiz) calisiyor('e2SaldiriSonuc', 'SANS ISC DShield beslemesi çekiliyor…');
    api('/api/arac/saldiriakisi').then(function (d) {
      if (d.hata) return hataYaz('e2SaldiriSonuc', d.hata);
      saldiriZaman = d;
      cizSaldiri(d);
      haritaCiz(d);
    }).catch(function (e) { hataYaz('e2SaldiriSonuc', e); });
  }

  function cizSaldiri(d) {
    yaz('e2SaldiriSonuc',
      '<div class="e2Kartlar">' +
      metrik((d.kayitlar || []).length, 'Takip edilen saldırgan IP', '#ef4444') +
      metrik(sayi(d.toplam_rapor), 'Toplam saldırı raporu', '#f59e0b') +
      metrik(((d.kayitlar || [])[0] || {}).ip || '-', 'Lider IP', '#37e0ff') +
      metrik((d.guncelleme || '').slice(11, 19) || '-', 'Güncelleme saati', '#22c55e') +
      '</div>' +
      tablo(['#', 'Saldırgan IP', 'Rapor', 'Hedef', 'Ülke', 'Şehir'],
        (d.kayitlar || []).map(function (x) {
          return [ kac(x.sira), '<span class="e2Mono">' + kac(x.ip) + '</span>',
            '<b>' + sayi(x.rapor) + '</b>', kac(x.hedef == null ? '-' : x.hedef),
            kac(x.ulke || '-'), kac(x.sehir || '-') ];
        })) +
      '<div class="e2Not">kaynak: ' + kac(d.kaynak || 'SANS ISC DShield') + ' — dünyanın en çok saldıran IP\'leri (kendi cihazınızdan değil)</div>');
  }

  function haritaCiz(d) {
    var t = $('e2SaldiriHarita');
    if (!t || !window.HaritaGercek) return;
    var kap = $('e2SaldiriKap');
    if (kap && kap.clientWidth < 40) return;
    var dpr = window.devicePixelRatio || 1;
    var G = (kap && kap.clientWidth) || 900, Y = 300;
    if (t.width !== Math.floor(G * dpr)) { t.width = Math.floor(G * dpr); t.height = Math.floor(Y * dpr); }
    var g = t.getContext('2d');
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    var zaman = (window.performance && performance.now) ? performance.now() : Date.now();
    var noktalar = (d.kayitlar || []).filter(function (x) { return typeof x.enlem === 'number'; });
    if (!window.karaResim2) {
      window.karaResim2 = new Image();
      window.karaResim2.src = 'dunya-kara.png';
    }
    var kara = (window.karaResim2 && window.karaResim2.complete && window.karaResim2.naturalWidth) ? window.karaResim2 : null;
    saldiriHarita = { g: g, G: G, Y: Y, noktalar: noktalar, kara: kara };
    kare(zaman);
    /* canlı döngü: yalnız panel görünürken, saniyede ~30 kare */
    if (window.HaritaGercek && HaritaGercek.canli) {
      HaritaGercek.canli('e2SaldiriHarita', 'p-saldiri', function (z) { kare(z); }, 33);
    }
  }

  function kare(zaman) {
    var s = saldiriHarita;
    if (!s) return;
    HaritaGercek.arkaplan(s.g, s.G, s.Y, s.kara);
    var nk = s.noktalar.map(function (x) { return { enlem: x.enlem, boylam: x.boylam, renk: '#ff5470' }; });
    if (nk.length) {
      /* hedef: kendi sunucunuzun konumu varsa o, yoksa ağırlık merkezi */
      var merkez = null;
      try {
        var sv = (window.Osint && Osint.S && Osint.S.sonuc) ? Osint.S.sonuc : null;
        var kl = sv && sv.konumlar ? sv.konumlar.filter(function (k) { return k.tur !== 'c2' && k.tur !== 'threat' && typeof k.enlem === 'number'; }) : [];
        if (kl.length) merkez = { enlem: kl[0].enlem, boylam: kl[0].boylam };
      } catch (e) {}
      var cift = nk.map(function (n, i) {
        var h = merkez || { enlem: 39.0, boylam: 35.0 };   /* Türkiye merkezli hedef */
        return { kaynak: [n.boylam, n.enlem], hedef: [h.boylam, h.enlem], renk: '#ff5470', hiz: 0.6 + ((i * 23) % 70) / 100 };
      });
      HaritaGercek.sinyaller(s.g, s.G, s.Y, cift, zaman);
      HaritaGercek.isaretci(s.g, HaritaGercek.proj(cift[0].hedef[0], cift[0].hedef[1], s.G, s.Y)[0],
        HaritaGercek.proj(cift[0].hedef[0], cift[0].hedef[1], s.G, s.Y)[1], '#2ee6a8', zaman, false, 'HEDEF AĞINIZ', 5.4);
      nk.forEach(function (n) {
        var p = HaritaGercek.proj(n.boylam, n.enlem, s.G, s.Y);
        HaritaGercek.isaretci(s.g, p[0], p[1], '#ff5470', zaman, false, '', 3.6);
      });
    } else {
      s.g.fillStyle = 'rgba(150,180,210,.7)';
      s.g.font = '12px Consolas, monospace'; s.g.textAlign = 'center';
      s.g.fillText('konum verisi yok — yeniden tarayın', s.G / 2, s.Y / 2);
    }
  }

  function saldiriOto() {
    var k = $('e2SaldiriOto');
    if (otoZaman) { clearInterval(otoZaman); otoZaman = null; }
    if (k && k.checked) {
      otoZaman = setInterval(function () {
        var p = $('p-saldiri');
        if (p && p.className.indexOf('acik') >= 0) saldiriTara(true);
      }, 60000);
      balon('🔄 Canlı akış 60 saniyede bir yenilenecek.');
    }
  }

  /* ====================== 8) KOD SIR AVCISI ====================== */
  function sirTara() {
    var yol = deger('e2SirGirdi') || 'C:/Users/kenan/OneDrive/Desktop';
    var gh = $('e2SirGithub') && $('e2SirGithub').checked;
    calisiyor('e2SirSonuc', 'dosyalar taranıyor (bu işlem 10-60 sn sürebilir)…');
    api('/api/arac/siravc', { yol: 'POST', govde: { yol: yol, limit: 400, github: gh ? 1 : 0 } }).then(function (d) {
      if (d.hata) return hataYaz('e2SirSonuc', d.hata);
      var bulgular = d.bulgular || [];
      yaz('e2SirSonuc',
        '<div class="e2Kartlar">' +
        metrik(d.taranan_dosya || 0, 'Taranan dosya', '#37e0ff') +
        metrik(d.kritik || 0, 'KRİTİK bulgu', d.kritik ? '#ef4444' : '#22c55e') +
        metrik(d.yuksek || 0, 'Yüksek bulgu', d.yuksek ? '#f59e0b' : '#22c55e') +
        metrik((d.sure_sn || 0) + ' sn', 'Tarama süresi', '#c084fc') +
        '</div>' +
        '<div class="e2Ipucu"><b>Özet:</b> ' + kac(d.ozet || '-') + '</div>' +
        (bulgular.length ? bulgular.slice(0, 40).map(function (b) {
          return '<div class="e2Sir' + (b.onem === 'kritik' ? '' : ' yuksek') + '"><b>' + kac(b.tur) + '</b> · ' + rozet(b.onem,
            b.onem === 'kritik' ? 'e2Kirmizi' : 'e2Turuncu') +
            '<span>' + kac(String(b.dosya).replace(/^.*[\\\/]/, '')) + ' : satır ' + kac(b.satir) + ' · ' + kac(b.maske) + '</span>' +
            '<span style="color:var(--renk2)">' + kac(b.oneri || '') + '</span></div>';
        }).join('') : '<div class="e2Alt">bulgu yok — temiz görünüyor ✔</div>') +
        (d.github && d.github.durum ? '<div class="e2Not" style="margin-top:8px">GitHub: ' + kac(d.github.durum) + '</div>' : ''));
    }).catch(function (e) { hataYaz('e2SirSonuc', e); });
  }

  /* ====================== 9) YEREL AĞ CİHAZLARI ====================== */
  function agTara() {
    calisiyor('e2AgSonuc', 'ARP tablosu + UPnP keşfi (3 sn)…');
    api('/api/arac/yerelag').then(function (d) {
      if (d.hata) return hataYaz('e2AgSonuc', d.hata);
      var cihazlar = d.cihazlar || [];
      yaz('e2AgSonuc',
        '<div class="e2Kartlar">' +
        metrik(cihazlar.length, 'Görülen cihaz', '#37e0ff') +
        metrik((d.yeni_cihazlar || []).length, 'YENİ cihaz', (d.yeni_cihazlar || []).length ? '#f59e0b' : '#22c55e') +
        metrik((d.ssdp || []).length, 'UPnP yanıtı', '#c084fc') +
        metrik(d.kendi_ip || '-', 'Bu bilgisayar', '#00ffa3') +
        '</div>' +
        ((d.yeni_cihazlar || []).length ? '<div class="e2Ipucu"><b>Dikkat:</b> ilk kez görülen cihaz(lar): ' +
          d.yeni_cihazlar.map(function (c) { return kac(c.ip) + ' (' + kac(c.uretici || '?') + ')'; }).join(', ') + '</div>' : '') +
        cihazlar.map(function (c) {
          return '<div class="e2Cihaz' + (c.yeni ? ' yeni' : '') + '"><div><b>' + kac(c.ip) + '</b>' +
            (c.ad ? ' <small>· ' + kac(c.ad) + '</small>' : '') +
            '<br><small>' + kac(c.mac || '-') + ' · ' + kac(c.uretici || 'bilinmiyor') + '</small></div>' +
            '<div>' + (c.yeni ? rozet('YENİ', 'e2Turuncu') : rozet(kac(c.tur || 'cihaz'), 'e2Gri')) + '</div></div>';
        }).join('') +
        ((d.ssdp || []).length ? '<div class="e2Kart"><div class="e2Baslik"><i>📺</i><span>UPnP / SSDP CİHAZLARI</span></div>' +
          d.ssdp.map(function (s) { return '<div class="e2Anahtar"><span class="e2Mono">' + kac(s.ip) + '</span><span>' + kac(s.model || '-') + '</span></div>'; }).join('') + '</div>' : '') +
        '<div class="e2Not">' + kac(d.not || '') + ' · kaynak: ' + kac(d.kaynak || 'kendi bilgisayarınız') + '</div>');
    }).catch(function (e) { hataYaz('e2AgSonuc', e); });
  }

  /* ====================== 10) ŞİFRE SIZINTI KONTROLÜ ====================== */
  function sifreKontrol() {
    var s = deger('e2SifreGirdi');
    if (!s) return hataYaz('e2SifreSonuc', 'şifre girin (cihazdan çıkmaz, yalnız SHA-1 ilk 5 karakteri gider)');
    calisiyor('e2SifreSonuc', 'HIBP k-anonymity sorgusu…');
    api('/api/arac/sifrekontrol', { yol: 'POST', govde: { sifre: s } }).then(function (d) {
      $('e2SifreGirdi').value = '';
      if (d.hata) return hataYaz('e2SifreSonuc', d.hata);
      var g = d.gucluluk || {};
      yaz('e2SifreSonuc',
        '<div class="e2Kartlar">' +
        metrik(d.bulundu ? sayi(d.sizinti_sayisi) : '0', 'Sızıntı kaydı', d.bulundu ? '#ef4444' : '#22c55e') +
        metrik((g.entropi_bit || 0) + ' bit', 'Entropi', '#37e0ff') +
        metrik(String(g.seviye || '-').toUpperCase(), 'Şifre gücü', g.seviye === 'güçlü' ? '#22c55e' : '#f59e0b') +
        metrik(g.uzunluk || 0, 'Uzunluk', '#c084fc') +
        '</div>' +
        '<div class="e2Kart"><div class="e2Baslik"><i>' + (d.bulundu ? '⚠️' : '✅') + '</i><span>' +
        (d.bulundu ? 'BU ŞİFRE SIZINTIDA GÖRÜLMÜŞ' : 'SIZINTIDA BULUNAMADI') + '</span></div>' +
        '<div class="e2Cubuk"><i style="width:' + Math.min(100, (g.entropi_bit || 0) / 1.2) + '%"></i></div>' +
        '<div class="e2Alt">' + ((d.oneriler || []).map(function (x) { return '• ' + kac(x); }).join('<br>') || '') + '</div>' +
        '<div class="e2Not" style="margin-top:8px">' + kac(d.not || '') + '</div></div>');
    }).catch(function (e) { hataYaz('e2SifreSonuc', e); });
  }

  function sifreUret() {
    var h = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*+-=?';
    var b = new Uint32Array(20);
    (window.crypto || window.msCrypto).getRandomValues(b);
    var s = '';
    for (var i = 0; i < 20; i++) s += h[b[i] % h.length];
    var k = $('e2SifreGirdi');
    if (k) { k.value = s; k.focus(); }
    balon('🔐 20 karakterlik güçlü şifre üretildi (yalnız bu ekranda, kaydedilmedi).');
  }

  /* ====================== 11) RAPOR PAKETİ ====================== */
  function raporUret(tur) {
    var baslik = deger('e2RaporBaslik') || 'ÜSTAD OSINT Tarama Raporu';
    var ozet = {}, bolumler = [];
    var sv = (window.Osint && Osint.S && Osint.S.sonuc) ? Osint.S.sonuc : null;
    if (sv) {
      ozet['Hedef'] = sv.hedef || '-';
      ozet['Bulgu'] = String((sv.bulgular || []).length);
      ozet['Risk'] = String(sv.risk || 0) + '/100';
      bolumler.push({ ad: 'Hedefler', satirlar: ['Hedef: ' + (sv.hedef || '-'), 'Risk: ' + (sv.risk || 0) + '/100'] });
      bolumler.push({ ad: 'Bulgular', satirlar: (sv.bulgular || []).slice(0, 60).map(function (b) {
        return (b.tur || '') + ' · ' + (b.hedef || '') + ' · ' + (b.olay || b.aciklama || '');
      }) });
    }
    if (saldiriZaman) {
      bolumler.push({ ad: 'Canlı Saldırı Akışı (DShield)', satirlar: (saldiriZaman.kayitlar || []).slice(0, 20).map(function (x) {
        return x.ip + ' · ' + x.rapor + ' rapor · ' + (x.ulke || '-');
      }) });
      ozet['Saldırgan IP'] = String((saldiriZaman.kayitlar || []).length);
    }
    if (!bolumler.length) bolumler.push({ ad: 'Bilgi', satirlar: ['Henüz tarama yapılmadı — önce OSINT Gösterge panelinden tarama başlatın.'] });
    calisiyor('e2RaporSonuc', tur === 'word' ? 'Word belgesi üretiliyor…' : 'HTML rapor üretiliyor…');
    api('/api/arac/raporpaket', { yol: 'POST', govde: { tur: tur, baslik: baslik, ozet: ozet, bolumler: bolumler } }).then(function (d) {
      if (d.hata) return hataYaz('e2RaporSonuc', d.hata);
      var yolVar = !!d.dosya;
      yaz('e2RaporSonuc',
        '<div class="e2Kartlar">' +
        metrik(tur === 'word' ? 'WORD' : 'HTML', 'Oluşturulan biçim', '#4da3ff') +
        metrik(sayi(d.boyut), 'Bayt', '#37e0ff') +
        metrik(d.bolum || 0, 'Bölüm', '#00ffa3') +
        metrik(d.qr ? 'VAR' : 'YOK', 'QR kod', d.qr ? '#22c55e' : '#f59e0b') +
        '</div>' +
        '<div class="e2Kart"><div class="e2Baslik"><i>🖨️</i><span>' + (yolVar ? 'DOSYA HAZIR' : 'RAPOR OLUŞTURULDU') + '</span></div>' +
        '<div class="e2Alt">' +
        (yolVar ? '<b>Yol:</b> <span class="e2Mono">' + kac(d.dosya) + '</span><br>' : '') +
        '<b>SHA-256:</b> <span class="e2Mono">' + kac(d.sha256 || '') + '</span>' +
        (d.kanit_sha256 ? '<br><b>Kanıt mührü:</b> <span class="e2Mono">' + kac(d.kanit_sha256) + '</span>' : '') +
        (d.qr ? '<br><b>QR:</b> <span class="e2Mono">' + kac(d.qr) + '</span>' : '') +
        (d.not ? '<br><span class="e2Not">' + kac(d.not) + '</span>' : '') +
        (yolVar ? '<br><span class="e2Not">Dosyayı Masaüstü → USTAD-OSINT-RAPORLAR klasöründe bulabilirsiniz.</span>' : '') +
        '</div></div>' +
        (d.html ? '<div class="e2Kart"><div class="e2Baslik"><i>📄</i><span>ÖNİZLEME (telefon sürümü)</span></div>' +
          '<div class="e2Not" style="max-height:220px;overflow:auto;white-space:pre-wrap">' +
          kac(String(d.html).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 1200)) + '</div></div>' : ''));
      balon('✅ Rapor oluşturuldu' + (yolVar ? ': ' + kac(String(d.dosya).replace(/^.*[\\\/]/, '')) : ''), 'iyi');
    }).catch(function (e) { hataYaz('e2RaporSonuc', e); });
  }

  /* ====================== 12) OLAY & BİLDİRİM MERKEZİ ====================== */
  var ANAHTARLAR = [['yeni_port', 'Yeni açılan port'], ['yeni_cve', 'Yeni kritik CVE'],
    ['kritik', 'Kritik bulgu'], ['whatsapp', 'WhatsApp\'a gönder'], ['eposta', 'E-posta özeti']];

  function bildirimYukle() {
    api('/api/arac/bildirim').then(function (d) {
      if (d.hata) return hataYaz('e2BildirimSonuc', d.hata);
      var a = d.ayar || {};
      yaz('e2BildirimSonuc',
        '<div class="e2Kart"><div class="e2Baslik"><i>🔔</i><span>HANGİ OLAYLARDA HABER VERİLSİN</span></div>' +
        ANAHTARLAR.map(function (x) {
          return '<div class="e2Anahtar"><span>' + kac(x[1]) + '</span>' +
            '<input type="checkbox" id="e2Ayar-' + x[0] + '"' + (a[x[0]] ? ' checked' : '') + '></div>';
        }).join('') +
        '<div class="e2Satir" style="margin-top:10px">' +
        '<button class="dug" id="e2BildirimKaydet">💾 AYARLARI KAYDET</button>' +
        '<button class="dug" id="e2BildirimIzin">🖥️ MASAÜSTÜ BİLDİRİMİ İZNİ</button>' +
        '<button class="dug" id="e2BildirimTest">🔔 TEST BİLDİRİMİ</button></div></div>' +
        '<div class="e2Kartlar">' +
        metrik((d.olaylar || []).length, 'Kayıtlı olay', '#37e0ff') +
        metrik(d.okunmamis || 0, 'Okunmamış', '#f59e0b') +
        '</div>' +
        tablo(['Zaman', 'Tip', 'Başlık', 'Önem'],
          (d.olaylar || []).map(function (o) {
            return [ '<span class="e2Mono">' + kac(String(o.zaman || '').slice(5, 19)) + '</span>', kac(o.tip || '-'),
              kac(o.baslik || '-'), rozet(o.onem || '-', o.onem === 'kritik' ? 'e2Kirmizi' : 'e2Turuncu') ];
          })) +
        '<div class="e2Not">WhatsApp bildirimi: masaüstünde kurulu zamanlanmış görev (' + kac('bildirim-tara.py') + ') her 30 dakikada yeni olayları gönderir.</div>');
      bagla('e2BildirimKaydet', bildirimKaydet);
      bagla('e2BildirimIzin', bildirimIzin);
      bagla('e2BildirimTest', bildirimTest);
    }).catch(function (e) { hataYaz('e2BildirimSonuc', e); });
  }

  function bildirimKaydet() {
    var ayar = {};
    ANAHTARLAR.forEach(function (x) { var k = $('e2Ayar-' + x[0]); ayar[x[0]] = !!(k && k.checked); });
    api('/api/arac/bildirim', { yol: 'POST', govde: { ayar: ayar } }).then(function (d) {
      if (d.hata) return balon('⚠ ' + kac(d.hata));
      balon('✅ Bildirim ayarları kaydedildi.', 'iyi');
    });
  }

  function bildirimIzin() {
    if (!('Notification' in window)) return balon('⚠ Bu tarayıcı masaüstü bildirimini desteklemiyor.');
    Notification.requestPermission().then(function (p) {
      balon(p === 'granted' ? '✅ Masaüstü bildirimi açıldı.' : '⚠ Bildirim izni verilmedi (' + p + ').', p === 'granted' ? 'iyi' : null);
    });
  }

  function bildirimTest() {
    var baslik = 'ÜSTAD OSINT test bildirimi';
    api('/api/arac/bildirim', { yol: 'POST', govde: { olay: { tip: 'test', baslik: baslik, onem: 'bilgi' } } }).then(function () {
      if ('Notification' in window && Notification.permission === 'granted') new Notification('ÜSTAD OSINT', { body: baslik });
      balon('🔔 Test olayı kaydedildi.', 'iyi');
      bildirimYukle();
    });
  }

  /* ================================ KURULUM ================================ */
  function kur() {
    bagla('e2CveDug', istismarTara);
    bagla('e2PostaDug', postaTara);
    bagla('e2BaslikDug', baslikAnaliz);
    bagla('e2SertDug', sertifikaTara);
    bagla('e2WebDug', webZafiyet);
    bagla('e2FidyeDug', fidyeTara);
    bagla('e2SaldiriDug', function () { saldiriTara(false); });
    bagla('e2SirDug', sirTara);
    bagla('e2AgDug', agTara);
    bagla('e2SifreDug', sifreKontrol);
    bagla('e2SifreUret', sifreUret);
    bagla('e2RaporWord', function () { raporUret('word'); });
    bagla('e2RaporHtml', function () { raporUret('html'); });
    var oto = $('e2SaldiriOto');
    if (oto) oto.onchange = saldiriOto;

    /* panel açılınca ilgili araç kendini hazırlasın */
    if (typeof OS !== 'undefined' && OS.panelAc && !OS.panelAc.__ek2Sarmal) {
      var eski = OS.panelAc;
      var yeni = function (id, sessiz) {
        eski.call(OS, id, sessiz);
        setTimeout(function () {
          if (id === 'saldiri') { if (!saldiriZaman) saldiriTara(true); else haritaCiz(saldiriZaman); }
          if (id === 'bildirim') bildirimYukle();
          if (id === 'sifre') { var g = $('e2SifreGirdi'); if (g) g.focus(); }
        }, 120);
      };
      yeni.__ek2Sarmal = true;
      OS.panelAc = yeni;
    }
    window.addEventListener('resize', function () { if (saldiriZaman) setTimeout(function () { haritaCiz(saldiriZaman); }, 120); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { setTimeout(kur, 260); });
  else setTimeout(kur, 260);

  return { kur: kur, istismar: istismarTara, posta: postaTara, baslik: baslikAnaliz, sertifika: sertifikaTara,
           webzafiyet: webZafiyet, fidye: fidyeTara, saldiri: saldiriTara, sir: sirTara, ag: agTara,
           sifre: sifreKontrol, rapor: raporUret, bildirim: bildirimYukle };
})();
