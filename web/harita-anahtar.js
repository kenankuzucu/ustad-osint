/* ==========================================================================
   ÜSTAD OSINT — HARİTA RENK ANAHTARI
   Her haritanın/grafiğin altına "hangi renk ne demek" açıklaması ekler.
   Renkler arayüz kodundan birebir alınmıştır (dunya.js, yuzey.js, osint.js, ek2.js,
   harita-gercek.js). Bu dosya yalnız AÇIKLAMA basar; çizime karışmaz.

   Yeni bir harita eklersen: id'sini ANAHTAR tablosuna ekle, gerisi kendiliğinden olur.
   ========================================================================== */
var HaritaAnahtar = (function () {
  'use strict';

  var G = {                               /* terrain (iklim) renkleri — dünya haritası */
    tip: 'gradyan',
    renkler: ['#cfe6f2', '#5c7a4e', '#b09355', '#2f6b3a'],
    ad: 'Kara renkleri = iklim kuşağı',
    acik: 'açık buz (kutup) · orman · çöl (bej) · ekvator ormanı'
  };

  var ORTAK_NOT = 'Renkler seçtiğin temaya göre tonlanır; anlamı değişmez. ' +
                  'Akan ışık paketleri = canlı sinyalin gittiği yön.';

  var ANAHTAR = {
    /* ---------------------------------------- 1) Saldırı yüzeyi grafiği (Ağ & SOC) */
    yuzeyTuval: {
      baslik: 'SALDIRI YÜZEYİ — RENK ANAHTARI',
      satirlar: [
        { renk: '#2ee6a8', ad: 'Yeşil ortadaki büyük daire', acik: 'BURASI — taramayı yapan kendi bilgisayarın' },
        { renk: '#37e0ff', ad: 'Mavi düğüm', acik: 'cihaz / servis (normal)' },
        { renk: '#ff5470', ad: 'Kırmızı', acik: 'KRİTİK — risk 70-100' },
        { renk: '#ff8f00', ad: 'Turuncu', acik: 'YÜKSEK — risk 45-69' },
        { renk: '#ffc107', ad: 'Sarı', acik: 'ORTA — risk 20-44' },
        { renk: '#7cffb2', ad: 'Açık yeşil', acik: 'DÜŞÜK — risk 0-19' },
        { tip: 'gradyan', renkler: ['#ff5470', '#ff8f00', '#ffc107', '#6f8ba3'], ad: 'Kenar (çizgi)', acik: 'kalın + renkli = kritik/yüksek riskli açık port · ince gri = normal bağlantı' },
        { not: 'Ortadaki çemberler cihazları, dıştaki noktalar açık portları gösterir. ' +
              'Zoom %55 altına inince servis etiketleri gizlenir. ' + ORTAK_NOT }
      ]
    },

    /* ---------------------------------------- 2) OSINT saldırı yüzeyi haritası */
    osGraf: {
      baslik: 'SALDIRI YÜZEYİ HARİTASI — RENK ANAHTARI',
      satirlar: [
        { renk: '#37e0ff', ad: 'Camgöbeği (merkez)', acik: 'kök alan adı — ana hedef' },
        { renk: '#8b5cf6', ad: 'Mor', acik: 'subdomain (alt alan adı)' },
        { renk: '#00d4a0', ad: 'Yeşil', acik: 'DNS kaydı / IP' },
        { renk: '#ff8f00', ad: 'Turuncu', acik: 'e-posta kaydı (MX)' },
        { renk: '#22d3ee', ad: 'Açık mavi', acik: 'web teknolojisi' },
        { renk: '#60a5fa', ad: 'Mavi', acik: 'bulut / CDN' },
        { renk: '#ff5470', ad: 'Kırmızı', acik: 'risk bulgusu (zafiyet, sızıntı, kötü yapılandırma)' },
        { renk: '#ffffff', ad: 'Kırmızı halka', acik: 'risk bulgusu taşıyan uç (dikkat edilecek yer)' },
        { not: 'Düğüm sayısı arttıkça grafik kendini kameraya sığdırır. ' + ORTAK_NOT }
      ]
    },

    /* ------------------- 3) Dünya haritası (OSINT gösterge paneli) */
    dunyaTuval: {
      baslik: 'DÜNYA HARİTASI — RENK ANAHTARI',
      satirlar: [
        { renk: '#2ee6a8', ad: 'Yeşil işaretçi', acik: 'BURASI — senin çıkış IP adresin' },
        { renk: '#ff5470', ad: 'Kırmızı işaretçi', acik: 'konumu çözülen diğer IP (bulgu / hedef)' },
        { renk: '#6f8ba3', ad: 'Gri-mavi kenar', acik: 'yerel ağ (özel adres) — haritada gerçek konumu yoktur' },
        G,
        { not: 'Kırmızı listede gri satır = özel adres, haritada gösterilemez. ' +
              'Okyanus koyuluğu derinlik, kıyı ışıması kıyı şeridi temsilidir. ' + ORTAK_NOT }
      ]
    },

    /* ------------------- 4) OSINT paneli IP konum haritası */
    osHarita: {
      baslik: 'IP KONUM HARİTASI — RENK ANAHTARI',
      satirlar: [
        { renk: '#ff5470', ad: 'Kırmızı nokta', acik: 'C2 — komuta-kontrol sunucusu (en tehlikeli)' },
        { renk: '#ff8f00', ad: 'Turuncu nokta', acik: 'tehdit IOC — zararlı/şüpheli IP veya alan adı' },
        { renk: '#37e0ff', ad: 'Mavi nokta', acik: 'bilgi amaçlı konum (hedefin sunucusu, nötr IP)' },
        { renk: '#ffffff', ad: 'Beyaz halka', acik: 'seçili / öne çıkan nokta' },
        G,
        { not: 'Sağdaki ülke listesindeki renkler YALNIZ sıralama içindir (1. en çok kayıt); ' +
              'aynı renk "aynı ülke" anlamına gelmez. ' + ORTAK_NOT }
      ]
    },

    /* ------------------- 5) Tehdit haritası */
    tehditHarita: {
      baslik: 'TEHDİT KONUMLARI — RENK ANAHTARI',
      satirlar: [
        { renk: '#ff5470', ad: 'Kırmızı nokta', acik: 'C2 — komuta-kontrol sunucusu' },
        { renk: '#ff8f00', ad: 'Turuncu nokta', acik: 'tehdit IOC — zararlı/şüpheli IP veya alan adı' },
        { renk: '#37e0ff', ad: 'Mavi nokta', acik: 'bilgi amaçlı / nötr konum' },
        { renk: '#5cffc0', ad: 'Yeşil akan ışık', acik: 'kendi konumun ile tehdit arasındaki sinyal' },
        G,
        { not: 'Kırmızı nokta yoğunluğu = en çok saldırı gelen bölge. ' +
              'Ülke listesi renkleri yalnız sıralama içindir. ' + ORTAK_NOT }
      ]
    },

    /* ------------------- 6) Canlı saldırı akışı (v1.6) */
    e2SaldiriHarita: {
      baslik: 'CANLI SALDIRI AKIŞI — RENK ANAHTARI',
      satirlar: [
        { renk: '#ff5470', ad: 'Kırmızı noktalar', acik: 'saldıran IP adresleri (SANS DShield gerçek kayıtları)' },
        { renk: '#2ee6a8', ad: 'Yeşil işaretçi', acik: 'HEDEF AĞINIZ — senin çıkış IP adresin' },
        { renk: '#ff5470', ad: 'Kırmızı akan yay', acik: 'saldırının yönü: kaynak → hedef' },
        G,
        { not: 'Yay yoğunluğu = o kaynaktan gelen rapor sayısı. ' +
              'Kırmızı yayların hepsi yeşil işaretçiye akar. ' + ORTAK_NOT }
      ]
    }
  };

  /* --------------------------------------------------------------- çizim */
  function kac(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function satirHtml(s) {
    if (s.not) return '<div class="hNot">' + kac(s.not) + '</div>';
    var sw;
    if (s.tip === 'gradyan' && s.renkler) {
      sw = '<s class="hSwGenis" style="background:linear-gradient(90deg,' + s.renkler.join(',') + ')"></s>';
    } else {
      sw = '<s class="hSw" style="--c:' + kac(s.renk) + '"></s>';
    }
    return '<div class="hSatir">' + sw +
           '<span><span class="hAd">' + kac(s.ad) + '</span>' +
           (s.acik ? ' <span class="hAcik">· ' + kac(s.acik) + '</span>' : '') + '</span></div>';
  }

  function kutu(tanim) {
    var d = document.createElement('div');
    d.className = 'hAnahtar';
    d.setAttribute('data-anahtar', '1');
    d.innerHTML = '<div class="hBaslik">🎨 ' + kac(tanim.baslik) + '</div>' +
                  '<div class="hSatirlar">' + tanim.satirlar.map(satirHtml).join('') + '</div>';
    return d;
  }

  function kur() {
    var eklenen = 0;
    Object.keys(ANAHTAR).forEach(function (tuvalId) {
      var t = document.getElementById(tuvalId);
      if (!t) return;
      var onceki = t.nextElementSibling;
      if (onceki && onceki.classList && onceki.classList.contains('hAnahtar')) return;  /* zaten var */
      /* başlıkta varsa mükerrer ekleme */
      if (t.parentNode && t.parentNode.querySelector('.hAnahtar')) return;
      t.insertAdjacentElement('afterend', kutu(ANAHTAR[tuvalId]));
      eklenen++;
    });
    return eklenen;
  }

  function boya() {
    /* panel görünmeden ölçü alınamıyorsa kısa aralıklarla tekrar dene */
    var n = kur();
    if (n === 0) setTimeout(kur, 300);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boya);
  } else {
    boya();
  }

  return { kur: kur, tablo: ANAHTAR };
})();
