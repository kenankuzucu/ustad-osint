# -*- coding: utf-8 -*-
"""osint.js — haritaCiz'i canlı (hareketli sinyal) çizime böler + canlı döngüleri kurar."""
import io
import os

KOK = os.path.dirname(os.path.abspath(__file__))
p = os.path.join(KOK, "web", "osint.js")
s = io.open(p, encoding="utf-8").read()

if "haritaKare" in s:
    print("osint.js zaten yamalı")
    raise SystemExit(0)

bas = s.index("  function haritaCiz(konumlar, ulkeler, kapId, tuvalId, notId, ulkeId) {")
son = s.index("  /* ================================ KARTLAR")
eski = s[bas:son]

YENI = '''  var sonHarita = {};          /* tuval başına son veri: canlı animasyon için */

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

'''

s = s[:bas] + YENI + s[son:]
io.open(p, "w", encoding="utf-8", newline="").write(s)
print("osint.js haritaKare eklendi:", "haritaKare" in s, "| canlı döngü:", "HaritaGercek.canli" in s)
