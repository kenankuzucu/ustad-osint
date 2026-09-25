# -*- coding: utf-8 -*-
"""v1.5 — Ultra gerçekçi harita + hareketli sinyaller yaması.
   dunya.js ve osint.js çizimlerini HaritaGercek motoruna bağlar; index.html'e betiği ekler."""
import io
import os

KOK = os.path.dirname(os.path.abspath(__file__))
W = os.path.join(KOK, "web")


def dosya(p):
    return io.open(p, encoding="utf-8").read()


def yaz(p, s):
    io.open(p, "w", encoding="utf-8", newline="").write(s)


# ------------------------------------------------------------------ 1) dunya.js
p = os.path.join(W, "dunya.js")
s = dosya(p)
if "HaritaGercek" in s:
    print("dunya.js zaten yamalı")
else:
    bas = s.index("  function ciz() {")
    son = s.index("    // işaretçiler")
    yeni_bas = '''  function ciz(zaman) {
    if (!g) return;
    zaman = zaman || ((window.performance && performance.now) ? performance.now() : Date.now());
    var st = getComputedStyle(document.documentElement);
    g.clearRect(0, 0, G, Y);
    /* ulta gerçekçi arka plan: okyanus derinliği + iklimli kara + kıyı parlaması + atmosfer */
    HaritaGercek.arkaplan(g, G, Y, karaHazir ? kara : null);
    /* hareketli sinyaller: kendi çıkışından (yoksa ağırlık merkezinden) her konuma akan paketler */
    if (cizgiGoster) {
      var gecerli = noktalar.filter(function (n) { return !n.yerel && typeof n.enlem === 'number'; });
      var cift = HaritaGercek.ciftler(gecerli, kendi, ['#5cffc0', '#37e0ff', '#ffcf4d', '#ff5470']);
      HaritaGercek.sinyaller(g, G, Y, cift, zaman);
      if (kendi && typeof kendi.enlem === 'number') {
        HaritaGercek.isaretci(g, HaritaGercek.proj(kendi.boylam, kendi.enlem, G, Y)[0],
          HaritaGercek.proj(kendi.boylam, kendi.enlem, G, Y)[1], '#2ee6a8', zaman, false, 'BURASI · ' + (kendi.ulke || 'çıkış'));
      }
    }
    /* işaretçiler */'''
    s = s[:bas] + yeni_bas + s[son + len("    // işaretçiler"):]

    # işaretçi döngüsünü gerçekçi motorla değiştir
    is_bas = s.index("    noktalar.forEach(function (n) {\n      if (n.yerel) return;\n      var p = proj(n.boylam, n.enlem);")
    is_son = s.index("    if (!noktalar.filter(function (n) { return !n.yerel; }).length) {")
    yeni_is = '''    noktalar.forEach(function (n) {
      if (n.yerel) return;
      var p = proj(n.boylam, n.enlem);
      var renk = n.kendi ? '#2ee6a8' : '#ff5470';
      var yazi = isimGoster ? ((n.sehir ? n.sehir + ', ' : '') + (n.ulke || '')).slice(0, 24) : '';
      HaritaGercek.isaretci(g, p[0], p[1], renk, zaman, secili === n.ip, yazi, n.kendi ? 6 : 4.6);
    });
'''
    s = s[:is_bas] + yeni_is + s[is_son:]

    # canlı döngüyü kur
    s = s.replace("""    boyutla();
    window.addEventListener('resize', boyutla);
    return { ciz: ciz, boyutla: boyutla, veri: veri };""",
"""    boyutla();
    window.addEventListener('resize', boyutla);
    /* sürekli animasyon: yalnız panel görünürken çizer */
    HaritaGercek.canli('dunyaTuval', 'p-dunya', function (zaman) { ciz(zaman); }, 33);
    return { ciz: ciz, boyutla: boyutla, veri: veri };""")
    yaz(p, s)
    print("dunya.js yamalandı:", "HaritaGercek.arkaplan" in s, "| canlı:", "HaritaGercek.canli" in s)


# ------------------------------------------------------------------ 2) osint.js
p2 = os.path.join(W, "osint.js")
s2 = dosya(p2)
if "HaritaGercek" in s2:
    print("osint.js zaten yamalı")
else:
    eski_arka = """    var b = t.b, renk = temaRenk();
    b.clearRect(0, 0, t.g, t.y);
    b.fillStyle = 'rgba(10,30,50,.35)'; b.fillRect(0, 0, t.g, t.y);
    if (karaHazir) { b.globalAlpha = .85; b.drawImage(karaResim, 0, 0, t.g, t.y); b.globalAlpha = 1; }
    b.strokeStyle = renk.cizgi; b.globalAlpha = .3; b.lineWidth = 1;
    for (var lon = -180; lon <= 180; lon += 30) { var x = (lon + 180) / 360 * t.g; b.beginPath(); b.moveTo(x, 0); b.lineTo(x, t.y); b.stroke(); }
    for (var lat = -60; lat <= 60; lat += 30) { var y = (90 - lat) / 180 * t.y; b.beginPath(); b.moveTo(0, y); b.lineTo(t.g, y); b.stroke(); }
    b.globalAlpha = 1;
"""
    yeni_arka = """    var b = t.b, renk = temaRenk();
    var zaman = (window.performance && performance.now) ? performance.now() : Date.now();
    /* ultra gerçekçi: okyanus derinliği + iklimli kara + kıyı parlaması + atmosfer */
    if (window.HaritaGercek) {
      HaritaGercek.arkaplan(b, t.g, t.y, karaHazir ? karaResim : null);
    } else {
      b.clearRect(0, 0, t.g, t.y);
      b.fillStyle = 'rgba(10,30,50,.35)'; b.fillRect(0, 0, t.g, t.y);
      if (karaHazir) { b.globalAlpha = .85; b.drawImage(karaResim, 0, 0, t.g, t.y); b.globalAlpha = 1; }
    }
"""
    if eski_arka not in s2:
        print("UYARI: osint.js arka plan bloğu bulunamadı")
    else:
        s2 = s2.replace(eski_arka, yeni_arka, 1)
        # işaretçi döngüsünü gerçekçi motora çevir + sinyal çiftleri ekle
        eski_is = """    var noktalar = (konumlar || []).filter(function (k) { return typeof k.enlem === 'number' && k.enlem !== null; });
    noktalar.forEach(function (k) {
      var x = (k.boylam + 180) / 360 * t.g, y = (90 - k.enlem) / 180 * t.y;
      var cl = k.tur === 'c2' ? '#ff5470' : (k.tur === 'threat' ? '#ff8f00' : '#37e0ff');
      var gr = b.createRadialGradient(x, y, 0, x, y, 20);
      gr.addColorStop(0, cl + '88'); gr.addColorStop(1, cl + '00');
      b.fillStyle = gr; b.beginPath(); b.arc(x, y, 20, 0, 7); b.fill();
      b.fillStyle = cl; b.beginPath(); b.arc(x, y, 4.4, 0, 7); b.fill();
      b.strokeStyle = '#fff'; b.lineWidth = 1.1; b.stroke();
    });"""
        yeni_is = """    var noktalar = (konumlar || []).filter(function (k) { return typeof k.enlem === 'number' && k.enlem !== null; });
    /* hareketli sinyaller: her tehdit/konum için ağırlık merkezinden akan paketler */
    if (window.HaritaGercek && noktalar.length) {
      var renkli = noktalar.map(function (k) {
        return { enlem: k.enlem, boylam: k.boylam, renk: k.tur === 'c2' ? '#ff5470' : (k.tur === 'threat' ? '#ff8f00' : '#37e0ff') };
      });
      var cift = HaritaGercek.ciftler(renkli, null, ['#ff5470', '#ff8f00', '#37e0ff', '#5cffc0']);
      HaritaGercek.sinyaller(b, t.g, t.y, cift, zaman);
    }
    noktalar.forEach(function (k) {
      var x = (k.boylam + 180) / 360 * t.g, y = (90 - k.enlem) / 180 * t.y;
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
    });"""
        if eski_is in s2:
            s2 = s2.replace(eski_is, yeni_is, 1)
            print("  işaretçiler gerçekçi motora bağlandı")
        else:
            print("  UYARI: osint.js işaretçi bloğu bulunamadı")
    yaz(p2, s2)
    print("osint.js yamalandı:", "HaritaGercek.arkaplan" in s2)


# ------------------------------------------------------------------ 3) index.html
p3 = os.path.join(W, "index.html")
s3 = dosya(p3)
if "harita-gercek.js" not in s3:
    s3 = s3.replace('<script src="yuzey.js"></script>',
                    '<script src="harita-gercek.js"></script>\n<script src="yuzey.js"></script>', 1)
    yaz(p3, s3)
    print("index.html: harita-gercek.js bağlandı")
else:
    print("index.html zaten bağlı")
print("kontrol:", dosya(p3).count("harita-gercek.js"))
