# -*- coding: utf-8 -*-
"""yuzey.js — saldırı yüzeyi grafiğine akan sinyal (hareketli paket) ekler."""
import io
import os

KOK = os.path.dirname(os.path.abspath(__file__))
p = os.path.join(KOK, "web", "yuzey.js")
s = io.open(p, encoding="utf-8").read()

if "AKAN SİNYAL" in s:
    print("yuzey.js zaten yamalı")
    raise SystemExit(0)

# 1) ciz() zaman alsın
s = s.replace("  function ciz() {\n    if (!g) return;\n    var st = getComputedStyle(document.documentElement);",
              "  function ciz(zaman) {\n    if (!g) return;\n    zaman = zaman || ((window.performance && performance.now) ? performance.now() : Date.now());\n    var st = getComputedStyle(document.documentElement);", 1)

# 2) kenarlardan sonra akan sinyaller
ESKI = """      g.stroke(); g.globalAlpha = 1;
    });

    // düğümler"""
YENI = """      g.stroke(); g.globalAlpha = 1;
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

    // düğümler"""
if ESKI not in s:
    print("UYARI: kenar bloğu bulunamadı")
else:
    s = s.replace(ESKI, YENI, 1)

# 3) canlı döngü
s = s.replace("""    boyutla();
    window.addEventListener('resize', boyutla);
    return { ciz: ciz, boyutla: boyutla, veri: veri };""",
"""    boyutla();
    window.addEventListener('resize', boyutla);
    if (window.HaritaGercek) HaritaGercek.canli('yuzeyTuval', 'p-yuzey', function (z) { ciz(z); }, 33);
    return { ciz: ciz, boyutla: boyutla, veri: veri };""", 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("yuzey.js akan sinyal:", "AKAN SİNYAL" in s, "| canlı:", "HaritaGercek.canli" in s)
