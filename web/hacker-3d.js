/* ==========================================================================
   ÜSTAD OSINT — 3D hareket motoru
   • .osKutu/.kart üzerinde fare ile gerçek 3D eğim (perspektifli)
   • eylem şeridindeki madalyona 3D parallaks
   • Matris/Terminal temasında düşen kod (matris yağmuru) — hafif, 22 fps
   Dokunmatik cihazda ve "hareketi azalt" ayarında kapanır.
   ========================================================================== */
var U3D = (function () {
  var egik = [];
  var matris = null;
  var fare = { x: 0, y: 0 };
  var dokunmatik = (typeof window !== 'undefined') &&
    (window.matchMedia && window.matchMedia('(pointer: coarse)').matches || 'ontouchstart' in window);
  var azHareket = (typeof window !== 'undefined') && window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ------------------------------ 3D EĞİM ------------------------------ */
  function hedefleriTopla() {
    egik = [];
    var seciciler = ['.osKutu', '.kart', '.kutu', '.panel .kart'];
    seciciler.forEach(function (s) {
      Array.prototype.forEach.call(document.querySelectorAll(s), function (e) {
        if (e.__u3d) return;
        e.__u3d = true;
        e.addEventListener('mousemove', function (o) { egimUygula(e, o); });
        e.addEventListener('mouseleave', function () { sifirla(e); });
        egik.push(e);
      });
    });
  }
  function egimUygula(e, o) {
    if (dokunmatik || azHareket) return;
    var r = e.getBoundingClientRect();
    var x = (o.clientX - r.left) / r.width - 0.5;   /* -0.5 … 0.5 */
    var y = (o.clientY - r.top) / r.height - 0.5;
    var d = 7;                                       /* derece şiddeti */
    e.style.transform = 'perspective(900px) rotateY(' + (x * d).toFixed(2) +
      'deg) rotateX(' + (-y * d).toFixed(2) + 'deg) translateZ(9px)';
  }
  function sifirla(e) { e.style.transform = ''; }

  /* ---------------------- madalyon 3D parallaks ---------------------- */
  function parallaks() {
    if (dokunmatik || azHareket) return;
    var gx = (fare.x / window.innerWidth - 0.5) * 2;
    var gy = (fare.y / window.innerHeight - 0.5) * 2;
    Array.prototype.forEach.call(document.querySelectorAll('.esKisi, .kunyeBuyuk'), function (e) {
      e.style.transform = 'perspective(700px) rotateY(' + (gx * 7).toFixed(2) +
        'deg) rotateX(' + (-gy * 6).toFixed(2) + 'deg) translateZ(14px)';
    });
  }

  /* --------------------------- MATRİS YAĞMURU --------------------------- */
  function matrisKur() {
    var tema = document.documentElement.getAttribute('data-tema') || '';
    var acik = (tema === 'matriks' || tema === 'terminal' || tema === 'neon' || tema === 'qdoled');
    if (!acik || azHareket) {
      document.body.classList.remove('matrisAcik');
      if (matris && matris.dur) { matris.dur(); matris = null; }
      return;
    }
    document.body.classList.add('matrisAcik');
    var tuval = document.getElementById('matrisKatman');
    if (!tuval) {
      tuval = document.createElement('canvas');
      tuval.id = 'matrisKatman';
      document.body.insertBefore(tuval, document.body.firstChild);
    }
    if (matris) { matris.tema = tema; return; }
    var b = tuval.getContext('2d');
    var harf = '01ABCDEF#$%&*+=<>/\\|AYZKN';
    var sutun = 0, dusen = [], sonKare = 0;
    var yesil = tema === 'terminal' ? ['#ffb000', '#ffd479']
      : (tema === 'neon' ? ['#00fff7', '#ff2bd6']
      : (tema === 'qdoled' ? ['#00ff8a', '#4da3ff'] : ['#00ff66', '#b6ff3d']));

    function boyutla() {
      tuval.width = window.innerWidth; tuval.height = window.innerHeight;
      sutun = Math.floor(tuval.width / 18);
      dusen = [];
      for (var i = 0; i < sutun; i++) dusen.push(Math.random() * -40);
    }
    function ciz(zaman) {
      if (!matris || !matris.calisiyor) return;
      if (zaman - sonKare < 45) { matris.raf = requestAnimationFrame(ciz); return; }  /* ~22 fps */
      sonKare = zaman;
      b.fillStyle = 'rgba(0,0,0,.10)';
      b.fillRect(0, 0, tuval.width, tuval.height);
      b.font = '14px Consolas, monospace';
      for (var i = 0; i < sutun; i++) {
        var h = harf.charAt(Math.floor(Math.random() * harf.length));
        var y = dusen[i] * 18;
        b.fillStyle = yesil[0];
        b.fillText(h, i * 18, y);
        b.fillStyle = yesil[1];
        b.fillText(harf.charAt(Math.floor(Math.random() * harf.length)), i * 18, y - 18);
        dusen[i] = y > tuval.height + Math.random() * 300 ? 0 : dusen[i] + 1;
      }
      matris.raf = requestAnimationFrame(ciz);
    }
    boyutla();
    window.addEventListener('resize', boyutla);
    matris = { calisiyor: true, raf: null, dur: function () { this.calisiyor = false; cancelAnimationFrame(this.raf); }, tema: tema };
    matris.raf = requestAnimationFrame(ciz);
  }

  function kur() {
    if (!dokunmatik && !azHareket) {
      window.addEventListener('mousemove', function (o) { fare.x = o.clientX; fare.y = o.clientY; parallaks(); });
    }
    hedefleriTopla();
    matrisKur();
    /* tema değişince yeniden kur */
    new MutationObserver(function () { setTimeout(function () { hedefleriTopla(); matrisKur(); }, 80); })
      .observe(document.documentElement, { attributes: true, attributeFilter: ['data-tema'] });
    /* panel/sekme değişiminde yeni kartlar olabilir */
    document.addEventListener('click', function () { setTimeout(hedefleriTopla, 120); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', kur);
  else setTimeout(kur, 60);

  return { kur: kur, hedefleriTopla: hedefleriTopla, matrisKur: matrisKur, dokunmatik: dokunmatik };
})();
