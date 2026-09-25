/* ==========================================================================
   ÜSTAD OSINT — ALARM & TRİYAJ  +  IOC KASASI
   Önem sıralı alarm listesi · durum değiştirme · yanlış pozitif · IOC süzgeci
   ========================================================================== */
var Alarm = (function () {
  'use strict';

  var alarmlar = [], iocler = [], suzgec = 'hepsi';

  function kur() {
    OS.$$('#alarm .cip').forEach(function (c) {
      c.onclick = function () {
        suzgec = c.getAttribute('data-onem');
        OS.$$('#alarm .cip').forEach(function (x) { x.classList.remove('sec'); });
        c.classList.add('sec');
        ciz();
      };
    });
    OS.$('iocKopyala').onclick = function () {
      var metin = iocler.map(function (i) { return i.tur + '\t' + i.deger; }).join('\n');
      pano(metin); OS.balon('⧉ IOC listesi panoya kopyalandı (' + iocler.length + ' kayıt).', 'iyi');
    };
    OS.$('iocIndir').onclick = function () {
      var csv = 'tur;deger;kaynak\n' + iocler.map(function (i) {
        return i.tur + ';' + i.deger + ';' + (i.kaynak || []).join(' ');
      }).join('\n');
      indir('ustad-osint-ioc.csv', csv, 'text/csv');
    };
  }

  function veri(tarama) {
    alarmlar = (tarama && tarama.alarmlar) || [];
    iocler = (tarama && tarama.iocler) || [];
    suzgecCiz();
    ciz();
    iocCiz();
  }

  function suzgecCiz() {
    var kap = OS.$('iocSuzgec');
    if (!kap) return;
    var turler = ['hepsi'];
    iocler.forEach(function (i) { if (turler.indexOf(i.tur) < 0) turler.push(i.tur); });
    kap.innerHTML = '';
    turler.forEach(function (tu) {
      var b = document.createElement('button');
      b.className = 'cip' + (OS.S.iocTur === tu ? ' sec' : '');
      b.textContent = tu.toUpperCase() + (tu === 'hepsi' ? '' : ' (' + iocler.filter(function (i) { return i.tur === tu; }).length + ')');
      b.onclick = function () { OS.S.iocTur = tu; suzgecCiz(); iocCiz(); };
      kap.appendChild(b);
    });
  }

  function ciz() {
    var kap = OS.$('alarmListesi');
    if (!kap) return;
    var sira = { kritik: 0, yuksek: 1, orta: 2, dusuk: 3, bilgi: 4 };
    var liste = alarmlar.slice().sort(function (a, b) {
      var f = (sira[a.onem] - sira[b.onem]);
      if (f !== 0) return f;
      return a.host.localeCompare(b.host) || a.port - b.port;
    });
    if (suzgec !== 'hepsi') liste = liste.filter(function (a) { return a.onem === suzgec; });
    OS.$('alarmSayac').textContent = liste.length + ' / ' + alarmlar.length + ' alarm';
    if (!liste.length) {
      kap.innerHTML = '<div class="bos">' + (alarmlar.length ? 'Bu süzgeçte alarm yok.' : 'Alarm yok — önce tarama yap.') + '</div>';
      return;
    }
    kap.innerHTML = '';
    liste.forEach(function (a) {
      var d = document.createElement('div');
      d.className = 'alarm ' + a.onem;
      d.innerHTML =
        '<div class="bas"><b>' + OS.kac(a.baslik) + '</b>' +
        '<span class="onemEtiket ' + OS.kac(a.onem) + '">' + OS.kac(a.onemEtiket) + '</span></div>' +
        '<div class="govdeYazi">' + OS.kac(a.aciklama) + '</div>' +
        '<div class="kanit">' + OS.kac(a.kanit || '(kanıt yok)') + '</div>' +
        '<div class="govdeYazi">💡 <b>Öneri:</b> ' + OS.kac(a.oneri) + '</div>' +
        '<div class="alt">' +
          '<span class="etiket">' + OS.kac(a.host) + (a.port ? ':' + a.port : '') + '</span>' +
          '<span class="etiket">' + OS.kac(a.id) + '</span>' +
          '<span class="etiket">' + OS.kac(a.durum) + '</span>' +
          '<button class="miniDug" data-durum="incelendi">İNCELENDİ</button>' +
          '<button class="miniDug" data-durum="kapatildi">KAPAT</button>' +
          '<button class="miniDug" data-yp>YANLIŞ POZİTİF</button>' +
        '</div>';
      OS.$$('[data-durum]', d).forEach(function (b) {
        b.onclick = function () { durumDegis(a.id, b.getAttribute('data-durum'), false); };
      });
      var ypDug = OS.$$('[data-yp]', d)[0];
      if (ypDug) ypDug.onclick = function () { durumDegis(a.id, 'yanlis-pozitif', true); };
      kap.appendChild(d);
    });
  }

  function durumDegis(id, yeni, yp) {
    OS.api('/api/alarm/durum', { yol: 'POST', govde: { tarama: OS.S.taramaId, alarm: id, durum: yeni, yanlisPozitif: yp } })
      .then(function (d) {
        if (d.hata) { OS.balon('⚠ ' + OS.kac(d.hata), 'kotu'); return; }
        var a = alarmlar.filter(function (x) { return x.id === id; })[0];
        if (a) { a.durum = yeni; a.yanlisPozitif = !!yp; }
        ciz();
        OS.balon('✅ ' + OS.kac(id) + ' → <b>' + OS.kac(yeni) + '</b>' + (yp ? ' (yanlış pozitif)' : ''), 'iyi');
      }).catch(function (e) { OS.balon('⚠ ' + OS.kac(e.message), 'kotu'); });
  }

  function iocCiz() {
    var kap = OS.$('iocListesi');
    if (!kap) return;
    var tu = OS.S.iocTur;
    var liste = tu === 'hepsi' ? iocler : iocler.filter(function (i) { return i.tur === tu; });
    OS.$('iocSayac').textContent = liste.length + ' kayıt';
    if (!liste.length) { kap.innerHTML = '<div class="bos">IOC bulunamadı.</div>'; return; }
    kap.innerHTML = '';
    liste.forEach(function (i, n) {
      var d = document.createElement('div');
      d.className = 'satir';
      d.innerHTML = '<span class="etiket">' + (n + 1) + '</span>' +
        '<span class="etiket">' + OS.kac(i.tur.toUpperCase()) + '</span>' +
        '<span class="anahtar">' + OS.kac(i.deger) + '</span>' +
        '<span class="soluk">' + OS.kac((i.kaynak || []).join(', ').slice(0, 40)) + '</span>';
      kap.appendChild(d);
    });
  }

  function pano(metin) {
    if (navigator.clipboard) { navigator.clipboard.writeText(metin).catch(function () {}); return; }
    var a = document.createElement('textarea');
    a.value = metin; document.body.appendChild(a); a.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(a);
  }

  function indir(ad, icerik, tip) {
    var b = new Blob([icerik], { type: (tip || 'text/plain') + ';charset=utf-8' });
    var u = URL.createObjectURL(b);
    var a = document.createElement('a');
    a.href = u; a.download = ad; document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(u); a.remove(); }, 800);
  }

  return { kur: kur, veri: veri, ciz: ciz, pano: pano, indir: indir };
})();
