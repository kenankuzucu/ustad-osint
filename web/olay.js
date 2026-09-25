/* ==========================================================================
   ÜSTAD OSINT — OLAY MÜDAHALESİ + ZAFİYET & ÖNERİ MOTORU + KOMUT ÜRETİCİ
   ========================================================================== */
var Olay = (function () {
  'use strict';

  var ADIMLAR = [
    { id: 'tespit', ad: '1 · TESPİT & DOĞRULAMA', aciklama: 'Alarm gerçek mi? Kaynak IP, zaman ve hedef cihaz doğrulanır; yanlış pozitif ayıklanır.' },
    { id: 'sinirla', ad: '2 · SINIRLAMA / İZOLE', aciklama: 'Etkilenen cihaz ağdan ayrılır veya port kapatılır; yayılma durdurulur.' },
    { id: 'kanit', ad: '3 · KANIT TOPLAMA', aciklama: 'Log, bellek görüntüsü, disk imajı ve dosya hash’leri alınır; zincir kaydı tutulur.' },
    { id: 'temizle', ad: '4 · TEMİZLEME', aciklama: 'Zararlı yazılım, kalıcılık (kullanıcı/görev/servis) ve açık kapatılır; parolalar yenilenir.' },
    { id: 'geri', ad: '5 · GERİ YÜKLEME', aciklama: 'Temiz yedekten dönülür, hizmetler doğrulanır, en az 48 saat izleme yapılır.' },
    { id: 'rapor', ad: '6 · RAPOR & DERS', aciklama: 'Kök neden, etki, maliyet ve iyileştirme maddeleri rapora yazılır; kural güncellenir.' }
  ];

  var tamam = {};

  function kur() {
    ciz();
    OS.$('olayKaydet').onclick = function () {
      try { localStorage.setItem('osint_olay', JSON.stringify({ tamam: tamam, kayit: OS.S.olayKayit })); } catch (e) {}
      OS.balon('💾 Olay akışı kaydedildi (' + say() + '/6 adım).', 'iyi');
    };
    OS.$('olaySifirla').onclick = function () {
      tamam = {}; OS.S.olayKayit = [];
      try { localStorage.removeItem('osint_olay'); } catch (e) {}
      ciz(); kayitCiz();
      OS.balon('↺ Olay akışı sıfırlandı.');
    };
    var zH = OS.$('zafiyetHazir');
    if (zH) zH.onclick = function () { OS.panelAc('tarama'); };
    OS.$('komutArac').onchange = komut;
    OS.$('komutHedef').oninput = komut;
    OS.$('komutKopya').onclick = function () {
      Alarm.pano(OS.$('komutCikti').textContent);
      OS.balon('⧉ Komut kopyalandı.', 'iyi');
    };
    try {
      var k = JSON.parse(localStorage.getItem('osint_olay') || 'null');
      if (k) { tamam = k.tamam || {}; OS.S.olayKayit = k.kayit || []; ciz(); kayitCiz(); }
    } catch (e) {}
  }

  function say() { return ADIMLAR.filter(function (a) { return tamam[a.id]; }).length; }

  function ciz() {
    var kap = OS.$('olayAdimlar');
    if (!kap) return;
    kap.innerHTML = '';
    ADIMLAR.forEach(function (a) {
      var d = document.createElement('div');
      d.className = 'adim' + (tamam[a.id] ? ' tamam' : '');
      d.innerHTML = '<i class="isaret">' + (tamam[a.id] ? '✅' : '⬜') + '</i>' +
        '<b>' + OS.kac(a.ad) + '</b><p>' + OS.kac(a.aciklama) + '</p>';
      d.onclick = function () {
        tamam[a.id] = !tamam[a.id];
        kayitEkle((tamam[a.id] ? '✔ tamamlandı: ' : '↺ geri alındı: ') + a.ad);
        ciz(); kayitCiz();
      };
      kap.appendChild(d);
    });
    OS.$('olayDurum').textContent = say() + '/6 adım';
  }

  function kayitEkle(metin) {
    OS.S.olayKayit.unshift({ zaman: new Date().toISOString().slice(0, 19).replace('T', ' '), metin: metin });
    if (OS.S.olayKayit.length > 200) OS.S.olayKayit.pop();
  }

  function kayitCiz() {
    var kap = OS.$('olayKayit');
    if (!kap) return;
    if (!OS.S.olayKayit.length) { kap.innerHTML = '<div class="bos">Henüz kayıt yok.</div>'; return; }
    kap.innerHTML = '';
    OS.S.olayKayit.forEach(function (k) {
      var d = document.createElement('div');
      d.className = 'satir';
      d.innerHTML = '<span class="etiket">' + OS.kac(k.zaman) + '</span><span class="anahtar">' + OS.kac(k.metin) + '</span>';
      kap.appendChild(d);
    });
  }

  /* ------------------------------ ZAFİYET & ÖNERİ ------------------------------ */
  function veri(tarama) {
    zafiyet(tarama);
    komut();
  }

  function zafiyet(t) {
    var kap = OS.$('zafiyetListe');
    if (!kap) return;
    if (!t || !t.hostlar || !t.hostlar.length) {
      kap.innerHTML = '<div class="bos">Tarama sonrası dolar — önce Tarama Merkezi’nden bir tarama başlat.</div>';
      return;
    }
    kap.innerHTML = '';
    var bulundu = false;
    t.hostlar.forEach(function (h) {
      var riskli = (h.portlar || []).filter(function (p) { return p.onem && p.onem !== 'bilgi'; });
      if (!riskli.length) return;
      bulundu = true;
      var d = document.createElement('div');
      d.className = 'madde';
      var ic = '<b>' + OS.kac(h.ip) + ' · ' + riskli.length + ' iyileştirme maddesi</b>';
      riskli.sort(function (a, b) { return ({ kritik: 0, yuksek: 1, orta: 2, dusuk: 3, bilgi: 4 }[a.onem] - { kritik: 0, yuksek: 1, orta: 2, dusuk: 3, bilgi: 4 }[b.onem]); });
      ic += '<div class="portlar" style="display:flex;flex-direction:column;gap:6px;margin-top:8px">';
      riskli.forEach(function (p) {
        ic += '<div class="satir"><span class="portCip ' + OS.kac(p.onem) + '">' + p.port + '</span>' +
          '<span class="anahtar"><b>' + OS.kac(p.servis || '?') + '</b> — ' + OS.kac(p.gerekce || '') +
          '<br>💡 ' + OS.kac(oneri(p.port)) + '</span></div>';
      });
      ic += '</div>';
      d.innerHTML = ic;
      kap.appendChild(d);
    });
    if (!bulundu) kap.innerHTML = '<div class="bos">✅ Riskli servis bulunmadı — tüm açık portlar bilgi seviyesinde.</div>';
  }

  function oneri(port) {
    var tablo = {
      21: 'FTP yerine SFTP/FTPS; anonim erişimi kapat (anon_upload, anon_mkdir off)',
      22: 'SSH: parola girişini kapat (PasswordAuthentication no), anahtar + fail2ban kullan',
      23: 'Telnet servisini kaldır, yönetimi SSH’e taşı',
      25: 'SMTP relay yetkisini kısıtla, AUTH zorunlu, SPF/DKIM/DMARC yayınla',
      53: 'DNS’i yalnız iç ağa aç; recursion’ı kapat, yanıt oranı sınırla',
      135: 'RPC’yi dış arayüze kapat; güvenlik duvarında yalnız yönetim IP’leri',
      137: 'NetBIOS’u kapat, SMB’yi doğrudan TCP 445 üzerinden ver',
      139: 'SMBv1’i kapat (Windows özelliği), 139’u dış arayüze açma',
      161: 'SNMPv3 + güçlü anahtar; public/private topluluk dizelerini değiştir',
      389: 'LDAP imzalama + TLS zorunlu; anonim bind kapat',
      445: 'SMB: SMBv1 kapalı, imzalama açık, dış arayüze açma; fidye koruması (denetimli klasör erişimi)',
      512: 'r-servisleri kaldır (rexec/rlogin/rsh), SSH kullan',
      873: 'rsync: yalnız anahtarla ve IP kısıtlı; modülleri auth-users ile koru',
      1080: 'Açık SOCKS proxy’yi kapat veya kimlik doğrulama ekle',
      1433: 'MSSQL: ağ erişimini uygulama sunucusuna kısıtla, karma mod yerine Windows kimlik doğrulaması',
      1521: 'Oracle listener’ı IP ile sınırla, gereksiz servisleri kapat',
      2049: 'NFS ihracını IP ile sınırla, no_root_squash kullanma, Kerberos düşün',
      2375: 'Docker API’yi 2375’ten kaldır; TLS + istemci sertifikası zorunlu',
      3306: 'MySQL: bind-address = 127.0.0.1, kullanıcı bazlı IP kısıtı, TLS',
      3389: 'RDP: VPN arkasına al, NLA zorunlu, MFA, hesap kilitleme politikası',
      5432: 'PostgreSQL: listen_addresses iç ağ, scram-sha-256, pg_hba ile IP kısıtı',
      5900: 'VNC: localhost’a bağla veya SSH tüneli, güçlü parola, 8 karakter sınırına dikkat',
      6379: 'Redis: requirepass + bind, protected-mode yes',
      9200: 'Elasticsearch: X-Pack güvenliği, 9200’ü dış arayüze kapat',
      11211: 'Memcached: -l 127.0.0.1, UDP kapat, SASL',
      27017: 'MongoDB: authorization: enabled, 27017’yi dış arayüze kapat',
      50070: 'Hadoop: Kerberos + kimlik doğrulamalı HDFS arayüzü'
    };
    return tablo[port] || 'Bu servisi yalnız ihtiyaç halinde açık tut; güvenlik duvarında kaynak IP kısıtı uygula';
  }

  /* ------------------------------ KOMUT ÜRETİCİ ------------------------------ */
  function komut() {
    var arac = OS.$('komutArac').value;
    var hedef = OS.$('komutHedef').value.trim() || (OS.S.tarama && OS.S.tarama.hedefler && OS.S.tarama.hedefler[0]) || '192.168.1.0/24';
    var portlar = '1-1024';
    var acikPortlar = [];
    if (OS.S.tarama && OS.S.tarama.hostlar) {
      OS.S.tarama.hostlar.forEach(function (h) {
        if (h.ip === hedef || !OS.$('komutHedef').value.trim()) {
          (h.portlar || []).forEach(function (p) { if (acikPortlar.indexOf(p.port) < 0) acikPortlar.push(p.port); });
        }
      });
    }
    var liste = acikPortlar.length ? acikPortlar.slice(0, 40).sort(function (a, b) { return a - b; }).join(',') : portlar;
    var cikti = '';
    if (arac === 'nmap-sV') {
      cikti = '# Servis/versiyon taraması (yalnız izinli hedef)\n' +
        'nmap -sT -sV --version-all -Pn -O --traceroute -p ' + liste + ' ' + hedef + '\n\n' +
        '# Hızlı özet çıktı\n' +
        'nmap -sT -sV -Pn --open ' + hedef + ' -oN tarama-' + hedef.replace(/[^\w]/g, '_') + '.txt';
    } else if (arac === 'nmap-vuln') {
      cikti = '# Zafiyet betikleri (kendi sisteminde / yazılı izinli hedefte)\n' +
        'nmap -sT -sV -Pn --script vuln,default,safe -p ' + liste + ' ' + hedef + '\n\n' +
        '# SMB ve web için hedefli betikler\n' +
        'nmap -Pn --script "smb-vuln-*,http-vuln-*,ssl-*" -p 445,80,443 ' + hedef;
    } else if (arac === 'sigma') {
      cikti = 'title: Cok Sayida Basarisiz Oturum Acma (Brute Force)\n' +
        'id: 8f2c1c9e-ustad-osint-0001\n' +
        'status: experimental\n' +
        'description: Ayni kaynaktan kisa surede cok sayida basarisiz kimlik dogrulama\n' +
        'logsource:\n  product: windows\n  service: security\n' +
        'detection:\n' +
        '  selection:\n    EventID: 4625\n' +
        '  timeframe: 5m\n' +
        '  condition: selection | count() by SourceIp > 8\n' +
        'level: high\n' +
        'tags:\n  - attack.credential_access\n  - attack.t1110\n\n' +
        '# Linux (sshd) icin Sigma esdegeri\n' +
        'logsource:\n  product: linux\n  service: sshd\n' +
        'detection:\n  selection:\n    message: "Failed password"\n' +
        '  condition: selection | count() by src_ip > 8';
    } else if (arac === 'ufw') {
      cikti = '# Kali/Linux — gereksiz servisleri kapat, kalanları kaynakla sınırla\n' +
        'sudo ufw default deny incoming\n' +
        'sudo ufw default allow outgoing\n' +
        'sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp   # SSH yalnız iç ağ\n' +
        (acikPortlar.length ? '# tespit edilen açık portlar için örnek kısıtlar:\n' +
          acikPortlar.slice(0, 8).map(function (p) { return '# sudo ufw allow from 192.168.1.0/24 to any port ' + p; }).join('\n') + '\n' : '') +
        'sudo ufw --force enable\nsudo ufw status verbose\n\n' +
        '# Dinlenen servisleri gör (kapatma kararı için)\nss -tulpn';
    } else {
      cikti = '# Windows — güvenlik duvarı kuralı (PowerShell, yönetici olarak)\n' +
        'New-NetFirewallRule -DisplayName "USTAD-OSINT 445 kisitla" -Direction Inbound -Protocol TCP `\n' +
        '  -LocalPort 445 -RemoteAddress 192.168.1.0/24 -Action Allow\n' +
        'New-NetFirewallRule -DisplayName "USTAD-OSINT 3389 kisitla" -Direction Inbound -Protocol TCP `\n' +
        '  -LocalPort 3389 -RemoteAddress 192.168.1.0/24 -Action Allow\n' +
        'New-NetFirewallRule -DisplayName "USTAD-OSINT 135 kapat" -Direction Inbound -Protocol TCP `\n' +
        '  -LocalPort 135 -Action Block\n\n' +
        '# SMBv1 kapat\n' +
        'Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart\n\n' +
        '# Dinleyen portları listele\n' +
        'Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalAddress,LocalPort,OwningProcess';
    }
    OS.$('komutCikti').textContent = cikti;
  }

  return { kur: kur, veri: veri, ciz: ciz, komut: komut };
})();
