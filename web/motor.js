/* ==========================================================================
   ÜSTAD OSINT — MOTOR (JS tarafı analiz çekirdeği)
   Python arka ucundaki kuralların birebir kopyası. Telefon (APK) sürümünde
   tarama Java köprüsünden gelir, analiz burada yapılır; böylece aynı paneller
   hem PC sunucusunda hem telefonda aynı sonucu üretir.
   ========================================================================== */
var MOTOR = (function () {

  var HIZLI_PORTLAR = [21, 22, 23, 25, 53, 69, 80, 110, 111, 135, 137, 139, 143, 161, 389, 443, 445, 465,
    512, 513, 514, 587, 623, 636, 873, 993, 995, 1025, 1080, 1433, 1521, 1723, 2049,
    2082, 2083, 2181, 2222, 2375, 3000, 3128, 3260, 3306, 3389, 4443, 5000, 5060, 5357,
    5432, 5601, 5672, 5900, 5901, 5984, 5985, 6000, 6379, 7001, 8000, 8008, 8080, 8081,
    8086, 8088, 8090, 8161, 8443, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 9418, 9999,
    10000, 11211, 27017, 27018, 50000, 50070];

  var RISK_TABLOSU = {
    21: ['FTP', 'yuksek', 'FTP kimlik bilgileri şifresiz gider; anonim erişim riski'],
    23: ['Telnet', 'kritik', 'Telnet tüm trafiği açık metin gönderir; yönetim için asla kullanılmamalı'],
    25: ['SMTP', 'orta', 'Açık posta aktarımı spam rölesi olarak kullanılabilir'],
    53: ['DNS', 'orta', 'Açık DNS çözümleyici amplifikasyon saldırılarında kullanılır'],
    69: ['TFTP', 'yuksek', 'Kimlik doğrulaması yok, dosya okuma/yazma açık'],
    111: ['rpcbind', 'orta', 'RPC port eşleyici bilgi sızdırır'],
    135: ['MSRPC', 'orta', 'Windows RPC uç noktası; dış ağa açık olmamalı'],
    137: ['NetBIOS-NS', 'orta', 'NetBIOS ad servisi bilgi sızdırır'],
    139: ['NetBIOS-SSN', 'yuksek', 'SMB oturum servisi; yanal hareket için sık kullanılır'],
    161: ['SNMP', 'yuksek', 'Varsayılan topluluk dizesi cihaz bilgilerini açığa çıkarır'],
    389: ['LDAP', 'orta', 'Dizin servisi; anonim bağlama kapatılmalı'],
    445: ['SMB', 'kritik', 'Fidye yazılımlarının ana yayılma yolu (EternalBlue ailesi)'],
    512: ['rexec', 'kritik', 'Kimlik doğrulaması zayıf uzak komut çalıştırma'],
    513: ['rlogin', 'kritik', 'Kimlik doğrulaması zayıf uzak oturum'],
    514: ['rsh', 'kritik', 'Şifresiz uzak kabuk'],
    873: ['rsync', 'yuksek', 'Anonim modül listeleme/kopyalama riski'],
    1080: ['SOCKS', 'yuksek', 'Açık proxy; trafik yönlendirmesi için kötüye kullanılır'],
    1433: ['MSSQL', 'yuksek', 'Veritabanı doğrudan ağa açık; brute-force hedefi'],
    1521: ['Oracle', 'yuksek', 'Veritabanı doğrudan ağa açık'],
    2049: ['NFS', 'yuksek', 'Paylaşımlar kimlik doğrulamasız bağlanabilir'],
    2375: ['Docker API', 'kritik', 'Kimlik doğrulamasız Docker API = tam sunucu ele geçirme'],
    3306: ['MySQL', 'yuksek', 'Veritabanı doğrudan ağa açık'],
    3389: ['RDP', 'kritik', 'Fidye yazılımlarının en çok kullandığı giriş kapısı; NLA + MFA şart'],
    5060: ['SIP', 'orta', 'VoIP; çağrı sahtekârlığı riski'],
    5432: ['PostgreSQL', 'yuksek', 'Veritabanı doğrudan ağa açık'],
    5900: ['VNC', 'kritik', 'Çoğu kurulumda zayıf/şifresiz ekran erişimi'],
    5901: ['VNC-1', 'kritik', 'Çoğu kurulumda zayıf/şifresiz ekran erişimi'],
    5984: ['CouchDB', 'kritik', 'Kimlik doğrulamasız ise tüm veriler açık'],
    6379: ['Redis', 'kritik', 'Kimlik doğrulamasız Redis = uzaktan kod çalıştırma'],
    9200: ['Elasticsearch', 'kritik', 'Kimlik doğrulamasız ise tüm indeksler açık'],
    11211: ['Memcached', 'kritik', 'Kimlik doğrulama yok; amplifikasyon + veri sızıntısı'],
    27017: ['MongoDB', 'kritik', 'Kimlik doğrulamasız MongoDB = tüm veritabanı açık'],
    50070: ['Hadoop NN', 'kritik', 'Kimlik doğrulamasız HDFS yönetim arayüzü']
  };

  var ONERI = {
    23: 'Telnet yerine SSH kullanın ve 23 numaralı portu kapatın',
    21: 'SFTP/FTPS\'e geçin; ftp anonim erişimini kapatın (anon_upload, anon_mkdir)',
    3389: 'RDP\'yi VPN arkasına alın, NLA zorunlu + MFA; dışarıya 3389 açmayın',
    445: 'SMB\'yi yalnız iç ağa verin; SMBv1\'i kapatın, imzalama ve fidye koruması açın',
    5900: 'VNC\'yi localhost\'a bağlayın veya SSH tünelinden geçirin; güçlü parola şart',
    3306: 'MySQL\'i bind-address ile 127.0.0.1\'e alın; kullanıcı bazlı IP kısıtı ekleyin',
    5432: 'PostgreSQL\'i listen_addresses ile iç ağla sınırlayın; scram-sha-256 kullanın',
    6379: 'Redis\'e requirepass + bind ekleyin; korumalı mod açık kalsın',
    9200: 'Elasticsearch\'te X-Pack güvenliğini açın; 9200\'ü dışarıya kapatın',
    27017: 'MongoDB yetkilendirmeyi açın (authorization: enabled); 27017\'yi dışarıya kapatın',
    11211: 'Memcached\'i localhost\'a bağlayın; UDP kapatın',
    2375: 'Docker API\'yi yalnız TLS + sertifika ile açın; 2375 asla açık olmasın',
    111: 'rpcbind\'i yalnız gerektiğinde ve iç ağda çalıştırın',
    161: 'SNMPv3\'e geçin; public/private topluluk dizelerini değiştirin',
    2049: 'NFS ihracını IP ile sınırlayın, no_root_squash kullanmayın',
    1433: 'MSSQL\'i iç ağa alın; karma kimlik doğrulama ve güçlü parola zorunlu',
    1521: 'Oracle listener\'ı IP ile sınırlayın; gereksiz servisleri kapatın'
  };

  var BANNER_IMZALARI = [
    [/SSH-[\d.]+-([^\s]+)/i, 'SSH'],
    [/^(?:HTTP\/[\d.]+ \d+|<!DOCTYPE|<!doctype|<html)/i, 'HTTP'],
    [/220[ -].*?(?:FTP|ProFTPD|vsFTPd|FileZilla|Microsoft FTP)/i, 'FTP'],
    [/220[ -].*?(?:SMTP|Postfix|Exim|Sendmail|ESMTP)/i, 'SMTP'],
    [/^\+OK.*(?:Dovecot|POP3)/im, 'POP3'],
    [/^\* OK.*(?:IMAP|Dovecot)/im, 'IMAP'],
    [/(?:MySQL|MariaDB).*?(?:native|handshake)/i, 'MySQL'],
    [/(?:Redis|redis_version)/i, 'Redis'],
    [/(?:MongoDB|mongod)/i, 'MongoDB'],
    [/RFB \d+\.\d+/i, 'VNC'],
    [/\x03\x00\x00/, 'RDP'],
    [/(?:SMB|Windows)/i, 'SMB'],
    [/(?:RTSP|Server:)/i, 'RTSP/HTTP'],
    [/(?:Elasticsearch|You Know, for Search)/i, 'Elasticsearch'],
    [/(?:Docker|Api-Version)/i, 'Docker API']
  ];

  var LOG_KURALLARI = [
    [/\b4625\b|failed password|authentication failure|başarısız oturum/i,
      'Başarısız oturum açma', 'orta', 'Kısa sürede çok sayıda başarısız giriş brute-force işaretidir'],
    [/\b4624\b.*?(?:type\s*3|network)/i,
      'Ağ üzerinden oturum açma', 'bilgi', 'Uzak oturum; beklenmeyen kaynak ise inceleyin'],
    [/\b4720\b|useradd|new user|yeni kullanıcı/i,
      'Yeni kullanıcı oluşturma', 'yuksek', 'Yetkisiz kalıcılık (persistence) yöntemidir'],
    [/\b4672\b|special privileges assigned|sudo:.*COMMAND/i,
      'Yetki yükseltme', 'yuksek', 'Ayrıcalıklı yetki ataması; kim, ne zaman doğrulanmalı'],
    [/\b1102\b|audit log (?:was )?cleared|log temizl/i,
      'Denetim günlüğü temizlendi', 'kritik', 'Saldırgan izini silmeye çalışıyor olabilir'],
    [/\b4688\b.*?(?:powershell|cmd\.exe|wscript|certutil|bitsadmin)/i,
      'Şüpheli süreç çalıştırma', 'yuksek', 'İndirme/çalıştırma araçları tespit edildi'],
    [/nmap|masscan|nikto|sqlmap|hydra|gobuster|dirb/i,
      'Tarama aracı izi', 'yuksek', 'Keşif (recon) aşaması göstergesi'],
    [/union\s+select|or\s+1=1|<script>|\.\.\/\.\.\/|%27/i,
      'Web uygulama saldırı kalıbı', 'kritik', 'SQLi / XSS / yol geçişi denemesi'],
    [/segmentation fault|kernel panic|oom-killer/i,
      'Sistem kararsızlığı', 'orta', 'Doğrudan saldırı değil ama hizmet kesintisi riski'],
    [/\b(?:deny|block|drop)\b.*?(?:firewall|iptables|ufw)/i,
      'Güvenlik duvarı müdahalesi', 'bilgi', 'Kural tetiklendi; kaynak IP\'yi izleyin']
  ];

  var IOC_DESENLERI = [
    ['ipv4', /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g],
    ['url', /\bhttps?:\/\/[^\s"'<>)]+/gi],
    ['alan', /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|tr|info|biz|top|xyz|site|online|shop)\b/gi],
    ['eposta', /\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b/gi],
    ['sha256', /\b[a-f0-9]{64}\b/gi],
    ['sha1', /\b[a-f0-9]{40}\b/gi],
    ['md5', /\b[a-f0-9]{32}\b/gi],
    ['cve', /\bCVE-\d{4}-\d{4,7}\b/gi]
  ];

  var ONEM_SIRA = { kritik: 0, yuksek: 1, orta: 2, dusuk: 3, bilgi: 4 };
  var ONEM_ETIKET = { kritik: 'KRİTİK', yuksek: 'YÜKSEK', orta: 'ORTA', dusuk: 'DÜŞÜK', bilgi: 'BİLGİ' };

  /* --------------------------------- yardımcılar --------------------------------- */
  function simdi() {
    var d = new Date(), p = function (n) { return ('0' + n).slice(-2); };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
      p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  function ozelIp(ip) {
    if (!ip) return true;
    var p = String(ip).split('.');
    if (p.length !== 4) return true;
    var a = parseInt(p[0], 10), b = parseInt(p[1], 10);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127 || a === 0 || a >= 224) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }

  function portListesi(mod, ek) {
    var p;
    if (mod === 'web') {
      p = [80, 81, 443, 591, 2082, 2083, 2086, 2087, 2095, 2096, 3000, 4443, 5000, 8000, 8008,
        8080, 8081, 8088, 8090, 8443, 8888, 9000, 9090, 9443, 10000];
    } else if (mod === 'yaygin') {
      p = []; for (var i = 1; i <= 1024; i++) p.push(i);
    } else if (mod === 'tam') {
      p = []; for (var j = 1; j <= 65535; j++) p.push(j);
    } else {
      p = HIZLI_PORTLAR.slice();
    }
    if (ek) {
      String(ek).split(/[,\s]+/).forEach(function (parca) {
        if (!parca) return;
        if (parca.indexOf('-') > 0) {
          var a = parseInt(parca.split('-')[0], 10), b = parseInt(parca.split('-')[1], 10);
          if (!isNaN(a) && !isNaN(b) && b >= a) for (var k = a; k <= b; k++) p.push(k);
        } else if (/^\d+$/.test(parca)) {
          p.push(parseInt(parca, 10));
        }
      });
    }
    var tek = {};
    p.forEach(function (x) { if (x >= 1 && x <= 65535) tek[x] = 1; });
    return Object.keys(tek).map(Number).sort(function (a, b) { return a - b; });
  }

  /* hedef: IP / CIDR / alan adı → IP listesi (alan adı çözümü Java/fetch tarafında) */
  function hedefCoz(metin, cozumHaritasi) {
    metin = String(metin || '').trim();
    if (!metin) return [];
    var ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    var m = metin.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
    if (m) {
      var taban = m[1].split('.').map(Number), bit = parseInt(m[2], 10);
      if (bit < 8 || bit > 32) return [];
      var sayi = (taban[0] << 24 >>> 0) + (taban[1] << 16) + (taban[2] << 8) + taban[3];
      var maske = bit === 0 ? 0 : (0xFFFFFFFF << (32 - bit)) >>> 0;
      var ag = (sayi & maske) >>> 0;
      var toplam = Math.pow(2, 32 - bit);
      var liste = [];
      var bas = (bit >= 31) ? 0 : 1, son = (bit >= 31) ? toplam : toplam - 1;
      for (var i = bas; i < son && liste.length < 4096; i++) {
        var v = (ag + i) >>> 0;
        liste.push([(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.'));
      }
      return liste;
    }
    if (ipv4.test(metin)) {
      var q = metin.split('.').map(Number);
      if (q.some(function (x) { return x > 255; })) return [];
      return [metin];
    }
    if (cozumHaritasi && cozumHaritasi[metin]) return [cozumHaritasi[metin]];
    return [];
  }

  function servisTahmin(port, banner) {
    var b = banner || '';
    var temel = RISK_TABLOSU[port];
    var ad = temel ? temel[0] : 'bilinmeyen';
    for (var i = 0; i < BANNER_IMZALARI.length; i++) {
      if (BANNER_IMZALARI[i][0].test(b)) {
        ad = BANNER_IMZALARI[i][1];
        break;
      }
    }
    var surum = '';
    var m = b.match(/([\w.\-]+)[/ ]([\d][\w.\-]*)/);
    if (m) surum = m[1] + ' ' + m[2];
    return { ad: ad, surum: surum, onem: temel ? temel[1] : 'bilgi', gerekce: temel ? temel[2] : '' };
  }

  function _oneri(port) {
    return ONERI[port] || 'Bu servisi yalnız ihtiyaç halinde açık tutun; güvenlik duvarında kaynak IP kısıtı uygulayın';
  }

  /* ham port kayıtlarını zenginleştir: servis, önem, gerekçe, öneri */
  function hostlariZenginlestir(hamHostlar) {
    return (hamHostlar || []).map(function (h) {
      var portlar = (h.portlar || []).map(function (p) {
        var t = servisTahmin(p.port, p.banner);
        return {
          port: p.port, durum: 'acik', servis: p.servis ? p.servis : t.ad, surum: p.surum || t.surum,
          banner: p.banner || '', tls: !!p.tls, sertifika: p.sertifika || null,
          onem: t.onem, gerekce: t.gerekce, oneri: _oneri(p.port)
        };
      }).sort(function (a, b) { return a.port - b.port; });
      return { ip: h.ip, ad: h.ad || '', isletim: h.isletim || '', portlar: portlar };
    });
  }

  function riskPuani(hostlar) {
    var puan = 0, nedenler = [];
    (hostlar || []).forEach(function (h) {
      var kritik = (h.portlar || []).filter(function (p) { return p.onem === 'kritik'; });
      var yuksek = (h.portlar || []).filter(function (p) { return p.onem === 'yuksek'; });
      if (kritik.length) {
        puan += 18 * kritik.length;
        nedenler.push(h.ip + ': ' + kritik.length + ' kritik servis açık (' +
          kritik.slice(0, 6).map(function (p) { return p.port; }).join(', ') + ')');
      }
      if (yuksek.length) {
        puan += 7 * yuksek.length;
        nedenler.push(h.ip + ': ' + yuksek.length + ' yüksek riskli servis');
      }
      if ((h.portlar || []).length >= 12) {
        puan += 8;
        nedenler.push(h.ip + ': çok sayıda açık port (' + h.portlar.length + ') — gereksiz servisleri kapatın');
      }
    });
    return { puan: Math.min(100, puan), nedenler: nedenler.slice(0, 12) };
  }

  function alarmUret(hostlar, taramaId) {
    var alarmlar = [], sayac = 1;
    function ekle(host, port, servis, onem, baslik, aciklama, kanit, oneri) {
      alarmlar.push({
        id: String(taramaId).slice(0, 6) + '-A' + ('00' + sayac).slice(-3),
        zaman: simdi(), host: host, port: port, servis: servis, onem: onem,
        onemEtiket: ONEM_ETIKET[onem] || String(onem).toUpperCase(),
        baslik: baslik, aciklama: aciklama, kanit: kanit, oneri: oneri,
        durum: 'yeni', yanlisPozitif: false
      });
      sayac++;
    }
    (hostlar || []).forEach(function (h) {
      (h.portlar || []).forEach(function (p) {
        var port = p.port, bilgi = RISK_TABLOSU[port];
        if (bilgi) {
          ekle(h.ip, port, p.servis || '', bilgi[1],
            bilgi[0] + ' (' + port + ') açık — ' + (ONEM_ETIKET[bilgi[1]] || bilgi[1]),
            bilgi[2], 'banner: ' + ((p.banner || '').slice(0, 160) || '(yanıt yok)'), _oneri(port));
        }
        if (p.banner && /(?:login|admin|default password|root:)/i.test(p.banner)) {
          ekle(h.ip, port, p.servis || '', 'yuksek', 'Yönetim/giriş arayüzü tespit edildi',
            'Banner metni giriş arayüzü işaret ediyor; varsayılan parola denemesi ve erişim kısıtı kontrol edilmeli',
            p.banner.slice(0, 200),
            'Arayüzü VPN/iç ağ ile sınırlayın, MFA ekleyin, varsayılan parolaları değiştirin');
        }
        if (p.tls) {
          ekle(h.ip, port, p.servis || '', 'bilgi', 'TLS hizmeti doğrulandı',
            'Şifreli servis dinliyor; sertifika geçerliliği ve sürüm kontrol edilmeli',
            'sertifika: ' + JSON.stringify(p.sertifika || null).slice(0, 200),
            'TLS 1.2+ zorlayın; sertifika süresi ve zayıf takas algoritmalarını denetleyin');
        }
      });
    });
    return alarmlar;
  }

  function iocCikar(hostlar, alarmlar) {
    var bulunan = {};
    function ekle(tur, deger, kaynak) {
      var anahtar = tur + '|' + String(deger).toLowerCase();
      if (!bulunan[anahtar]) bulunan[anahtar] = { tur: tur, deger: deger, kaynak: [], ilk: simdi() };
      if (bulunan[anahtar].kaynak.indexOf(kaynak) < 0) bulunan[anahtar].kaynak.push(kaynak);
    }
    function tara(metin, kaynak, tavan) {
      if (!metin) return;
      IOC_DESENLERI.forEach(function (cift) {
        var tur = cift[0], desen = cift[1];
        desen.lastIndex = 0;
        var m, n = 0;
        while ((m = desen.exec(metin)) !== null && n < tavan) {
          n++;
          var deger = m[0];
          if (tur === 'ipv4' && ozelIp(deger)) continue;
          ekle(tur, deger, kaynak);
          if (desen.lastIndex === m.index) desen.lastIndex++;
        }
      });
    }
    (hostlar || []).forEach(function (h) {
      ekle('ipv4', h.ip, 'tarama:' + h.ip);
      (h.portlar || []).forEach(function (p) {
        tara(((p.banner || '') + ' ' + (p.surum || '')), h.ip + ':' + p.port, 6);
      });
    });
    (alarmlar || []).forEach(function (a) { tara(a.kanit || '', a.id, 4); });
    return Object.keys(bulunan).map(function (k) { return bulunan[k]; })
      .sort(function (a, b) { return (a.tur + a.deger).localeCompare(b.tur + b.deger); });
  }

  function graf(hostlar, yerelIp) {
    var dugumler = [], kenarlar = [];
    dugumler.push({ id: 'self', tip: 'merkez', ad: 'ANALİZ NOKTASI', ip: yerelIp || '127.0.0.1', risk: 0 });
    (hostlar || []).forEach(function (h, i) {
      var kid = 'h' + i;
      var agirlik = { kritik: 34, yuksek: 20, orta: 10, dusuk: 5, bilgi: 1 };
      var deg = (h.portlar || []).reduce(function (t, p) { return t + (agirlik[p.onem] || 3); }, 0);
      dugumler.push({
        id: kid, tip: 'cihaz', ad: h.ad || h.ip, ip: h.ip, risk: Math.min(100, deg),
        portSayisi: (h.portlar || []).length, isletim: h.isletim || ''
      });
      kenarlar.push({ kaynak: 'self', hedef: kid, tip: 'ağ' });
      (h.portlar || []).forEach(function (p, j) {
        var sid = kid + 'p' + j;
        dugumler.push({
          id: sid, tip: 'servis', ad: (p.servis || 'bilinmeyen') + ' ' + p.port, ip: h.ip,
          port: p.port, servis: p.servis, onem: p.onem, riskli: (p.onem === 'kritik' || p.onem === 'yuksek'),
          tls: !!p.tls
        });
        kenarlar.push({ kaynak: kid, hedef: sid, tip: p.onem || 'bilgi' });
      });
    });
    return { dugumler: dugumler, kenarlar: kenarlar };
  }

  /* --------------------------------- LOG / SIEM --------------------------------- */
  function logCoz(metin, kaynakAdi) {
    var satirlar = String(metin || '').split(/\r?\n/).filter(function (s) { return s.trim(); });
    var olaylar = [], bulgular = [], sayac = {};
    satirlar.slice(0, 20000).forEach(function (satir, i) {
      var ipM = satir.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      var zM = satir.match(/(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);
      var oM = satir.match(/\b(4\d{3}|11\d{2}|5\d{3})\b/);
      var kayit = {
        satir: i + 1, zaman: zM ? zM[1] : '', ip: ipM ? ipM[0] : '', olayId: oM ? oM[1] : '',
        kural: '', onem: '', metin: satir.slice(0, 400)
      };
      for (var k = 0; k < LOG_KURALLARI.length; k++) {
        var ku = LOG_KURALLARI[k];
        if (ku[0].test(satir)) {
          kayit.kural = ku[1]; kayit.onem = ku[2];
          var anahtar = ku[1] + '|' + kayit.ip;
          sayac[anahtar] = (sayac[anahtar] || 0) + 1;
          if (sayac[anahtar] === 1) {
            bulgular.push({
              zaman: kayit.zaman || simdi(), onem: ku[2], onemEtiket: ONEM_ETIKET[ku[2]],
              baslik: ku[1], ip: kayit.ip, olayId: kayit.olayId, aciklama: ku[3],
              kanit: satir.slice(0, 300), adet: 1
            });
          }
          break;
        }
      }
      olaylar.push(kayit);
    });
    bulgular.forEach(function (b) { b.adet = sayac[b.baslik + '|' + b.ip] || 1; });
    bulgular.forEach(function (b) {
      if (b.adet >= 8 && (b.onem === 'orta' || b.onem === 'dusuk')) {
        b.onem = 'kritik'; b.onemEtiket = 'KRİTİK';
        b.aciklama += ' · Aynı kaynaktan ' + b.adet + ' tekrar: otomatik blok önerilir';
      }
    });
    var iocler = [], gorulen = {};
    IOC_DESENLERI.forEach(function (cift) {
      var tur = cift[0], desen = cift[1];
      desen.lastIndex = 0;
      var m, n = 0;
      while ((m = desen.exec(String(metin || ''))) !== null && n < 80) {
        var deger = m[0];
        if (desen.lastIndex === m.index) desen.lastIndex++;
        if (tur === 'ipv4' && ozelIp(deger)) continue;
        var anahtar = tur + '|' + deger.toLowerCase();
        if (gorulen[anahtar]) continue;
        gorulen[anahtar] = 1; n++;
        iocler.push({ tur: tur, deger: deger, kaynak: [kaynakAdi || 'yapıştırılan metin'] });
      }
    });
    var kuralSayac = {}, ipSayac = {};
    olaylar.forEach(function (o) {
      if (o.kural) kuralSayac[o.kural] = (kuralSayac[o.kural] || 0) + 1;
      if (o.ip) ipSayac[o.ip] = (ipSayac[o.ip] || 0) + 1;
    });
    return {
      satirSayisi: satirlar.length, olaylar: olaylar, bulgular: bulgular, iocler: iocler,
      ozet: {
        kaynak: kaynakAdi || 'yapıştırılan metin', satir: satirlar.length,
        kuralSayaci: Object.keys(kuralSayac).map(function (k) { return [k, kuralSayac[k]]; })
          .sort(function (a, b) { return b[1] - a[1]; }),
        enCokIp: Object.keys(ipSayac).map(function (k) { return [k, ipSayac[k]]; })
          .sort(function (a, b) { return b[1] - a[1]; }).slice(0, 10),
        kritik: bulgular.filter(function (b) { return b.onem === 'kritik'; }).length,
        yuksek: bulgular.filter(function (b) { return b.onem === 'yuksek'; }).length
      }
    };
  }

  /* tek çağrıda tüm analiz: ham hostlar → panel nesnesi parçaları */
  function analiz(hamHostlar, taramaId, yerelIp) {
    var hostlar = hostlariZenginlestir(hamHostlar);
    var alarmlar = alarmUret(hostlar, taramaId);
    var iocler = iocCikar(hostlar, alarmlar);
    var r = riskPuani(hostlar);
    return {
      hostlar: hostlar, alarmlar: alarmlar, iocler: iocler,
      risk: r.puan, riskNedenleri: r.nedenler, graf: graf(hostlar, yerelIp)
    };
  }

  return {
    portListesi: portListesi, hedefCoz: hedefCoz, servisTahmin: servisTahmin,
    hostlariZenginlestir: hostlariZenginlestir, riskPuani: riskPuani, alarmUret: alarmUret,
    iocCikar: iocCikar, graf: graf, analiz: analiz, logCoz: logCoz,
    ozelIp: ozelIp, simdi: simdi, ONEM_ETIKET: ONEM_ETIKET, ONEM_SIRA: ONEM_SIRA,
    RISK_TABLOSU: RISK_TABLOSU, ONERI: ONERI
  };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = MOTOR;
