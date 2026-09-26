# -*- coding: utf-8 -*-
"""index.html'e resimdeki OSINT süitini ekler: eylem şeridi, menü grubu, 17 panel, künye."""
import io, os, re

YOL = r"C:\Users\kenan\Downloads\Programs\PROJELERİM\USTAD-OSINT PC\web\index.html"
s = io.open(YOL, encoding="utf-8").read()

# ------------------------------------------------------------------ 1) CSS
if "osint.css" not in s:
    s = s.replace('<link rel="stylesheet" href="stil.css">',
                  '<link rel="stylesheet" href="stil.css">\n<link rel="stylesheet" href="osint.css">')

# ------------------------------------------------------- 2) üst eylem şeridi
EYLEM = '''
<!-- ============================== EYLEM ŞERİDİ ============================== -->
<div class="eylemSerit" id="eylemSerit">
  <div class="esAd">
    <div class="amblem" style="width:38px;height:38px"><span class="amblemHalka"></span></div>
    <div>
      <b>ÜSTAD OSINT</b>
      <span>Open Source Intelligence</span>
    </div>
  </div>
  <button class="esDug" data-git="scan"><i>🎯</i>SCAN</button>
  <button class="esDug" data-git="analyze"><i>🔍</i>ANALYZE</button>
  <button class="esDug" data-git="discover"><i>🧭</i>DISCOVER</button>
  <button class="esDug" data-git="map"><i>🗺️</i>MAP</button>
  <button class="esDug" data-git="report"><i>📄</i>REPORT</button>
  <div class="esKisi">
    <img src="foto-kurucu.png" alt="Üstad Kenan Kuzucu">
    <div>
      <b>Üstad Kenan Kuzucu</b>
      <span>OSINT Araştırmacısı</span>
    </div>
  </div>
</div>
'''
if 'class="eylemSerit"' not in s:
    s = s.replace('</header>', '</header>\n' + EYLEM, 1)

# ------------------------------------------------------------ 3) menü grupları
MENU = ['<div class="menuGrup">// OSINT MODÜLLERİ</div>']
OS_MENU = [
    ("osint", "🎛️", "#2d7dff", "OSINT GÖSTERGE"),
    ("osarama", "🔎", "#37e0ff", "OSINT ARAMA"),
    ("domain", "🌐", "#4f9dff", "DOMAIN KEŞFİ"),
    ("subdomain", "🧩", "#8b5cf6", "SUBDOMAIN TARAMA"),
    ("ipasn", "📡", "#2ee6a8", "IP / ASN ANALİZİ"),
    ("whois", "📋", "#ffc107", "WHOIS / RDAP"),
    ("dns", "🗂️", "#00d4a0", "DNS ANALİZİ"),
    ("eposta", "✉️", "#ff8f00", "E-POSTA İSTİHBARATI"),
    ("sosyal", "👥", "#ff5470", "SOSYAL MEDYA"),
    ("kullanici", "🧍", "#e879f9", "KULLANICI ADI ARAMA"),
    ("github", "🐙", "#a9c2d6", "GITHUB İSTİHBARATI"),
    ("webtek", "🧬", "#22d3ee", "WEB TEKNOLOJİLERİ"),
    ("cloud", "☁️", "#60a5fa", "CLOUD KEŞFİ"),
    ("sizinti", "💧", "#f43f5e", "VERİ SIZINTISI TESPİTİ"),
    ("darkweb", "🕶️", "#7c3aed", "DARK WEB ARAMA"),
    ("tehdit", "🔥", "#ef4444", "TEHDİT HARİTASI"),
    ("osrapor", "📑", "#d4af37", "RAPORLAR"),
]
for pid, ikon, renk, ad in OS_MENU:
    MENU.append('<button class="menuDug" data-panel="%s" style="--renk:%s"><i>%s</i><span>%s</span><b id="say-%s"></b></button>'
                % (pid, renk, ikon, ad, pid))
MENU.append('<div class="menuGrup">// AĞ &amp; SOC KONSOLU</div>')
if '// OSINT MODÜLLERİ' not in s:
    s = s.replace('<div class="menuBaslik">// PANELLER</div>', "\n    ".join(MENU), 1)

# --------------------------------------------------------------- 4) künye
KUNYE_ESKI = re.search(r'<div class="kunye">.*?</div>\s*</div>', s, re.S)
if KUNYE_ESKI:
    s = s.replace(KUNYE_ESKI.group(0),
                  '<div class="kunyeBuyuk">\n'
                  '      <img src="foto-kurucu.png" alt="Üstad Kenan Kuzucu">\n'
                  '      <b>Üstad Kenan Kuzucu</b>\n'
                  '      <span>OSINT Araştırmacısı</span>\n'
                  '      <em>“Bilgi, gücün en temiz halidir.”</em>\n'
                  '    </div>', 1)
    # sürüm yazısını korumak için ayrı satır
if 'surumYazi' not in s:
    s = s.replace('<div class="menuYasal">',
                  '<div class="kunyeSurum" style="text-align:center;font-size:10.5px;color:var(--soluk)">'
                  'v<span id="surumYazi">1.2</span> · yerel çalışır</div>\n      <div class="menuYasal">', 1)

# --------------------------------------------------- 5) OSINT panelleri (HTML)
SEKME_HTML = """
    <!-- ============================ OSINT GÖSTERGE ============================ -->
    <section class="panel" id="p-osint">
      <div class="sekmeler" id="osSekmeler">
        <button class="sekme sec" data-sekme="hizli">Hızlı Tarama</button>
        <button class="sekme" data-sekme="detay">Detaylı Analiz</button>
        <button class="sekme" data-sekme="ozel">Özel Arama</button>
        <button class="sekme" data-sekme="toplu">Toplu Tarama</button>
        <button class="sekme" data-sekme="rapor">Rapor Oluştur</button>
      </div>

      <div class="araAlan">
        <div class="araSatir">
          <div class="araKutu">
            <i>🌐</i>
            <input type="text" id="osHedef" placeholder="example.com · 8.8.8.8 · https://site.com" autocomplete="off">
          </div>
          <button class="araDug" id="osBasla">▶ TARAMA BAŞLAT</button>
        </div>
        <div class="modKutular" id="osModuller">
          <label class="modKutu"><input type="checkbox" data-mod="subdomain" checked> Subdomain</label>
          <label class="modKutu"><input type="checkbox" data-mod="dns" checked> DNS</label>
          <label class="modKutu"><input type="checkbox" data-mod="whois" checked> WHOIS</label>
          <label class="modKutu"><input type="checkbox" data-mod="ip" checked> IP/ASN</label>
          <label class="modKutu"><input type="checkbox" data-mod="sosyal"> Sosyal Medya</label>
          <label class="modKutu"><input type="checkbox" data-mod="github"> GitHub</label>
          <label class="modKutu"><input type="checkbox" data-mod="sizinti" checked> Veri Sızıntısı</label>
          <label class="modKutu"><input type="checkbox" data-mod="cloud" checked> Cloud</label>
          <label class="modKutu"><input type="checkbox" data-mod="tehdit" checked> Tehdit</label>
          <label class="modKutu"><input type="checkbox" id="osTumModul"> Tüm Modüller</label>
        </div>
        <div id="osIlerleme" style="display:none">
          <div class="ilerlemeCizgi"><i id="osIlerlemeCubuk" style="width:6%"></i></div>
          <div class="sonucYazi" id="osIlerlemeYazi">hazırlanıyor…</div>
        </div>
      </div>

      <div class="osKartlar" id="osKartlar">
        <div class="osKart" style="--ton:#4f9dff"><div class="osIkon">🌐</div><div><div class="deger" id="osSaySubdomain">0</div><div class="ad">Subdomain</div><div class="alt">keşfedildi</div></div></div>
        <div class="osKart" style="--ton:#2ee6a8"><div class="osIkon">📇</div><div><div class="deger" id="osSayIp">0</div><div class="ad">IP Adresi</div><div class="alt">tespit edildi</div></div></div>
        <div class="osKart" style="--ton:#ff5470"><div class="osIkon">🔌</div><div><div class="deger" id="osSayServis">0</div><div class="ad">Açık Servis</div><div class="alt">bulundu</div></div></div>
        <div class="osKart" style="--ton:#8b5cf6"><div class="osIkon">✉️</div><div><div class="deger" id="osSayEposta">0</div><div class="ad">E-posta</div><div class="alt">keşfedildi</div></div></div>
        <div class="osKart" style="--ton:#ff8f00"><div class="osIkon">📄</div><div><div class="deger" id="osSaySizinti">0</div><div class="ad">Veri Sızıntısı</div><div class="alt">tespit edildi</div></div></div>
        <div class="osKart" style="--ton:#60a5fa"><div class="osIkon">☁️</div><div><div class="deger" id="osSayCloud">0</div><div class="ad">Cloud Servis</div><div class="alt">bulundu</div></div></div>
      </div>

      <div class="osIzgara">
        <div class="osKutu">
          <div class="osKutuBaslik"><i>🕸️</i> Saldırı Yüzeyi Haritası <span class="sag" id="osGrafNot">bekliyor</span></div>
          <div class="osHarita" id="osGrafKap"><canvas id="osGraf"></canvas></div>
        </div>
        <div class="osKutu">
          <div class="osKutuBaslik"><i>🌍</i> Dünya Haritası — IP Konumları <span class="sag" id="osHaritaNot">bekliyor</span></div>
          <div class="osHarita" id="osHaritaKap">
            <canvas id="osHarita"></canvas>
            <div class="ulkeListe" id="osUlkeListe"></div>
          </div>
        </div>
      </div>

      <div class="osIzgara uc">
        <div class="osKutu">
          <div class="osKutuBaslik"><i>📑</i> Son Bulunan Bulgular <span class="sag" id="osBulguNot">0 kayıt</span></div>
          <div class="osKutuGovde" id="osBulgular"><div class="osIskelet">Henüz tarama yapılmadı.</div></div>
        </div>
        <div class="osKutu">
          <div class="osKutuBaslik"><i>🧬</i> Teknolojiler <span class="sag" id="osTekNot">0</span></div>
          <div class="osKutuGovde" id="osTeknoloji"><div class="osIskelet">—</div></div>
        </div>
        <div class="osKutu">
          <div class="osKutuBaslik"><i>🔌</i> Açık Portlar <span class="sag" id="osPortNot">0</span></div>
          <div class="osKutuGovde" id="osPortlar"><div class="osIskelet">—</div></div>
        </div>
      </div>

      <div class="raporSerit">
        <button class="rapDug" id="osRaporHtml">📄 HTML Rapor</button>
        <button class="rapDug" id="osRaporJson">🗂️ JSON Veri</button>
        <button class="rapDug" id="osRaporCsv">📊 CSV Verisi</button>
        <button class="rapDug" id="osRaporEkran">🖼️ Ekran Görüntüsü</button>
        <button class="rapDug ana" id="osRaporTum">📄 TÜM SONUÇLARI RAPORLA</button>
      </div>
    </section>
"""

MODULLER = [
    ("osarama", "🔎", "#37e0ff", "OSINT Arama", "Hedef hakkında tüm modülleri tek seferde çalıştırır", "alan adı, IP veya URL", True),
    ("domain", "🌐", "#4f9dff", "Domain Keşfi", "Alan adının DNS kayıtları, WHOIS özeti ve web durumu", "ornek.com", True),
    ("subdomain", "🧩", "#8b5cf6", "Subdomain Tarama", "Sertifika şeffaflığı ve pasif DNS kaynaklarıyla alt alan keşfi", "ornek.com", True),
    ("ipasn", "📡", "#2ee6a8", "IP / ASN Analizi", "Konum, ISS, ASN, ağ bloğu, proxy/hosting göstergeleri", "8.8.8.8", False),
    ("whois", "📋", "#ffc107", "WHOIS / RDAP", "Tescil bilgileri, kayıtçı, ad sunucuları, süre ve askı durumu", "ornek.com", True),
    ("dns", "🗂️", "#00d4a0", "DNS Analizi", "A, AAAA, MX, TXT, NS, SOA, CAA, SRV kayıtları + SPF/DMARC denetimi", "ornek.com", True),
    ("eposta", "✉️", "#ff8f00", "E-posta İstihbaratı", "MX, SPF, tek kullanımlık servis, rol hesabı, Gravatar izi", "isim@ornek.com", False),
    ("sosyal", "👥", "#ff5470", "Sosyal Medya", "Kullanıcı adının platformlardaki varlığı ve profil bağlantıları", "kullanici_adi", False),
    ("kullanici", "🧍", "#e879f9", "Kullanıcı Adı Arama", "25+ platformda hesap varlığı (durum + içerik işareti)", "kullanici_adi", False),
    ("github", "🐙", "#a9c2d6", "GitHub İstihbaratı", "Profil, depolar, diller, kurumlar ve commit e-posta sızıntısı", "torvalds", False),
    ("webtek", "🧬", "#22d3ee", "Web Teknolojileri", "Sunucu, CMS, dil, analitik, güvenlik başlıkları ve TLS sertifikası", "https://site.com", True),
    ("cloud", "☁️", "#60a5fa", "Cloud Keşfi", "S3 / GCS / Azure kova varlık ve açıklık kontrolü", "ornek.com", True),
    ("sizinti", "💧", "#f43f5e", "Veri Sızıntısı Tespiti", "Açık .env/.git/yedek/konfig probu — yumuşak 404 ayıklamalı", "https://site.com", True),
    ("darkweb", "🕶️", "#7c3aed", "Dark Web Arama", "Sızıntı kaydı sorgusu (HIBP anahtarı) + dork bağlantıları", "isim@ornek.com", False),
    ("tehdit", "🔥", "#ef4444", "Tehdit Haritası", "Botnet C2, phishing ve ele geçirilmiş sistem beslemeleri", "boş bırak — tüm beslemeler", False),
]
PANELLER = [SEKME_HTML]
for pid, ikon, renk, ad, aciklama, yer, zorunlu in MODULLER:
    PANELLER.append("""
    <!-- ---------------------------- %s ---------------------------- -->
    <section class="panel" id="p-%s">
      <div class="modBaslik" style="--ton:%s">
        <div class="mIkon">%s</div>
        <div><h2>%s</h2><p>%s</p></div>
      </div>
      <div class="modForm">
        <input type="text" id="%sGirdi" placeholder="%s" autocomplete="off">
        <button class="modDug" id="%sDug">▶ ÇALIŞTIR</button>
        <span class="sonucYazi" id="%sDurum"></span>
      </div>
      <div class="osKutu"><div class="osKutuBaslik"><i>📊</i> Sonuçlar <span class="sag" id="%sOzet"></span></div>
        <div class="osKutuGovde" id="%sSonuc"><div class="osIskelet">Sonuç bekleniyor…</div></div></div>
    </section>
""" % (ad, pid, renk, ikon, ad, aciklama, pid, yer, pid, pid, pid, pid))
PANELLER.append("""
    <!-- ---------------------------- RAPORLAR ---------------------------- -->
    <section class="panel" id="p-osrapor">
      <div class="modBaslik" style="--ton:#d4af37">
        <div class="mIkon">📑</div>
        <div><h2>Raporlar</h2><p>Tarama ve OSINT bulgularını belgeye dönüştür</p></div>
      </div>
      <div class="osIzgara">
        <div class="osKutu"><div class="osKutuBaslik"><i>🧾</i> Kayıtlı taramalar</div>
          <div class="osKutuGovde" id="osRaporListe"><div class="osIskelet">yükleniyor…</div></div></div>
        <div class="osKutu"><div class="osKutuBaslik"><i>📦</i> OSINT özeti</div>
          <div class="osKutuGovde" id="osRaporOzet"><div class="osIskelet">Henüz OSINT taraması yapılmadı.</div></div></div>
      </div>
      <div class="raporSerit">
        <button class="rapDug" id="osRaporHtml2">📄 HTML Rapor</button>
        <button class="rapDug" id="osRaporJson2">🗂️ JSON Veri</button>
        <button class="rapDug" id="osRaporCsv2">📊 CSV Verisi</button>
        <button class="rapDug ana" id="osRaporTum2">📄 TÜM SONUÇLARI RAPORLA</button>
      </div>
    </section>
""")
if 'id="p-osint"' not in s:
    s = s.replace('  </main>', "".join(PANELLER) + '  </main>', 1)

# ------------------------------------------------------------------ 6) betik
if 'osint.js' not in s:
    s = s.replace('<script src="kopru.js"></script>',
                  '<script src="kopru.js"></script>\n<script src="osint.js"></script>')

io.open(YOL, "w", encoding="utf-8").write(s)
print("index.html güncellendi:", len(s), "bayt")
for anahtar in ['eylemSerit', "// OSINT MODÜLLERİ", 'id="p-osint"', 'id="p-tehdit"', 'id="p-osrapor"', 'osint.js', 'osint.css', 'kunyeBuyuk']:
    print("  ", anahtar, "→", anahtar in s)
