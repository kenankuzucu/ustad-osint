# -*- coding: utf-8 -*-
"""ÜSTAD OSINT v1.6 — YENİ NESİL ARAÇLAR: 12 paneli + menü grubunu index.html'e ekler.
Idempotent: ikinci çalıştırmada hiçbir şey eklemez."""
import io
import os

KOK = os.path.dirname(os.path.abspath(__file__))
YOL = os.path.join(KOK, "web", "index.html")

MENU = """    <div class="menuGrup">// YENİ NESİL ARAÇLAR (v1.6)</div>
    <button class="menuDug" data-panel="istismar" style="--renk:#ef4444"><i>🚨</i><span>AKTİF İSTİSMAR RADARI</span><b id="say-istismar"></b></button>
    <button class="menuDug" data-panel="postaguv" style="--renk:#37e0ff"><i>📧</i><span>E-POSTA KALKANI</span><b id="say-postaguv"></b></button>
    <button class="menuDug" data-panel="baslik" style="--renk:#f59e0b"><i>🔎</i><span>MAİL BAŞLIĞI ANALİZİ</span><b id="say-baslik"></b></button>
    <button class="menuDug" data-panel="sertifika" style="--renk:#c084fc"><i>📜</i><span>SERTİFİKA LOGU (CT)</span><b id="say-sertifika"></b></button>
    <button class="menuDug" data-panel="webzaf" style="--renk:#22c55e"><i>🛡️</i><span>WEB YAPILANDIRMA</span><b id="say-webzaf"></b></button>
    <button class="menuDug" data-panel="fidye" style="--renk:#ff2d55"><i>🕵️</i><span>FİDYE YAZILIMI RADARI</span><b id="say-fidye"></b></button>
    <button class="menuDug" data-panel="saldiri" style="--renk:#ff8f00"><i>🌍</i><span>CANLI SALDIRI AKIŞI</span><b id="say-saldiri"></b></button>
    <button class="menuDug" data-panel="siravc" style="--renk:#d4af37"><i>🔑</i><span>KOD SIR AVCISI</span><b id="say-siravc"></b></button>
    <button class="menuDug" data-panel="yerelag" style="--renk:#4da3ff"><i>📶</i><span>YEREL AĞ CİHAZLARI</span><b id="say-yerelag"></b></button>
    <button class="menuDug" data-panel="sifrekontrol" style="--renk:#00ffa3"><i>🔐</i><span>ŞİFRE SIZINTI KONTROLÜ</span><b id="say-sifrekontrol"></b></button>
    <button class="menuDug" data-panel="raporpaket" style="--renk:#ffb400"><i>🖨️</i><span>RAPOR PAKETİ (WORD/QR)</span><b id="say-raporpaket"></b></button>
    <button class="menuDug" data-panel="bildirim" style="--renk:#8b5cf6"><i>🔔</i><span>OLAY &amp; BİLDİRİM</span><b id="say-bildirim"></b></button>
"""

PANELLER = """

    <!-- ==================== v1.6 YENİ NESİL ARAÇLAR ==================== -->

    <section class="panel" id="p-istismar" style="--ton:#ef4444">
      <div class="panelBaslik">
        <h2>🚨 AKTİF İSTİSMAR RADARI</h2>
        <p>CVE <b>gerçekten kullanılıyor mu?</b> CISA KEV (aktif istismar listesi) + FIRST EPSS (istismar olasılığı)</p>
      </div>
      <div class="e2Ipucu"><b>Ne işe yarar?</b> Zafiyet listeleri çok CVE yazar; bunlardan hangisinin <b>gerçekten saldırıda
        kullanıldığını</b> söyler. KEV'de olan CVE acil yamanmalıdır; EPSS yüzdesi 30 gün içindeki istismar olasılığıdır.
        <span class="ornek">Örnek: CVE-2024-3094 → EPSS %86 · yüzdelik 99.7 → "hemen yamala"</span>
        <span class="ornek">Virgülle çok CVE: CVE-2021-44228, CVE-2023-44487, CVE-2022-22965</span></div>
      <div class="e2Satir">
        <input class="e2Girdi genis" id="e2CveGirdi" placeholder="CVE-2024-3094" value="CVE-2024-3094">
        <button class="dug" id="e2CveDug">🚨 İSTİSMAR DURUMUNU SORGULA</button>
      </div>
      <div id="e2IstismarSonuc"><div class="e2Alt">Sorgu bekleniyor…</div></div>
    </section>

    <section class="panel" id="p-postaguv" style="--ton:#37e0ff">
      <div class="panelBaslik">
        <h2>📧 E-POSTA SAHTECİLİK KALKANI</h2>
        <p>SPF · DKIM · DMARC denetimi — biri senin adına sahte mail atabiliyor mu?</p>
      </div>
      <div class="e2Ipucu"><b>Ne işe yarar?</b> Alan adınızın e-posta kimlik doğrulamasını denetler. DMARC politikası
        <b>none</b> ise sahte mailler hiçbir engelle karşılaşmadan gelen kutunuza düşebilir (müşterinize sizin adınıza
        yazılabilir). Panel, kopyalayıp yapıştıracağınız doğru kaydı da verir.
        <span class="ornek">Örnek: ustadkenankuzucu.com.tr → SPF var, DMARC p=none → "p=quarantine yap" önerisi</span></div>
      <div class="e2Satir">
        <input class="e2Girdi genis" id="e2PostaGirdi" placeholder="alan-adi.com" value="ustadkenankuzucu.com.tr">
        <button class="dug" id="e2PostaDug">📧 POSTA GÜVENLİĞİNİ DENETLE</button>
      </div>
      <div id="e2PostaSonuc"><div class="e2Alt">Sorgu bekleniyor…</div></div>
    </section>

    <section class="panel" id="p-baslik" style="--ton:#f59e0b">
      <div class="panelBaslik">
        <h2>🔎 MAİL BAŞLIĞI ADLİ ANALİZİ</h2>
        <p>Şüpheli mailin başlıklarını yapıştır — sahte mi, gerçek mi?</p>
      </div>
      <div class="e2Ipucu"><b>Ne işe yarar?</b> Mail uygulamasında "Kaynağı göster / Özgün iletiyi indir" ile aldığınız
        başlıkları buraya yapıştırırsınız. Program SPF/DKIM/DMARC sonucunu, gerçek gönderen IP'yi, sunucu zincirini ve
        gecikmeleri çıkarıp <b>sahte olabilir</b> kararı verir. Cevap yazmadan önce kesin bilgi.
        <span class="ornek">Örnek: Reply-To farklı alan adı + SPF fail → risk 85/100 ("YÜKSEK — sahte olabilir")</span></div>
      <div class="e2Satir"><textarea class="e2Alan" id="e2BaslikAlan" placeholder="From: &quot;ÜSTAD SALON&quot; <bilgi@ornek.com>&#10;Return-Path: <...>&#10;Received: from ...&#10;Authentication-Results: ..."></textarea></div>
      <div class="e2Satir"><button class="dug" id="e2BaslikDug">🔎 BAŞLIKLARI ÇÖZÜMLE</button>
        <span class="e2Not">hiçbir veri sunucuya kaydedilmez · çözümleme cihazınızda yapılır</span></div>
      <div id="e2BaslikSonuc"><div class="e2Alt">Başlık bekleniyor…</div></div>
    </section>

    <section class="panel" id="p-sertifika" style="--ton:#c084fc">
      <div class="panelBaslik">
        <h2>📜 SERTİFİKA LOGU (CT) — ALT ALAN KEŞFİ</h2>
        <p>Sertifika şeffaflık loglarındaki tüm alan adları; crt.sh çöktüğünde yedek kaynak</p>
      </div>
      <div class="e2Ipucu"><b>Ne işe yarar?</b> Her HTTPS sertifikası halka açık loglara yazılır — sizin haberiniz olmadan
        açılmış alt alanlar orada görünür. Yeni çıkan adlar (<b>YENİ</b>) uyarı sebebidir.
        <span class="ornek">Örnek: ustadkenankuzucu.com.tr → 2 sertifika, 6 ad (wildcard dahil)</span></div>
      <div class="e2Satir">
        <input class="e2Girdi genis" id="e2SertGirdi" placeholder="alan-adi.com" value="ustadkenankuzucu.com.tr">
        <button class="dug" id="e2SertDug">📜 SERTİFİKA LOGLARINI TARA</button>
      </div>
      <div id="e2SertSonuc"><div class="e2Alt">Sorgu bekleniyor…</div></div>
    </section>

    <section class="panel" id="p-webzaf" style="--ton:#22c55e">
      <div class="panelBaslik">
        <h2>🛡️ WEB YAPILANDIRMA DENETİMİ</h2>
        <p>Yalnız <b>kendi alan adlarınız</b> — hassas dosya sızıntısı, HTTP metotları, CORS, güvenlik başlıkları</p>
      </div>
      <div class="e2Ipucu"><b>Ne işe yarar?</b> Sitenizde açıkta kalmış <span class="e2Mono">.env</span>/<span class="e2Mono">.git</span>
        gibi dosyaları, gereksiz açık HTTP metotlarını ve eksik güvenlik başlıklarını (HSTS, CSP, X-Frame) bulur; ardından
        <b>NGINX ve .htaccess</b> için kopyala-yapıştır düzeltme satırlarını verir.
        <span class="ornek">Örnek: /.env → HTTP 403 (kapalı ✔) · eksik: strict-transport-security, x-frame-options</span></div>
      <div class="e2Satir">
        <input class="e2Girdi genis" id="e2WebGirdi" placeholder="kendi alan adınız" value="ustadkenankuzucu.com.tr">
        <button class="dug" id="e2WebDug">🛡️ YAPILANDIRMAYI DENETLE</button>
        <span class="e2Not">kapsam: veri/izleme.json listesi (kendi alan adlarınız)</span>
      </div>
      <div id="e2WebSonuc"><div class="e2Alt">Sorgu bekleniyor…</div></div>
    </section>

    <section class="panel" id="p-fidye" style="--ton:#ff2d55">
      <div class="panelBaslik">
        <h2>🕵️ FİDYE YAZILIMI RADARI</h2>
        <p>Son kurbanlar: kim, hangi sektör, hangi grup, teslim tarihi</p>
      </div>
      <div class="e2Ipucu"><b>Ne işe yarar?</b> Fidye gruplarının sızdırdığı kurban listesini gösterir. Kendi sektörünüzde
        hareket var mı, hangi grup aktif, hangi ülkeler hedefte — hepsini görürsünüz. Saldırı gelmeden önce tedbir alma sebebi.
        <span class="ornek">Örnek: 24 saatte 100 kurban · "Technology" sektörü · grup N0n · teslim 2026-09-28</span></div>
      <div class="e2Satir">
        <input class="e2Girdi" id="e2FidyeUlke" placeholder="ülke kodu (TR) — boş = hepsi">
        <button class="dug" id="e2FidyeDug">🕵️ SON KURBANLARI GETİR</button>
      </div>
      <div id="e2FidyeSonuc"><div class="e2Alt">Sorgu bekleniyor…</div></div>
    </section>

    <section class="panel" id="p-saldiri" style="--ton:#ff8f00">
      <div class="panelBaslik">
        <h2>🌍 CANLI SALDIRI AKIŞI</h2>
        <p>Dünyada şu an en çok saldıran IP'ler (SANS ISC DShield) — haritada sinyaller canlı akar</p>
      </div>
      <div class="e2Ipucu"><b>Ne işe yarar?</b> Küresel sensör ağına gelen gerçek saldırı raporlarını listeler; harita
        üzerinde her saldırgan IP'den ağınıza doğru <b>akan sinyalleri</b> gösterir. "Tehdit sadece bize gelmiyor,
        dünya sürekli taranıyor" gerçeğini gözle görülür hâle getirir.
        <span class="ornek">Örnek: 13.94.254.200 → 319.739 saldırı raporu (1. sırada)</span></div>
      <div class="e2Satir">
        <button class="dug" id="e2SaldiriDug">🌍 AKIŞI YENİLE</button>
        <label class="onay"><input type="checkbox" id="e2SaldiriOto"> 60 saniyede bir otomatik yenile</label>
      </div>
      <div class="e2HaritaKap" id="e2SaldiriKap"><canvas id="e2SaldiriHarita"></canvas></div>
      <div id="e2SaldiriSonuc"><div class="e2Alt">Sorgu bekleniyor…</div></div>
    </section>

    <section class="panel" id="p-siravc" style="--ton:#d4af37">
      <div class="panelBaslik">
        <h2>🔑 KOD SIR AVCISI</h2>
        <p>Bilgisayarınızdaki projelerde açıkta kalmış API anahtarı / şifre avı (değerler maskelenir)</p>
      </div>
      <div class="e2Ipucu"><b>Ne işe yarar?</b> Kod içine gömülü kalmış anahtarları bulur — bunlar sızarsa hesabınız
        ele geçirilir. Bulunan değer yalnız ilk 4 + son 4 karakter olarak gösterilir; program size "şu anahtarı iptal et,
        şuraya taşı" der.
        <span class="ornek">Örnek: proje/ayar.py:12 → GitHub token · ghp_1a2b…9f0c · kritik</span></div>
      <div class="e2Satir">
        <input class="e2Girdi genis" id="e2SirGirdi" placeholder="taranacak klasör" value="C:/Users/kenan/OneDrive/Desktop">
        <label class="onay"><input type="checkbox" id="e2SirGithub"> GitHub depolarımı da tara</label>
        <button class="dug" id="e2SirDug">🔑 SIRLARI ARA</button>
      </div>
      <div id="e2SirSonuc"><div class="e2Alt">Sorgu bekleniyor…</div></div>
    </section>

    <section class="panel" id="p-yerelag" style="--ton:#4da3ff">
      <div class="panelBaslik">
        <h2>📶 YEREL AĞ CİHAZLARI</h2>
        <p>Modeminize bağlı cihazlar (ARP + UPnP) · yeni bağlanan cihaz uyarısı</p>
      </div>
      <div class="e2Ipucu"><b>Ne işe yarar?</b> Ağınıza bağlı cihazları IP/MAC ve üretici adıyla listeler; ilk kez görülen
        cihazı <b>YENİ</b> diye işaretler. Komşu wifi şifrenizi bulmuş mu, eski cihaz hâlâ bağlı mı — buradan anlarsınız.
        <span class="ornek">Örnek: 192.168.1.1 · aa:bb:.. · TP-Link · router.local</span></div>
      <div class="e2Satir"><button class="dug" id="e2AgDug">📶 AĞI TARA</button>
        <span class="e2Not">ARP tablosu + UPnP keşfi (3 sn) · hiçbir paket ağa gönderilmez</span></div>
      <div id="e2AgSonuc"><div class="e2Alt">Sorgu bekleniyor…</div></div>
    </section>

    <section class="panel" id="p-sifrekontrol" style="--ton:#00ffa3">
      <div class="panelBaslik">
        <h2>🔐 ŞİFRE SIZINTI KONTROLÜ</h2>
        <p>Şifreniz herhangi bir sızıntıda görülmüş mü? (şifre cihazdan çıkmaz — k-anonymity)</p>
      </div>
      <div class="e2Ipucu"><b>Ne işe yarar?</b> Şifreniz geçmiş bir sızıntıda yer aldıysa saldırganlar onu listelerde
        deniyor demektir. Buradaki kontrol <b>şifrenizi göndermez</b>: yalnızca özetinin ilk 5 karakteri gider, karşılaştırma
        cihazınızda yapılır (HIBP k-anonymity).
        <span class="ornek">Örnek: "123456" → milyonlarca sızıntı kaydı · entropi çok düşük · zayıf</span></div>
      <div class="e2Satir">
        <input class="e2Girdi genis" id="e2SifreGirdi" type="password" placeholder="kontrol edilecek şifre (kaydedilmez)">
        <button class="dug" id="e2SifreDug">🔐 SIZINTIDA ARA</button>
        <button class="dug" id="e2SifreUret">🎲 GÜÇLÜ ŞİFRE ÜRET</button>
      </div>
      <div id="e2SifreSonuc"><div class="e2Alt">Şifre bekleniyor…</div></div>
    </section>

    <section class="panel" id="p-raporpaket" style="--ton:#ffb400">
      <div class="panelBaslik">
        <h2>🖨️ RAPOR PAKETİ (WORD / HTML + QR)</h2>
        <p>Renkli Word belgesi veya yazdırılabilir HTML · SHA-256 kanıt mührü + QR kod</p>
      </div>
      <div class="e2Ipucu"><b>Ne işe yarar?</b> Ekrandaki sonuçları işyerine/müşteriye verilecek düzenli bir belgeye
        çevirir. Belgenin SHA-256 özeti ve QR kodu basılır — sonradan değiştirilmediğini kanıtlar.
        <span class="ornek">Örnek: 2026-09-25-1630-rapor.docx → Masaüstü\\USTAD-OSINT-RAPORLAR (42 KB, QR ekli)</span></div>
      <div class="e2Satir">
        <input class="e2Girdi genis" id="e2RaporBaslik" placeholder="rapor başlığı" value="ÜSTAD OSINT Tarama Raporu">
        <button class="dug" id="e2RaporWord">📄 WORD BELGESİ ÜRET</button>
        <button class="dug" id="e2RaporHtml">🖨️ HTML RAPOR ÜRET</button>
      </div>
      <div id="e2RaporSonuc"><div class="e2Alt">Rapor bekleniyor…</div></div>
    </section>

    <section class="panel" id="p-bildirim" style="--ton:#8b5cf6">
      <div class="panelBaslik">
        <h2>🔔 OLAY &amp; BİLDİRİM MERKEZİ</h2>
        <p>Hangi olaylarda haber verilsin · masaüstü bildirimi · WhatsApp'a gönderim</p>
      </div>
      <div class="e2Ipucu"><b>Ne işe yarar?</b> "Yeni port açıldı / yeni kritik CVE çıktı" gibi olaylarda masaüstü bildirimi
        ve WhatsApp mesajı alırsınız. Zamanlanmış görev her 30 dakikada yeni olayları kontrol eder; telefonunuzda olmasanız
        bile haberdar olursunuz.
        <span class="ornek">Örnek: 16:42 · yeni_port · "8080 portu açıldı (192.168.1.1)" · kritik</span></div>
      <div id="e2BildirimSonuc"><div class="e2Alt">Ayarlar yükleniyor…</div></div>
    </section>
"""

ISARET = "<!-- v1.6 panelleri -->"


def main():
    s = io.open(YOL, encoding="utf-8").read()
    eklendi = []
    if 'id="p-istismar"' not in s:
        # 1) menü: "MİNİ TERMİNAL" düğmesinden sonra yeni grup
        for capa in ('<button class="menuDug" data-panel="kanit"', '<button class="menuDug" data-panel="terminal"'):
            j = s.find(capa)
            if j > 0:
                # düğmenin bulunduğu satırın SONUNA ekle
                satir_sonu = s.find("\n", j)
                s = s[:satir_sonu + 1] + MENU + s[satir_sonu + 1:]
                eklendi.append("menu")
                break
        # 2) paneller: </main> öncesi
        s = s.replace("  </main>", ISARET + PANELLER + "  </main>", 1)
        eklendi.append("paneller")
    # 3) css/js bağlantıları
    if "ek2.css" not in s:
        s = s.replace('<link rel="stylesheet" href="ek.css">',
                      '<link rel="stylesheet" href="ek.css">\n<link rel="stylesheet" href="ek2.css">', 1)
        eklendi.append("ek2.css")
    if "ek2.js" not in s:
        s = s.replace('<script src="ek.js"></script>',
                      '<script src="ek.js"></script>\n<script src="ek2.js"></script>', 1)
        eklendi.append("ek2.js")
    io.open(YOL, "w", encoding="utf-8", newline="").write(s)
    h = io.open(YOL, encoding="utf-8").read()
    print("eklenen:", ", ".join(eklendi) if eklendi else "hiçbir şey (zaten var)")
    print("panel sayısı:", h.count('<section class="panel"'), "| menü düğmesi:", h.count("menuDug"))
    print("kontrol → p-istismar:", h.count('id="p-istismar"'), "p-bildirim:", h.count('id="p-bildirim"'),
          "| ek2.css:", h.count("ek2.css"), "| ek2.js:", h.count("ek2.js"))


if __name__ == "__main__":
    main()
