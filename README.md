<div align="center">

# 🛡️ ÜSTAD OSINT
### Blue Team SOC Konsolu · Yerel Ağ Görünürlüğü · Açık Kaynak İstihbarat

**Tek arayüz — üç platform:** 🖥️ Windows (PC) · 🐉 Kali Linux (WSL) · 📱 Android (APK)

`49 panel` · `21 OSINT modülü` · `8 ek araç` · `12 yeni nesil araç` · `15 tema` · `3D katman`

© 2026 **Kenan Kuzucu** · Tüm hakları saklıdır · 5846 FSEK

</div>

---

## 📖 Bu nedir?

**ÜSTAD OSINT**, kendi bilgisayarınızı ve kendi alan adlarınızı **savunma amacıyla** izleyen
bir güvenlik konsoludur. İnternetteki hazır "hacker paneli" taklitlerinin aksine:

- **Uydurma veri üretmez.** Her panel gerçek bir kaynaktan beslenir; kaynak anahtar istiyorsa
  "anahtar gerekli" der, sahte kayıt basmaz.
- **Kendi ağınıza ve kendi alan adlarınıza bakar.** Dışarıyı taramaz (izinsiz tarama TCK 243/244).
- **Her panelde "Ne işe yarar + Örnek" kutusu vardır.** Aracı kullanmak için uzman olmak gerekmez.
- **Haritalarda renk anahtarı vardır.** Her haritanın/grafiğin altında "hangi renk ne demek" kutusu
  bulunur: risk ölçeği (kırmızı kritik → turuncu → sarı → yeşil), C2 / tehdit IOC / nötr noktalar,
  kendi konumun, iklim kuşağı renkleri ve akan sinyalin yönü açıkça yazılır.
- **Yaptığı her iddiayı ölçülebilir kanıtla söyler** (aşağıdaki "doğrulanmış sonuçlar" bölümü gerçek çıktılardır).

---

## 🚀 12 yeni nesil araç (v1.6)

| # | Araç | Ne işe yarar | Doğrulanmış örnek (gerçek çıktı) |
|---|------|--------------|----------------------------------|
| 1 | 🚨 **Aktif istismar radarı** | Bir CVE gerçekten saldırıda kullanılıyor mu? (CISA KEV + FIRST EPSS) | `CVE-2021-44228` → KEV: **evet**, EPSS **1.0** → *"ACİL — aktif istismar ediliyor"* |
| 2 | 📧 **E-posta sahtecilik kalkanı** | SPF / DKIM / DMARC denetimi + kopyalanacak doğru DNS kaydı | `ustadkenankuzucu.com.tr` → 80/100 · DMARC **p=none** (sahte mail serbest) → `p=quarantine` önerisi |
| 3 | 🔎 **Mail başlığı adli analizi** | Şüpheli mail gerçek mi, sahte mi? (çevrimdışı çözümleme) | Sahte örnek → **risk 100/100** · SPF fail · Reply-To başka alan adı |
| 4 | 📜 **Sertifika şeffaflık logu (CT)** | Haberiniz olmadan açılmış alt alan adları | 2 sertifika · 3 alan adı · yeni açılanlar **YENİ** işaretli |
| 5 | 🛡️ **Web yapılandırma denetimi** | Açıkta kalan `.env`/`.git`, gereksiz HTTP metotları, eksik güvenlik başlıkları, çerez bayrakları + **NGINX/htaccess düzeltme satırları** | 70/100 · açık hassas dosya **0** · 6 eksik başlık |
| 6 | 🕵️ **Fidye yazılımı radarı** | Sızdırılan kurban listesi: sektör, grup, teslim tarihi | 100 kurban · en aktif grup **qilin** · Türkiye: 0 (o anki gerçek) |
| 7 | 🌍 **Canlı saldırı akışı** | Dünyada en çok saldıran IP'ler + haritada **akan sinyaller** | 20 IP · **1.630.575** saldırı raporu · 1. sıra `13.94.254.200` (Amsterdam) |
| 8 | 🔑 **Kod sır avcısı** | Projelerinize gömülü kalmış API anahtarı/şifre avı (değerler maskeli) | Kendi projelerimde 0 bulgu · kontrol dosyasında AWS+OpenAI+MySQL → **2 kritik + 1 yüksek** yakalandı |
| 9 | 📶 **Yerel ağ cihazları** | Modeme bağlı cihazlar + **yeni cihaz** uyarısı | 7 cihaz görüldü · 192.168.1.1 TP-Link · yeni cihazda uyarı |
| 10 | 🔐 **Şifre sızıntı kontrolü** | Şifreniz bir sızıntıda görülmüş mü? (HIBP k-anonymity — şifre cihazdan çıkmaz) | `123456` → **210.461.208** kayıt · güçlü şifre → 0 |
| 11 | 🖨️ **Rapor paketi** | Renkli Word belgesi / yazdırılabilir HTML + QR kod + **SHA-256 kanıt mührü** | 38.431 baytlık `.docx` üretildi (kanıt özetiyle) |
| 12 | 🔔 **Olay & bildirim merkezi** | Yeni port / yeni kritik CVE olayında masaüstü + WhatsApp haberi | Her 30 dakikada otomatik kontrol |

### v1.5 ek araçları (8 modül)
Pasif radar (Shodan InternetDB) · CVE eşleme (NVD + CIRCL) · Arşiv geçmişi (Wayback CDX) ·
urlscan.io · Alt alan ele geçirme (takeover) · Savunma kuralları (Firewall üretimi) ·
Toplu tarama · Kanıt zinciri (SHA-256) · **DEĞİŞİM (FARK) paneli** ·
günlük otomatik HTML raporu (Hermes zamanlanmış görevi).

---

## 🗺️ Haritalar: ultra gerçekçi ve **hareketli**

Dünya ve tehdit haritaları tek motordan çizilir (`web/harita-gercek.js`):

- Okyanus derinlik gradyanı + sonar ızgarası
- Enlem bazlı **iklim paleti** (kutup buzu → tayga → çöl → ekvator ormanı)
- Işıyan kıyı şeridi, gece/gündüz terminatörü, vinyet
- **Akan sinyaller:** her saldırgan IP'den ağınıza doğru kuyruklu ışık paketleri + çarpan radar halkaları
- Animasyon yalnız panel açıkken çalışır (arka planda durur), kare başına tuval ayırmaz

**Ölçüm:** karelerin **%5–7'si** değişiyor (hareket gerçek), 129+ farklı renk kümesi (düz dolgu değil).

---

## 🎨 Görünüm

- **15 tema** — hacker paletleri (Matris `#00ff66`, Terminal `#ffb400`, Neon `#00ffe7`, Zifiri `#00a6ff`) ve **QD-OLED 4K** teması
- **Her modül kendi renginde** yazı + simge (panel renk uyumu)
- **3D katman:** perspektifli zemin ızgarası, kartlarda fare ile eğilme, madalyon parallaksı, kod yağmuru
- Keskin 4K tipografi (ağırlık + mono rakamlar + anti-aliasing)
- Altın **ÜSTAD madalyon amblemi** (animasyonlu altın halka)

---

## 🖥️ Kurulum ve çalıştırma

### Windows (PC) — tek tık
```
USTAD-OSINT-BASLAT.bat   →   menü: 1) Konsolu aç  2) Tarama  3) nmap kur  4) Rapor
```
Elle: `python ustad-osint.py --port 8787` → `http://127.0.0.1:8787`
Arayüzsüz tarama: `python ustad-osint.py --tarama 192.168.1.0/24 --mod hizli --rapor cikti.txt`

### Kali Linux (WSL)
```bash
./kali-baslat.sh          # nmap 7.99 kontrolü + konsol
```

### Android (APK)
İndirme merkezi: **https://kenankuzucu.github.io/ustad-apk-indir/**
Sürüm 1.6 (kod 6) · minSdk 21 (Android 5+) · imzalı (`CN=Ustad Kenan Kuzucu`)
Kurulumda Play Protect uyarısı çıkarsa "Yine de yükle" deyin.

---

## ✅ Doğrulanmış sonuçlar (bu makinede ölçüldü)

| Ölçüm | Sonuç |
|---|---|
| Yerel ağ taraması (192.168.1.0/24) | 254 hedef · 56 canlı · 4 cihaz · 12 açık port · 7 alarm (2 kritik) · 4 IOC · risk 50/100 |
| Kendi alan adlarım | `ustadkenankuzucu.com.tr` + `ustadcyber.com.tr` → risk 11/100 · 8 port · 4 CVE · 1 kritik |
| Tehdit beslemeleri | 5 C2 · 300 phishing · 679 ele geçirilmiş sistem · 1.710 Spamhaus CIDR · 123.240 skorlu IP · 14.345 zararlı URL |
| CVE akışı | Son hafta 2.520 CVE (NVD) |
| Panel sayısı | 49 panel / 49 menü düğmesi · **0 JavaScript hatası** |
| Python ↔ JS parite | Masaüstü (Python) ve APK (JavaScript) motoru **birebir** aynı sonuç (EPSS, DMARC puanı, sızıntı sayısı, kanıt özeti) |
| APK bütünlüğü | **30/30 asset** kaynakla birebir (sha256) |

---

## ⚠️ Dürüst sınırlar (uydurma yok)

- **APK'da çalışmayan iki araç:** 🔑 kod sır avcısı (Android'de dosya sistemi erişimi yok) ve
  📶 yerel ağ cihazları (`arp` komutu yok). Panel *"bu araç masaüstü sürümünde çalışır"* der, sahte sonuç üretmez.
- **Rapor paketi** telefonda Word yerine HTML önizlemesi verir (dosya sistemi yok).
- **certspotter ücretsiz kotası** sertifika panelinde zaman zaman *"kota sınırı (HTTP 429)"* hatası gösterir;
  `crt.sh` zaten sık sık 502 döner. Kalıcı çözüm: ücretsiz API anahtarı.
- **HIBP veri sızıntısı modülü** API anahtarı ister; anahtarsız çalışan **Pwned Passwords** kullanılır.
- **SMTP e-posta doğrulaması** Türkiye'de 25. port kapalı olduğu için yapılmaz → MX + servis izi kullanılır.
- **Kaspersky HTTPS denetimi** yapan makinelerde `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE` ayarı gerekir
  (`ca-bundle.pem`), aksi hâlde Node testleri sertifika hatası verir; uygulama kodunu etkilemez.

---

## ⚖️ YASAL UYARI

Bu yazılım **yalnızca kendi ağınızda ve kendi alan adlarınızda** kullanılmak üzere yazılmıştır.
Başkasına ait sistemleri izinsiz taramak, test etmek veya veri toplamak:

> **Türk Ceza Kanunu madde 243** (bilişim sistemine girme) ve **madde 244** (sistemi engelleme, bozma, verileri yok etme)
> kapsamında **suçtur**. Ayrıca 5651 sayılı kanun ve KVKK düzenlemeleri geçerlidir.

Kapsam dışı alan adları için program panelleri *"kapsam dışı — yalnız kendi alan adlarınız taranır"* diyerek
işlemi durdurur. Sorumluluk kullanıcıdadır.

---

## 🏗️ Mimari

```
ustad-osint.py            → HTTP sunucu (tek dosya, yalnız Python stdlib) + /api/* uç noktaları
osint-araclar.py          → 21 OSINT modülü + uç yönlendirici (uclari_isle)
osint-ek.py               → v1.5 ek araçları (8 modül)
osint-ek2a/b/c.py         → v1.6 yeni nesil araçlar (12 modül)
gunluk-rapor.py           → günlük otomatik tarama + DEĞİŞİM raporu
bildirim-tara.py          → olay tarayıcı (yeni port / yeni CVE / risk değişimi)
web/                      → arayüz: index.html, stil.css, cekirdi.js + modül JS/CSS'leri
  ├── motor-osint.js      → Python çekirdeğinin JavaScript kopyası (APK için) — 5.090 satır
  ├── ek2.js / ek2.css    → 12 yeni nesil panel
  ├── harita-gercek.js    → ultra gerçekçi + hareketli harita motoru
  └── panel-renk.css      → modül renk uyumu
araclar/build-osint-konsol.sh → APK derleme (Gradle'sız: aapt2 + javac + d8 + apksigner)
araclar/cdp-test.py       → başsız Chrome ile arayüz testi (kanıt üretir)
```

**Üç katmanlı APK mimarisi** (telefonda Python yok):
1. Java köprüsü — ağ istekleri ve TLS
2. `motor-osint.js` — analiz/istihbarat kurallarının JS kopyası (gerçek internete köprüden çıkar)
3. `kopru.js` — `/api/*` isteklerini Java + motora yönlendirir

**Panel ekleme kalıbı:** `<section class="panel" id="p-X" style="--ton:#renk">` + `<button class="menuDug" data-panel="X">`
→ düğmeler HTML'de statik olmalı (JS ile sonradan eklenen düğme tıklamaya cevap vermez).

---

## 🧪 Kanıt üretme (bu projede kural)

```bash
# 1) Arayüzü başsız Chrome ile sınar, ekran görüntüsü bırakır
python araclar/cdp-test.py "http://127.0.0.1:8787/#istismar" test.js ekran.png 240

# 2) Python ↔ JS parite karşılaştırması
node ek2-parite-test.js          # motor-osint.js ↔ Python uçları birebir mi

# 3) APK bütünlüğü: her asset kaynakla birebir mi
python -c "import zipfile,io,os; z=zipfile.ZipFile('build/USTAD-OSINT-v1.6.apk'); ..."
```

Kural: bir iş **bitirilmeden önce ölçülür**. Ekran görüntüsü + sayısal ölçüm + uzaktan doğrulama.

---

## 📜 Sürüm geçmişi

| Sürüm | Öne çıkanlar |
|---|---|
| **v1.6** | 12 yeni nesil araç, 49 panel, kod sır avcısı, fidye radarı, canlı saldırı akışı (hareketli harita), QR'lı Word raporu, olay bildirimleri, APK v1.6 (30/30 asset) |
| v1.5 | 8 ek araç, DEĞİŞİM (FARK) paneli, günlük otomatik rapor, ultra gerçekçi hareketli haritalar, panel renk uyumu |
| v1.4 | QD-OLED 4K teması, keskin tipografi, 15 tema |
| v1.3 | Altın ÜSTAD madalyon kimliği, hacker temaları, 3D katman |
| v1.2 | 18 modüllü OSINT süiti, dünya haritası, saldırı yüzeyi grafiği |
| v1.0–1.1 | Ağ/SOC konsolu (11 panel), yerel ağ taraması, risk motoru, APK |

---

<div align="center">

**ÜSTAD OSINT** · Kenan Kuzucu · Gaziantep / Türkiye

*"Kendi evini bilmeyen, başkasının kapısını koruyamaz."*

© 2026 TÜM HAKLARI SAKLIDIR · 5846 FSEK

</div>
