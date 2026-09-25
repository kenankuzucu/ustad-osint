# ÜSTAD OSINT v1.0 — Saldırı Yüzeyi ve Blue Team SOC Konsolu

Yerel çalışan, **tek arayüzlü** ağ görünürlüğü ve savunma konsolu.
PC (Windows), Kali Linux (WSL veya gerçek Kali) ve Android (APK) üzerinde aynı arayüz.

```
USTAD-OSINT\
├─ ustad-osint.py          → arka uç + tarama motoru (tek dosya, sadece Python stdlib)
├─ USTAD-OSINT-BASLAT.bat  → Windows başlatıcı (çift tıkla)
├─ kali-baslat.sh          → Kali başlatıcı (bash kali-baslat.sh)
├─ arac-harita.py          → dünya haritası katmanını üretir (gerektiğinde)
├─ web\
│   ├─ index.html          → 11 panel
│   ├─ stil.css            → 10 tema
│   ├─ cekirdi.js          → çekirdek + gösterge paneli
│   ├─ tarama.js           → tarama merkezi
│   ├─ yuzey.js            → saldırı yüzeyi haritası (canlı grafik)
│   ├─ dunya.js            → dünya haritası (IP konum)
│   ├─ alarm.js            → alarm & triyaj + IOC kasası
│   ├─ log.js              → log / SIEM analizi
│   ├─ olay.js             → olay müdahalesi + zafiyet & öneri + komut üretici
│   ├─ rapor.js            → rapor & kanıt (sha256)
│   ├─ ayar.js             → ayarlar & kapsam onayı
│   └─ dunya-kara.png      → çevrimdışı dünya haritası katmanı (17 KB)
└─ assets\                 → harita kaynağı (geojson) + önizleme
```

## Çalıştırma

### Windows (PC)
`USTAD-OSINT-BASLAT.bat` dosyasına çift tıkla → menüden seç:
1. Yalnız bu bilgisayardan erişim (önerilen)
2. Telefon/tablet de bağlansın (yerel ağa açılır — adres ekranda yazar)
3. nmap durumunu kontrol et + kurulum bilgisi

Elle: `python ustad-osint.py --port 8787`

### Kali Linux
```bash
chmod +x kali-baslat.sh
./kali-baslat.sh          # yalnız yerel
./kali-baslat.sh --ag     # ağdaki diğer cihazlar da bağlanabilsin
```
nmap Kali'de genelde kuruludur. Değilse:
```bash
sudo apt update && sudo apt install -y nmap
```
nmap bulunursa motor otomatik nmap'e geçer; yoksa yerleşik soket motoru kullanılır
(aynı panel, aynı alarmlar; nmap servis/versiyon bilgisini daha zengin verir).

### nmap kurulumu (Windows)
1. https://nmap.org/download.html → `nmap-7.9x-setup.exe`
2. Kurulumda **Npcap** seçeneğini de kur
3. Kurulumdan sonra pencereyi kapat/aç
4. Paket yöneticisiyle: `winget install Insecure.Nmap`

## Paneller (11)

| # | Panel | Ne yapar |
|---|-------|----------|
| 1 | **Gösterge Paneli** | Risk halkası, açık port/cihaz/alarm/IOC sayaçları, servis dağılımı, son alarmlar |
| 2 | **Saldırı Yüzeyi Haritası** | Merkez → cihaz → servis düğümleri; risk ısısı renge yansır, düğüme tıklayınca detay |
| 3 | **Tarama Merkezi** | Gerçek TCP taraması; canlı ilerleme, cihaz listesi, log akışı, iptal |
| 4 | **Alarm & Triyaj** | Önem sıralı alarmlar; durum: yeni → incelendi → kapandı / yanlış pozitif |
| 5 | **IOC Kasası** | IP, alan adı, URL, e-posta, karma (hash) iz göstergeleri; JSON kopyala |
| 6 | **Dünya Haritası** | Konumların küre üzerinde işareti; kendi çıkış IP'n "bu cihaz" olarak işaretli |
| 7 | **Log / SIEM Analizi** | auth.log, syslog, Windows olay satırlarını çözer; kural eşleşmesi, tekrar sayısı, en çok IP |
| 8 | **Olay Müdahalesi** | 6 adımlı müdahale akışı; zaman çizelgesi; tarama verisinden otomatik görev listesi |
| 9 | **Zafiyet & Öneri** | Açık port → risk gerekçesi + sertleştirme önerisi; nmap/Sigma/güvenlik duvarı komut üretici |
| 10 | **Rapor & Kanıt** | Yönetici özeti + kanıt zinciri (sha256); TXT/JSON indir, PDF olarak yazdır |
| 11 | **Ayarlar & Kapsam** | Kapsam onayı (zorunlu), izinli hedefler, sistem durumu, tema |

## Tarama modları
- **hizli** — ~100 yaygın port (varsayılan, hızlı)
- **web** — 80/443 odaklı web portları
- **yaygin** — 1-1024
- **tam** — 1-65535 (yavaş; nmap varsa nmap ile)

Hedef olarak IP (`192.168.1.108`), CIDR (`192.168.1.0/24`) veya alan adı verilebilir.
`192.168.1.0/24` gibi ağ taramalarında önce canlı cihaz keşfi yapılır, sonra yalnız
canlı cihazların portları taranır.

## Doğrulanmış gerçek sonuç (bu makinede)
Kendi yerel ağında (192.168.1.0/24) yapılan tarama:
```
Cihaz            : 4
Açık port        : 12
Alarm            : 7 (kritik 2)
IOC              : 4
Yüzey risk puanı : 50/100
  192.168.1.1   → 53 DNS, 80 HTTP, 139 NetBIOS, 443 HTTPS, 445 SMB(KRİTİK)
  192.168.1.100 → 80 HTTP
  192.168.1.108 → 135 MSRPC, 139 NetBIOS, 445 SMB(KRİTİK)
  192.168.1.109 → 8008, 8443, 9000
```

## Gizlilik ve internet
- Tarama **tamamen yerel**: veri hiçbir yere gönderilmez.
- Yalnız **IP konum** çözümlemesi için `ipwho.is` adresine IP sorgusu gider (harita işaretleri).
  İnternet yoksa konsol çalışmaya devam eder; harita "yerel adres" der.
- Dünya haritası katmanı **dosyadan** çizilir (çevrimdışı çalışır).

## YASAL UYARI
Bu araç yalnız **sahibi olduğun** sistemlerde veya **yazılı izin aldığın** sistemlerde
kullanılmak üzere tasarlandı. Arayüz, tarama başlatmadan önce "kapsam onayı" ister ve
bu onay arka uçta da zorunludur. İzinsiz tarama Türkiye'de TCK 243/244 kapsamında suçtur.

## ANDROID APK (aynı arayüz, telefonda kendi taraması)

`USTAD-OSINT-v1.0.apk` — 611 KB · paket `tr.com.ustadkenankuzucu.osint` · Android 5.0+ (minSdk 21)

- Telefonda **kendi soket motoruyla** gerçek tarama yapar (PC'ye ihtiyaç yok).
  - Java motor: `Tarayici.java` (port tarama + banner + TLS sertifika okuma)
  - Analiz: `web/motor.js` — Python kurallarının birebir kopyası
    (doğrulandı: 8 ölçütün 8'i Python ile **aynı sonucu** verdi)
  - Köprü: `web/kopru.js` — `/api` çağrılarını Java'ya yönlendirir
- Kurulum: APK'yı telefona kopyala → dokun → "bilinmeyen kaynak" iznini ver.
  - Kurulmazsa: **Play Store → profil → Play Protect → ⚙ → "Uygulamaları Play Protect ile tara" KAPAT**
- Rapor dosyaları: Dosya Yöneticisi → **İndirilenler/KENAN-OSINT/**

### Doğrulananlar (APK)
| Ölçüt | Sonuç |
|---|---|
| assets ↔ kaynak sha256 | 18/18 birebir aynı |
| classes.dex içinde motor | `taramaYap` / `yerelBilgi` / `adCoz` var |
| Java motoru gerçek ağda | 192.168.1.1 → 5 açık port, Python ile **aynı** (53/80/139/443/445) |
| Arayüz + köprü taraması | 4 cihaz · 12 port · 7 alarm (2 kritik) · 4 IOC · risk 50/100 |
| Dünya haritası (köprü ile) | 88.242.202.232 · Şahinbey/Türkiye işaretlendi |
| Telefon ölçüsü 412×915 | yatay taşma yok, menü kaydırılabilir, kartlar 2 kolon |

---

# v1.2 — OSINT SÜİTİ (resimdeki 18 modüllü panelin aynısı)

Masaüstündeki **ÜSTAD OSINT Konsolu** kısayoluna çift tıkla → menü → **OSINT MODÜLLERİ**.

## Ne var?
| # | Modül | Gerçek kaynak |
|---|---|---|
| 1 | OSINT Gösterge | 6 istatistik kartı · saldırı yüzeyi grafiği · dünya haritası · bulgular · teknolojiler · açık portlar · rapor şeridi |
| 2 | OSINT Arama | Bir aramada modüllerin tamamı |
| 3 | Domain Keşfi | ip-api · dns.google · RDAP |
| 4 | Subdomain Tarama | api.subdomain.center · hackertarget |
| 5 | IP / ASN Analizi | ip-api.com (+ ipwho.is yedeği) |
| 6 | WHOIS / RDAP | rdap.org |
| 7 | DNS Analizi | dns.google (A·AAAA·MX·TXT·NS·CNAME·SOA) |
| 8 | E-posta İstihbaratı | MX + SPF/DMARC + servis izleri |
| 9 | Sosyal Medya | platform varlık taraması |
| 10 | Kullanıcı Adı Arama | 29 platform, **canlı testle doğrulanmış** kurallar |
| 11 | GitHub İstihbaratı | api.github.com (profil + depolar + dil) |
| 12 | Web Teknolojileri | gerçek HTTP başlıkları + imza taraması |
| 13 | Cloud Keşfi | S3 · GCS · Azure kova adı kontrolü |
| 14 | Veri Sızıntısı | açık .env/.git/config yolu probu + HIBP (anahtar) |
| 15 | Dark Web Arama | takas/veri sızıntısı kaynak izleri |
| 16 | Tehdit Haritası | Feodo · OpenPhish · EmergingThreats · Spamhaus DROP · ipsum · URLhaus · Phishing Army · NVD CVE |
| 17 | Raporlar | HTML · JSON · CSV · özet görseli (PNG) · TÜM SONUÇLARI RAPORLA |
| 18 | Ayarlar | GitHub/HIBP anahtarı, önbellek, kapsam onayı |

## Ölçülen sonuçlar (gerçek, 2026-09-25)
* 12/12 modül gerçek veri döndürüyor; tarayıcı konsolunda **0 hata**
* Subdomain: **547** (github.com) · **350** (nmap.org) · kendi sitende 1
* Tehdit: **5 botnet C2 · 300 phishing · 679 ele geçirilmiş sistem · 1710 Spamhaus CIDR · 123.240 skorlu IP · 14.345 zararlı URL · 95.157 phishing alan adı**, haritada **65 konum / 16 ülke**
* CVE: son 1 haftada **2520** yayınlanan CVE (CVSS 10.0 örnekleriyle)
* Kullanıcı adı: 29 platformun **14'ü doğrulanmış eşleşme**, 9'u dürüstçe "doğrulanamadı" (bot duvarı), 6'sı hesap yok
* Raporlar: HTML 2,4 KB · JSON 42 KB · CSV 0,6 KB indirildi
* Kendi sitende: risk 11/100 · 4 bulgu (DMARC yok + 3 eksik güvenlik başlığı)

## Dürüst sınırlar
* **HIBP** (veri sızıntısı kaydı) API anahtarı ister → anahtarsızken modül "anahtar gerekli" der, **uydurma kayıt üretmez**.
* SMTP kullanıcı doğrulaması Türkiye'de 25 portu kapalı olduğu için yapılamaz (ölçüldü) → MX + servis izi kullanılır.
* crt.sh şu an 502 veriyor (site tarafı) → subdomain için subdomain.center + hackertarget kullanılır.
* Instagram / Reddit / GitLab / Facebook bot duvarı arkasında → modül "doğrulanamadı" der, yanlış sonuç vermez.
* Yalnız **sahibi olduğun** ve **yazılı izin aldığın** sistemlerde tarama yap. İzinsiz tarama TCK 243/244.

---
ÜSTAD OSINT v1.2 · 2026 · Kenan Kuzucu

---

# APK v1.1 — telefonda OSINT süiti de çalışıyor

Dosya: `CEP TELEFONUN İÇİN  USTADIN YAPTIĞI APK DOSYALAR` klasöründe **USTAD-OSINT-v1.1.apk**
Boyut 670.835 bayt · paket `tr.com.ustadkenankuzucu.osint` · sürüm 1.1 (kod 2) · Android 5+ (minSdk 21)
sha256: `3799726d5478e9b3340d4d637348cd3d...` · imza: CN=Ustad Kenan Kuzucu (siber.jks)

## Yenilik: `web/motor-osint.js` (1820 satır)
Python çekirdeğinin (`osint-araclar.py`) telefonda çalışan birebir kopyası. Telefonda Python yok;
köprü (`Kopru.veriCekTam` / `veriGonder` / `adCoz`) üzerinden gerçek internetten veri çeker.
`kopru.js` bu dosyayı kendisi yükler — `index.html` değişmedi.

## Doğrulananlar (bağımsız test)
| Ölçüt | Sonuç |
|---|---|
| APK ↔ kaynak sha256 | 21/21 asset birebir aynı |
| dex içinde köprü yöntemleri | `veriCekTam` · `veriGonder` · `adCoz` · `taramaYap` · `portTara` · `yerelBilgi` — hepsi var |
| Telefon yolu (sahte Java köprüsü ile gerçek tarayıcı testi) | motor yüklendi (12 modül) · 14 köprü + 7 `veriCek` çağrısı · **0 hata** |
| Köprüden gerçek veri | GitHub -> "Linus Torvalds" + 12 depo · DNS -> 9 kayıt tipi · Web Teknoloji -> `nginx/1.24.0` + 4 eksik güvenlik başlığı |
| Bilinmeyen uç nokta | dürüst hata mesajı ("bilinmeyen araç uç noktası") |
| Python <-> JS parite | sayılar/risk/bulgu/graf ve tüm modül anahtarları birebir (ayrıntı: skill `ustad-osint-bakim`) |

## Telefonda dürüst sınırlar (uydurma yok)
* **Çerez başlığı** köprüden geçmez -> "Çerez Secure bayrağı yok" uyarısı telefonda çıkmaz (bilinçli güvenlik tercihi).
* **GitHub kişisel anahtarı** köprüde özel başlık gönderilemediği için telefonda anonim çalışır (60 istek/saat).
* **TLS incelemesi** yapan ağlarda sertifika alanı boş döner (WebView'da `getpeercert` karşılığı yok).
* Kurulmazsa: Play Store -> Play Protect -> "Uygulamaları Play Protect ile tara" **kapat**.

---
ÜSTAD OSINT v1.1 · 2026 · Kenan Kuzucu

---

# v1.3 — Madalyon kimlik · 4 hacker teması · 3D katman

## 1) Profil madalyonu (senin fotoğrafın DEĞİL)
Masaüstündeki altın madalyon amblemi (`f063ec25-...png`) işlendi: yuvarlak kesim, altın yüzük,
dış ışıltı (glow), üstte cam parlaması. `web/foto-kurucu.png` (256x256, 138 KB) olarak kaydedildi.
- Üst eylem şeridinde 56px, sol menü künyesinde 104px — ikisinde altın haleli, nefes alan animasyon.
- Künye madalyonunun arkasında **dönen altın hale** (9 sn tur).
- Eski fotoğraf `USTAD-OSINT/yedek/foto-kurucu-eski-foto.png`, büyük madalyon `yedek/madalyon-560.png`.

## 2) Hacker temaları (toplam 14 tema)
| Tema | Zemin | Vurgu |
|---|---|---|
| **Matris** | saf siyah | `#00ff41` neon yeşil |
| **Terminal** | siyah-amber | `#ffb000` amber + `#3dff8a` |
| **Neon Siber** | siyah-mor | `#00fff7` camgöbeği + `#ff2bd6` magenta |
| **Zifiri** | saf siyah | `#00a3ff` elektrik mavisi |

Üst şeritteki noktalar 10'dan **14'e** çıktı; seçim tarayıcıda ve telefonda hatırlanır.

## 3) 3D katman (`hacker-3d.css` + `hacker-3d.js`)
- **Kayan 3D zemin ızgarası** (perspektifli, temaya göre renklenir) — koyu temalarda açık, açık temalarda kapalı.
- **Kartlarda gerçek 3D eğim:** fare kartın üzerinde gezerken `rotateX/rotateY` ile eğilir, üzerine gelince neon gölge.
- **Menü ve eylem düğmelerinde 3D derinlik** (translateZ + rotateX), madalyonda 3D parallaks.
- **Matris yağmuru:** Matris/Terminal/Neon temalarında arka planda düşen kod (22 fps sınırlı, hafif).
- Eylem şeridinde soldan sağa **tarama ışığı**, başlıklarda neon parlama.
- Dokunmatik cihazda ve "hareketi azalt" ayarında otomatik sadeleşir (telefonda akıcı kalır).

## 4) Doğrulama (ölçülü)
| Ölçüt | Sonuç |
|---|---|
| Tema noktası | 14/14 (Matris, Terminal, Neon Siber, Zifiri dahil) |
| Matris teması | zemin `rgb(0,0,0)` · vurgu `#00ff41` · yağmur katmanı 1484x1249 dolu · 0 hata |
| Neon teması | zemin `rgb(6,3,13)` · vurgu `#00fff7` · yağmur camgöbeği/magenta |
| 3D eğim | kartta `rotateY(2.09°) rotateX(1.77°) translateZ(9px)` uygulandı |
| 3D parallaks | madalyonda `rotateY(4.2°) rotateX(2.41°) translateZ(14px)` |
| Zemin ızgarası | gerçek `matrix3d(...)` perspektif dönüşümü |
| Telefon (412x915) | taşma yok, yağmur 431x955 çalışıyor, eğim dokunmatikte kapalı (tasarım gereği) |

## 5) APK v1.3
`CEP TELEFONUN İÇİN  USTADIN YAPTIĞI APK DOSYALAR\USTAD-OSINT-v1.3.apk` · 777.462 bayt · sürüm 1.3 (kod 4)
sha256 `fdb4776509edd7c6d4cafe50e2326a9e...` · **23/23 asset kaynakla birebir** · imzalı (CN=Ustad Kenan Kuzucu)

---
ÜSTAD OSINT v1.3 · 2026 · Kenan Kuzucu

---

# v1.4 — QD-OLED 4K görünüm · güçlü keskin yazılar · güçlendirilmiş renkler

## 1) Yeni tema: QD-OLED 4K (15. tema)
Gerçek siyah zemin `#000` (OLED'de piksel tamamen söner), kuantum noktası gibi doygun ana renkler:
`#00ff8a` yeşil · `#4da3ff` mavi · `#ff2d55` kırmızı · `#ffcf4d` altın.
Kartlar siyahtan yukarı doğru ince gradyan, panel başlıkları koyu-yeşil şerit, seçili menü satırında yeşil kenar çizgisi.
Arka planda QD-OLED'e özel yeşil-mavi kod yağmuru (daha hafif, %30 opaklık).

## 2) Güçlendirilmiş hacker paletleri (eskileri "yavan" duruyordu)
| Tema | Önce | Şimdi |
|---|---|---|
| Matris | `#00ff41` | **`#00ff66`** + `#b6ff3d` (asit yeşili), soluk yazı `#48c47a` (daha okunur) |
| Terminal | `#ffb000` | **`#ffb400`** + `#4dff9b`, amber vurgular daha parlak |
| Neon Siber | `#00fff7` | **`#00ffe7`** + `#ff2bd6`, zemin tam siyah, çizgiler daha mor |
| Zifiri | `#00a3ff` | **`#00a6ff`** + buz beyazı, kontrast yükseltildi |

## 3) Güçlü keskin yazılar (`keskin-4k.css`)
- Başlıklar için **Segoe UI Variable Display / Bahnschrift** yığını, ağırlık **750-800**.
- Sayılar ve teknik değerler için **Cascadia Mono**, ağırlık **800**, `tabular-nums` (rakamlar alt alta hizalı).
- `antialiased` yumuşatma, `optimizeLegibility`, `font-synthesis:none` → bulanık/soluk metin yok.
- QD-OLED'de ince parlak kenar çizgileri, seçili menüde 3px neon şerit.

## 4) 4K / TV ölçekleme (ölçüldü)
| Ekran genişliği | Punto çarpanı | Taban punto | Sol menü |
|---|---|---|---|
| 1500px | 1.00 | 15.0px | 240px |
| 2560px (ölçüldü) | **1.24** | **18.6px** | 316px |
| 3000px+ | 1.36 | 20.4px | 348px |

Ayrıca 2x yoğunlukta ince ayırıcı çizgiler; haritalar ve grafikler zaten `devicePixelRatio` ile çiziliyor
(4K/high-DPI ekranda bulanık değil) — ölçüm: harita tuvali 1149x290 → cihaz oranıyla ölçekleniyor.

## 5) Doğrulama
| Ölçüt | Sonuç |
|---|---|
| Tema sayısı | **15/15** (QD-OLED 4K dahil), tarayıcıda ve telefonda hatırlanıyor |
| QD-OLED | zemin `rgb(0,0,0)` · vurgu `#00ff8a` · yağmur 2544x1289 dolu (33.807 örnek) · 0 hata |
| Yazı tipi (ölçüldü) | sayılar Cascadia Mono 800 + tabular-nums · başlıklar 750 · `antialiased` |
| 4K ölçek | 2560px'te punto 15 → **18.6px**, çarpan 1.24 |
| Telefon 412x915 | taşma yok · QD-OLED siyah zemin · yağmur 431x955 çalışıyor · eğim dokunmatikte kapalı |

## 6) APK v1.4
`CEP TELEFONUN İÇİN  USTADIN YAPTIĞI APK DOSYALAR\USTAD-OSINT-v1.4.apk` · 781.624 bayt · sürüm 1.4 (kod 5)
**24/24 asset kaynakla birebir** · `keskin-4k.css` + `hacker-3d.css/js` içinde · 15 tema içinde
sha256 `d8eb0f9a7080efb86a2f2997358db518...` · imzalı (CN=Ustad Kenan Kuzucu)

---

# v1.5 — EK ARAÇLAR (Pasif Radar · CVE · Arşiv · Takeover · Savunma · Toplu · Terminal · Kanıt)

Sol menüde **// EK ARAÇLAR (v1.5)** grubu açıldı: 8 yeni panel. Hepsi **gerçek veriyle** çalışır,
hiçbiri uydurma kayıt üretmez. Her panelin başında sarı-yeşil bir kutu vardır:
**"Ne işe yarar?" + "Örnek:" + "Kaynak:"** — panel panel gezmeden ne işe yaradığını hatırlarsın.

## 1) Paneller ve ne işe yaradıkları

| # | Panel | Ne işe yarar? (kısa) | Canlı testte çıkan örnek |
|---|---|---|---|
| 1 | 🛰️ **PASİF RADAR** | Hedefe **hiç dokunmadan** internetten görünen portları, teknolojileri ve bilinen zafiyetleri listeler | `ustadkenankuzucu.com.tr` → 213.238.183.223 · **8 port** (53/80/143/443/587/995/3306/52230) · **4 CVE**, en ağırı Exim **CVSS 9.8** · CPE: exim 4.99.2, openresty, litespeed, mysql 8.0.45 |
| 2 | 🧨 **CVE EŞLEŞTİRME** | Ürün + sürüm yaz, o sürümle ilgili NVD kayıtlarını CVSS puanıyla getirir | `nginx 1.24.0` → **120 kayıt**; `wordpress 6.4` → 120 kayıt |
| 3 | 🕰️ **ARŞİV & GÖRÜNTÜ** | Sitenin eski sürümleri, silinmiş yolları + başkalarının yaptığı gerçek taramaların ekran görüntüsü/DOM'u | `example.com` → **200 arşiv kaydı**, ilk kayıt **20.01.2002**, son 22.10.2021 · urlscan.io'da **10 tarama** (IP + sonuç/ekran/DOM bağlantıları) |
| 4 | 🧲 **SUBDOMAIN TAKEOVER** | Sahipsiz CNAME'i (silinmiş servise bakan alt alan) bulur, imzayı doğrular → **risk yüksek** | `github.com` → **51 alt alan**, **16 şüpheli**; `blog-freeze.github.com` → 404 + "There isn't a GitHub Pages site here" = **risk yüksek** |
| 5 | 🛡️ **SAVUNMA DUVARI** | Zararlı IP listesini **Windows Güvenlik Duvarı .ps1** betiğine çevirir (+ geri alma betiği) | **2.409 IP** toplandı (EmergingThreats 679 · ET Block IPs 1.737 · Feodo 5) |
| 6 | 🗃️ **TOPLU TARAMA** | Birden çok alan adını sırayla profiller, **risk sıralı tablo** çıkarır | `example.com` risk **11/100** (4 bulgu) · `github.com` risk **7/100** (2 bulgu) |
| 7 | ⌨️ **MİNİ TERMİNAL** | Panel gezmeden komutla çalıştırma (↑/↓ geçmiş) | `pasif 1.1.1.1` → 7 port · `dns example.com` → A/AAAA/MX/TXT/NS… · `takeover ornek.com` · `kanit` |
| 8 | 🔗 **KANIT ZİNCİRİ** | Raporun **SHA-256 özeti + zaman damgası + zincir mührü** — "bu rapor değiştirilmedi" kanıtı | örnek mühür: `a07cb5ac…` · zincir no #1 |

Ayrıca **🔊 SESLİ ÖZET** düğmesi rapor şeritlerine eklendi: son taramanın özetini **Türkçe sesli** okur
(telefonda Android TTS, PC'de Chrome/Edge sesi — `tr-TR` sesi otomatik seçilir).

## 2) Mini terminal komutları

```
yardım                          komut listesi
scan <hedef>                    tam profil (DNS, WHOIS, alt alan, web teknolojisi…)
dns <ad> · whois <ad> · ip <ad|IP> · sub <ad>
kullanici <ad>                  platformlarda hesap araması
pasif <hedef>                   dokunmadan port + CVE
cve <ürün> [sürüm]              zafiyet eşleştirme
arsiv <ad> · urlscan <ad>       geçmiş + gerçek taramalar
takeover <ad> · savunma         sahipsiz subdomain · engel listesi
toplu <ad1> <ad2> …             çoklu hedef
leak <e-posta> · tehdit · kanit · ses · temizle
```

## 3) Yeni kaynaklar (hepsi anahtarsız, canlı doğrulandı)

| Kaynak | Ne veriyor | Durum |
|---|---|---|
| `internetdb.shodan.io` | IP'nin internetten görünen port/CPE/CVE listesi | ✔ `1.1.1.1` → 7 port |
| `cveawg.mitre.org/api/cve/<ID>` | CVE başlık/özet/CVSS | ✔ çalışıyor |
| `services.nvd.nist.gov` CVE API | Ürün adına göre zafiyet kayıtları | ✔ 120 kayıt (nginx) |
| `web.archive.org/cdx` | Arşiv geçmişi (2002'ye kadar) | ✔ 200 kayıt |
| `urlscan.io/api/v1/search` | Gerçek taramalar + ekran görüntüsü | ✔ 10 kayıt |
| `rules.emergingthreats.net` + `feodotracker.abuse.ch` | Ele geçirilmiş/zararlı IP listeleri | ✔ 2.409 IP |
| `crt.sh` | Sertifika şeffaflığı | ✘ şu an 502 (yedek: subdomain.center + hackertarget) |

## 4) Dosyalar (v1.5)

| Dosya | Ne yapar |
|---|---|
| `osint-ek.py` | 8 modülün Python çekirdeği (Pasif Radar, CVE, Arşiv, urlscan, Takeover, Savunma, Toplu, Kanıt) + önbellek (30dk/6sa/24sa) |
| `web/ek.js` | Panellerin arayüzü + mini terminal + sesli özet |
| `web/ek.css` | Bilgi kutuları, tablolar, rozetler, terminal görünümü |
| `ek-paneller.py` | Panelleri/menüyü `index.html`'e ekler (idempotent) |
| `veri/ek-onbellek.json` | Sorgu önbelleği (tekrar sorguda hızlı yanıt) |
| `veri/kanit-zinciri.json` | Kanıt zinciri kayıtları |

`osint-ek.py` yüklenemezse ana çekirdek çalışmaya devam eder (yalnız ek paneller "çekirdek yüklenemedi" der) —
mevcut 12 modül ve SOC konsolu bozulmaz.

## 5) Doğrulama (canlı, tarayıcıda ölçüldü)

| Ölçüt | Sonuç |
|---|---|
| Panel sayısı | 28 → **36** (8 yeni) · menü düğmesi 36 |
| "Ne işe yarar" kutusu | **8/8** panelde, hepsinde örnek satırı var |
| JavaScript hatası | **0** (üç ayrı tarayıcı testinde) |
| Pasif Radar | 8 port · 4 CVE · 0 hata |
| CVE eşleştirme | 120 kayıt · 0 hata |
| Arşiv + urlscan | 200 kayıt · 10 tarama |
| Takeover | 51 alt alan · 16 şüpheli (imza doğrulamalı) |
| Savunma duvarı | 2.409 IP · iki .ps1 indirme düğmesi aktif |
| Toplu tarama | 2 hedef · risk tablosu · 0 hata |
| Terminal | 3 komut · 30 satır çıktı · `[object Object]` kalıntısı yok |
| Sesli özet | çağrıldı, hata yok |

## 6) Nerede kullanılır (yasal)

Tarama yalnız **kendi sistemlerin** için. Pasif Radar ve Arşiv hedefe istek göndermez (hedef log görmez);
takeover/toplu tarama kendi alan adlarında çalıştırılır. İzinsiz tarama TCK 243/244 kapsamındadır.
Savunma Duvarı betiğini yalnız **kendi bilgisayarında** yönetici olarak çalıştır.

## 7) Devam: DEĞİŞİM (FARK) paneli + günlük otomatik rapor

**Panel `DEĞİŞİM (FARK)`** — iki tarama arasındaki farkı söyler:
- `⚖️ SON TARAMAYI KAYDET` → o anki durumu (port · alt alan · CVE · bulgu · risk) saklar.
- `🔍 FARKI GÖSTER` → "yeni açılan port / kapanan port / yeni alt alan / yeni CVE / risk değişimi" tablosu.
- Değişiklik yoksa dürüstçe **"Değişim yok. Sakin gün."** yazar.
- Port/CVE verisi pasif radardan tamamlanır (profil ucu port döndürmez) — yoksa "13 port kapandı" gibi
  yanlış alarm verirdi.
- Hedef başına son **30 kayıt** saklanır (geçmiş tablosu panelde görünür).

**Her sabah 09:00 otomatik tarama** (`gunluk-rapor.py`):
- Kendi alan adlarını (`veri/izleme.json`) tarar, önceki güne göre değişimi hesaplar,
  masaüstüne `USTAD-OSINT-RAPORLAR\<tarih>-rapor.html` yazar.
- Hermes zamanlanmış görevi `ustad-osint-gunluk.py` sarmalayıcısını çalıştırır; çıktı rapor özetidir.
- Elle çalıştırma: `cd Desktop\USTAD-OSINT && python gunluk-rapor.py`
- İlk rapor (2026-09-25) gerçek veri: iki alan adı da risk 11/100 · portlar 53,80,143,443,587,995,3306,52230 ·
  4 zafiyet kaydı · 1 kritik.

## 8) Panel renk uyumu (referans görseldeki renk düzeni)

`web/panel-renk.css` tek dosya: her panelin **başlığı, simgesi, kartı ve menü satırı kendi modül renginde**.
- İstatistik kartları renkli çerçeve + renkli sayı (SUBDOMAIN mavi, IP ADRESİ turkuaz, AÇIK SERVİS kırmızı,
  E-POSTA mor, VERİ SIZINTISI sarı, CLOUD camgöbeği).
- Risk etiketleri referans görselin renkleriyle: Yüksek `#ef4444` · Orta `#f59e0b` · Düşük `#22c55e`.
- Port durumu: Açık yeşil, riskli port kırmızı; kutu başlıklarında camgöbeği vurgu çubuğu.
- `--ton` tanımsız kartlarda eski tema görünümü korunur (hiçbir şey bozulmaz).

## 9) Ultra gerçekçi harita + hareketli sinyaller

Ortak motor `web/harita-gercek.js` (Dünya haritası, tehdit haritası ve OSINT haritası aynı motoru kullanır):
- **Okyanus:** derinlik gradyanı + sonar ızgarası + vinyet (uydudan bakıyormuş hissi).
- **Kara:** enlem bazlı iklim renkleri — kutup buz, tayga yeşili, çöl sarısı, ekvator ormanı; PNG'nin beyaz
  dolgusu `source-in` ile ezilir, `multiply` ile gölgeler korunur.
- **Kıyı şeridi:** ışıyan kıyı (parlama üretip gövdeyi silerek) → kıtalar belirgin.
- **Hareketli sinyal:** her bağlantı için kuyruklu ışık paketleri + hedefte çarpan radar halkaları;
  saldırı yüzeyi grafiğinde kenarlar üzerinde akan paketler (kritik kenarda 3 paket).
- Animasyon **yalnız panel açıkken** çalışır (arka planda durur), kare başına canvas ayırmaz.
- Ölçüm (tarayıcıda, iki kare arası fark): Dünya haritası **%7**, tehdit haritası **%5** hareket ·
  154 farklı renk kümesi (düz dolgu değil, gerçek doku).

---

# v1.6 — YENİ NESİL ARAÇLAR (12 panel)

Sol menüde **// YENİ NESİL ARAÇLAR (v1.6)** grubu. Her panelde "Ne işe yarar + Örnek" kutusu var.

| # | Araç | Ne yapar | Doğrulanmış örnek |
|---|------|----------|-------------------|
| 1 | AKTİF İSTİSMAR RADARI | CVE gerçekten istismar ediliyor mu (CISA KEV + EPSS) | CVE-2024-3094 → EPSS %86 · yüzdelik 99.7 |
| 2 | E-POSTA KALKANI | SPF/DKIM/DMARC denetimi + kopyalanacak doğru kayıt | ustadkenankuzucu.com.tr → DMARC **p=none** (sahte mail serbest) |
| 3 | MAİL BAŞLIĞI ANALİZİ | Şüpheli mail gerçek mi sahte mi | Sahte örnek → risk 100/100 · SPF fail · Reply-To başka alan |
| 4 | SERTİFİKA LOGU (CT) | Haberiniz olmadan açılmış alt alanlar | 2 sertifika · 3 alan adı · yeniler işaretli |
| 5 | WEB YAPILANDIRMA | Açıkta kalan .env/.git, eksik güvenlik başlıkları + düzeltme satırları | 70/100 · 6 eksik başlık · hassas dosyalar 403 (kapalı) |
| 6 | FİDYE YAZILIMI RADARI | Son kurbanlar, gruplar, sektörler, ülkeler | 100 kurban · en aktif grup qilin |
| 7 | CANLI SALDIRI AKIŞI | Dünyada en çok saldıran IP'ler + haritada akan sinyaller | 20 IP · 1.630.575 rapor · 13.94.254.200 Amsterdam |
| 8 | KOD SIR AVCISI | Kod içine gömülü anahtar/şifre avı (değerler maskeli) | Kendi projelerinde 0 bulgu · kontrol testi 2 kritik yakalandı |
| 9 | YEREL AĞ CİHAZLARI | Ağınızdaki cihazlar + yeni cihaz uyarısı | 7 cihaz görüldü · 1 YENİ · 192.168.1.1 TP-Link |
| 10 | ŞİFRE SIZINTI KONTROLÜ | Şifreniz sızıntıda var mı (şifre cihazdan çıkmaz) | 123456 → 210.461.208 kayıt |
| 11 | RAPOR PAKETİ | Renkli Word + QR + SHA-256 kanıt mührü | 38.431 bayt .docx üretildi (Masaüstü USTAD-OSINT-RAPORLAR) |
| 12 | OLAY & BİLDİRİM | Yeni port/CVE olayında masaüstü + WhatsApp haberi | Her 30 dakikada otomatik kontrol |

**Telefonda dürüst sınır:** kod sır avcısı (8) ve yerel ağ taraması (9) masaüstünde çalışır;
APK'da "bu araç masaüstü sürümünde çalışır" der, uydurma sonuç vermez. Diğer 10 araç telefonda da çalışır.

**Android APK (v1.6):** 863.916 bayt · sürüm 1.6 (kod 6) · 30/30 asset kaynakla birebir · imzalı.
Kurulum: dosyayı telefona kopyala, aç; Play Protect uyarısı çıkarsa "Yine de yükle" de.

---
ÜSTAD OSINT v1.6 · 2026 · Kenan Kuzucu
