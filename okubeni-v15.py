# -*- coding: utf-8 -*-
"""OKU-BENI.md — v1.5 (Ek Araçlar) bölümünü ekler."""
import io
import os
import re

KOK = os.path.dirname(os.path.abspath(__file__))
YOL = os.path.join(KOK, "OKU-BENI.md")

BOLUM = '''
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

---
ÜSTAD OSINT v1.5 · 2026 · Kenan Kuzucu
'''


def main():
    metin = io.open(YOL, encoding="utf-8").read()
    if "v1.5 — EK ARAÇLAR" in metin:
        print("zaten var, dokunulmadı")
        return
    # eski "---\nÜSTAD OSINT v1.4 · ..." kuyruğunu kaldır, yeni bölümü ekle
    metin = re.sub(r"\n---\nÜSTAD OSINT v1\.4 · 2026 · Kenan Kuzucu\n?$", "\n", metin)
    metin = metin.rstrip("\n") + "\n" + BOLUM
    io.open(YOL, "w", encoding="utf-8", newline="").write(metin)
    print("OKU-BENI satır:", len(metin.splitlines()))


if __name__ == "__main__":
    main()
