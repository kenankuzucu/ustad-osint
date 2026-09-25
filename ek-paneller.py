# -*- coding: utf-8 -*-
"""ÜSTAD OSINT v1.5 — yeni panelleri (Ek Araçlar) index.html'e ekler.
Idempotent: zaten eklenmişse tekrar eklemez. CRLF değil LF yazar, UTF-8 korunur."""
import io
import os
import re

KOK = os.path.dirname(os.path.abspath(__file__))
YOL = os.path.join(KOK, "web", "index.html")
ISARET = "<!-- ===== EK ARAÇLAR v1.5 (pasif radar, cve, arşiv, takeover, savunma, toplu, terminal, kanıt) ===== -->"

MENU = """    <div class="menuGrup">// EK ARAÇLAR (v1.5)</div>
    <button class="menuDug" data-panel="pasif" style="--renk:#00ffa3"><i>🛰️</i><span>PASİF RADAR</span><b id="say-pasif"></b></button>
    <button class="menuDug" data-panel="cve" style="--renk:#ff5d5d"><i>🧨</i><span>CVE EŞLEŞTİRME</span><b id="say-cve"></b></button>
    <button class="menuDug" data-panel="arsiv" style="--renk:#ffb400"><i>🕰️</i><span>ARŞİV &amp; GÖRÜNTÜ</span><b id="say-arsiv"></b></button>
    <button class="menuDug" data-panel="takeover" style="--renk:#c084fc"><i>🧲</i><span>SUBDOMAIN TAKEOVER</span><b id="say-takeover"></b></button>
    <button class="menuDug" data-panel="savunma" style="--renk:#33d17a"><i>🛡️</i><span>SAVUNMA DUVARI</span><b id="say-savunma"></b></button>
    <button class="menuDug" data-panel="toplu" style="--renk:#4da3ff"><i>🗃️</i><span>TOPLU TARAMA</span><b id="say-toplu"></b></button>
    <button class="menuDug" data-panel="terminal" style="--renk:#00ff66"><i>⌨️</i><span>MİNİ TERMİNAL</span><b id="say-terminal"></b></button>
    <button class="menuDug" data-panel="kanit" style="--renk:#d4af37"><i>🔗</i><span>KANIT ZİNCİRİ</span><b id="say-kanit"></b></button>
"""

PANELLER = """
    <!-- ---------------------------- PASİF RADAR ---------------------------- -->
    <section class="panel" id="p-pasif">
      <div class="modBaslik" style="--ton:#00ffa3">
        <div class="mIkon">🛰️</div>
        <div><h2>Pasif Radar (Hedefe Dokunmadan)</h2><p>İnternetten görünen portlar, teknolojiler ve bilinen zafiyetler</p></div>
      </div>
      <div class="osIpucu">
        <b>Ne işe yarar?</b> Hedefe <u>hiç istek göndermeden</u> dışarıdan görünen açık portları, o portlardaki teknolojileri ve bilinen zafiyetleri listeler — hedef sistem bu sorguyu görmez, log'a düşmez.
        <span class="ornek">Örnek: <b>ustadkenankuzucu.com.tr</b> → IP 213.238.183.223 · 8 port (53/80/443/3306…) · Exim CVE-2026-45185 <b>CVSS 9.8</b> "dışarıdan görünüyor" bilgisi geldi.</span>
        <span class="not">Kaynak: internetdb.shodan.io + MITRE CVE (anahtarsız). Yalnız sahibi olduğun sistemler için.</span>
      </div>
      <div class="modForm">
        <input type="text" id="pasifGirdi" placeholder="ornek.com veya 1.1.1.1" autocomplete="off">
        <button class="modDug" id="pasifDug">▶ PASİF TARA</button>
        <button class="modDug ekIkincil" id="pasifZorla">↻ YENİLE</button>
        <span class="sonucYazi" id="pasifDurum"></span>
      </div>
      <div class="osKutu"><div class="osKutuBaslik"><i>📡</i> Dışarıdan görünenler <span class="sag" id="pasifOzet"></span></div>
        <div class="osKutuGovde" id="pasifSonuc"><div class="osIskelet">Sonuç bekleniyor…</div></div></div>
    </section>

    <!-- ---------------------------- CVE EŞLEŞTİRME ---------------------------- -->
    <section class="panel" id="p-cve">
      <div class="modBaslik" style="--ton:#ff5d5d">
        <div class="mIkon">🧨</div>
        <div><h2>CVE Eşleştirme (Teknoloji → Zafiyet)</h2><p>Tespit edilen ürün/sürüm ile NVD kayıtlarını eşler</p></div>
      </div>
      <div class="osIpucu">
        <b>Ne işe yarar?</b> Web Teknolojileri panelinin bulduğu ürün adı + sürümü yazın; o sürümle ilgili <b>bilinen açıkları (CVE)</b> CVSS puanıyla listeler. Sürümün geçtiği kayıtlar en üste gelir.
        <span class="ornek">Örnek: <b>nginx 1.24.0</b> → NVD'de 120 kayıt, açıklamasında 1.24 geçenler öne alınır. <b>wordpress 6.4</b> → 120 kayıt.</span>
        <span class="not">Kaynak: NVD CVE API (anahtarsız). "Olası eşleşme"dir; kesin sonuç için sürüm aralığı doğrulanmalı.</span>
      </div>
      <div class="modForm">
        <input type="text" id="cveGirdi" placeholder="ürün: nginx, wordpress, openssh…" autocomplete="off">
        <input type="text" id="cveSurum" placeholder="sürüm (isteğe bağlı): 1.24.0" autocomplete="off" style="max-width:200px">
        <button class="modDug" id="cveDug">▶ EŞLEŞTİR</button>
        <span class="sonucYazi" id="cveDurum"></span>
      </div>
      <div class="osKutu"><div class="osKutuBaslik"><i>🧨</i> Eşleşen kayıtlar <span class="sag" id="cveOzet"></span></div>
        <div class="osKutuGovde" id="cveSonuc"><div class="osIskelet">Sonuç bekleniyor…</div></div></div>
    </section>

    <!-- ---------------------------- ARŞİV & GÖRÜNTÜ ---------------------------- -->
    <section class="panel" id="p-arsiv">
      <div class="modBaslik" style="--ton:#ffb400">
        <div class="mIkon">🕰️</div>
        <div><h2>Arşiv &amp; Ekran Görüntüsü</h2><p>Wayback Machine geçmişi + urlscan.io gerçek taramaları</p></div>
      </div>
      <div class="osIpucu">
        <b>Ne işe yarar?</b> Sitenin <b>eski sürümlerini, silinmiş sayfalarını</b> ve başkalarının yaptığı gerçek taramaların <b>ekran görüntüsünü/DOM'unu</b> gösterir. Silinmiş ama sunucuda kalmış yollar (ör. /admin, /eski-panel) buradan çıkar.
        <span class="ornek">Örnek: <b>example.com</b> → 200 arşiv kaydı, ilk kayıt 2002, son 2021. urlscan.io'da 10 gerçek tarama (IP + ekran görüntüsü bağlantısıyla).</span>
        <span class="not">Kaynak: archive.org CDX + urlscan.io (anahtarsız).</span>
      </div>
      <div class="modForm">
        <input type="text" id="arsivGirdi" placeholder="ornek.com" autocomplete="off">
        <button class="modDug" id="arsivDug">▶ ARŞİVİ AÇ</button>
        <span class="sonucYazi" id="arsivDurum"></span>
      </div>
      <div class="osIzgara">
        <div class="osKutu"><div class="osKutuBaslik"><i>🗄️</i> Wayback geçmişi <span class="sag" id="arsivOzet"></span></div>
          <div class="osKutuGovde" id="arsivSonuc"><div class="osIskelet">Sonuç bekleniyor…</div></div></div>
        <div class="osKutu"><div class="osKutuBaslik"><i>📸</i> urlscan.io taramaları <span class="sag" id="urlscanOzet"></span></div>
          <div class="osKutuGovde" id="urlscanSonuc"><div class="osIskelet">Sonuç bekleniyor…</div></div></div>
      </div>
    </section>

    <!-- ---------------------------- SUBDOMAIN TAKEOVER ---------------------------- -->
    <section class="panel" id="p-takeover">
      <div class="modBaslik" style="--ton:#c084fc">
        <div class="mIkon">🧲</div>
        <div><h2>Subdomain Takeover Taraması</h2><p>Sahipsiz CNAME'ler: silinmiş servise bakan alt alanlar</p></div>
      </div>
      <div class="osIpucu">
        <b>Ne işe yarar?</b> Bir alt alan adı (ör. <b>eski.magaza.com</b>) kapanmış bir servise (Shopify, GitHub Pages, Heroku…) CNAME ile bakıyorsa, o servis hesabı yeniden açan biri siteyi <b>ele geçirebilir</b>. Bu panel imzayı arayıp "risk yüksek" der.
        <span class="ornek">Örnek: eski.magaza.com → silinmiş Shopify mağazası → "Sorry, this shop is currently unavailable" imzası bulunursa <b>risk: yüksek</b>.</span>
        <span class="not">Kaynak: dns.google (CNAME zinciri) + 20 servis imzası (anahtarsız).</span>
      </div>
      <div class="modForm">
        <input type="text" id="takeoverGirdi" placeholder="ornek.com" autocomplete="off">
        <button class="modDug" id="takeoverDug">▶ TARAMA</button>
        <span class="sonucYazi" id="takeoverDurum"></span>
      </div>
      <div class="osKutu"><div class="osKutuBaslik"><i>🧲</i> Şüpheli alt alanlar <span class="sag" id="takeoverOzet"></span></div>
        <div class="osKutuGovde" id="takeoverSonuc"><div class="osIskelet">Sonuç bekleniyor…</div></div></div>
    </section>

    <!-- ---------------------------- SAVUNMA DUVARI ---------------------------- -->
    <section class="panel" id="p-savunma">
      <div class="modBaslik" style="--ton:#33d17a">
        <div class="mIkon">🛡️</div>
        <div><h2>Savunma Duvarı (IOC → Güvenlik Duvarı)</h2><p>Ele geçirilmiş sistem listesini Windows kurallarına çevirir</p></div>
      </div>
      <div class="osIpucu">
        <b>Ne işe yarar?</b> Tehdit beslemelerindeki <b>ele geçirilmiş/zararlı IP'leri</b> Windows Güvenlik Duvarı'na ekleyen bir <b>.ps1 betiği</b> üretir; yanında tek tıkla <b>geri alma</b> betiği de var. Yani OSINT burada saldırı değil <b>savunma</b> için çalışır.
        <span class="ornek">Örnek: canlı testte <b>2409 zararlı IP</b> toplandı (EmergingThreats + Feodo). Betiği yönetici olarak çalıştırınca hepsi engellenir.</span>
        <span class="not">Kaynak: EmergingThreats + Feodo Tracker (anahtarsız). Yalnız kendi bilgisayarında çalıştır.</span>
      </div>
      <div class="modForm">
        <button class="modDug" id="savunmaDug">▶ LİSTEYİ ÜRET</button>
        <button class="modDug ekIndir" id="savunmaIndir" disabled>⬇ .PS1 BETİĞİNİ İNDİR</button>
        <button class="modDug ekIkincil" id="savunmaGeri" disabled>↩ GERİ ALMA BETİĞİ</button>
        <span class="sonucYazi" id="savunmaDurum"></span>
      </div>
      <div class="osKutu"><div class="osKutuBaslik"><i>🛡️</i> Sonuç <span class="sag" id="savunmaOzet"></span></div>
        <div class="osKutuGovde" id="savunmaSonuc"><div class="osIskelet">Sonuç bekleniyor…</div></div></div>
    </section>

    <!-- ---------------------------- TOPLU TARAMA ---------------------------- -->
    <section class="panel" id="p-toplu">
      <div class="modBaslik" style="--ton:#4da3ff">
        <div class="mIkon">🗃️</div>
        <div><h2>Toplu Tarama (Çoklu Hedef)</h2><p>Birden çok alan adını sırayla profiller, risk sıralı tablo çıkarır</p></div>
      </div>
      <div class="osIpucu">
        <b>Ne işe yarar?</b> Elindeki bütün alan adlarını tek seferde tarar ve <b>riski en yüksekten aşağıya</b> sıralar. "Hangi sitemde eski panel/scanner var?" sorusunun cevabı tek tabloda.
        <span class="ornek">Örnek: 5 alan adı yaz → DNS/WHOIS/IP/subdomain/web teknolojisi toplanır, risk puanı 100 üzerinden sıralanır.</span>
        <span class="not">Her satır için ayrı istek gider; 25 hedefe kadar önerir.</span>
      </div>
      <div class="modForm ekFormBlok">
        <textarea id="topluGirdi" rows="4" placeholder="ornek.com&#10;site2.com&#10;github.com"></textarea>
        <button class="modDug" id="topluDug">▶ TOPLU TARA</button>
        <span class="sonucYazi" id="topluDurum"></span>
      </div>
      <div class="osKutu"><div class="osKutuBaslik"><i>🗃️</i> Risk tablosu <span class="sag" id="topluOzet"></span></div>
        <div class="osKutuGovde" id="topluSonuc"><div class="osIskelet">Sonuç bekleniyor…</div></div></div>
    </section>

    <!-- ---------------------------- MİNİ TERMİNAL ---------------------------- -->
    <section class="panel" id="p-terminal">
      <div class="modBaslik" style="--ton:#00ff66">
        <div class="mIkon">⌨️</div>
        <div><h2>Mini Terminal</h2><p>Tek satırda OSINT: scan · dns · whois · ip · pasif · cve · arşiv · takeover · leak</p></div>
      </div>
      <div class="osIpucu">
        <b>Ne işe yarar?</b> Panel panel gezmeden komutla çalıştırma. Yaz <b>yardım</b> ile komut listesi gelir.
        <span class="ornek">Örnekler: <b>scan ustadkenankuzucu.com.tr</b> · <b>dns example.com</b> · <b>pasif 1.1.1.1</b> · <b>cve nginx 1.24.0</b> · <b>arsiv example.com</b> · <b>takeover ornek.com</b> · <b>leak mail@ornek.com</b> · <b>kanit</b></span>
        <span class="not">Yazdığın her komut geçmişe eklenir (↑ / ↓ tuşları çalışır).</span>
      </div>
      <div class="ekTerminal" id="termKutu">
        <div class="ekTerminalGovde" id="termCikti"><div class="ekTermSatir ekBilgi">ÜSTAD OSINT terminali hazır. "yardım" yaz.</div></div>
        <div class="ekTermGirdi">
          <span class="ekTermImlec">ustad@osint:~$</span>
          <input type="text" id="termGirdi" autocomplete="off" spellcheck="false" placeholder="yardım">
          <button class="modDug" id="termDug">ÇALIŞTIR</button>
        </div>
      </div>
    </section>

    <!-- ---------------------------- KANIT ZİNCİRİ ---------------------------- -->
    <section class="panel" id="p-kanit">
      <div class="modBaslik" style="--ton:#d4af37">
        <div class="mIkon">🔗</div>
        <div><h2>Kanıt Zinciri (Değiştirilemez Rapor)</h2><p>Raporun SHA-256 özeti + zaman damgası + zincir mührü</p></div>
      </div>
      <div class="osIpucu">
        <b>Ne işe yarar?</b> Bir raporun <b>sonradan değiştirilmediğini</b> ispatlar: içeriğin SHA-256 özeti alınır, önceki kaydın özetiyle birlikte mühürlenir ve zaman damgasıyla saklanır. Karşı tarafa/mahkemeye "bu rapor aynen böyleydi" deme imkanı verir.
        <span class="ornek">Örnek: son taramanı mühürle → <b>sha256 a07cb5ac…</b> · mührü değiştirirsen zincir tutmaz.</span>
        <span class="not">Kayıt: veri/kanit-zinciri.json (cihazında kalır).</span>
      </div>
      <div class="modForm">
        <button class="modDug" id="kanitDug">🔒 SON TARAMAYI MÜHÜRLE</button>
        <button class="modDug ekIkincil" id="kanitYaz" disabled>⬇ KANIT DOSYASINI İNDİR</button>
        <span class="sonucYazi" id="kanitDurum"></span>
      </div>
      <div class="osKutu"><div class="osKutuBaslik"><i>🔗</i> Zincir kayıtları <span class="sag" id="kanitOzet"></span></div>
        <div class="osKutuGovde" id="kanitSonuc"><div class="osIskelet">Kayıt bekleniyor…</div></div></div>
    </section>
"""


def main():
    with io.open(YOL, encoding="utf-8") as f:
        html = f.read()
    if ISARET in html:
        print("zaten eklenmiş, dokunulmadı")
        return
    # 1) menü düğmeleri: RAPORLAR düğmesinden sonra
    hedef = '<button class="menuDug" data-panel="osrapor"'
    i = html.index(hedef)
    j = html.index("</button>", i) + len("</button>\n")
    html = html[:j] + MENU + html[j:]
    # 2) paneller: </main> öncesine
    html = html.replace("  </main>", ISARET + PANELLER + "  </main>", 1)
    # 3) stil + betik bağla
    html = html.replace('<script src="osint.js"></script>',
                        '<link rel="stylesheet" href="ek.css">\n<script src="osint.js"></script>', 1)
    html = html.replace('<script src="hacker-3d.js"></script>',
                        '<script src="ek.js"></script>\n<script src="hacker-3d.js"></script>', 1)
    with io.open(YOL, "w", encoding="utf-8", newline="") as f:
        f.write(html)
    print("eklendi · menü düğmesi:", html.count('data-panel="pasif"'),
          "| panel:", html.count('id="p-pasif"'), "| ek.css:", html.count("ek.css"), "| ek.js:", html.count("ek.js"))


if __name__ == "__main__":
    main()
