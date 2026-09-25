# -*- coding: utf-8 -*-
"""ÜSTAD OSINT v1.5 — DEĞİŞİM (FARK) panelini index.html'e ekler. Idempotent."""
import io
import os

KOK = os.path.dirname(os.path.abspath(__file__))
YOL = os.path.join(KOK, "web", "index.html")

MENU = """    <button class="menuDug" data-panel="fark" style="--renk:#ff9f43"><i>⚖️</i><span>DEĞİŞİM (FARK)</span><b id="say-fark"></b></button>
"""

PANEL = """
    <!-- ---------------------------- DEĞİŞİM (FARK) ---------------------------- -->
    <section class="panel" id="p-fark">
      <div class="modBaslik" style="--ton:#ff9f43">
        <div class="mIkon">⚖️</div>
        <div><h2>Değişim (Fark) Radarı</h2><p>İki tarama arasında ne değişti: yeni port, yeni alt alan, yeni CVE</p></div>
      </div>
      <div class="osIpucu">
        <b>Ne işe yarar?</b> Sistemlerdeki değişim en önemli sinyaldir: dün olmayan bir port bugün açıldıysa ya yeni bir servis kurdun ya da birisi kurdu. Bu panel iki taramanın farkını <b>yeni açılan / kapanan port, yeni alt alan, yeni CVE, risk değişimi</b> olarak gösterir.
        <span class="ornek">Örnek: bugün 8 port vardı, yarın 9 olursa <b>"yeni açılan: 8080"</b> diye kırmızı yazar. Pekiştirici: günlük otomatik rapor masaüstünde <b>USTAD-OSINT-RAPORLAR</b> klasörüne yazılır.</span>
        <span class="not">Kayıt cihazında (tarayıcı belleği) tutulur; APK'da da çalışır. Günlük otomatik tarama: `gunluk-rapor.py`.</span>
      </div>
      <div class="modForm">
        <input type="text" id="farkGirdi" placeholder="ornek.com" autocomplete="off">
        <button class="modDug" id="farkKaydet">💾 TARAMAYI KAYDET</button>
        <button class="modDug" id="farkGoster">⚖️ FARKI GÖSTER</button>
        <button class="modDug ekIkincil" id="farkTemizle">🗑️ GEÇMİŞİ SİL</button>
        <span class="sonucYazi" id="farkDurum"></span>
      </div>
      <div class="osIzgara">
        <div class="osKutu"><div class="osKutuBaslik"><i>⚖️</i> Fark sonucu <span class="sag" id="farkOzet"></span></div>
          <div class="osKutuGovde" id="farkSonuc"><div class="osIskelet">Karşılaştırma bekleniyor…</div></div></div>
        <div class="osKutu"><div class="osKutuBaslik"><i>🕒</i> Kayıtlı anlık görüntüler <span class="sag" id="farkGecmisOzet"></span></div>
          <div class="osKutuGovde" id="farkGecmis"><div class="osIskelet">Kayıt yok.</div></div></div>
      </div>
    </section>
"""


def main():
    s = io.open(YOL, encoding="utf-8").read()
    if 'id="p-fark"' in s:
        print("zaten var")
        return
    hedef = '<button class="menuDug" data-panel="kanit"'
    i = s.index(hedef)
    j = s.index("</button>", i) + len("</button>\n")
    s = s[:j] + MENU + s[j:]
    s = s.replace("  </main>", PANEL + "  </main>", 1)
    io.open(YOL, "w", encoding="utf-8", newline="").write(s)
    print("fark paneli:", s.count('id="p-fark"'), "| menü:", s.count('data-panel="fark"'))


if __name__ == "__main__":
    main()
