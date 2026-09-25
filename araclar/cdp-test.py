# -*- coding: utf-8 -*-
"""CDP test sürücüsü: JS ifadesini gerçek Chrome'da çalıştırır ve SONUCU yazdırır + ekran görüntüsü alır."""
import os, sys, json, time, subprocess, shutil, tempfile, urllib.request, asyncio, socket, base64

CHROME = [r"C:\Program Files\Google\Chrome\Application\chrome.exe",
          r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
          os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe")]


def bos_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def calistir(url, js_ifade, bekle=25, png=None, tam=False, pencere=None):
    import websockets
    # Telefon ölçüsünde denemek için: CDP_PENCERE=412,915
    pencere = pencere or os.environ.get("CDP_PENCERE", "1500,1100")
    chrome = next((c for c in CHROME if os.path.exists(c)), None)
    if not chrome:
        return "Chrome bulunamadı"
    port = bos_port()
    profil = os.path.join(os.environ.get("TEMP", tempfile.gettempdir()), "cdpt_" + str(int(time.time() * 1000)))
    shutil.rmtree(profil, ignore_errors=True)
    surec = subprocess.Popen([chrome, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
                              "--window-size=" + pencere, "--remote-debugging-port=" + str(port),
                              "--user-data-dir=" + profil, url],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    hedef = None
    for _ in range(60):
        time.sleep(0.5)
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/json" % port, timeout=3) as c:
                liste = json.load(c)
            hedef = next((t for t in liste if t.get("type") == "page" and t.get("webSocketDebuggerUrl")), None)
            if hedef:
                break
        except Exception:
            continue
    if not hedef:
        surec.kill()
        return "Chrome hedefi açılamadı"

    async def gorev():
        async with websockets.connect(hedef["webSocketDebuggerUrl"], max_size=64 * 1024 * 1024) as ws:
            no = [0]

            async def gonder(method, params=None):
                no[0] += 1
                await ws.send(json.dumps({"id": no[0], "method": method, "params": params or {}}))
                while True:
                    y = json.loads(await asyncio.wait_for(ws.recv(), timeout=bekle + 120))
                    if y.get("id") == no[0]:
                        return y

            await gonder("Runtime.enable")
            await gonder("Page.enable")
            time.sleep(2.5)
            # Gerçek telefon görünümü: CDP_MOBIL=412x915 (Chrome pencere alt sınırını atlar)
            mobil = os.environ.get("CDP_MOBIL")
            if mobil:
                try:
                    gw, gh = [int(x) for x in mobil.lower().replace("x", ",").split(",")[:2]]
                    await gonder("Emulation.setDeviceMetricsOverride",
                                 {"width": gw, "height": gh, "deviceScaleFactor": 2.625, "mobile": True})
                    await gonder("Emulation.setTouchEmulationEnabled", {"enabled": True, "maxTouchPoints": 5})
                    await gonder("Page.reload", {})
                    await asyncio.sleep(3.0)
                except Exception as hata:
                    print("mobil emülasyon kurulamadı:", hata)
            y = await gonder("Runtime.evaluate", {"expression": js_ifade, "awaitPromise": True,
                                                 "returnByValue": True, "userGesture": True})
            sonuc = ""
            try:
                sonuc = y["result"]["result"]["value"]
                if sonuc is None:
                    sonuc = json.dumps(y["result"], ensure_ascii=False)[:1500]
            except Exception:
                sonuc = json.dumps(y, ensure_ascii=False)[:2000]
            if sonuc in ("", "{}"):
                sonuc = "RAW: " + json.dumps(y, ensure_ascii=False)[:1200]
            if png:
                time.sleep(1.2)
                s = await gonder("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": bool(tam)})
                veri = s.get("result", {}).get("data")
                if veri:
                    open(png, "wb").write(base64.b64decode(veri))
                    sonuc = str(sonuc) + "\n\n[EKRAN] " + png
            return sonuc

    try:
        return asyncio.run(gorev())
    finally:
        try:
            surec.kill()
        except Exception:
            pass
        time.sleep(0.4)
        shutil.rmtree(profil, ignore_errors=True)


if __name__ == "__main__":
    url = sys.argv[1]
    js = open(sys.argv[2], encoding="utf-8").read() if os.path.exists(sys.argv[2]) else sys.argv[2]
    png = sys.argv[3] if len(sys.argv) > 3 else None
    bekle = int(sys.argv[4]) if len(sys.argv) > 4 else 25
    print(calistir(url, js, bekle, png))
