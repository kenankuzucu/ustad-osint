#!/usr/bin/env bash
# ÜSTAD OSINT — Android APK derleme (Gradle'sız: aapt2 + javac + d8 + apksigner)
# Telefonda kendi soket motoruyla GERÇEK tarama yapar (analiz motor.js içinde).
set -e
P="/c/Users/kenan/AndroidBuild/ustad-osint-app"
BT="/c/Users/kenan/AndroidBuild/tools/bt30/android-11"
JDK="/c/Users/kenan/AndroidBuild/tools/jdk8/jdk8u504-b01"
AJAR_W="C:/Users/kenan/AndroidBuild/tools/platform30/android-11/android.jar"
D8_W="C:/Users/kenan/AndroidBuild/tools/bt30/android-11/lib/d8.jar"
APS_W="C:/Users/kenan/AndroidBuild/tools/bt30/android-11/lib/apksigner.jar"
JAVA="$JDK/bin/java.exe"
KS_W="C:/Users/kenan/OneDrive/Desktop/SIBER-APK-ANAHTAR-SAKLA/siber.jks"
CIKTI="USTAD-OSINT-v1.6.apk"

cd "$P"
rm -rf build 2>/dev/null || true
mkdir -p build/gen build/classes build/dex

echo "=== 1) aapt2 compile ==="
"$BT/aapt2.exe" compile --dir res -o build/res.zip
echo "res.zip: $(stat -c%s build/res.zip) bayt"

echo "=== 2) aapt2 link (assets dahil) ==="
"$BT/aapt2.exe" link -o build/base.apk -I "$AJAR_W" --manifest AndroidManifest.xml \
  -A "C:/Users/kenan/AndroidBuild/ustad-osint-app/assets" \
  -R build/res.zip --java build/gen --min-sdk-version 21 --target-sdk-version 30 --auto-add-overlay
echo "base.apk: $(stat -c%s build/base.apk) bayt"

echo "=== 3) javac ==="
"$JDK/bin/javac.exe" -encoding UTF-8 -source 1.8 -target 1.8 -bootclasspath "$AJAR_W" -cp "$AJAR_W" \
  -d build/classes $(find src build/gen -name "*.java")
echo "sınıf: $(find build/classes -name '*.class' | wc -l)"

echo "=== 4) d8 (dex) ==="
"$JAVA" -cp "$D8_W" com.android.tools.r8.D8 --lib "$AJAR_W" --min-api 21 --release \
  --output build/dex $(find build/classes -name "*.class" | tr '\n' ' ')
echo "classes.dex: $(stat -c%s build/dex/classes.dex) bayt"

echo "=== 5) dex apk içine ==="
python - <<'PY'
import zipfile, os
apk = r"C:\Users\kenan\AndroidBuild\ustad-osint-app\build\base.apk"
dex = r"C:\Users\kenan\AndroidBuild\ustad-osint-app\build\dex\classes.dex"
with zipfile.ZipFile(apk, "a", zipfile.ZIP_DEFLATED) as z:
    z.write(dex, "classes.dex")
print("classes.dex eklendi →", os.path.getsize(apk), "bayt")
PY

echo "=== 6) zipalign ==="
"$BT/zipalign.exe" -f -p 4 build/base.apk build/hizali.apk

echo "=== 7) imzalama ==="
"$JAVA" -jar "$APS_W" sign --ks "$KS_W" --ks-pass pass:siber2026 --key-pass pass:siber2026 \
  --v1-signing-enabled true --v2-signing-enabled true --out "build/$CIKTI" build/hizali.apk

echo "=== 8) doğrulama ==="
"$JAVA" -jar "$APS_W" verify --print-certs "build/$CIKTI" | head -4
"$BT/zipalign.exe" -c -p 4 "build/$CIKTI" && echo "hizalama: TAMAM"
"$BT/aapt2.exe" dump badging "build/$CIKTI" 2>/dev/null | head -6
echo "APK boyutu: $(stat -c%s "build/$CIKTI") bayt"
