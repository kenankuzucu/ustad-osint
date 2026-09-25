@echo off
setlocal
chcp 65001 >nul
title USTAD OSINT - Saldiri Yuzeyi ve SOC Konsolu
cd /d "%~dp0"
set LOG=%~dp0baslatma-gunlugu.txt
echo ====================================================== > "%LOG%"
echo USTAD OSINT baslatiliyor >> "%LOG%"
date /t >> "%LOG%"
time /t >> "%LOG%"

echo ======================================================================
echo   USTAD OSINT v1.0  -  Saldiri Yuzeyi ve Blue Team SOC Konsolu
echo ======================================================================
echo.

rem ---- Python bul ----
set PY=
where py >nul 2>&1
if not errorlevel 1 set PY=py
if not defined PY goto PY_YOK_1
goto PY_VAR_1
:PY_YOK_1
where python >nul 2>&1
if not errorlevel 1 set PY=python
:PY_VAR_1
if not defined PY goto PYTHON_YOK
echo Python bulundu: kullanilacak komut = %PY%
echo Python: %PY% >> "%LOG%"
%PY% --version >> "%LOG%" 2>&1
echo.

echo [1] Sadece bu bilgisayardan erisim - guvenli, onerilen
echo [2] Telefon ve tablet de baglansin - yerel aga acilir
echo [3] nmap durumunu kontrol et ve kurulum bilgisi ver
echo [4] Tani: ortami kontrol et ve sunucuyu acmadan cik
echo.
set SECIM=1
set /p SECIM=Secim girin 1-4, bos birakip Enter = 1 : 
if /i "%SECIM%"=="2" goto AG
if /i "%SECIM%"=="3" goto NMAP
if /i "%SECIM%"=="4" goto TANI

:YEREL
call :PORTKONTROL
if defined ZATEN goto ZATEN_ACIK
echo.
echo Yerel adres : http://127.0.0.1:8787
echo Tarayici aciliyor. Kapatmak icin bu pencerede Ctrl+C ya da pencereyi kapat.
echo.
start "" "http://127.0.0.1:8787"
echo Sunucu baslatiliyor... >> "%LOG%"
%PY% ustad-osint.py --port 8787 >> "%LOG%" 2>&1
echo.
echo Sunucu kapandi. Gunluk dosyasi: %LOG%
pause
goto SON

:AG
call :PORTKONTROL
if defined ZATEN goto ZATEN_ACIK
echo.
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do set YERELIP=%%a
echo Yerel adres  : http://127.0.0.1:8787
echo Telefondan   : http://%YERELIP%:8787
echo.
echo Telefondan erisim icin sunucu 0.0.0.0 uzerinde dinler. >> "%LOG%"
start "" "http://127.0.0.1:8787"
%PY% ustad-osint.py --port 8787 --disari-ac >> "%LOG%" 2>&1
echo.
echo Sunucu kapandi. Gunluk dosyasi: %LOG%
pause
goto SON

:NMAP
echo.
where nmap >nul 2>&1
if not errorlevel 1 goto NMAP_VAR
echo nmap BULUNAMADI - yerlesik soket motoru kullanilacak, her sey calisir.
echo Windows'a nmap kurulumu:
echo    1. https://nmap.org/download.html adresinden nmap-7.9x-setup.exe indirin
echo    2. Kurulumda Npcap secenegini de kurun - ham tarama icin gerekir
echo    3. Kurulumdan sonra bu pencereyi kapatip yeniden acin
echo    Alternatif tek komut:  winget install Insecure.Nmap
echo.
pause
goto SON
:NMAP_VAR
nmap --version
echo.
pause
goto SON

:TANI
echo.
echo ---- ORTAM TANISI ----
echo Proje klasoru : %~dp0
echo Python        : %PY%
%PY% --version
echo.
echo Dosya kontrolu:
if exist ustad-osint.py goto D1
echo   [X] ustad-osint.py BULUNAMADI - dosyalar eksik
goto D2
:D1
echo   [OK] ustad-osint.py var
:D2
if exist web\index.html goto D3
echo   [X] web klasoru eksik
goto D4
:D3
echo   [OK] web klasoru var
:D4
echo.
echo Port 8787 dinleniyor mu:
netstat -ano | findstr :8787
echo.
echo Bu cikti bos ise sunucu kapali demektir.
pause
goto SON

:PORTKONTROL
set ZATEN=
netstat -ano | findstr /c:"LISTENING" | findstr /c:":8787" >nul 2>&1
if not errorlevel 1 set ZATEN=1
goto :eof

:ZATEN_ACIK
echo.
echo Konsol ZATEN ACIK - 8787 portu dinleniyor.
echo Tarayici aciliyor: http://127.0.0.1:8787
echo Kapatmak icin eski siyah pencereyi kapatin.
echo.
start "" "http://127.0.0.1:8787"
ping -n 4 127.0.0.1 >nul
goto SON

:PYTHON_YOK
echo.
echo [HATA] Python bulunamadi. Bu program Python ile calisir.
echo   1. https://www.python.org/downloads/ adresinden indirin
echo   2. Kurulumda Add python.exe to PATH secenegini isaretleyin
echo   3. Kurulumdan sonra bu pencereyi kapatip yeniden acin
echo.
pause
goto SON

:SON
endlocal
exit /b 0
