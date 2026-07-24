@echo off
echo ==========================================
echo   VPN Client - EXE Build Script
echo ==========================================
echo.

:: Python yoxla
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [XETA] Python tapilmadi! Python qurasdirin.
    echo https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Lazimi paketleri qurasdır
echo [1/3] Paketler qurasdirılir...
pip install PyQt5 requests PySocks pyinstaller --quiet

:: EXE yarat
echo [2/3] EXE yaradilir...
pyinstaller --onefile --noconsole --name "VPNClient" --clean vpn_client.py

:: Config faylini kopyala
echo [3/3] Fayl kopyalanir...
copy config.py dist\config.py >nul 2>&1

echo.
echo ==========================================
echo   HAZIRDIR!
echo   EXE: dist\VPNClient.exe
echo   dist\ qovlugunu istifadeciye verin.
echo ==========================================
pause
