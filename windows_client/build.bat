@echo off
cd /d "%~dp0"

set "OUTPUT_DIR=C:\Users\user\Desktop\test"

echo ==========================================
echo   VPN Client - EXE Build Script
echo ==========================================
echo.

:: Python tap
set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY (
    where py >nul 2>&1 && set "PY=py"
)
if not defined PY (
    if exist "C:\Python311\python.exe" set "PY=C:\Python311\python.exe"
)
if not defined PY (
    if exist "C:\Program Files\Python311\python.exe" set "PY=C:\Program Files\Python311\python.exe"
)
if not defined PY (
    for /f "delims=" %%i in ('dir /s /b C:\Users\%USERNAME%\AppData\Local\Programs\Python\python.exe 2^>nul') do set "PY=%%i"
)
if not defined PY (
    echo [XETA] Python tapilmadi!
    echo https://www.python.org/downloads/ saytindan yukleyin.
    echo Qurasdirma zamani "Add Python to PATH" secimini isaretleyin!
    pause
    exit /b 1
)

echo Python: %PY%
%PY% --version

echo.
echo [1/3] Paketler qurasdirılır...
%PY% -m pip install PyQt5 requests PySocks pyinstaller --quiet

echo [2/3] EXE yaradılır...
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
%PY% -m PyInstaller --onefile --noconsole --name "VPNClient" --distpath "%OUTPUT_DIR%" --clean vpn_client.py

echo [3/3] Config kopyalanir...
copy /Y config.py "%OUTPUT_DIR%\config.py" >nul

echo.
echo ==========================================
echo   HAZIRDIR!
echo   Fayl: %OUTPUT_DIR%\VPNClient.exe
echo ==========================================
explorer "%OUTPUT_DIR%"
pause
