@echo off
echo ==========================================
echo   VPN Client - EXE Build Script
echo ==========================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found! Please install Python.
    echo https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Install required packages
echo [1/3] Installing packages...
pip install PyQt5 requests PySocks pyinstaller --quiet

:: Build EXE
echo [2/3] Building EXE...
pyinstaller --onefile --noconsole --name "VPNClient" --clean vpn_client.py

:: Copy config file
echo [3/3] Copying files...
copy config.py dist\config.py >nul 2>&1

echo.
echo ==========================================
echo   DONE!
echo   EXE: dist\VPNClient.exe
echo   Give the dist\ folder to the user.
echo ==========================================
pause
