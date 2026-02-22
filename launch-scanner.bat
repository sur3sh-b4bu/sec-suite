@echo off
echo ====================================
echo  CyberSec Suite - Security Launcher
echo ====================================
echo.
echo Launching Chrome with cross-origin access enabled...
echo This allows the scanner to send cookies and CSRF tokens correctly.
echo.

:: Find Chrome installation
set "CHROME_PATH="
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" (
    set "CHROME_PATH=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
) else if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" (
    set "CHROME_PATH=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
) else if exist "%LocalAppData%\Google\Chrome\Application\chrome.exe" (
    set "CHROME_PATH=%LocalAppData%\Google\Chrome\Application\chrome.exe"
)

if "%CHROME_PATH%"=="" (
    echo [ERROR] Chrome not found. Please install Chrome or run manually:
    echo   chrome.exe --user-data-dir="C:/ChromeDev" --disable-web-security --disable-site-isolation-trials
    pause
    exit /b 1
)

:: Get the directory this bat file is in
set "SCRIPT_DIR=%~dp0"

:: Launch Chrome with security disabled and open the scanner
start "" "%CHROME_PATH%" --user-data-dir="C:/ChromeDev" --disable-web-security --disable-site-isolation-trials "%SCRIPT_DIR%html\sqli.html"

echo Chrome launched! The SQLi scanner should open automatically.
echo.
echo IMPORTANT: Close ALL other Chrome windows first for this to work.
echo.
timeout /t 5
