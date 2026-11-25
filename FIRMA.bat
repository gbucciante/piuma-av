@echo off
rem Crea il certificato di firma locale di PiumaAV e firma i suoi script: doppio clic.
rem Per toglierlo: FIRMA.bat rimuovi
net session >NUL 2>&1
if %errorlevel% neq 0 (
    if "%1"=="" (powershell -NoProfile -Command "Start-Process -FilePath \"%~f0\" -Verb RunAs") else (powershell -NoProfile -Command "Start-Process -FilePath \"%~f0\" -ArgumentList %1 -Verb RunAs")
    exit /b
)
if /i "%1"=="rimuovi" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install\windows\firma.ps1" -Rimuovi
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install\windows\firma.ps1"
)
echo.
pause
