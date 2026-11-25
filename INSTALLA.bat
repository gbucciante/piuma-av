@echo off
rem Installa PiumaAV: doppio clic su questo file.
rem Chiede i permessi di amministratore e avvia lo script di installazione.
net session >NUL 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath \"%~f0\" -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install\windows\install.ps1"
echo.
pause
