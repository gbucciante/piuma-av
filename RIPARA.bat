@echo off
rem Ripara i permessi di PiumaAV, avvia la protezione e crea un file di diagnosi.
net session >NUL 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath \"%~f0\" -Verb RunAs"
    exit /b
)
set "OUT=%TEMP%\piuma-diagnosi.txt"
set "PD=%ProgramData%\PiumaAV"
set "PYTHONIOENCODING=utf-8"
echo Attendere circa 30 secondi...
echo ===== PiumaAV diagnosi %DATE% %TIME% ===== > "%OUT%"
whoami /groups | findstr /i "S-1-16-12288 S-1-5-32-544" >> "%OUT%" 2>&1
echo --- ripristino permessi >> "%OUT%"
takeown /F "%PD%" /R /A >NUL 2>&1
icacls "%PD%" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /Q >> "%OUT%" 2>&1
icacls "%PD%\*" /reset /T /C /Q >> "%OUT%" 2>&1
set "DB=%ProgramFiles%\ClamAV\database"
takeown /F "%DB%" /R /A >NUL 2>&1
icacls "%DB%" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /Q >> "%OUT%" 2>&1
icacls "%DB%\*" /reset /T /C /Q >> "%OUT%" 2>&1
icacls "%ProgramFiles%\PiumaAV" /reset /T /C /Q >NUL 2>&1
sc stop clamd >NUL 2>&1
timeout /t 3 /nobreak >NUL
sc start clamd >> "%OUT%" 2>&1
icacls "%PD%" >> "%OUT%" 2>&1
icacls "%PD%\config.toml" >> "%OUT%" 2>&1
echo --- python >> "%OUT%"
py -3 --version >> "%OUT%" 2>&1
echo --- piuma status (come amministratore) >> "%OUT%"
py -3 "%ProgramFiles%\PiumaAV\piuma_run.py" status >> "%OUT%" 2>&1
echo --- attivita pianificata >> "%OUT%"
schtasks /Query /TN PiumaAV /V /FO LIST >> "%OUT%" 2>&1
schtasks /Run /TN PiumaAV >> "%OUT%" 2>&1
timeout /t 15 /nobreak >NUL
schtasks /Query /TN PiumaAV /V /FO LIST | findstr /i "Stato Status Ultimo Last" >> "%OUT%" 2>&1
echo --- processi >> "%OUT%"
tasklist /FI "IMAGENAME eq pythonw.exe" >> "%OUT%" 2>&1
echo --- log errori avvio >> "%OUT%"
type "%PD%\logs\avvio-errori.log" >> "%OUT%" 2>&1
type "%TEMP%\PiumaAV\avvio-errori.log" >> "%OUT%" 2>&1
echo --- ultime righe piuma.log >> "%OUT%"
powershell -NoProfile -Command "Get-Content \"$env:ProgramData\PiumaAV\logs\piuma.log\" -Tail 40" >> "%OUT%" 2>&1
start "" notepad "%OUT%"
echo Fatto. Si e' aperto il Blocco note con la diagnosi: copia tutto il testo e mandalo.
pause
