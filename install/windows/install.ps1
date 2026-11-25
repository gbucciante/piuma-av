# Installazione di PiumaAV su Windows 10/11
# Eseguire da PowerShell come Amministratore, dalla cartella del progetto:
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\install\windows\install.ps1
#
# Cosa fa:
#   1. installa Python e ClamAV (motore + firme) con winget, se mancano
#   2. configura ClamAV: aggiornamento firme e servizio clamd (firme in RAM)
#   3. installa PiumaAV in C:\Program Files\PiumaAV
#   4. crea l'attivita' pianificata che avvia la protezione all'accesso

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$ProjectDir = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$InstallDir = Join-Path $env:ProgramFiles "PiumaAV"
$DataDir    = Join-Path $env:ProgramData "PiumaAV"
$ClamDir    = Join-Path $env:ProgramFiles "ClamAV"

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

# Avviso delle modifiche al sistema (richiesto anche dalla policy di firma, CODE_SIGNING_POLICY.md)
Write-Host "PiumaAV sta per modificare questo PC:" -ForegroundColor Yellow
Write-Host "  - installa Python e ClamAV (winget) e il servizio ClamAV"
Write-Host "  - copia PiumaAV in $InstallDir e i dati in $DataDir"
Write-Host "  - crea le attivita' pianificate 'PiumaAV' e 'PiumaAV Watchdog'"
Write-Host "  - aggiunge una sezione al file hosts per bloccare i siti malevoli"
Write-Host "  - aggiunge regole al Windows Firewall (gruppo 'PiumaAV') e la protezione dagli exploit per browser, Office e PDF"
Write-Host "Tutto si annulla con install\windows\uninstall.ps1 (vedi README.md)."


# PiumaAV non usa un ambiente virtuale (venv): i lanciatori .exe creati da venv e
# da pip non sono firmati e Windows (Smart App Control, criteri aziendali) puo'
# bloccarli con "Accesso negato". Si usa il python.exe ufficiale, firmato, con le
# librerie in $InstallDir\lib e il piccolo script piuma_run.py.
$LibDir = Join-Path $InstallDir "lib"
$Runner = Join-Path $InstallDir "piuma_run.py"
function Invoke-Piuma {
    param([string[]]$PiumaArgs, [switch]$Optional)
    try {
        & $PyExe $Runner @PiumaArgs
        if ($LASTEXITCODE -ne 0) { throw "codice di uscita $LASTEXITCODE" }
    } catch {
        if (-not $Optional) { throw }
        Write-Warning "Passaggio non riuscito ($_). Verra' ripetuto automaticamente quando PiumaAV e' in esecuzione."
    }
}

function Refresh-Path {
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [Environment]::GetEnvironmentVariable("Path", "User")
}

# --------------------------------------------------------------- 1. dipendenze
# I file estratti da uno zip scaricato hanno il "contrassegno web": lo si toglie
Get-ChildItem -LiteralPath $ProjectDir -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

Step "Controllo Python"
$py = Get-Command py -ErrorAction SilentlyContinue
if (-not $py) {
    winget install -e --id Python.Python.3.12 --scope machine --accept-source-agreements --accept-package-agreements
    Refresh-Path
}
$PyExe = (& py -3 -c "import sys; print(sys.executable)").Trim()
$PyWExe = Join-Path (Split-Path $PyExe) "pythonw.exe"
Write-Host "Python: $PyExe"

Step "Controllo ClamAV"
if (-not (Test-Path (Join-Path $ClamDir "clamscan.exe"))) {
    winget install -e --id Cisco.ClamAV --accept-source-agreements --accept-package-agreements
    if (-not (Test-Path (Join-Path $ClamDir "clamscan.exe"))) {
        throw "Installazione di ClamAV non riuscita. Scaricare l'installer .msi da https://www.clamav.net/downloads e rieseguire questo script."
    }
}

# --------------------------------------------------------------- 2. ClamAV
Step "Configurazione di ClamAV"
$DbDir = Join-Path $ClamDir "database"
New-Item -ItemType Directory -Force -Path $DbDir | Out-Null

$fresh = Join-Path $ClamDir "freshclam.conf"
if (-not (Test-Path $fresh)) {
    @"
DatabaseDirectory "$DbDir"
DatabaseMirror database.clamav.net
UpdateLogFile "$ClamDir\freshclam.log"
"@ | Set-Content -Encoding ASCII $fresh
}

$clamdConf = Join-Path $ClamDir "clamd.conf"
if (-not (Test-Path $clamdConf)) {
    @"
DatabaseDirectory "$DbDir"
TCPSocket 3310
TCPAddr 127.0.0.1
LogFile "$ClamDir\clamd.log"
LogFileMaxSize 5M
LogRotate yes
# controlla ogni 10 minuti se ci sono firme nuove e le ricarica
SelfCheck 600
StreamMaxLength 100M
MaxFileSize 100M
MaxScanSize 400M
"@ | Set-Content -Encoding ASCII $clamdConf
}

Step "Primo download delle firme (puo' richiedere qualche minuto)"
& (Join-Path $ClamDir "freshclam.exe") --config-file="$fresh"

Step "Servizio clamd"
if (-not (Get-Service -Name clamd -ErrorAction SilentlyContinue)) {
    & (Join-Path $ClamDir "clamd.exe") --install-service
}
Set-Service -Name clamd -StartupType Automatic
Start-Service -Name clamd

# --------------------------------------------------------------- 3. PiumaAV
Step "Installazione di PiumaAV in $InstallDir"
if (Test-Path $InstallDir) {
    # Resti di un'installazione precedente: si ripristinano i permessi normali
    # e si rimuove la vecchia venv (le versioni 0.5.0 iniziali la usavano).
    Write-Host "Pulizia dell'installazione precedente..."
    # PiumaAV gia' in esecuzione tiene aperte le sue librerie: va fermato prima di aggiornarle
    Stop-ScheduledTask -TaskName "PiumaAV" -ErrorAction SilentlyContinue
    Stop-ScheduledTask -TaskName "PiumaAV Watchdog" -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*piuma_run.py*" -or $_.ExecutablePath -like "$InstallDir\*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    cmd /c "takeown /F `"$InstallDir`" /R /A >NUL 2>&1"
    cmd /c "icacls `"$InstallDir`" /reset /T /C /Q >NUL 2>&1"
    Remove-Item -Recurse -Force (Join-Path $InstallDir "venv") -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
& $PyExe -m pip install --upgrade --disable-pip-version-check --no-warn-script-location `
    --target "$LibDir" "$ProjectDir[tray]"
if ($LASTEXITCODE -ne 0) { throw "Installazione delle librerie di PiumaAV non riuscita (pip)." }
# YARA e' facoltativo: se per questa versione di Python non c'e' il pacchetto pronto, si prosegue
& $PyExe -m pip install --upgrade --disable-pip-version-check --no-warn-script-location `
    --target "$LibDir" "yara-python>=4.3"
if ($LASTEXITCODE -ne 0) {
    # Per le versioni di Python piu' recenti yara-python non ha pacchetti pronti: si usa yara-x
    & $PyExe -m pip install --upgrade --disable-pip-version-check --no-warn-script-location `
        --target "$LibDir" "yara-x>=1.0"
    if ($LASTEXITCODE -ne 0) { Write-Warning "YARA non installato: PiumaAV funziona lo stesso con gli altri motori." }
}
Copy-Item -Force (Join-Path $PSScriptRoot "piuma_run.py") $Runner
& $PyExe $Runner --help | Out-Null
if ($LASTEXITCODE -ne 0) { throw "PiumaAV non si avvia: controlla i messaggi qui sopra." }

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$cfg = Join-Path $DataDir "config.toml"
if (-not (Test-Path $cfg)) {
    (Get-Content (Join-Path $ProjectDir "config.example.toml")) `
        -replace '^# freshclam_config = .*$', "freshclam_config = '$fresh'" |
        Set-Content -Encoding UTF8 $cfg
}

# Collegamento al comando da riga di comando
$cmd = Join-Path $InstallDir "piuma.cmd"
"@echo off`r`n`"$PyExe`" `"$Runner`" %*" | Set-Content -Encoding ASCII $cmd
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$InstallDir", "Machine")
}

# I file di regole YARA contengono "pezzi" di malware come testo: Defender potrebbe
# scambiarli per minacce. Si esclude solo quella cartella (contiene solo testo).
Add-MpPreference -ExclusionPath (Join-Path $DataDir "yara") -ErrorAction SilentlyContinue

Step "Autoprotezione: cartelle modificabili solo dagli amministratori"
# SID: S-1-5-32-544 Administrators, S-1-5-18 SYSTEM, S-1-5-32-545 Users (nomi indipendenti dalla lingua)
# $InstallDir sta in Program Files, gia' modificabile solo dagli amministratori:
# si lasciano i suoi permessi standard.
# Gli utenti possono LEGGERE configurazione e log (serve all'icona e a "piuma status"),
# ma solo amministratori e SYSTEM possono modificarli.
function Lock-Dir($dir) {
    # Permessi espliciti solo sulla cartella (ereditabili); file e sottocartelle li
    # ereditano con /reset. NON usare /T con /grant: sui file le voci (OI)(CI)
    # vengono scartate e il file resta senza permessi (nemmeno per gli amministratori).
    cmd /c "takeown /F `"$dir`" /R /A >NUL 2>&1"
    icacls "$dir" /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /Q | Out-Null
    cmd /c "icacls `"$dir\*`" /reset /T /C /Q >NUL 2>&1"
}
Lock-Dir $DataDir
Lock-Dir $DbDir

Step "Download delle firme extra (MalwareBazaar, regole YARA-Forge, siti malevoli)"
Invoke-Piuma -PiumaArgs "update" -Optional

# --------------------------------------------------------------- 4. avvio automatico
Step "Avvio automatico all'accesso (icona nell'area di notifica)"
$action   = New-ScheduledTaskAction -Execute $PyWExe -Argument "`"$Runner`" tray"
$trigger  = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
            -Priority 7
Register-ScheduledTask -TaskName "PiumaAV" -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "PiumaAV"
Start-Sleep -Seconds 8
$running = Get-CimInstance Win32_Process -Filter "Name = 'pythonw.exe'" -ErrorAction SilentlyContinue |
           Where-Object { $_.CommandLine -like "*piuma_run.py*tray*" }
if ($running) {
    Write-Host "Protezione avviata. Lo scudo verde potrebbe essere tra le icone nascoste (freccia ^ vicino all'orologio)." -ForegroundColor Green
} else {
    Write-Warning "L'icona di PiumaAV non risulta avviata. Ultimi messaggi:"
    foreach ($f in @("$DataDir\logs\avvio-errori.log", "$DataDir\logs\piuma.log")) {
        if (Test-Path $f) { Write-Host "--- $f"; Get-Content $f -Tail 15 }
    }
}

Step "Watchdog: riavvia la protezione se viene fermata"
$wdAction  = New-ScheduledTaskAction -Execute $PyWExe -Argument "`"$Runner`" watchdog"
$wdTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
             -RepetitionInterval (New-TimeSpan -Minutes 5)
$wdSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
             -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName "PiumaAV Watchdog" -Action $wdAction -Trigger $wdTrigger -Principal $principal `
    -Settings $wdSettings -Force | Out-Null

Step "Protezione dagli exploit per browser, Office e lettori PDF"
try { & (Join-Path $PSScriptRoot "exploit-protection.ps1") }
catch { Write-Warning "Protezione dagli exploit non applicata ($_)." }

Step "Firma digitale locale degli script (certificato autofirmato)"
if ((Get-AuthenticodeSignature $PSCommandPath).Status -eq "Valid") {
    # Pacchetto ufficiale gia' firmato (SignPath): niente certificato locale, si copiano gli script cosi' come sono
    $Tools = Join-Path $InstallDir "tools"
    New-Item -ItemType Directory -Force -Path $Tools | Out-Null
    Get-ChildItem $PSScriptRoot -Filter *.ps1 | Where-Object Name -ne "install.ps1" | Copy-Item -Destination $Tools -Force
    Write-Host "Script gia' firmati digitalmente: certificato locale non necessario."
} else {
    try { & (Join-Path $PSScriptRoot "firma.ps1") -InstallDir $InstallDir }
    catch { Write-Warning "Firma non riuscita ($_): PiumaAV funziona lo stesso." }
}

Step "Registrazione dell'integrita' dei file"
Invoke-Piuma -PiumaArgs "integrity","--record" -Optional

Step "Fatto!"
Write-Host "Consigliato: rafforza anche Microsoft Defender (blocca i virus prima che partano):"
Write-Host "  .\install\windows\harden-defender.ps1"
Write-Host "PiumaAV e' attivo (icona a forma di scudo vicino all'orologio)."
Write-Host "Comandi utili (in un nuovo terminale):"
Write-Host "  piuma status"
Write-Host "  piuma scan C:\Users\$env:USERNAME\Downloads"
Write-Host "  piuma scan D:\            (scansione di un intero disco)"
Write-Host "  piuma quarantine list"
