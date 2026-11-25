# Rafforza Microsoft Defender: e' il modo piu' efficace per BLOCCARE i virus
# PRIMA che partano (Defender ha un driver nel kernel, PiumaAV no).
#
# Uso (PowerShell come Amministratore):
#   .\harden-defender.ps1            applica le regole in modalita' blocco
#   .\harden-defender.ps1 -Audit     solo registrazione (prova di una settimana, nessun blocco)
#   .\harden-defender.ps1 -Undo      ripristina le impostazioni predefinite
#
# Include l'"Accesso controllato alle cartelle" (anti-ransomware): Documenti,
# Immagini, Desktop ecc. diventano modificabili solo da programmi fidati.
# Se un tuo programma legittimo non riesce piu' a salvare, consentilo da
# Sicurezza di Windows > Protezione ransomware > Consenti app.
#
# Funziona con Windows 10/11 Home e Pro, solo se Defender e' l'antivirus attivo.

#Requires -RunAsAdministrator
param([switch]$Audit, [switch]$Undo)
$ErrorActionPreference = "Stop"
# Avviato da PowerShell 7 (pwsh), Windows PowerShell 5.1 eredita i percorsi dei moduli di pwsh
# e non riesce a caricare i propri (es. Get-AuthenticodeSignature): si usano quelli di sistema.
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $env:PSModulePath = "$env:ProgramFiles\WindowsPowerShell\Modules;" + [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
}

$status = Get-MpComputerStatus
if (-not $status.AntivirusEnabled -or $status.AMRunningMode -ne "Normal") {
    Write-Warning "Microsoft Defender non e' l'antivirus attivo (modalita': $($status.AMRunningMode)). Nessuna modifica."
    exit 1
}

# Regole ASR (Attack Surface Reduction) consigliate da Microsoft: bloccano le
# tecniche usate dai malware anche quando il file non e' ancora conosciuto.
$asr = [ordered]@{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Driver vulnerabili firmati usati dagli attacchi"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Adobe Reader che avvia altri programmi"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Office che avvia altri programmi"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Furto di password dalla memoria di sistema (lsass)"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Eseguibili arrivati via email/webmail"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Script offuscati"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "JavaScript/VBScript che lanciano file scaricati"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Office che crea file eseguibili"
    "75668c1f-73b5-4cf4-bb93-3ecf5cb7cc84" = "Office che inietta codice in altri processi"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Outlook che avvia altri programmi"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Persistenza tramite WMI"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Programmi non firmati avviati da chiavette USB"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Macro di Office che chiamano funzioni di sistema"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Protezione avanzata contro i ransomware"
}

if ($Undo) {
    Remove-MpPreference -AttackSurfaceReductionRules_Ids @($asr.Keys) -ErrorAction SilentlyContinue
    Set-MpPreference -PUAProtection Disabled -CloudBlockLevel Default -CloudExtendedTimeout 0 `
                     -EnableNetworkProtection Disabled -EnableControlledFolderAccess Disabled
    Write-Host "Impostazioni di Defender riportate ai valori predefiniti." -ForegroundColor Green
    exit 0
}

$mode = if ($Audit) { "AuditMode" } else { "Enabled" }

Write-Host "==> Protezione cloud alta e app potenzialmente indesiderate (PUA)" -ForegroundColor Cyan
Set-MpPreference -MAPSReporting Advanced `
                 -SubmitSamplesConsent SendSafeSamples `
                 -CloudBlockLevel High `
                 -CloudExtendedTimeout 50 `
                 -PUAProtection $(if ($Audit) { "AuditMode" } else { "Enabled" }) `
                 -DisableRealtimeMonitoring $false `
                 -DisableBehaviorMonitoring $false `
                 -DisableIOAVProtection $false `
                 -DisableScriptScanning $false `
                 -DisableArchiveScanning $false `
                 -DisableRemovableDriveScanning $false `
                 -SignatureUpdateInterval 4

Write-Host "==> Protezione di rete (blocca siti di phishing/malware in tutti i browser)" -ForegroundColor Cyan
Set-MpPreference -EnableNetworkProtection $mode

Write-Host "==> Accesso controllato alle cartelle (anti-ransomware)" -ForegroundColor Cyan
Set-MpPreference -EnableControlledFolderAccess $mode
# PiumaAV gira con il pythonw.exe di sistema
$py = (& py -3 -c "import sys; print(sys.executable)" 2>$null)
if ($py) {
    $pyw = Join-Path (Split-Path $py.Trim()) "pythonw.exe"
    if (Test-Path $pyw) { Add-MpPreference -ControlledFolderAccessAllowedApplications $pyw }
}

Write-Host "==> Regole ASR in modalita' $mode" -ForegroundColor Cyan
Add-MpPreference -AttackSurfaceReductionRules_Ids @($asr.Keys) `
                 -AttackSurfaceReductionRules_Actions @($asr.Keys | ForEach-Object { $mode })
$asr.GetEnumerator() | ForEach-Object { Write-Host ("   - " + $_.Value) }

Write-Host "`n==> Aggiornamento firme di Defender" -ForegroundColor Cyan
Update-MpSignature -ErrorAction SilentlyContinue

Write-Host "`nFatto." -ForegroundColor Green
if ($Audit) {
    Write-Host "Modalita' prova: nulla viene bloccato. Dopo qualche giorno controlla il Visualizzatore eventi"
    Write-Host "(Microsoft > Windows > Windows Defender > Operational, eventi 1121/1122) e poi rilancia senza -Audit."
} else {
    Write-Host "Se un programma legittimo viene bloccato, lo vedi in Sicurezza di Windows > Cronologia protezione."
    Write-Host "Per annullare tutto: .\harden-defender.ps1 -Undo"
}
Write-Host "Importante: lascia attiva la 'Protezione da manomissioni' di Defender (Sicurezza di Windows >"
Write-Host "Protezione da virus e minacce > Gestisci impostazioni): impedisce ai virus di spegnere Defender."
