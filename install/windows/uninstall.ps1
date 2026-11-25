# Disinstallazione di PiumaAV (Amministratore). ClamAV resta installato:
# per rimuoverlo:  winget uninstall Cisco.ClamAV
#Requires -RunAsAdministrator
# Avviato da PowerShell 7 (pwsh), Windows PowerShell 5.1 eredita i percorsi dei moduli di pwsh
# e non riesce a caricare i propri (es. Get-AuthenticodeSignature): si usano quelli di sistema.
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $env:PSModulePath = "$env:ProgramFiles\WindowsPowerShell\Modules;" + [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
}
$runner = "$env:ProgramFiles\PiumaAV\piuma_run.py"
if (Test-Path $runner) { & py -3 $runner blocklist remove 2>$null }
# Regole firewall di PiumaAV e protezione dagli exploit tornano come prima
Remove-NetFirewallRule -Group "PiumaAV" -ErrorAction SilentlyContinue
$ep = "$env:ProgramFiles\PiumaAV\tools\exploit-protection.ps1"
if (Test-Path $ep) { & $ep -Undo }
Unregister-ScheduledTask -TaskName "PiumaAV" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "PiumaAV Watchdog" -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*PiumaAV\piuma_run.py*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Remove-MpPreference -ExclusionPath "$env:ProgramData\PiumaAV\yara" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$env:ProgramFiles\PiumaAV" -ErrorAction SilentlyContinue
$p = [Environment]::GetEnvironmentVariable("Path", "Machine") -replace [regex]::Escape(";$env:ProgramFiles\PiumaAV"), ""
[Environment]::SetEnvironmentVariable("Path", $p, "Machine")
Write-Host "PiumaAV rimosso. Quarantena e log restano in $env:ProgramData\PiumaAV (eliminali a mano se vuoi)."
# Certificato di firma locale di PiumaAV
foreach ($store in "Root", "TrustedPublisher", "My") {
    Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq "CN=PiumaAV - firma locale" } |
        ForEach-Object { Remove-Item $_.PSPath -ErrorAction SilentlyContinue }
}
