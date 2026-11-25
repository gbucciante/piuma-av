# Disinstallazione di PiumaAV (Amministratore). ClamAV resta installato:
# per rimuoverlo:  winget uninstall Cisco.ClamAV
#Requires -RunAsAdministrator
$runner = "$env:ProgramFiles\PiumaAV\piuma_run.py"
if (Test-Path $runner) { & py -3 $runner blocklist remove 2>$null }
Unregister-ScheduledTask -TaskName "PiumaAV" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "PiumaAV Watchdog" -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*PiumaAV\piuma_run.py*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
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
