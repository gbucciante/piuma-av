# Firma digitale locale (certificato autofirmato) per gli script di PiumaAV.
# Eseguire come Amministratore. Viene richiamato anche da install.ps1.
#
# Cosa fa:
#   1. crea sul TUO PC un certificato di firma del codice "PiumaAV - firma locale"
#      (la chiave privata nasce qui e non e' esportabile: non viaggia nello zip)
#   2. lo rende attendibile su questo PC (Autorita' radice + Autori attendibili)
#   3. firma gli script PowerShell di PiumaAV in "C:\Program Files\PiumaAV\tools"
#   4. CANCELLA la chiave privata: nessuno (nemmeno un virus) potra' piu' usarla
#      per firmare altro. Per rifirmare basta rieseguire questo script.
#
# Per togliere tutto:  .\firma.ps1 -Rimuovi
#
# Limiti: un certificato autofirmato vale solo su questo PC. Non elimina gli avvisi
# di SmartScreen o di Smart App Control (servono certificati commerciali) e non si
# possono firmare i file .bat e .py: quelli restano protetti dal controllo di
# integrita' di PiumaAV.

#Requires -RunAsAdministrator
param([switch]$Rimuovi, [string]$InstallDir = (Join-Path $env:ProgramFiles "PiumaAV"))
$ErrorActionPreference = "Stop"
$Subject = "CN=PiumaAV - firma locale"

function Remove-PiumaCerts {
    foreach ($store in "Root", "TrustedPublisher", "My") {
        Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -eq $Subject } |
            ForEach-Object { Remove-Item $_.PSPath -DeleteKey -ErrorAction SilentlyContinue
                             Remove-Item $_.PSPath -ErrorAction SilentlyContinue }
    }
}

if ($Rimuovi) {
    Remove-PiumaCerts
    Write-Host "Certificato PiumaAV rimosso da questo PC." -ForegroundColor Green
    return
}

# Script da firmare: copiati in Program Files (dove solo gli amministratori scrivono)
$Tools = Join-Path $InstallDir "tools"
New-Item -ItemType Directory -Force -Path $Tools | Out-Null
foreach ($f in "uninstall.ps1", "harden-defender.ps1", "exploit-protection.ps1", "firma.ps1") {
    $src = Join-Path $PSScriptRoot $f
    if ((Test-Path $src) -and ($src -ne (Join-Path $Tools $f))) { Copy-Item -Force $src $Tools }
}

Remove-PiumaCerts       # un solo certificato alla volta
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject `
        -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy NonExportable `
        -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(10)

$cer = Join-Path $env:TEMP "piuma-firma.cer"
Export-Certificate -Cert $cert -FilePath $cer | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
Remove-Item $cer -Force

$ok = 0
Get-ChildItem $Tools -Filter *.ps1 | ForEach-Object {
    $r = Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $cert -HashAlgorithm SHA256
    if ($r.Status -eq "Valid") { $ok++ } else { Write-Warning "$($_.Name): $($r.StatusMessage)" }
}

# La chiave privata non serve piu': la si cancella (resta solo la parte pubblica)
Remove-Item "Cert:\LocalMachine\My\$($cert.Thumbprint)" -DeleteKey

Write-Host "Firmati $ok script in $Tools con '$Subject' (impronta $($cert.Thumbprint))." -ForegroundColor Green
Write-Host "Verifica:  Get-AuthenticodeSignature `"$Tools\*.ps1`" | Format-Table Status, Path"
