# Configurazione SignPath (da fare dopo l'approvazione)

Dopo che SignPath Foundation ha accettato il progetto:

1. **SignPath** (https://app.signpath.io), organizzazione creata per PiumaAV:
   - attiva la verifica in due passaggi (MFA) sul tuo account;
   - *Trusted build systems*: collega **GitHub.com** e abilitalo per il progetto;
   - progetto con slug **`piuma-av`**, repository `https://github.com/gbucciante/piuma-av`;
   - artifact configuration con slug **`windows-zip`**: incolla `artifact-configuration.xml`;
   - artifact configuration con slug **`windows-installer`**: incolla `artifact-configuration-installer.xml`
     (firma `PiumaAV-X.Y.Z-Setup.exe`);
   - signing policy con slug **`release-signing`** (certificato della Foundation),
     *approval* manuale obbligatoria, approvatore: `gbucciante`;
   - crea un utente CI (*Users > Add CI user*) con ruolo *Submitter* sulla policy e copia il suo token.
2. **GitHub** (Settings > Secrets and variables > Actions):
   - secret `SIGNPATH_API_TOKEN` = token dell'utente CI;
   - variable `SIGNPATH_ORGANIZATION_ID` = id dell'organizzazione (in SignPath, *Settings*).
3. Per una release: aggiorna la versione in `piuma/__init__.py` e `pyproject.toml`,
   crea il tag `vX.Y.Z` e fai push. La GitHub Action costruisce il pacchetto, lo manda a
   SignPath e attende: approva la richiesta nel portale SignPath. Poi costruisce l'installer
   con gli script firmati e chiede una seconda firma (approvala). Zip, installer e i loro
   SHA-256 vengono allegati alla release.

Verifica su Windows di un file firmato:
`Get-AuthenticodeSignature .\install\windows\install.ps1` deve mostrare `Valid` e
firmatario `SignPath Foundation`.
