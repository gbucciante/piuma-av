# PiumaAV

Antivirus **leggero e multipiattaforma** (Windows, macOS, Linux) con:

- 🛡️ **Protezione in tempo reale**: i file nuovi o modificati nelle cartelle a rischio vengono analizzati appena salvati
- 🔄 **Aggiornamento automatico delle firme** (predefinito: ogni 4 ore)
- 🔍 **Scansione su richiesta** di cartelle, file o interi dischi (anche chiavette USB)
- 🗄️ **Quarantena** recuperabile, **notifiche** desktop, **scansioni pianificate**
- 🪶 Icona nell'area di notifica con menu rapido

## Motori di rilevamento (dalla versione 0.2)

PiumaAV usa **più motori insieme**: un file è considerato infetto se almeno uno lo riconosce.

| Motore | Sistemi | Cosa porta |
|---|---|---|
| **Microsoft Defender** (via AMSI e MpCmdRun) | Windows | Il motore più efficace tra quelli gratuiti: ~99,9% nei test AV-Comparatives, con analisi cloud |
| **ClamAV** + firme ufficiali | tutti | Milioni di firme, ottimo su archivi, email, malware Linux |
| **MalwareBazaar** (abuse.ch) | tutti | Hash dei malware raccolti ogni giorno dalla comunità, aggiunti a ClamAV. **Richiede una chiave gratuita**: registrati su https://auth.abuse.ch, poi scrivi `abusech_auth_key = "LA-TUA-CHIAVE"` nella sezione `[feeds]` del file di configurazione (su Windows `C:\ProgramData\PiumaAV\config.toml`, da modificare come amministratore). Senza chiave viene semplicemente saltato. |
| **YARA-Forge** | tutti | Regole che riconoscono intere *famiglie* di malware, anche varianti nuove |

Le sole rilevazioni YARA vengono **segnalate** ma non messe in quarantena (`yara_quarantine = false`),
per evitare che un falso positivo sposti un file buono. Se sul PC è attivo un altro antivirus al posto
di Defender, il motore "defender" usa quello tramite AMSI.

### Bloccare prima dell'esecuzione
Un programma come PiumaAV vede un file subito *dopo* che è stato salvato: per bloccarlo *prima* che parta
serve un driver nel kernel firmato da Microsoft, cosa che solo i produttori di antivirus possono fare.
Defender ce l'ha già: lo script `install\windows\harden-defender.ps1` lo rende molto più severo
(protezione cloud alta, app indesiderate, protezione di rete, 14 regole anti-attacco ASR). Prova prima
con `-Audit` e annulla con `-Undo`.

## Protezioni aggiuntive (dalla versione 0.3)

| Protezione | Come funziona | Sistemi |
|---|---|---|
| **Autoprotezione** | Cartelle del programma e delle firme modificabili solo dagli amministratori; controllo d'integrità con elenco di hash firmato (HMAC): se un virus altera un file, arriva un avviso; un *watchdog* ogni 5 minuti riavvia la protezione se è stata fermata | tutti |
| **Aggiornamenti verificati** | Firme ClamAV firmate digitalmente (verificate da freshclam); download solo HTTPS; lo zip di YARA-Forge è confrontato con l'hash SHA-256 pubblicato da GitHub; ogni file viene controllato prima di sostituire il vecchio | tutti |
| **Reputazione VirusTotal** *(facoltativa)* | Per eseguibili e script non riconosciuti, chiede a VirusTotal quanti antivirus lo segnalano. Invia **solo l'hash**, mai il file. Serve una chiave API gratuita | tutti |
| **Avvio automatico** | Fotografa registro (Run/RunOnce, Winlogon), servizi, attività pianificate, LaunchAgents, systemd, cron… e avvisa di ogni voce nuova, analizzando il programma indicato | tutti |
| **Anti-ransomware** | File esca nascosti nelle cartelle sorvegliate; allarme se molti file diventano "cifrati" in pochi secondi, se compaiono estensioni da ransomware o note di riscatto. Su Windows indica anche i processi che scrivono di più. La protezione preventiva delle cartelle è l'*Accesso controllato alle cartelle* di Defender, attivato da `harden-defender.ps1` | tutti |
| **Blocco siti malevoli** | Liste aggiornate di domini che distribuiscono malware (URLhaus) scritte in una sezione dedicata del file `hosts`: nessun programma riesce più a contattarli | tutti (macOS: `sudo piuma blocklist`) |

Comandi relativi:
```text
piuma integrity                 controlla che programma e firme non siano stati manomessi
piuma autostart list|check      mostra / controlla i programmi ad avvio automatico
piuma autostart accept          accetta come legittime le voci attuali
piuma blocklist update|remove   aggiorna o toglie il blocco dei siti malevoli
```

## Novità della versione 0.4

| Funzione | Cosa fa |
|---|---|
| **Analisi del comportamento** | Ogni mezzo secondo guarda i processi nuovi: segnala Word/Excel/Outlook/PDF che aprono PowerShell o cmd, PowerShell codificato o che scarica ed esegue codice, certutil/mshta/regsvr32 usati per scaricare, tentativi di spegnere Defender, reverse shell, `curl … \| sh`. Le regole **critiche** (es. cancellazione delle copie shadow, tipica del ransomware) terminano subito il processo. L'eseguibile di ogni nuovo processo viene anche analizzato con i motori. |
| **Chiavette USB** | Appena colleghi una chiavetta o un disco esterno viene analizzato tutto in background; segnala anche `autorun.inf` e collegamenti che si spacciano per cartelle. |
| **Processi in esecuzione** | Ogni 12 ore (e con `piuma scan --processes`) analizza gli eseguibili e le DLL caricate da tutti i processi; termina quelli infetti e isola il file. Su Windows `--memory` analizza anche la memoria. I file di sistema non vengono mai terminati o spostati: solo avviso. |
| **Modalità leggera** | `piuma mode leggera` o il menu dell'icona: spegne ClamAV (~1–1,5 GB di RAM in meno) e usa motore Defender + hash MalwareBazaar (pochi MB) + YARA. Consigliata su Windows con poca RAM. |
| **Disattiva protezione** | Dal menu dell'icona: per 15 min, 30 min, 1 ora o fino al riavvio, con conferma; si riattiva da sola. Da terminale: `piuma pause 30m`, `piuma resume`. Solo un amministratore può farlo, quindi un virus senza privilegi non può spegnerla. |

## Novità della versione 0.6

| Funzione | Cosa fa |
|---|---|
| **Blocco Internet per programmi sconosciuti** (Windows) | Quando parte un programma *nuovo*, **senza firma digitale**, che si trova in una cartella dell'utente (Download, Desktop, AppData, Temp…), PiumaAV crea una regola del Windows Firewall che gli impedisce di collegarsi a Internet e ti avvisa. Molti virus "chiamano casa" appena partono: così restano isolati. Per sbloccarlo: menu dello scudo › *Programmi bloccati da Internet*, oppure `piuma firewall allow <percorso>`. Browser, Office, aggiornamenti e tutti i programmi firmati o installati in Program Files non vengono toccati. `piuma firewall reset` toglie tutte le regole. Limite: la regola arriva entro circa mezzo secondo dall'avvio, un collegamento immediato può passare. |
| **Protezione dagli exploit** (Windows) | L'installazione impone a browser, Office e lettori PDF le difese di Windows DEP, ASLR, SEHOP e CFG, che rendono molto più difficile sfruttare una falla di quei programmi. Lo stato precedente viene salvato: `tools\exploit-protection.ps1 -Undo` lo ripristina (lo fa anche la disinstallazione). |
| **Controlli automatici su GitHub** | Dependabot segnala le librerie con vulnerabilità note, i test girano da soli su Linux e Windows e CodeQL (impostazione "Default" di GitHub, in Settings › Code security) analizza il codice a ogni modifica. |

## Novità della versione 0.5: motore euristico PiumaHeur

Accanto a Defender e ClamAV ora c'è un piccolo motore **tutto di PiumaAV**, che non ha bisogno di firme e
quindi può accorgersi anche di file mai visti prima. Assegna a ogni file un **punteggio di rischio da 0 a 100**:

| Cosa guarda | Esempi |
|---|---|
| **Compressione/offuscamento** | sezioni UPX/ASPack/Themida, entropia molto alta, sezioni scrivibili ed eseguibili, pochissime funzioni importate |
| **Funzioni sospette usate insieme** | iniezione in altri processi, "process hollowing", keylogger, scarica-ed-esegui, cifratura di massa |
| **Firma digitale** | su Windows verifica la firma (WinVerifyTrust): un programma firmato e valido abbassa molto il punteggio, una firma falsa lo alza |
| **Nomi ingannevoli** | `fattura.pdf.exe`, carattere RTLO che inverte il nome, eseguibile rinominato in `.docx`/`.jpg` |
| **Script** | PowerShell/VBS/JS offuscati, che scaricano ed eseguono codice o cancellano i backup (`vssadmin delete shadows`) |

- Da **60** punti: **solo avviso** (il file resta dov'è).
- Da **90** punti: **quarantena**. Le soglie si cambiano in `[engine]` (`heuristic_alert_score`, `heuristic_quarantine_score`).
- È leggero: legge solo l'intestazione del file e un campione per l'entropia; gira per ultimo, solo sui file che gli altri motori hanno giudicato puliti. Attivo anche in modalità leggera.

**Falsi positivi misurati:** su 514 eseguibili Windows puliti (numpy, Qt, PySide6, pywin32, Node.js, CMake,
PyInstaller, ecc.) **nessuno** ha raggiunto 60 punti (massimo 40). Un programma legittimo compresso con UPX
arriva a 60: viene segnalato ma non spostato.
**Limite:** non è stato provato su malware reale (per sicurezza non ne scarico). Un'euristica semplice si
aggira facilmente: è un aiuto in più, non una garanzia.

## Perché è leggero

| Accorgimento | Effetto |
|---|---|
| Notifiche del sistema operativo (ReadDirectoryChangesW / FSEvents / inotify) invece di rileggere il disco | ~0% CPU quando non succede nulla |
| Si sorvegliano solo i punti d'ingresso del malware (Download, Desktop, Documenti, Temp, Esecuzione automatica) | nessun rallentamento di giochi, compilazioni, ecc. |
| Firme caricate una sola volta in RAM dal servizio `clamd` | ogni file si analizza in millisecondi |
| Servizio avviato a bassa priorità di CPU e disco | il PC resta reattivo durante le scansioni |
| Download incompleti (`.crdownload`, `.part`) ignorati fino al termine | niente doppie scansioni |

> **Nota sulla memoria**: il database completo di ClamAV in RAM occupa circa 1–1,5 GB (è il prezzo
> di milioni di firme). Su PC con poca memoria si può fermare `clamd` e impostare `mode = "clamscan"`:
> il consumo a riposo scende a ~30 MB, ma ogni scansione in tempo reale diventa più lenta (i file vengono
> raggruppati per limitarne l'impatto).

## Installazione

Scarica/estrai la cartella del progetto, poi:

### Windows 10/11
**Modo semplice:** scarica `PiumaAV-X.Y.Z-Setup.exe` dalla pagina
[Releases](https://github.com/gbucciante/piuma-av/releases), fai doppio clic, rispondi *Sì*
alla richiesta di Windows e segui le schermate (Avanti › Installa). Ci vogliono 5-15 minuti.
Per toglierlo: *Impostazioni › App › App installate › PiumaAV › Disinstalla*.
L'installer (cartella `installer/`, Inno Setup) esegue lo stesso `install.ps1` descritto qui sotto
e salva il resoconto in `C:\Program Files\PiumaAV\setup\installazione.log`.

**Modo manuale:** apri **PowerShell come amministratore** nella cartella del progetto ed esegui:
```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install\windows\install.ps1
```
Lo script installa Python e ClamAV (tramite `winget`), scarica le firme, avvia il servizio `clamd`,
installa PiumaAV in `C:\Program Files\PiumaAV` e lo fa partire automaticamente a ogni accesso.
Per rimuoverlo: `.\install\windows\uninstall.ps1`.

### macOS
```bash
./install/macos/install.sh
```
Richiede [Homebrew](https://brew.sh). Alla fine concedi **Accesso completo al disco** al Python indicato
dallo script, altrimenti macOS impedisce di sorvegliare Scrivania, Documenti e Download.

### Linux (Debian/Ubuntu, Fedora, Arch, openSUSE)
```bash
sudo ./install/linux/install.sh
```
Installa ClamAV dai pacchetti della distribuzione e PiumaAV come servizio systemd (`piuma-av`).

### Firma digitale locale (facoltativa)

L'installazione crea sul PC un certificato autofirmato "PiumaAV - firma locale" e firma gli script
PowerShell di PiumaAV (in `C:\Program Files\PiumaAV\tools`). La chiave privata nasce sul PC, non è
esportabile e **viene cancellata subito dopo la firma**, quindi nessuno può usarla per firmare altro.
Per rifare la firma: `FIRMA.bat`; per togliere il certificato: `FIRMA.bat rimuovi` (lo toglie anche la
disinstallazione). Limiti: vale solo su quel PC, non elimina gli avvisi di SmartScreen/Smart App Control
(servono certificati commerciali) e i file `.bat`/`.py` non si possono firmare: li protegge il controllo
di integrità.

## Uso

```text
piuma status                         stato di motore, firme, quarantena
piuma scan C:\Users\me\Downloads     scansiona una cartella
piuma scan D:\ E:\                   scansiona interi dischi
piuma scan --quick                   scansione rapida delle cartelle a rischio
piuma scan --report-only D:\         segnala soltanto, senza spostare nulla
piuma update                         aggiorna subito le firme
piuma quarantine list                elenca i file in quarantena
piuma quarantine restore <id>        ripristina un file (falso positivo)
piuma quarantine delete <id>         elimina definitivamente
piuma run                            servizio senza icona (server, Linux)
piuma tray                           servizio con icona nell'area di notifica
piuma scan --processes [--memory]    controlla i processi in esecuzione
piuma mode [leggera|completa]        mostra o cambia la modalita'
piuma pause 15m|30m|1h|reboot        sospende la protezione (si riattiva da sola)
piuma resume                         riattiva subito la protezione
```
Codice di uscita di `scan`: `0` nessuna minaccia, `1` minacce trovate, `2`/`3` errore.

## Configurazione

Il file `config.toml` si trova in:
- Windows: `C:\ProgramData\PiumaAV\config.toml`
- macOS: `~/Library/Application Support/PiumaAV/config.toml`
- Linux: `/etc/piuma-av/config.toml`

Vedi [`config.example.toml`](config.example.toml): cartelle sorvegliate, esclusioni, azione sulle minacce
(`quarantine` / `report` / `delete`), frequenza aggiornamenti, scansioni pianificate.
Dopo una modifica riavvia PiumaAV (menu dell'icona → Esci, poi riaccedi, oppure
`systemctl restart piuma-av` su Linux).

## Prova senza rischi

Il file di test standard **EICAR** è innocuo ma ogni antivirus lo riconosce. Crealo nella cartella
Download incollando questo comando in PowerShell (la stringa è divisa in due pezzi apposta, così questa
guida non viene scambiata per un virus):
```powershell
$a = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$'; $b = 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content "$env:USERPROFILE\Downloads\eicar.txt" ($a + $b) -NoNewline
```
Su Linux/macOS: `printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/Downloads/eicar.txt`
Entro un paio di secondi deve sparire, comparire una notifica e risultare in `piuma quarantine list`.
(Se hai anche Microsoft Defender attivo, potrebbe intercettarlo per primo.)

## Limiti, onestamente

> Sull'autoprotezione: un malware che ottiene i privilegi di amministratore può comunque fermare
> qualsiasi programma che non abbia un driver nel kernel. PiumaAV lo rende più difficile e soprattutto
> **rumoroso** (avvisi di integrità, watchdog). Lascia attiva la *Protezione da manomissioni* di Defender.
> L'analisi del comportamento controlla i processi ogni mezzo secondo: un comando che dura meno
> può sfuggire. Senza driver nel kernel il processo viene fermato *dopo* che è partito, non prima.
> L'anti-ransomware avvisa ma non può fermare da solo il processo che cifra: per questo su Windows
> conviene attivare anche l'Accesso controllato alle cartelle.

PiumaAV è un buon secondo livello di difesa ma **non sostituisce Microsoft Defender** né un antivirus
commerciale:
- **Rileva, non blocca in anticipo**: la protezione in tempo reale analizza il file subito *dopo* che è stato
  scritto; non c'è un driver nel kernel che impedisca l'apertura o l'esecuzione prima del controllo.
- **Soprattutto firme**: ClamAV riconosce malware noto; l'euristica PiumaHeur è volutamente prudente e il suo tasso di
  rilevamento su Windows è inferiore a quello dei prodotti commerciali.
- Sorveglia le cartelle configurate, non l'intero disco (scelta voluta per la leggerezza; i dischi interi si
  analizzano con `piuma scan` o con una scansione pianificata).

Il consiglio è di lasciare **Defender attivo** (su Windows convivono senza problemi) e usare PiumaAV per
scansioni mirate di dischi e chiavette, controllo dei download e su sistemi (Linux, macOS) che non hanno
una protezione integrata.

## Sviluppo

```bash
pip install -e ".[dev,tray]"
pytest            # i test usano un motore finto: ClamAV non è necessario
```
Struttura: `engine.py` (dialogo con clamd/clamscan) · `scanner.py` (esclusioni, azioni) ·
`realtime.py` (sorveglianza file) · `updater.py` (freshclam) · `quarantine.py` · `service.py` · `cli.py` · `tray.py`.

Licenza: GPL-2.0 (la stessa di ClamAV).

## Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org)

I pacchetti Windows ufficiali (pagina [Releases](https://github.com/gbucciante/piuma-av/releases))
sono costruiti da questo repository con GitHub Actions; quando la firma SignPath è attiva, i loro
script PowerShell sono firmati digitalmente. Ruoli del team, cosa viene firmato e come: [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md).
Privacy (nessuna telemetria; elenco dei servizi contattati): [PRIVACY.md](PRIVACY.md).

## Licenza

PiumaAV è distribuito con licenza **GNU GPL versione 2** (vedi `LICENSE`), la stessa di ClamAV.
