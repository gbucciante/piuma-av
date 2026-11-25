# Privacy

*English summary below.*

PiumaAV **non ha telemetria**: non invia statistiche, dati d'uso né file a chi lo sviluppa.
Si collega solo ai servizi elencati qui, per scaricare aggiornamenti o (se lo attivi tu) per
chiedere la reputazione di un file. Ogni voce si disattiva nel file di configurazione
(su Windows `C:\ProgramData\PiumaAV\config.toml`).

| Servizio | Quando | Cosa viene inviato | Come disattivarlo | Privacy del servizio |
|---|---|---|---|---|
| Mirror firme ClamAV (Cisco Talos, `database.clamav.net`) tramite freshclam | aggiornamento firme (ogni 4 ore) | normale richiesta di download (indirizzo IP, versione di ClamAV) | `[update] enabled = false` | https://www.cisco.com/c/en/us/about/legal/privacy-full.html |
| GitHub (YARA-Forge, `github.com`, `api.github.com`) | aggiornamento regole YARA | richiesta di download | `[feeds] yara_forge = false` | https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement |
| abuse.ch (MalwareBazaar, URLhaus) | aggiornamento hash e lista siti malevoli | richiesta di download; per MalwareBazaar la *tua* chiave gratuita, solo se la inserisci | `[feeds] enabled = false`, `[protection] domain_blocking = false` | https://abuse.ch/privacy-policy/ |
| VirusTotal (`www.virustotal.com`) | **solo se attivata** (`[reputation] enabled = true` con la tua chiave) | **solo l'hash SHA-256** dei file sconosciuti, mai il file | predefinita disattivata | https://policies.google.com/privacy (VirusTotal fa parte di Google) |
| Microsoft Defender (motore "defender", solo Windows) | scansioni tramite AMSI / MpCmdRun | ciò che Defender invia secondo le *tue* impostazioni di Windows (protezione cloud, invio campioni) | togli `"defender"` da `[engine] engines` | https://privacy.microsoft.com/privacystatement |
| winget / python.org / clamav.net | **solo durante l'installazione** | download di Python e ClamAV | installarli a mano prima | rispettive privacy policy |

I log, la quarantena e i risultati restano sul tuo PC (`C:\ProgramData\PiumaAV`).

## English summary

PiumaAV has **no telemetry** and never uploads files. This program will not transfer any
information to other networked systems unless specifically requested by the user or the
person installing or operating it, except for downloading malware signatures and threat
feeds from the services in the table above (ClamAV/Cisco Talos, GitHub, abuse.ch).
VirusTotal hash lookups are opt-in and send only file hashes. Every network feature can be
disabled in `config.toml`. Third-party privacy policies are linked in the table.
