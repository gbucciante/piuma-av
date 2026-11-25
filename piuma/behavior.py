"""Analisi del comportamento dei processi.

Ogni mezzo secondo PiumaAV guarda quali processi sono nati (con `psutil`, costo
trascurabile) e controlla chi li ha avviati e con quali parametri. Molti
attacchi non usano un "file virus" ma programmi legittimi di Windows
(PowerShell, mshta, certutil...) comandati da un documento o da uno script:
le firme non li vedono, il comportamento si'.

Esempi di regole:
  * Word/Excel/Outlook/Acrobat che avviano PowerShell, cmd, script o LOLBin
  * PowerShell con comandi codificati, nascosti o che scaricano ed eseguono
  * certutil/bitsadmin/mshta/regsvr32/rundll32 usati per scaricare codice
  * cancellazione delle copie shadow e dei backup (tipico del ransomware)
  * Linux/macOS: "curl ... | sh", reverse shell, payload base64 eseguiti

Le regole "critiche" (es. cancellazione dei backup) possono terminare subito il
processo (`kill_critical = true`); le altre producono un avviso.
Inoltre l'eseguibile di ogni nuovo processo viene analizzato con i motori di
PiumaAV: se e' un malware noto il processo viene terminato e il file isolato.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from dataclasses import dataclass

from .config import IS_WINDOWS, Config
from .pause import is_paused

log = logging.getLogger(__name__)

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe",
          "visio.exe", "msaccess.exe", "acrord32.exe", "acrobat.exe", "foxitpdfreader.exe",
          "hwp.exe", "wordpad.exe"}
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
LOLBINS = {"rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "wmic.exe",
           "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe", "msiexec.exe", "schtasks.exe",
           "forfiles.exe", "hh.exe", "odbcconf.exe", "esentutl.exe"}


@dataclass
class Rule:
    id: str
    description: str
    severity: str                 # "alta" | "critica"
    pattern: re.Pattern | None = None        # sulla riga di comando
    names: frozenset[str] | None = None      # nome del processo (minuscolo)
    parents: frozenset[str] | None = None    # nome del processo padre


def _r(p: str) -> re.Pattern:
    return re.compile(p, re.I)


RULES: list[Rule] = [
    # ---- documenti che lanciano programmi (macro malevole, exploit)
    Rule("office-child", "Un documento (Office/PDF) ha avviato una shell o un programma di sistema", "alta",
         names=frozenset(SCRIPT_HOSTS | LOLBINS), parents=frozenset(OFFICE)),
    # ---- PowerShell sospetto
    Rule("ps-encoded", "PowerShell con comando codificato (Base64)", "alta",
         pattern=_r(r"\s-(e|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{20,}"),
         names=frozenset({"powershell.exe", "pwsh.exe", "powershell", "pwsh"})),
    Rule("ps-download-exec", "PowerShell che scarica ed esegue codice da Internet", "alta",
         pattern=_r(r"(iex|invoke-expression).{0,200}(downloadstring|downloaddata|invoke-webrequest|iwr |"
                    r"net\.webclient|start-bitstransfer|irm )|(downloadstring|downloaddata|net\.webclient).{0,200}(iex|invoke-expression)"),
         names=frozenset({"powershell.exe", "pwsh.exe", "powershell", "pwsh"})),
    Rule("ps-hidden-bypass", "PowerShell nascosto con criteri di sicurezza disattivati", "alta",
         pattern=_r(r"(-w(indowstyle)?\s+h(idden)?).*(-ep|-exec(utionpolicy)?)\s+bypass|"
                    r"(-ep|-exec(utionpolicy)?)\s+bypass.*(-w(indowstyle)?\s+h(idden)?)"),
         names=frozenset({"powershell.exe", "pwsh.exe"})),
    Rule("ps-amsi-bypass", "Tentativo di disattivare l'antivirus (AMSI / Defender)", "critica",
         pattern=_r(r"amsiutils|amsiinitfailed|amsiscanbuffer|set-mppreference.{0,80}"
                    r"(disablerealtimemonitoring|disableioavprotection|disablebehaviormonitoring)\s+(\$true|1)|"
                    r"add-mppreference.{0,40}exclusionpath")),
    # ---- LOLBin usati per scaricare/eseguire
    Rule("certutil-download", "certutil usato per scaricare o decodificare file", "alta",
         pattern=_r(r"-urlcache|-decode|-decodehex|verifyctl.*http"), names=frozenset({"certutil.exe"})),
    Rule("bitsadmin-download", "bitsadmin usato per scaricare file", "alta",
         pattern=_r(r"/transfer|/addfile"), names=frozenset({"bitsadmin.exe"})),
    Rule("mshta-remote", "mshta esegue script remoti o inline", "alta",
         pattern=_r(r"https?://|javascript:|vbscript:"), names=frozenset({"mshta.exe"})),
    Rule("regsvr32-squiblydoo", "regsvr32 carica uno scriptlet remoto", "alta",
         pattern=_r(r"/i:\s*https?://|scrobj\.dll"), names=frozenset({"regsvr32.exe"})),
    Rule("rundll32-script", "rundll32 usato per eseguire script", "alta",
         pattern=_r(r"javascript:|mshtml,runhtmlapplication|url\.dll,.*(openurl|fileprotocolhandler).*https?://"),
         names=frozenset({"rundll32.exe"})),
    Rule("wmic-create", "WMIC avvia processi (movimento laterale/persistenza)", "alta",
         pattern=_r(r"process\s+call\s+create|/node:"), names=frozenset({"wmic.exe"})),
    # ---- distruzione dei backup: tipico del ransomware
    Rule("shadow-delete", "Cancellazione delle copie shadow / dei backup (tipico ransomware)", "critica",
         pattern=_r(r"vssadmin(\.exe)?\s+(delete\s+shadows|resize\s+shadowstorage)|"
                    r"wmic(\.exe)?\s+shadowcopy\s+delete|win32_shadowcopy.{0,40}delete|"
                    r"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup)|"
                    r"bcdedit(\.exe)?.{0,40}(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)")),
    Rule("defender-tamper", "Tentativo di spegnere la protezione di sistema", "critica",
         pattern=_r(r"sc(\.exe)?\s+(stop|delete|config)\s+(windefend|wdnissvc|sense|piuma)|"
                    r"taskkill.{0,40}(msmpeng|piuma|clamd)|net\s+stop\s+(windefend|clamd)")),
    Rule("clear-logs", "Cancellazione dei registri eventi di Windows", "alta",
         pattern=_r(r"wevtutil(\.exe)?\s+cl\s|clear-eventlog")),
    # ---- Linux / macOS
    Rule("pipe-to-shell", "Scarica uno script da Internet e lo esegue direttamente", "alta",
         pattern=_r(r"(curl|wget)\s[^|;]*https?://[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")),
    Rule("reverse-shell", "Possibile reverse shell (controllo remoto del computer)", "critica",
         pattern=_r(r"bash\s+-i\s*>&?\s*/dev/tcp/|/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+|"
                    r"\bnc(at)?\b.{0,40}\s-e\s+/bin/(ba)?sh|socat.{0,60}exec:.{0,20}sh|"
                    r"python\d?\s+-c\s+.{0,80}socket.{0,200}(dup2|pty\.spawn)")),
    Rule("base64-exec", "Esegue codice nascosto in Base64", "alta",
         pattern=_r(r"base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh\b|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64")),
    Rule("osascript-shell", "AppleScript che esegue comandi di shell scaricati", "alta",
         pattern=_r(r"do shell script.{0,120}(curl|wget)"), names=frozenset({"osascript"})),
]


def evaluate(name: str, cmdline: str, parent: str) -> list[Rule]:
    """Restituisce le regole violate da un processo."""
    name, parent = name.lower(), parent.lower()
    hits = []
    for rule in RULES:
        if rule.names is not None and name not in rule.names:
            continue
        if rule.parents is not None and parent not in rule.parents:
            continue
        if rule.pattern is not None and not rule.pattern.search(cmdline):
            continue
        hits.append(rule)
    return hits


class BehaviorMonitor:
    def __init__(self, cfg: Config, scanner=None, alert=None, poll: float = 0.5):
        import psutil  # noqa: F401  (dipendenza obbligatoria dalla 0.4)
        self.cfg = cfg
        self.scanner = scanner
        self.poll = poll
        self.alert = alert or self._default_alert
        self._known: set[int] = set()
        self._scanned: dict[str, float] = {}      # eseguibile -> mtime gia' analizzato
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.my_pid = os.getpid()
        self.netguard = None
        if IS_WINDOWS and cfg.protection.network_guard:
            from .netguard import NetGuard
            self.netguard = NetGuard(cfg)

    # ------------------------------------------------------------- analisi
    def inspect(self, proc) -> list[Rule]:
        import psutil
        try:
            with proc.oneshot():
                name = proc.name()
                cmd = " ".join(proc.cmdline())
                try:
                    parent = proc.parent()
                    pname = parent.name() if parent else ""
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pname = ""
                exe = ""
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return []
        hits = evaluate(name, cmd, pname)
        for rule in hits:
            killed = False
            if rule.severity == "critica" and self.cfg.behavior.kill_critical:
                killed = self._kill(proc)
            self.alert(rule, name, proc.pid, cmd, pname, killed)
        if self.netguard and exe:          # prima della scansione, che puo' richiedere qualche secondo
            try:
                self.netguard.check(exe)
            except Exception:  # noqa: BLE001 - il firewall non deve fermare l'analisi
                log.exception("firewall: errore su %s", exe)
        if self.scanner and self.cfg.behavior.scan_new_processes and exe:
            self._scan_executable(proc, exe)
        return hits

    def _scan_executable(self, proc, exe: str) -> None:
        try:
            mtime = os.path.getmtime(exe)
        except OSError:
            return
        if self._scanned.get(exe) == mtime:
            return
        self._scanned[exe] = mtime
        if len(self._scanned) > 20000:
            self._scanned.clear()
        # il processo va fermato PRIMA di spostare il file (su Windows e' bloccato)
        res = self.scanner.engine.scan_file(exe)
        if res.infected:
            from .procscan import is_system_file
            if is_system_file(exe):        # mai terminare/spostare file di sistema per un possibile falso positivo
                log.warning("file di sistema segnalato: %s (%s)", exe, res.signature)
                return
            self._kill(proc)
            self.scanner.handle(res, "processo in esecuzione")

    @staticmethod
    def _kill(proc) -> bool:
        import psutil
        try:
            proc.kill()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def _default_alert(self, rule: Rule, name: str, pid: int, cmd: str, parent: str, killed: bool) -> None:
        from .notify import notify
        action = "processo TERMINATO" if killed else "processo lasciato in esecuzione"
        log.warning("COMPORTAMENTO SOSPETTO [%s] %s: %s (PID %d, avviato da %s) -> %s | %s",
                    rule.severity, rule.id, name, pid, parent or "?", action, cmd[:400])
        if self.cfg.notifications:
            notify(f"PiumaAV: comportamento sospetto ({rule.severity})",
                   f"{rule.description}\n{name} (avviato da {parent or '?'}) - {action}")

    # ------------------------------------------------------------- ciclo
    def _loop(self) -> None:
        import psutil
        self._known = set(psutil.pids())        # i processi gia' esistenti li vede la scansione processi
        while not self._stop.wait(self.poll):
            try:
                current = set(psutil.pids())
            except OSError:
                continue
            if is_paused(self.cfg.data_dir):
                self._known = current
                continue
            for pid in current - self._known:
                if pid == self.my_pid:
                    continue
                try:
                    self.inspect(psutil.Process(pid))
                except psutil.NoSuchProcess:
                    pass
                except Exception:
                    log.exception("errore nell'analisi del processo %s", pid)
            self._known = current

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="behavior", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
