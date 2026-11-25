"""Sorveglianza dei punti di avvio automatico.

Quasi ogni malware, per sopravvivere a un riavvio, si registra in uno dei
"punti di avvio" del sistema. PiumaAV ne fotografa lo stato e, ogni pochi
minuti, segnala ogni voce NUOVA o MODIFICATA, analizzando subito il file
indicato.

  Windows: chiavi Run/RunOnce del registro (HKLM, HKCU, WOW6432Node),
           Winlogon Shell/Userinit, cartelle Esecuzione automatica,
           attivita' pianificate, servizi.
  macOS:   LaunchAgents / LaunchDaemons (utente e sistema), Login Items.
  Linux:   unita' systemd, cron, ~/.config/autostart, rc.local, profili shell.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import re
import shlex
import subprocess
from pathlib import Path

from .config import IS_MAC, IS_WINDOWS, Config

log = logging.getLogger(__name__)

Entries = dict[str, str]     # chiave univoca -> comando/contenuto


# ------------------------------------------------------------------ raccolta
def _file_digest(p: Path) -> str:
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()[:16]
    except OSError:
        return "?"


def _dir_entries(prefix: str, folder: Path, pattern: str = "*") -> Entries:
    out: Entries = {}
    if folder.is_dir():
        for p in sorted(folder.glob(pattern)):
            if p.is_file():
                out[f"{prefix}:{p}"] = f"{p} #{_file_digest(p)}"
    return out


def _windows_entries() -> Entries:
    import winreg  # type: ignore[import-not-found]
    out: Entries = {}
    run_keys = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ]
    for hive_name, hive in (("HKLM", winreg.HKEY_LOCAL_MACHINE), ("HKCU", winreg.HKEY_CURRENT_USER)):
        for sub in run_keys:
            try:
                with winreg.OpenKey(hive, sub) as k:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        out[f"reg:{hive_name}\\{sub}\\{name}"] = str(value)
                        i += 1
            except OSError:
                continue
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon") as k:
            for name in ("Shell", "Userinit"):
                try:
                    out[f"reg:Winlogon\\{name}"] = str(winreg.QueryValueEx(k, name)[0])
                except OSError:
                    pass
    except OSError:
        pass
    # servizi con avvio automatico (Start 0-2)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") as root:
            i = 0
            while True:
                try:
                    svc = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, svc) as k:
                        start = winreg.QueryValueEx(k, "Start")[0]
                        if start <= 2:
                            image = winreg.QueryValueEx(k, "ImagePath")[0]
                            out[f"service:{svc}"] = str(image)
                except OSError:
                    continue
    except OSError:
        pass
    # cartelle Esecuzione automatica
    for base in (os.environ.get("APPDATA"), os.environ.get("ProgramData")):
        if base:
            out.update(_dir_entries("startup", Path(base) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"))
    # attivita' pianificate
    try:
        proc = subprocess.run(["schtasks", "/Query", "/FO", "CSV", "/V"], capture_output=True, text=True,
                              errors="replace", timeout=120, creationflags=0x08000000)
        rows = list(csv.reader(io.StringIO(proc.stdout)))
        if rows:
            header = rows[0]
            try:
                i_name, i_run = header.index("TaskName"), header.index("Task To Run")
            except ValueError:     # Windows in italiano: intestazioni tradotte -> 2a e 9a colonna
                i_name, i_run = 1, 8
            for r in rows[1:]:
                if len(r) > max(i_name, i_run) and r[i_name] != header[i_name]:
                    out[f"task:{r[i_name]}"] = r[i_run]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return out


def _mac_entries() -> Entries:
    out: Entries = {}
    for d in (Path.home() / "Library/LaunchAgents", Path("/Library/LaunchAgents"),
              Path("/Library/LaunchDaemons"), Path("/Library/StartupItems")):
        out.update(_dir_entries("launchd", d, "*.plist") if d.name != "StartupItems" else _dir_entries("startupitem", d))
    try:
        proc = subprocess.run(["osascript", "-e", 'tell application "System Events" to get the path of every login item'],
                              capture_output=True, text=True, timeout=30)
        for item in proc.stdout.strip().split(", "):
            if item:
                out[f"loginitem:{item}"] = item
    except (OSError, subprocess.TimeoutExpired):
        pass
    return out


def _linux_entries() -> Entries:
    out: Entries = {}
    home_dirs = [Path(p) for p in {str(Path.home()), *[str(h) for h in Path("/home").glob("*")]} if Path(p).is_dir()]
    for d in (Path("/etc/systemd/system"), Path("/usr/local/lib/systemd/system"), Path("/etc/init.d"),
              Path("/etc/cron.d"), Path("/etc/cron.hourly"), Path("/etc/cron.daily"),
              Path("/etc/xdg/autostart"), Path("/var/spool/cron/crontabs"), Path("/var/spool/cron")):
        out.update(_dir_entries("sys", d))
    for f in (Path("/etc/crontab"), Path("/etc/rc.local"), Path("/etc/ld.so.preload")):
        if f.is_file():
            out[f"file:{f}"] = f"{f} #{_file_digest(f)}"
    for h in home_dirs:
        out.update(_dir_entries("user", h / ".config/autostart"))
        out.update(_dir_entries("user", h / ".config/systemd/user"))
        for rc in (".bashrc", ".profile", ".bash_profile", ".zshrc"):
            f = h / rc
            if f.is_file():
                out[f"file:{f}"] = f"{f} #{_file_digest(f)}"
    return out


def collect() -> Entries:
    try:
        if IS_WINDOWS:
            return _windows_entries()
        if IS_MAC:
            return _mac_entries()
        return _linux_entries()
    except Exception:   # mai bloccare il servizio per questo
        log.exception("errore nella lettura dei punti di avvio")
        return {}


# ------------------------------------------------------------------ confronto
_PATH_RE = re.compile(r'"([^"]+)"|(\S+)')


def target_path(command: str) -> str | None:
    """Estrae il percorso del programma da una riga di comando."""
    cmd = os.path.expandvars(command.split(" #")[0].strip())
    m = _PATH_RE.match(cmd)
    if not m:
        return None
    first = m.group(1) or m.group(2)
    if os.path.isfile(first):
        return first
    try:      # "C:\Program Files\x.exe" senza virgolette
        parts = shlex.split(cmd, posix=not IS_WINDOWS)
    except ValueError:
        parts = cmd.split()
    for i in range(len(parts), 0, -1):
        cand = " ".join(parts[:i]).strip('"')
        if os.path.isfile(cand):
            return cand
    return None


class AutostartMonitor:
    def __init__(self, cfg: Config, scanner=None, collector=collect):
        self.cfg = cfg
        self.scanner = scanner
        self.collect = collector
        self.baseline_file = cfg.data_dir / "autostart_baseline.json"

    def _load(self) -> Entries | None:
        try:
            return json.loads(self.baseline_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def accept(self, entries: Entries | None = None) -> int:
        entries = self.collect() if entries is None else entries
        self.baseline_file.write_text(json.dumps(entries, indent=1, sort_keys=True), encoding="utf-8")
        return len(entries)

    def check(self) -> list[tuple[str, str, str]]:
        """Restituisce le modifiche [(tipo, chiave, valore)] e aggiorna la fotografia."""
        from .notify import notify
        current = self.collect()
        baseline = self._load()
        if baseline is None:
            self.accept(current)        # primo avvio: fotografia iniziale
            return []
        changes = []
        for key, value in current.items():
            if key not in baseline:
                changes.append(("NUOVO", key, value))
            elif baseline[key] != value:
                changes.append(("MODIFICATO", key, value))
        for key in baseline.keys() - current.keys():
            changes.append(("RIMOSSO", key, baseline[key]))
        for kind, key, value in changes:
            if kind == "RIMOSSO":
                log.info("avvio automatico rimosso: %s", key)
                continue
            log.warning("AVVIO AUTOMATICO %s: %s -> %s", kind, key, value)
            verdict = ""
            path = target_path(value)
            if self.scanner and path:
                res = self.scanner.scan_file(path, source="avvio automatico")
                if res is not None and res.infected:
                    verdict = f"\nMINACCIA: {res.signature}"
            if self.cfg.notifications:
                notify("PiumaAV: programma aggiunto all'avvio",
                       f"{kind}: {key.split(':', 1)[-1][-80:]}\n{value[:120]}{verdict}")
        if changes:
            self.accept(current)
        return changes
