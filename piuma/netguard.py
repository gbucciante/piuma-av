"""Blocco di Internet per i programmi sconosciuti (solo Windows).

Quando parte un programma NUOVO che:
  * si trova in una cartella dell'utente (Download, Desktop, AppData, Temp...),
  * non ha una firma digitale valida,
  * non e' gia' stato approvato,
PiumaAV crea una regola del Windows Firewall che gli impedisce di collegarsi a
Internet e avvisa. Dal menu dello scudo ("Programmi bloccati da Internet") o con
`piuma firewall allow <percorso>` lo si sblocca.

Cosa NON fa, volutamente: non cambia la politica generale del firewall e non
tocca i programmi firmati o installati in Program Files / Windows, quindi
browser, Office, aggiornamenti di Windows e simili continuano a funzionare.
Limite: la regola viene creata entro circa mezzo secondo dall'avvio del
programma; un collegamento fatto nei primissimi istanti puo' passare.
Tutte le regole stanno nel gruppo "PiumaAV" e si tolgono con `piuma firewall reset`.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path

from .config import IS_WINDOWS, Config

log = logging.getLogger(__name__)

GROUP = "PiumaAV"
PREFIX = "PiumaAV blocco: "
STATE = "netguard.json"
_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def _ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _powershell(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, errors="replace", timeout=60,
                          creationflags=_NO_WINDOW)


def user_writable_roots() -> list[str]:
    roots = [os.environ.get(v, "") for v in ("USERPROFILE", "TEMP", "TMP", "PUBLIC")]
    return [os.path.normcase(os.path.abspath(r)) for r in roots if r]


class NetGuard:
    def __init__(self, cfg: Config, runner=_powershell, signature_check=None):
        self.cfg = cfg
        self.run = runner
        if signature_check is None:
            from .heuristic import verify_signature_windows
            signature_check = verify_signature_windows
        self.signed = signature_check
        self.path = cfg.data_dir / STATE
        self._lock = threading.Lock()
        self._seen: dict[str, float] = {}
        self.state = self._load()

    # ------------------------------------------------------------- stato
    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return {"allowed": list(data.get("allowed", [])), "blocked": dict(data.get("blocked", {}))}
        except (OSError, ValueError):
            return {"allowed": [], "blocked": {}}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.state, indent=1), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("impossibile salvare %s: %s", self.path, exc)

    @staticmethod
    def _key(exe: str) -> str:
        return os.path.normcase(os.path.abspath(exe))

    def blocked(self) -> list[str]:
        self.state = self._load()
        return sorted(self.state["blocked"])

    # ------------------------------------------------------------- decisione
    def should_block(self, exe: str) -> bool:
        key = self._key(exe)
        if not key.endswith((".exe", ".scr", ".com")):
            return False
        roots = user_writable_roots()
        if not any(key == r or key.startswith(r.rstrip("\\/") + os.sep) for r in roots):
            return False
        parent = os.path.dirname(key)
        if os.path.basename(parent) == "scripts" and (
                os.path.exists(os.path.join(parent, "python.exe")) or
                os.path.exists(os.path.join(os.path.dirname(parent), "python.exe"))):
            return False                # lanciatori di pip/venv (pip.exe...): non sono programmi nuovi
        self.state = self._load()       # l'icona puo' aver approvato qualcosa nel frattempo
        if key in self.state["allowed"] or key in self.state["blocked"]:
            return False
        return self.signed(exe) is not True        # firmato e valido: lo si lascia stare

    def check(self, exe: str) -> bool:
        """Da chiamare per ogni nuovo processo. True se e' stato appena bloccato."""
        try:
            mtime = os.path.getmtime(exe)
        except OSError:
            return False
        with self._lock:
            if self._seen.get(exe) == mtime:
                return False
            self._seen[exe] = mtime
            if len(self._seen) > 20000:
                self._seen.clear()
        if not self.should_block(exe):
            return False
        return self.block(exe)

    # ------------------------------------------------------------- regole
    def block(self, exe: str) -> bool:
        key = self._key(exe)
        name = PREFIX + os.path.basename(exe)
        res = self.run(f"New-NetFirewallRule -DisplayName {_ps_quote(name)} -Group {_ps_quote(GROUP)} "
                       f"-Direction Outbound -Action Block -Profile Any -Program {_ps_quote(exe)} | Out-Null")
        if res.returncode != 0:
            log.warning("firewall: impossibile bloccare %s: %s", exe, (res.stderr or "").strip()[:300])
            return False
        with self._lock:
            self.state = self._load()
            self.state["blocked"][key] = time.time()
            self._save()
        log.warning("FIREWALL: bloccato l'accesso a Internet di un programma nuovo senza firma: %s", exe)
        if self.cfg.notifications:
            from .notify import notify
            notify("PiumaAV: programma bloccato da Internet",
                   f"{os.path.basename(exe)} e' nuovo e non ha firma digitale.\n"
                   "Se ti fidi: menu dello scudo > Programmi bloccati da Internet.")
        return True

    def _remove_rule(self, exe: str) -> bool:
        res = self.run(f"Get-NetFirewallRule -Group {_ps_quote(GROUP)} -ErrorAction SilentlyContinue | "
                       f"Where-Object {{ ($_ | Get-NetFirewallApplicationFilter).Program -eq {_ps_quote(exe)} }} | "
                       "Remove-NetFirewallRule")
        return res.returncode == 0

    def allow(self, exe: str) -> bool:
        key = self._key(exe)
        original = next((p for p in self.state["blocked"] if p == key), key)
        ok = self._remove_rule(exe) or self._remove_rule(original)
        with self._lock:
            self.state = self._load()
            self.state["blocked"].pop(key, None)
            if key not in self.state["allowed"]:
                self.state["allowed"].append(key)
            self._save()
        log.info("firewall: consentito %s", exe)
        return ok

    def reset(self) -> bool:
        """Toglie TUTTE le regole create da PiumaAV (le approvazioni restano)."""
        res = self.run(f"Remove-NetFirewallRule -Group {_ps_quote(GROUP)} -ErrorAction SilentlyContinue; exit 0")
        with self._lock:
            self.state = self._load()
            self.state["blocked"] = {}
            self._save()
        return res.returncode == 0
