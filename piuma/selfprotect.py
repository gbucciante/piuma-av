"""Autoprotezione di PiumaAV.

* Controllo d'integrita': un elenco firmato (HMAC-SHA256) degli hash dei file
  del programma e delle firme. Se un virus modifica o cancella qualcosa,
  PiumaAV se ne accorge e avvisa.
* Battito cardiaco + watchdog: il servizio scrive un "battito" ogni minuto;
  un'attivita' separata (`piuma watchdog`, avviata dal sistema ogni 5 minuti
  con privilegi elevati) lo riavvia se il battito si ferma.
* Le cartelle del programma sono rese modificabili solo dagli amministratori
  dagli script di installazione (icacls su Windows, root su Linux/macOS).

Limite onesto: un malware che ottiene i privilegi di amministratore puo'
comunque disattivare qualsiasi programma senza driver nel kernel; queste misure
lo rendono piu' difficile e, soprattutto, rumoroso.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import subprocess
import time
from pathlib import Path

from .config import IS_MAC, IS_WINDOWS, Config

log = logging.getLogger(__name__)

PACKAGE_DIR = Path(__file__).resolve().parent
HEARTBEAT_MAX_AGE = 180   # secondi


# ------------------------------------------------------------------ integrita'
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def protected_files(cfg: Config) -> list[Path]:
    files = sorted(PACKAGE_DIR.glob("*.py"))
    yara_dir = Path(cfg.engine.yara_rules_dir) if cfg.engine.yara_rules_dir else cfg.data_dir / "yara"
    for p in (yara_dir / "rules.yarc", Path(cfg.feeds.clamav_database_dir) / "piuma_malwarebazaar.hsb",
              cfg.data_dir / "piuma_hashes.bin"):
        if p.exists():
            files.append(p)
    return files


class Integrity:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.manifest = cfg.data_dir / "integrity.json"
        self.keyfile = cfg.data_dir / "integrity.key"

    def _key(self) -> bytes:
        if not self.keyfile.exists():
            self.keyfile.parent.mkdir(parents=True, exist_ok=True)
            self.keyfile.write_bytes(secrets.token_bytes(32))
            try:
                os.chmod(self.keyfile, 0o600)
            except OSError:
                pass
        return self.keyfile.read_bytes()

    def _sign(self, files: dict[str, str]) -> str:
        body = json.dumps(files, sort_keys=True).encode()
        return hmac.new(self._key(), body, hashlib.sha256).hexdigest()

    def record(self) -> int:
        """Registra lo stato attuale come 'buono' (dopo installazione o aggiornamento legittimo)."""
        files = {str(p): _sha256(p) for p in protected_files(self.cfg)}
        data = {"files": files, "hmac": self._sign(files), "time": time.time()}
        self.manifest.write_text(json.dumps(data, indent=1), encoding="utf-8")
        return len(files)

    def update_entries(self, paths: list[Path]) -> None:
        """Aggiorna solo alcune voci (es. firme appena scaricate e verificate)."""
        if not self.manifest.exists():
            self.record()
            return
        problems = self.verify()
        files = json.loads(self.manifest.read_text(encoding="utf-8"))["files"]
        if any(p.startswith("ELENCO") for p in problems):
            log.warning("elenco d'integrita' non valido: lo ricreo")
            self.record()
            return
        for p in paths:
            if p.exists():
                files[str(p)] = _sha256(p)
        data = {"files": files, "hmac": self._sign(files), "time": time.time()}
        self.manifest.write_text(json.dumps(data, indent=1), encoding="utf-8")

    def verify(self) -> list[str]:
        """Restituisce l'elenco dei problemi trovati (vuoto = tutto a posto)."""
        if not self.manifest.exists():
            return []
        try:
            data = json.loads(self.manifest.read_text(encoding="utf-8"))
            files = data["files"]
        except (ValueError, KeyError):
            return ["ELENCO d'integrita' illeggibile"]
        if not hmac.compare_digest(data.get("hmac", ""), self._sign(files)):
            return ["ELENCO d'integrita' manomesso (firma HMAC non valida)"]
        problems = []
        for path, digest in files.items():
            p = Path(path)
            if not p.exists():
                problems.append(f"file mancante: {path}")
            elif _sha256(p) != digest:
                problems.append(f"file modificato: {path}")
        return problems


# ------------------------------------------------------------------ battito / watchdog
def write_heartbeat(cfg: Config) -> None:
    try:
        cfg.heartbeat_file.write_text(str(time.time()), encoding="ascii")
    except OSError as exc:
        log.debug("battito non scritto: %s", exc)


def heartbeat_age(cfg: Config) -> float:
    try:
        return time.time() - float(cfg.heartbeat_file.read_text(encoding="ascii"))
    except (OSError, ValueError):
        return float("inf")


def restart_service() -> bool:
    if IS_WINDOWS:
        cmd = ["schtasks", "/Run", "/TN", "PiumaAV"]
    elif IS_MAC:
        cmd = ["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/com.piuma-av"]
    else:
        cmd = ["systemctl", "restart", "piuma-av"]
    try:
        return subprocess.run(cmd, capture_output=True, timeout=60,
                              creationflags=0x08000000 if IS_WINDOWS else 0).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def watchdog(cfg: Config) -> int:
    """Da eseguire periodicamente: riavvia PiumaAV se non da' segni di vita."""
    from .notify import notify
    age = heartbeat_age(cfg)
    if age <= HEARTBEAT_MAX_AGE:
        return 0
    log.warning("PiumaAV non risponde da %s: riavvio", "sempre" if age == float("inf") else f"{age:.0f}s")
    ok = restart_service()
    notify("PiumaAV", "La protezione si era fermata ed e' stata riavviata" if ok
           else "ATTENZIONE: la protezione e' ferma e non riesco a riavviarla")
    return 0 if ok else 1
