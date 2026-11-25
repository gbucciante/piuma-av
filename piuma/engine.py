"""Motori di scansione.

PiumaAV puo' usare piu' motori insieme (CompositeEngine): un file e'
considerato infetto se almeno uno lo riconosce.
  * ClamAV (clamd o clamscan)             - firme ufficiali + feed extra
  * Microsoft Defender (solo Windows)     - vedi engines_defender.py
  * YARA (regole YARA-Forge)              - vedi engines_yara.py

Modalita' di ClamAV:
  * ClamdEngine   - parla con il demone clamd (firme gia' caricate in RAM):
                    velocissimo, usato per la protezione in tempo reale.
  * ClamscanEngine - lancia clamscan.exe/clamscan: non richiede servizi attivi,
                    ma carica le firme a ogni avvio (lento per singoli file,
                    ottimo per scansioni di intere cartelle).
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .config import IS_WINDOWS, EngineConfig

log = logging.getLogger(__name__)

CHUNK = 64 * 1024


@dataclass
class ScanResult:
    path: str
    infected: bool
    signature: str | None = None
    error: str | None = None


class EngineError(RuntimeError):
    pass


class BaseEngine:
    name = "base"
    prefers_batch = False     # True = conviene passare molti file insieme (clamscan)

    def scan_file(self, path: str) -> ScanResult:
        raise NotImplementedError

    def scan_files(self, paths: list[str]) -> list[ScanResult]:
        return [self.scan_file(p) for p in paths]

    def scan_tree(self, root: str, skip=lambda p: False) -> Iterator[ScanResult]:
        batch: list[str] = []
        for path in iter_files(root, skip):
            batch.append(path)
            if len(batch) >= (2000 if self.prefers_batch else 1):
                yield from self.scan_files(batch)
                batch = []
        yield from self.scan_files(batch)

    def reload(self) -> None:
        pass

    def version(self) -> str:
        return "?"


def iter_files(root: str, skip=lambda p: False) -> Iterator[str]:
    """Percorre ricorsivamente una cartella senza seguire i link simbolici."""
    if os.path.isfile(root):
        if not skip(root):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=lambda e: log.debug("walk: %s", e)):
        dirnames[:] = [d for d in dirnames if not skip(os.path.join(dirpath, d))]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if os.path.islink(full) or skip(full):
                continue
            yield full


# --------------------------------------------------------------------------- clamd

class ClamdEngine(BaseEngine):
    name = "clamd"

    def __init__(self, cfg: EngineConfig):
        self.cfg = cfg

    def _connect(self) -> socket.socket:
        if self.cfg.clamd_socket and not IS_WINDOWS and os.path.exists(self.cfg.clamd_socket):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.cfg.clamdscan_timeout)
            s.connect(self.cfg.clamd_socket)
            return s
        s = socket.create_connection((self.cfg.clamd_host, self.cfg.clamd_port), timeout=self.cfg.clamdscan_timeout)
        return s

    def _command(self, cmd: bytes) -> str:
        with self._connect() as s:
            s.sendall(b"z" + cmd + b"\0")
            return _recv_all(s)

    def ping(self) -> bool:
        try:
            return self._command(b"PING") == "PONG"
        except OSError:
            return False

    def version(self) -> str:
        return self._command(b"VERSION")

    def reload(self) -> None:
        try:
            self._command(b"RELOAD")
        except OSError as exc:
            log.warning("impossibile ricaricare le firme in clamd: %s", exc)

    def scan_file(self, path: str) -> ScanResult:
        # INSTREAM: il contenuto viene inviato da noi, quindi funziona anche se
        # clamd gira con un utente che non ha accesso al file.
        try:
            with open(path, "rb") as fh, self._connect() as s:
                s.sendall(b"zINSTREAM\0")
                while chunk := fh.read(CHUNK):
                    s.sendall(struct.pack("!L", len(chunk)) + chunk)
                s.sendall(struct.pack("!L", 0))
                reply = _recv_all(s)
        except (PermissionError, FileNotFoundError) as exc:
            return ScanResult(path, False, error=str(exc))
        except OSError as exc:
            # tipicamente: file piu' grande di StreamMaxLength (clamd chiude la connessione)
            return ScanResult(path, False, error=f"clamd: {exc}")
        return _parse_clamd_reply(path, reply)


def _recv_all(s: socket.socket) -> str:
    data = b""
    while True:
        part = s.recv(4096)
        if not part:
            break
        data += part
        if data.endswith(b"\0"):
            break
    return data.rstrip(b"\0").decode("utf-8", "replace").strip()


def _parse_clamd_reply(path: str, reply: str) -> ScanResult:
    # "stream: OK" | "stream: Win.Test.EICAR_HDB-1 FOUND" | "... ERROR"
    body = reply.split(":", 1)[1].strip() if ":" in reply else reply
    if body.endswith("FOUND"):
        return ScanResult(path, True, signature=body[:-len("FOUND")].strip())
    if body == "OK":
        return ScanResult(path, False)
    return ScanResult(path, False, error=body)


# ------------------------------------------------------------------------ clamscan

FOUND_RE = re.compile(r"^(?P<path>.+): (?P<sig>.+) FOUND$")


def find_binary(name: str, explicit: str = "") -> str | None:
    if explicit:
        return explicit if os.path.exists(explicit) else None
    exe = name + (".exe" if IS_WINDOWS else "")
    found = shutil.which(exe)
    if found:
        return found
    candidates = []
    if IS_WINDOWS:
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                     os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
            candidates.append(Path(base) / "ClamAV" / exe)
    else:
        candidates += [Path("/opt/homebrew/bin") / name, Path("/usr/local/bin") / name,
                       Path("/usr/bin") / name, Path("/usr/sbin") / name, Path("/usr/local/sbin") / name,
                       Path("/opt/homebrew/sbin") / name]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


class ClamscanEngine(BaseEngine):
    name = "clamscan"
    prefers_batch = True

    def __init__(self, cfg: EngineConfig):
        self.cfg = cfg
        self.binary = find_binary("clamscan", cfg.clamscan_path)
        if not self.binary:
            raise EngineError("clamscan non trovato: installare ClamAV (vedi README)")

    def _base_args(self) -> list[str]:
        mb = self.cfg.max_file_size_mb
        return [self.binary, "--no-summary", "--infected", "--stdout",
                f"--max-filesize={mb}M", f"--max-scansize={mb * 4}M"] + \
               ([f"--database={self.cfg.database_dir}"] if self.cfg.database_dir else [])

    def version(self) -> str:
        return subprocess.run([self.binary, "--version"], capture_output=True, text=True).stdout.strip()

    def scan_files(self, paths: list[str]) -> list[ScanResult]:
        """Scansiona un gruppo di file con un solo avvio di clamscan."""
        if not paths:
            return []
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".lst", encoding="utf-8") as fh:
            fh.write("\n".join(paths))
            listfile = fh.name
        try:
            proc = subprocess.run(self._base_args() + [f"--file-list={listfile}"],
                                  capture_output=True, text=True, errors="replace",
                                  creationflags=_NO_WINDOW)
        finally:
            os.unlink(listfile)
        infected = _parse_clamscan(proc.stdout)
        if proc.returncode == 2 and not infected:
            log.warning("clamscan ha segnalato errori: %s", proc.stderr.strip()[:500])
        return [ScanResult(p, p in infected, infected.get(p)) for p in paths]

    def scan_file(self, path: str) -> ScanResult:
        return self.scan_files([path])[0]


def _parse_clamscan(output: str) -> dict[str, str]:
    found = {}
    for line in output.splitlines():
        m = FOUND_RE.match(line.strip())
        if m:
            found[m.group("path")] = m.group("sig")
    return found


_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0   # CREATE_NO_WINDOW: niente finestre nere su Windows


# ------------------------------------------------------------------------ composito

class CompositeEngine(BaseEngine):
    """Esegue piu' motori in sequenza: basta che uno riconosca la minaccia."""

    def __init__(self, engines: list[BaseEngine]):
        self.engines = engines

    @property
    def name(self) -> str:  # type: ignore[override]
        return " + ".join(e.name for e in self.engines)

    @property
    def prefers_batch(self) -> bool:  # type: ignore[override]
        return any(e.prefers_batch for e in self.engines)

    def scan_files(self, paths: list[str]) -> list[ScanResult]:
        results = {p: ScanResult(p, False) for p in paths}
        todo = list(paths)
        for eng in self.engines:
            if not todo:
                break
            try:
                found = eng.scan_files(todo)
            except Exception as exc:          # un motore guasto non deve fermare gli altri
                log.warning("motore %s in errore: %s", eng.name, exc)
                continue
            for r in found:
                if r.infected:
                    results[r.path] = r
                elif r.error and not results[r.path].error:
                    results[r.path].error = f"{eng.name}: {r.error}"
            todo = [p for p in todo if not results[p].infected]
        return [results[p] for p in paths]

    def scan_file(self, path: str) -> ScanResult:
        return self.scan_files([path])[0]

    def reload(self) -> None:
        for e in self.engines:
            e.reload()

    def version(self) -> str:
        return "; ".join(f"{e.name}: {e.version()}" for e in self.engines)

    def replace(self, old: BaseEngine, new: BaseEngine) -> None:
        self.engines[self.engines.index(old)] = new


# --------------------------------------------------------------------------- factory

def create_clamav_engine(cfg: EngineConfig) -> BaseEngine:
    mode = cfg.mode
    if mode in ("auto", "clamd"):
        eng = ClamdEngine(cfg)
        if eng.ping():
            log.info("motore ClamAV: clamd (%s)", eng.version())
            return eng
        if mode == "clamd":
            raise EngineError("clamd non raggiungibile")
        log.info("clamd non disponibile, uso clamscan")
    return ClamscanEngine(cfg)


def create_engine(cfg: EngineConfig, data_dir: Path | None = None, reputation=None) -> BaseEngine:
    """Crea i motori elencati in cfg.engines, saltando quelli non disponibili."""
    engines: list[BaseEngine] = []
    for name in cfg.engines:
        try:
            if name == "clamav":
                engines.append(create_clamav_engine(cfg))
            elif name == "defender":
                from .engines_defender import DefenderEngine
                eng = DefenderEngine(cfg.max_file_size_mb)
                if eng.available():
                    engines.append(eng)
                else:
                    log.info("Microsoft Defender non disponibile su questo sistema: salto")
            elif name == "hash":
                from .engines_hash import HASHES_BIN, HashEngine
                eng = HashEngine((data_dir or Path(".")) / HASHES_BIN, cfg.max_file_size_mb * 1024 * 1024)
                if eng.available():
                    engines.append(eng)
                else:
                    log.info("archivio hash non ancora scaricato: lancia 'piuma update'")
            elif name == "heuristic":
                from .heuristic import HeuristicEngine
                engines.append(HeuristicEngine(cfg.heuristic_alert_score))
            elif name == "yara":
                from .engines_yara import YaraEngine
                eng = YaraEngine(Path(cfg.yara_rules_dir) if cfg.yara_rules_dir else
                                 (data_dir or Path(".")) / "yara")
                if eng.available():
                    engines.append(eng)
                else:
                    log.info("YARA non disponibile (libreria o regole mancanti): salto")
            else:
                log.warning("motore sconosciuto: %s", name)
        except (EngineError, ImportError) as exc:
            log.warning("motore %s non disponibile: %s", name, exc)
    if reputation is not None and reputation.enabled:
        from .reputation import VirusTotalEngine
        vt = VirusTotalEngine(reputation, (data_dir or Path(".")) / "virustotal_cache.json")
        if vt.available():
            engines.append(vt)      # per ultimo: interpellato solo se gli altri non trovano nulla
        else:
            log.warning("VirusTotal attivato ma manca la chiave API (virustotal_api_key)")
    # l'euristica per ultima: viene interpellata solo se nessun motore a firme ha trovato nulla
    engines.sort(key=lambda e: e.name == "piuma-heur")
    if not engines:
        raise EngineError("nessun motore di scansione disponibile: installare ClamAV (vedi README)")
    return engines[0] if len(engines) == 1 else CompositeEngine(engines)
