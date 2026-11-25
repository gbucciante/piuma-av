"""Logica comune di scansione: esclusioni, gestione delle minacce, statistiche."""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .config import Config
from .engine import BaseEngine, ScanResult
from .notify import notify
from .quarantine import Quarantine, delete_file

log = logging.getLogger(__name__)


@dataclass
class ScanReport:
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    scanned: int = 0
    skipped: int = 0
    errors: int = 0
    threats: list[tuple[str, str, str]] = field(default_factory=list)   # (path, firma, azione)

    @property
    def duration(self) -> float:
        return (self.finished or time.time()) - self.started


class Scanner:
    def __init__(self, cfg: Config, engine: BaseEngine):
        self.cfg = cfg
        self.engine = engine
        self.quarantine = Quarantine(cfg.quarantine_dir)
        self._lock = threading.Lock()
        # Non si scansionano mai le cartelle del programma stesso (quarantena, log).
        self._excluded = [os.path.normcase(os.path.abspath(p)) for p in
                          [*cfg.exclude, str(cfg.data_dir)]]
        self.max_bytes = cfg.engine.max_file_size_mb * 1024 * 1024

    # ------------------------------------------------------------ esclusioni
    def is_excluded(self, path: str) -> bool:
        norm = os.path.normcase(os.path.abspath(path))
        for ex in self._excluded:
            if norm == ex or norm.startswith(ex.rstrip("\\/") + os.sep):
                return True
        return norm.endswith(tuple(self.cfg.exclude_extensions))

    def _too_big(self, path: str) -> bool:
        try:
            return os.path.getsize(path) > self.max_bytes
        except OSError:
            return True

    def _skip(self, path: str) -> bool:
        return self.is_excluded(path) or (os.path.isfile(path) and self._too_big(path))

    # ------------------------------------------------------------ scansione
    def scan_file(self, path: str, source: str = "manuale") -> ScanResult | None:
        if self._skip(path) or not os.path.isfile(path):
            return None
        result = self.engine.scan_file(path)
        self.handle(result, source)
        return result

    def scan_paths(self, paths: list[str], progress: Callable[[ScanResult], None] | None = None,
                   source: str = "manuale", stop: threading.Event | None = None) -> ScanReport:
        report = ScanReport()
        for root in paths:
            if not os.path.exists(root):
                log.warning("percorso inesistente: %s", root)
                continue
            for result in self.engine.scan_tree(root, self._skip):
                report.scanned += 1
                if result.error:
                    report.errors += 1
                    log.debug("errore su %s: %s", result.path, result.error)
                action = self.handle(result, source)
                if action:
                    report.threats.append((result.path, result.signature or "?", action))
                if progress:
                    progress(result)
                if stop is not None and stop.is_set():
                    break
        report.finished = time.time()
        log.info("scansione %s terminata: %d file, %d minacce, %d errori in %.1fs",
                 source, report.scanned, len(report.threats), report.errors, report.duration)
        return report

    # ------------------------------------------------------- gestione minacce
    def handle(self, result: ScanResult, source: str) -> str | None:
        if not result.infected:
            return None
        sig = result.signature or "sconosciuta"
        action = self.cfg.action
        if sig.startswith("YARA:") and not self.cfg.engine.yara_quarantine and action != "report":
            action = "report"        # regole euristiche: si avvisa, non si sposta
        from .heuristic import heur_score
        score = heur_score(sig)
        if score is not None and score < self.cfg.engine.heuristic_quarantine_score and action != "report":
            action = "report"        # PiumaHeur: sotto la soglia alta si avvisa soltanto
        with self._lock:
            try:
                if action == "quarantine":
                    entry = self.quarantine.add(result.path, sig)
                    done = f"messo in quarantena (id {entry.id})"
                elif action == "delete":
                    delete_file(result.path)
                    done = "eliminato"
                else:
                    done = "solo segnalato"
            except OSError as exc:
                done = f"azione fallita: {exc}"
        log.warning("MINACCIA [%s] %s -> %s (%s)", source, result.path, sig, done)
        if self.cfg.notifications:
            notify("PiumaAV: minaccia rilevata", f"{Path(result.path).name}\n{sig}\n{done}")
        return done
