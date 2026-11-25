"""Protezione in tempo reale.

Usa le API del sistema operativo per ricevere notifiche dei file creati o
modificati (ReadDirectoryChangesW su Windows, FSEvents su macOS, inotify su
Linux, tramite la libreria `watchdog`) e li scansiona appena smettono di
cambiare. Nessun polling del disco: a riposo il consumo di CPU e' ~0.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .pause import is_paused
from .scanner import Scanner

log = logging.getLogger(__name__)


class _Handler(FileSystemEventHandler):
    def __init__(self, rt: "RealtimeProtection"):
        self.rt = rt

    def _guard(self, path, kind, dest=None):
        if self.rt.guard is not None and not is_paused(self.rt.scanner.cfg.data_dir):
            try:
                self.rt.guard.on_event(path, kind, dest)
            except Exception:
                log.exception("errore nel controllo anti-ransomware")

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._guard(event.src_path, "created")
            self.rt.enqueue(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._guard(event.src_path, "modified")
            self.rt.enqueue(event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._guard(event.src_path, "moved", event.dest_path)
            self.rt.enqueue(event.dest_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._guard(event.src_path, "deleted")

    def on_closed(self, event: FileSystemEvent) -> None:   # solo Linux (inotify)
        if not event.is_directory:
            self.rt.enqueue(event.src_path, settled=True)


class RealtimeProtection:
    def __init__(self, scanner: Scanner, paths: list[str], settle_seconds: float = 1.5, workers: int = 1,
                 guard=None):
        self.scanner = scanner
        self.guard = guard            # RansomwareGuard facoltativo
        self.paths = [p for p in paths if os.path.isdir(p)]
        for p in paths:
            if p not in self.paths:
                log.warning("cartella da sorvegliare non trovata, la salto: %s", p)
        self.settle = settle_seconds
        self.workers = max(1, workers)
        self._pending: dict[str, float] = {}         # path -> istante ultimo evento
        self._pending_lock = threading.Lock()
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._stop = threading.Event()
        self._observer = Observer()
        self._threads: list[threading.Thread] = []
        self.scanned = 0

    @property
    def _batch(self) -> bool:
        # Con clamscan (senza demone) raggruppiamo i file per evitare di
        # ricaricare le firme a ogni singolo file.
        return self.scanner.engine.prefers_batch

    # ------------------------------------------------------------- eventi
    def enqueue(self, path: str, settled: bool = False) -> None:
        if self.scanner.is_excluded(path) or is_paused(self.scanner.cfg.data_dir):
            return
        with self._pending_lock:
            # "settled" (file chiuso) => scansiona subito senza attendere
            self._pending[path] = 0.0 if settled else time.monotonic()

    def _dispatcher(self) -> None:
        while not self._stop.wait(0.25):
            now = time.monotonic()
            ready = []
            with self._pending_lock:
                for path, ts in list(self._pending.items()):
                    if now - ts >= self.settle:
                        ready.append(path)
                        del self._pending[path]
            for path in ready:
                self._queue.put(path)

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                first = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            batch = [first]
            if self._batch:
                time.sleep(0.5)       # raccoglie altri file: un solo avvio di clamscan
                while len(batch) < 500:
                    try:
                        batch.append(self._queue.get_nowait())
                    except queue.Empty:
                        break
            self._scan(batch)

    def _scan(self, paths: list[str]) -> None:
        paths = [p for p in dict.fromkeys(paths) if os.path.isfile(p)]
        if not paths:
            return
        try:
            if self._batch:
                todo = [p for p in paths if not self.scanner._skip(p)]
                for res in self.scanner.engine.scan_files(todo):
                    self.scanner.handle(res, "tempo reale")
                self.scanned += len(todo)
            else:
                for p in paths:
                    if self.scanner.scan_file(p, source="tempo reale") is not None:
                        self.scanned += 1
        except Exception:  # un errore non deve mai fermare la protezione
            log.exception("errore durante la scansione in tempo reale")

    # ------------------------------------------------------------- ciclo vita
    def start(self) -> None:
        handler = _Handler(self)
        for p in self.paths:
            try:
                self._observer.schedule(handler, p, recursive=True)
                log.info("monitoraggio in tempo reale: %s", p)
            except OSError as exc:
                log.warning("impossibile monitorare %s: %s", p, exc)
        self._observer.start()
        self._threads = [threading.Thread(target=self._dispatcher, name="rt-dispatch", daemon=True)]
        self._threads += [threading.Thread(target=self._worker, name=f"rt-worker-{i}", daemon=True)
                          for i in range(self.workers)]
        for t in self._threads:
            t.start()

    def stop(self) -> None:
        self._stop.set()
        self._observer.stop()
        self._observer.join(timeout=5)
        for t in self._threads:
            t.join(timeout=5)
