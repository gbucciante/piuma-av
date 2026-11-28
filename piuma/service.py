"""Servizio in background: protezione in tempo reale + aggiornamenti + scansioni pianificate."""

from __future__ import annotations

import json
import logging
import signal
import threading
import time

from .config import Config
from .engine import ClamdEngine, ClamscanEngine, CompositeEngine, create_engine
from .feeds import update_all as update_feeds
from . import blocklist
from .autostart import AutostartMonitor
from .notify import notify
from .ransomware import RansomwareGuard
from .behavior import BehaviorMonitor
from .procscan import scan_processes
from .usb import UsbMonitor
from . import pause as pause_mod
from .selfprotect import Integrity, write_heartbeat
from .realtime import RealtimeProtection
from .scanner import Scanner
from .updater import update_signatures

log = logging.getLogger(__name__)


class _State:
    """Ricorda quando sono stati eseguiti aggiornamenti/scansioni (sopravvive ai riavvii)."""

    def __init__(self, path):
        self.path = path
        try:
            self.data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.data = {}

    def last(self, key: str) -> float:
        return float(self.data.get(key, 0))

    def mark(self, key: str, **extra) -> None:
        try:                       # rilegge: anche `piuma update` da terminale scrive qui
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        self.data[key] = time.time()
        self.data.update(extra)
        try:
            self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        except OSError as exc:
            log.debug("stato non salvato: %s", exc)


def last_update(cfg: Config) -> float | None:
    """Istante dell'ultimo aggiornamento delle firme riuscito (None se mai)."""
    try:
        value = json.loads(cfg.state_file.read_text(encoding="utf-8")).get("update")
        return float(value) if value else None
    except (OSError, ValueError, TypeError):
        return None


def format_when(ts: float | None) -> str:
    if not ts:
        return "mai"
    import datetime as dt
    return dt.datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M")


def record_program_version(cfg: Config) -> None:
    """Annota data e ora in cui questa versione di PiumaAV e' partita per la prima volta."""
    from . import __version__
    st = _State(cfg.state_file)
    if st.data.get("version") != __version__:
        st.mark("program_update", version=__version__)
        log.info("PiumaAV aggiornato alla versione %s il %s", __version__,
                 format_when(st.last("program_update")))


def program_updated(cfg: Config) -> float | None:
    """Istante in cui e' stata installata la versione attuale (None se non ancora registrato)."""
    from . import __version__
    try:
        data = json.loads(cfg.state_file.read_text(encoding="utf-8"))
        if data.get("version") == __version__ and data.get("program_update"):
            return float(data["program_update"])
    except (OSError, ValueError, TypeError):
        pass
    return None


class Service:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.stop_event = threading.Event()
        self.engine = create_engine(cfg.engine, cfg.data_dir, cfg.reputation)
        self.scanner = Scanner(cfg, self.engine)
        try:
            record_program_version(cfg)
        except Exception:  # noqa: BLE001 - mai bloccare l'avvio per questo
            log.debug("versione non registrata", exc_info=True)
        self.state = _State(cfg.state_file)
        self.realtime: RealtimeProtection | None = None

    def _due(self, key: str, hours: float) -> bool:
        return time.time() - self.state.last(key) >= hours * 3600

    def _maybe_upgrade_engine(self) -> None:
        """Se all'avvio clamd non era pronto (es. subito dopo il boot), passa a clamd appena risponde."""
        if self.cfg.engine.mode != "auto":
            return
        subs = self.engine.engines if isinstance(self.engine, CompositeEngine) else [self.engine]
        for old in subs:
            if isinstance(old, ClamscanEngine):
                clamd = ClamdEngine(self.cfg.engine)
                if clamd.ping():
                    log.info("clamd ora disponibile: passo al motore veloce")
                    if isinstance(self.engine, CompositeEngine):
                        self.engine.replace(old, clamd)
                    else:
                        self.engine = clamd
                        self.scanner.engine = clamd

    def _scheduler(self) -> None:
        while not self.stop_event.is_set():
            self._maybe_upgrade_engine()
            if self.cfg.update.enabled and self._due("update", self.cfg.update.interval_hours):
                ok = "clamav" not in self.cfg.engine.engines or update_signatures(self.cfg.update, None)
                feeds_ok = update_feeds(self.cfg)
                if self.cfg.protection.domain_blocking:
                    blocklist.update(self.cfg)
                if ok or feeds_ok:
                    self.engine.reload()     # clamd e YARA caricano le firme nuove
                if ok:
                    self.state.mark("update")
                    log.info("firme aggiornate il %s", format_when(self.state.last("update")))
                else:
                    # riprova tra 30 minuti invece di aspettare l'intervallo intero
                    self.state.data["update"] = time.time() - self.cfg.update.interval_hours * 3600 + 1800
            paused = pause_mod.is_paused(self.cfg.data_dir)
            if not paused and self.cfg.processes.enabled and self._due("processes", self.cfg.processes.interval_hours):
                try:
                    scan_processes(self.cfg, self.scanner)
                except Exception:
                    log.exception("errore nel controllo dei processi")
                self.state.mark("processes")
            for job in ([] if paused else self.cfg.scheduled_scans):
                key = f"scan:{job.name}"
                if self._due(key, job.interval_hours):
                    log.info("avvio scansione pianificata '%s'", job.name)
                    self.scanner.scan_paths(job.paths, source=f"pianificata:{job.name}", stop=self.stop_event)
                    self.state.mark(key)
            self.stop_event.wait(60)

    def _check_integrity(self) -> None:
        problems = Integrity(self.cfg).verify()
        if problems:
            log.critical("INTEGRITA' COMPROMESSA: %s", "; ".join(problems[:10]))
            notify("PiumaAV: possibile manomissione",
                   f"{len(problems)} file del programma o delle firme sono stati alterati.\n{problems[0][:120]}")

    def _monitor(self) -> None:
        """Controlli leggeri e frequenti, separati dalle scansioni lunghe."""
        p = self.cfg.protection
        autostart = AutostartMonitor(self.cfg, self.scanner) if p.autostart_monitor else None
        last_auto = last_integrity = 0.0
        was_paused = pause_mod.is_paused(self.cfg.data_dir)
        integ = Integrity(self.cfg)
        if p.integrity_check and not integ.manifest.exists():
            log.info("integrita': registrati %d file", integ.record())
        while not self.stop_event.is_set():
            now = time.time()
            paused = pause_mod.is_paused(self.cfg.data_dir)
            if paused != was_paused:          # notifica quando la pausa inizia o finisce
                if not paused:
                    notify("PiumaAV", "Protezione riattivata")
                    log.info("protezione riattivata")
                was_paused = paused
            if autostart and not paused and now - last_auto >= p.autostart_interval_minutes * 60:
                autostart.check()
                last_auto = now
            if p.integrity_check and now - last_integrity >= 3600:
                self._check_integrity()
                last_integrity = now
            self.stop_event.wait(30)

    def run(self) -> None:
        log.info("PiumaAV avviato (motori: %s, azione: %s)", self.engine.name, self.cfg.action)
        write_heartbeat(self.cfg)
        guard = None
        if self.cfg.protection.ransomware:
            guard = RansomwareGuard(self.cfg, self.cfg.realtime.paths)
            guard.plant_canaries()
        if self.cfg.realtime.enabled:
            self.realtime = RealtimeProtection(self.scanner, self.cfg.realtime.paths,
                                               self.cfg.realtime.settle_seconds, self.cfg.realtime.workers,
                                               guard=guard)
            self.realtime.start()
        self.extras = []
        for enabled, cls in ((self.cfg.behavior.enabled, BehaviorMonitor), (self.cfg.usb.enabled, UsbMonitor)):
            if enabled:
                try:
                    mon = cls(self.cfg, self.scanner)
                    mon.start()
                    self.extras.append(mon)
                except ImportError as exc:
                    log.warning("%s non disponibile: %s (pip install psutil)", cls.__name__, exc)
        for target, name in ((self._scheduler, "scheduler"), (self._monitor, "monitor")):
            threading.Thread(target=target, name=name, daemon=True).start()

        def _sig(*_):
            self.stop_event.set()
        for s in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(s, _sig)
            except ValueError:   # non nel thread principale (es. avviato dall'icona di sistema)
                pass
        try:
            beats = 0
            while not self.stop_event.wait(1):
                beats += 1
                if beats % 30 == 0:
                    write_heartbeat(self.cfg)      # letto dal watchdog
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        self.stop_event.set()
        if self.realtime:
            self.realtime.stop()
        for mon in getattr(self, "extras", []):
            mon.stop()
        log.info("PiumaAV arrestato")
