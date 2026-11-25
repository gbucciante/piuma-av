"""Scansione automatica di chiavette USB e dischi esterni appena collegati.

Ogni pochi secondi PiumaAV confronta l'elenco dei dischi montati; quando ne
compare uno rimovibile lo analizza tutto in background (senza rallentare il
PC) e avvisa a fine scansione. Segnala anche i file `autorun.inf` e i
collegamenti (.lnk) che si spacciano per cartelle, trucchi tipici dei virus da
chiavetta.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path

from .config import IS_MAC, IS_WINDOWS, Config
from .pause import is_paused

log = logging.getLogger(__name__)

DRIVE_REMOVABLE = 2


def _is_removable_windows(mountpoint: str) -> bool:
    import ctypes
    return ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(mountpoint)) == DRIVE_REMOVABLE  # type: ignore[attr-defined]


def removable_mounts() -> set[str]:
    """Punti di montaggio dei dischi rimovibili/esterni attualmente collegati."""
    import psutil
    found = set()
    for part in psutil.disk_partitions(all=False):
        mp = part.mountpoint
        try:
            if IS_WINDOWS:
                if "removable" in part.opts or _is_removable_windows(mp):
                    found.add(mp)
            elif IS_MAC:
                if mp.startswith("/Volumes/") and mp != "/":
                    found.add(mp)
            elif mp.startswith(("/media/", "/run/media/", "/mnt/")):
                found.add(mp)
        except OSError:
            continue
    return found


def usb_tricks(root: str) -> list[str]:
    """Trucchi tipici dei virus da chiavetta, nella cartella principale del disco."""
    issues = []
    try:
        entries = os.listdir(root)
    except OSError:
        return issues
    lower = {e.lower(): e for e in entries}
    if "autorun.inf" in lower:
        issues.append(f"file autorun.inf presente: {os.path.join(root, lower['autorun.inf'])}")
    folders = {e.lower() for e in entries if os.path.isdir(os.path.join(root, e))}
    for e in entries:
        if e.lower().endswith(".lnk") and (e[:-4].lower() in folders or len(entries) <= 3):
            issues.append(f"collegamento che imita una cartella: {os.path.join(root, e)}")
    return issues


class UsbMonitor:
    def __init__(self, cfg: Config, scanner, lister=removable_mounts, poll: float = 3.0):
        self.cfg = cfg
        self.scanner = scanner
        self.lister = lister
        self.poll = poll
        self._stop = threading.Event()
        self._known: set[str] = set()
        self._thread: threading.Thread | None = None
        self.reports: dict[str, object] = {}

    def scan_drive(self, mount: str) -> None:
        from .notify import notify
        name = Path(mount).name or mount
        log.info("disco esterno collegato: %s, scansione in corso", mount)
        if self.cfg.notifications:
            notify("PiumaAV", f"Disco {name} collegato: scansione in corso...")
        tricks = usb_tricks(mount)
        for t in tricks:
            log.warning("CHIAVETTA SOSPETTA: %s", t)
        rep = self.scanner.scan_paths([mount], source=f"USB {name}", stop=self._stop)
        self.reports[mount] = rep
        msg = f"{name}: {rep.scanned} file analizzati, {len(rep.threats)} minacce"
        if tricks:
            msg += f", {len(tricks)} elementi sospetti (autorun/collegamenti)"
        if self.cfg.notifications:
            notify("PiumaAV: scansione disco completata", msg)

    def check_once(self) -> list[str]:
        current = self.lister()
        new = sorted(current - self._known)
        self._known = current
        if is_paused(self.cfg.data_dir):
            return []
        for mount in new:
            threading.Thread(target=self.scan_drive, args=(mount,), name=f"usb-{mount}", daemon=True).start()
        return new

    def _loop(self) -> None:
        self._known = set() if self.cfg.usb.scan_already_connected else self.lister()
        while not self._stop.is_set():
            try:
                self.check_once()
            except Exception:
                log.exception("errore nel controllo dei dischi esterni")
            self._stop.wait(self.poll)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="usb", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
