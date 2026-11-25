"""Controllo dei processi gia' in esecuzione.

Un malware partito prima di PiumaAV (o prima dell'ultimo aggiornamento delle
firme) e' gia' in memoria: la protezione sui file non lo vede piu'. Questa
scansione:
  1. raccoglie gli eseguibili di tutti i processi attivi e le librerie
     (DLL / .so / .dylib) che hanno caricato;
  2. li analizza con tutti i motori di PiumaAV;
  3. se trova una minaccia termina il processo e isola il file;
  4. (Windows, facoltativo) analizza anche la MEMORIA dei processi con
     `clamscan --memory` e/o con la scansione rapida di Defender, che controlla
     memoria e punti di avvio.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field

from .config import IS_WINDOWS, Config

log = logging.getLogger(__name__)


@dataclass
class ProcessReport:
    processes: int = 0
    files: int = 0
    threats: list[tuple[str, str, list[int], str]] = field(default_factory=list)  # file, firma, pid, azione
    memory: list[str] = field(default_factory=list)


def running_images(include_modules: bool = True) -> dict[str, set[int]]:
    """Mappa file eseguibile/libreria -> PID che lo usano."""
    import psutil
    images: dict[str, set[int]] = {}
    me = os.getpid()
    for proc in psutil.process_iter(["pid", "exe"]):
        pid = proc.info["pid"]
        if pid == me:
            continue
        exe = proc.info.get("exe")
        if exe and os.path.isfile(exe):
            images.setdefault(exe, set()).add(pid)
        if include_modules:
            try:
                for m in proc.memory_maps(grouped=True):
                    p = m.path
                    if not p or not os.path.isabs(p):
                        continue
                    low = p.lower()
                    is_lib = low.endswith((".dll", ".exe", ".so", ".dylib", ".ocx", ".cpl", ".sys")) or ".so." in low
                    if is_lib and os.path.isfile(p):
                        images.setdefault(p, set()).add(pid)
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError, NotImplementedError):
                pass
    return images


def _kill(pids: set[int]) -> list[int]:
    import psutil
    killed = []
    for pid in pids:
        try:
            psutil.Process(pid).kill()
            killed.append(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return killed


CLAM_MEM_RE = re.compile(r"^(?P<what>.+?): (?P<sig>\S+) FOUND$")


def clamav_memory_scan() -> list[str]:
    """Solo Windows: clamscan --memory analizza la memoria dei processi."""
    from .engine import find_binary
    exe = find_binary("clamscan")
    if not (IS_WINDOWS and exe):
        return []
    # senza --kill: si segnala soltanto, per non terminare per errore processi di sistema
    proc = subprocess.run([exe, "--memory", "--infected", "--no-summary"],
                          capture_output=True, text=True, errors="replace", timeout=3600,
                          creationflags=0x08000000)
    return [line.strip() for line in proc.stdout.splitlines() if line.strip().endswith("FOUND")]


def defender_quick_scan() -> list[str]:
    """Solo Windows: scansione rapida di Defender (memoria, avvio, cartelle di sistema)."""
    from .engines_defender import find_mpcmdrun, parse_mpcmdrun
    exe = find_mpcmdrun()
    if not exe:
        return []
    proc = subprocess.run([exe, "-Scan", "-ScanType", "1"], capture_output=True, text=True, errors="replace",
                          timeout=3600, creationflags=0x08000000)
    if proc.returncode == 2:
        return [f"Defender: {parse_mpcmdrun(proc.stdout) or 'minaccia trovata'} (gestita da Defender)"]
    return []


def _system_paths() -> tuple[str, ...]:
    if IS_WINDOWS:
        root = os.environ.get("SystemRoot", r"C:\Windows")
        return tuple(os.path.normcase(os.path.join(root, d)) for d in ("System32", "SysWOW64", "WinSxS", "explorer.exe"))
    return ("/usr/lib/", "/lib/", "/usr/lib64/", "/lib64/", "/system/", "/usr/libexec/", "/sbin/", "/usr/sbin/")


def is_system_file(path: str) -> bool:
    """File di sistema: in caso di rilevamento si avvisa soltanto (un falso positivo bloccherebbe il PC)."""
    return os.path.normcase(path).startswith(_system_paths())


def scan_processes(cfg: Config, scanner, memory: bool | None = None, images_fn=running_images) -> ProcessReport:
    import psutil
    rep = ProcessReport(processes=len(psutil.pids()))
    images = images_fn(cfg.processes.include_modules)
    paths = [p for p in images if not scanner.is_excluded(p)]
    rep.files = len(paths)
    log.info("controllo processi: %d processi, %d file in uso", rep.processes, rep.files)
    for i in range(0, len(paths), 200):
        for res in scanner.engine.scan_files(paths[i:i + 200]):
            if not res.infected:
                continue
            system = is_system_file(res.path)
            killed = _kill(images.get(res.path, set())) if cfg.processes.kill_infected and not system else []
            if system:
                saved, scanner.cfg.action = scanner.cfg.action, "report"
                try:
                    action = (scanner.handle(res, "processo di sistema") or "") + " (file di sistema: verifica manuale)"
                finally:
                    scanner.cfg.action = saved
            else:
                action = scanner.handle(res, "processo in esecuzione") or ""
            if killed:
                action = f"processi {killed} terminati, {action}"
            rep.threats.append((res.path, res.signature or "?", sorted(images.get(res.path, set())), action))
    if memory if memory is not None else cfg.processes.memory_scan:
        if IS_WINDOWS:
            rep.memory += clamav_memory_scan()
            rep.memory += defender_quick_scan()
        for m in rep.memory:
            log.warning("MEMORIA: %s", m)
    return rep
