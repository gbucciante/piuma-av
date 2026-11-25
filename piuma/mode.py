"""Modalita' completa / leggera.

* completa: Defender (su Windows) + ClamAV + hash + YARA. ClamAV tiene le
  firme in RAM (~1-1,5 GB).
* leggera:  ClamAV viene spento. Restano il motore di Defender (AMSI, gia'
  presente in Windows), gli hash MalwareBazaar (file su disco, pochi MB di RAM)
  e le regole YARA. Consigliata su Windows con poca memoria. Su macOS/Linux
  manca un motore principale: la protezione si riduce molto.

La scelta e' salvata in `<cartella dati>/mode.json`, cosi' non serve
modificare il file di configurazione; `piuma mode leggera|completa` o il menu
dell'icona la cambiano e fermano/avviano il servizio clamd.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

from .config import IS_MAC, IS_WINDOWS

log = logging.getLogger(__name__)

MODES = ("completa", "leggera")


def mode_file(data_dir: Path) -> Path:
    return Path(data_dir) / "mode.json"


def read_mode(data_dir: Path) -> str | None:
    try:
        m = json.loads(mode_file(data_dir).read_text(encoding="utf-8")).get("mode")
        return m if m in MODES else None
    except (OSError, ValueError):
        return None


def engines_for(mode: str, base: list[str]) -> list[str]:
    """Elenco motori per la modalita' scelta, partendo da quello configurato."""
    if mode == "leggera":
        out = [e for e in base if e != "clamav"]
        if "hash" not in out:
            out.insert(1 if out[:1] == ["defender"] else 0, "hash")
        if IS_WINDOWS and "defender" not in out:
            out.insert(0, "defender")
        return out
    out = list(base)
    if "clamav" not in out:
        out.insert(1 if out[:1] == ["defender"] else 0, "clamav")
    # in modalita' completa gli hash li carica gia' ClamAV (.hsb)
    return [e for e in out if e != "hash"]


def _clamd_service(enable: bool) -> bool:
    if IS_WINDOWS:
        cmds = [["sc", "config", "clamd", "start=", "auto" if enable else "demand"],
                ["sc", "start" if enable else "stop", "clamd"]]
    elif IS_MAC:
        plist = Path.home() / "Library/LaunchAgents/com.piuma-av.clamd.plist"
        dom = f"gui/{os.getuid()}"
        cmds = [["launchctl", "bootstrap", dom, str(plist)]] if enable else \
               [["launchctl", "bootout", f"{dom}/com.piuma-av.clamd"]]
    else:
        svc = "clamav-daemon"
        for cand in ("clamav-daemon", "clamd@scan", "clamd"):
            if subprocess.run(["systemctl", "cat", cand], capture_output=True).returncode == 0:
                svc = cand
                break
        cmds = [["systemctl", "enable" if enable else "disable", "--now", svc]]
    ok = True
    for c in cmds:
        try:
            r = subprocess.run(c, capture_output=True, text=True, timeout=60,
                               creationflags=0x08000000 if IS_WINDOWS else 0)
            ok &= r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            ok = False
    return ok


def set_mode(data_dir: Path, mode: str, manage_service: bool = True) -> bool:
    if mode not in MODES:
        raise ValueError(f"modalita' sconosciuta: {mode} (usa: {', '.join(MODES)})")
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    mode_file(data_dir).write_text(json.dumps({"mode": mode}), encoding="utf-8")
    log.info("modalita' impostata: %s", mode)
    if manage_service:
        ok = _clamd_service(enable=(mode == "completa"))
        if not ok:
            log.warning("non sono riuscito a %s il servizio clamd (servono i privilegi di amministratore?)",
                        "avviare" if mode == "completa" else "fermare")
        return ok
    return True
