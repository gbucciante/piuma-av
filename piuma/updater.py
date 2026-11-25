"""Aggiornamento automatico delle firme tramite freshclam (strumento ufficiale ClamAV)."""

from __future__ import annotations

import logging
import subprocess

from .config import IS_WINDOWS, UpdateConfig
from .engine import BaseEngine, find_binary

log = logging.getLogger(__name__)


def update_signatures(cfg: UpdateConfig, engine: BaseEngine | None = None) -> bool:
    binary = find_binary("freshclam", cfg.freshclam_path)
    if not binary:
        log.error("freshclam non trovato: impossibile aggiornare le firme")
        return False
    args = [binary, "--stdout"]
    if cfg.freshclam_config:
        args.append(f"--config-file={cfg.freshclam_config}")
    log.info("aggiornamento firme in corso...")
    try:
        proc = subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=1800,
                              creationflags=0x08000000 if IS_WINDOWS else 0)
    except subprocess.TimeoutExpired:
        log.error("freshclam: tempo scaduto")
        return False
    out = (proc.stdout + proc.stderr).strip()
    # 0 = aggiornato, 1 = gia' aggiornato (alcune versioni)
    if proc.returncode in (0, 1):
        updated = "updated" in out.lower() and "up-to-date" not in out.lower()
        log.info("firme %s", "aggiornate" if updated else "gia' aggiornate")
        if engine is not None:
            engine.reload()    # clamd ricarica le nuove firme in memoria
        return True
    if "locked by another process" in out.lower():
        log.info("freshclam gia' in esecuzione altrove (servizio di sistema): salto")
        return True
    log.error("freshclam fallito (codice %s): %s", proc.returncode, out[-800:])
    return False
