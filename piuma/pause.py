"""Sospensione temporanea della protezione.

`piuma pause 15m|30m|1h|reboot` (o il menu dell'icona) sospende la protezione:
tempo reale, analisi del comportamento, USB, avvio automatico e scansioni
pianificate. Allo scadere del tempo, o al riavvio del PC con "reboot",
riprende da sola. Il servizio resta acceso (il watchdog non interviene) e gli
aggiornamenti delle firme continuano.

Sicurezza: lo stato e' salvato nella cartella dati, scrivibile solo dagli
amministratori, quindi un programma senza privilegi non puo' spegnere
l'antivirus. Dall'icona viene chiesta una conferma esplicita.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)

DURATIONS = {"15m": 15 * 60, "30m": 30 * 60, "1h": 3600}
_cache: dict[str, tuple[float, bool]] = {}
_lock = threading.Lock()


def _file(data_dir: Path) -> Path:
    return Path(data_dir) / "pause.json"


def boot_time() -> float:
    try:
        import psutil
        return round(psutil.boot_time())
    except Exception:
        return 0.0


def parse_duration(text: str) -> int | str:
    text = text.strip().lower()
    if text in ("reboot", "riavvio"):
        return "reboot"
    if text in DURATIONS:
        return DURATIONS[text]
    m = re.fullmatch(r"(\d+)\s*(m|min|h|ore?)", text)
    if not m:
        raise ValueError("usa 15m, 30m, 1h oppure reboot")
    n = int(m.group(1)) * (3600 if m.group(2).startswith(("h", "o")) else 60)
    if not 60 <= n <= 24 * 3600:
        raise ValueError("durata tra 1 minuto e 24 ore")
    return n


def pause(data_dir: Path, duration: int | str) -> dict:
    state = {"since": time.time(), "boot": boot_time()}
    if duration == "reboot":
        state["until"] = "reboot"
    else:
        state["until"] = time.time() + int(duration)
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    _file(data_dir).write_text(json.dumps(state), encoding="utf-8")
    _cache.clear()
    log.warning("PROTEZIONE SOSPESA %s", "fino al riavvio" if duration == "reboot"
                else f"per {int(duration) // 60} minuti")
    return state


def resume(data_dir: Path) -> None:
    _file(data_dir).unlink(missing_ok=True)
    _cache.clear()
    log.info("protezione riattivata")


def status(data_dir: Path) -> dict | None:
    """None se attiva, altrimenti lo stato della pausa."""
    try:
        state = json.loads(_file(data_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    until = state.get("until")
    if until == "reboot":
        if state.get("boot") and abs(state["boot"] - boot_time()) > 5:
            resume(data_dir)               # il PC e' stato riavviato
            return None
        return state
    if not isinstance(until, (int, float)) or time.time() >= until:
        resume(data_dir)
        return None
    return state


def is_paused(data_dir: Path) -> bool:
    """Versione con cache di 1 secondo, da chiamare spesso (es. a ogni evento sui file)."""
    key = str(data_dir)
    now = time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < 1.0:
            return hit[1]
    value = status(data_dir) is not None
    with _lock:
        _cache[key] = (now, value)
    return value


def describe(state: dict | None) -> str:
    if state is None:
        return "attiva"
    if state["until"] == "reboot":
        return "sospesa fino al riavvio"
    left = max(0, int(state["until"] - time.time()))
    return f"sospesa, si riattiva tra {left // 60} min {left % 60} s"


def confirm(message: str) -> bool:
    """Chiede conferma all'utente (finestra di sistema). Senza interfaccia: True."""
    import sys
    try:
        if sys.platform.startswith("win"):
            import ctypes
            MB_YESNO, MB_ICONWARNING, MB_TOPMOST, IDYES = 0x4, 0x30, 0x40000, 6
            return ctypes.windll.user32.MessageBoxW(None, message, "PiumaAV",  # type: ignore[attr-defined]
                                                    MB_YESNO | MB_ICONWARNING | MB_TOPMOST) == IDYES
        if sys.platform == "darwin":
            import subprocess
            esc = message.replace('"', '\\"')
            r = subprocess.run(["osascript", "-e", f'display dialog "{esc}" buttons {{"Annulla", "Sospendi"}} '
                                f'default button "Annulla" with icon caution'], capture_output=True)
            return r.returncode == 0 and b"Sospendi" in r.stdout
        import shutil
        import subprocess
        if shutil.which("zenity"):
            return subprocess.run(["zenity", "--question", "--title=PiumaAV", f"--text={message}"]).returncode == 0
    except Exception:
        return False
    return True
