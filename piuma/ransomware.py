"""Protezione anti-ransomware (euristica, senza driver).

Tre segnali, combinati:
 1. File esca ("canary"): documenti finti nascosti nelle cartelle sorvegliate.
    Nessun programma legittimo ha motivo di toccarli: se vengono modificati,
    rinominati o cancellati e' quasi certamente un ransomware.
 2. Raffica di modifiche: molti file cambiati in pochi secondi, con contenuto
    ad alta entropia (dati cifrati) o con estensioni tipiche del ransomware.
 3. Note di riscatto: file come "HOW_TO_DECRYPT.txt" che compaiono.

Quando scatta l'allarme PiumaAV avvisa subito l'utente, registra i file colpiti
e (su Windows) indica quali processi stanno scrivendo di piu' sul disco, cosi'
si puo' spegnere il PC o staccare la rete prima che il danno si estenda.
La protezione *preventiva* delle cartelle (blocco delle scritture non
autorizzate) su Windows e' l'"Accesso controllato alle cartelle" di Defender,
attivato da harden-defender.ps1.
"""

from __future__ import annotations

import collections
import logging
import math
import os
import re
import subprocess
import threading
import time
from pathlib import Path

from .config import IS_WINDOWS, Config

log = logging.getLogger(__name__)

# Su Windows i file vengono nascosti con attrib; altrove il punto iniziale li nasconde.
CANARY_NAMES = (["~$piuma_esca_contratti.docx", "~$piuma_esca_bilancio.xlsx"] if IS_WINDOWS
                else [".piuma_esca_contratti.docx", ".piuma_esca_bilancio.xlsx"])
RANSOM_EXT = {".locked", ".encrypted", ".enc", ".crypt", ".crypted", ".cry", ".crypto", ".locky", ".zepto",
              ".cerber", ".wallet", ".wncry", ".wnry", ".wcry", ".onion", ".lockbit", ".conti", ".ryk",
              ".djvu", ".stop", ".phobos", ".makop", ".akira", ".play", ".royal", ".blackcat", ".basta"}
NOTE_RE = re.compile(r"(how|help|restore|recover|decrypt|readme|read_me|ripristin|istruzion).{0,20}"
                     r"(decrypt|files|restore|recover|instruction|ransom|riscatto|file)", re.I)
# formati gia' compressi: alta entropia normale, non e' un indizio
COMPRESSED_EXT = {".zip", ".7z", ".rar", ".gz", ".xz", ".bz2", ".jpg", ".jpeg", ".png", ".gif", ".webp",
                  ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".pdf", ".docx", ".xlsx", ".pptx", ".odt",
                  ".msi", ".cab", ".iso", ".dmg", ".apk", ".jar", ".woff2", ".heic", ".zst"}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_encrypted(path: str, sample: int = 65536) -> bool:
    if os.path.splitext(path)[1].lower() in COMPRESSED_EXT:
        return False
    try:
        with open(path, "rb") as fh:
            data = fh.read(sample)
    except OSError:
        return False
    return len(data) >= 1024 and entropy(data) > 7.6


_FAKE_DOCX = (b"PK\x03\x04" + b"\x00" * 26 +
              "Documento riservato - non modificare.\n".encode() * 200)


class RansomwareGuard:
    def __init__(self, cfg: Config, folders: list[str], alert=None):
        self.cfg = cfg
        self.p = cfg.protection
        self.folders = [f for f in folders if os.path.isdir(f)]
        self.events: collections.deque[tuple[float, str, bool]] = collections.deque()
        self.lock = threading.Lock()
        self.last_alert = 0.0
        self.alert = alert or self._default_alert
        self.canaries: set[str] = set()

    # ------------------------------------------------------------- esche
    def plant_canaries(self) -> None:
        if not self.p.canary_files:
            return
        for folder in self.folders:
            for name in CANARY_NAMES:
                path = os.path.join(folder, name)
                try:
                    if not os.path.exists(path):
                        with open(path, "wb") as fh:
                            fh.write(_FAKE_DOCX)
                        if IS_WINDOWS:   # nascosto e di sistema: l'utente non lo vede
                            subprocess.run(["attrib", "+h", "+s", path], capture_output=True,
                                           creationflags=0x08000000)
                    self.canaries.add(os.path.normcase(os.path.abspath(path)))
                except OSError as exc:
                    log.debug("esca non creata in %s: %s", folder, exc)

    def is_canary(self, path: str) -> bool:
        return os.path.normcase(os.path.abspath(path)) in self.canaries

    # ------------------------------------------------------------- eventi
    def on_event(self, path: str, kind: str, dest: str | None = None) -> None:
        """kind: created | modified | moved | deleted. Chiamato dalla protezione in tempo reale."""
        now = time.time()
        if self.is_canary(path):
            self._trigger(f"un file esca e' stato {'cancellato' if kind == 'deleted' else 'toccato'}: {path}", [path])
            return
        target = dest or path
        name = os.path.basename(target)
        if kind in ("created", "moved") and NOTE_RE.search(name) and name.lower().endswith((".txt", ".html", ".hta", ".url")):
            self._suspicious(now, target, strong=True, why="nota di riscatto")
        if os.path.splitext(target)[1].lower() in RANSOM_EXT:
            self._suspicious(now, target, strong=True, why="estensione da ransomware")
        elif kind in ("modified", "moved", "created"):
            self._suspicious(now, target, strong=False)

    def _suspicious(self, now: float, path: str, strong: bool, why: str = "") -> None:
        with self.lock:
            self.events.append((now, path, strong))
            window = self.p.ransomware_burst_seconds
            while self.events and now - self.events[0][0] > window:
                self.events.popleft()
            recent = list(self.events)
        strong_hits = [p for _, p, s in recent if s]
        if len(strong_hits) >= 3:
            self._trigger(f"{len(strong_hits)} file con segni di ransomware ({why})", strong_hits)
            return
        paths = list(dict.fromkeys(p for _, p, _ in recent))     # file distinti
        if len(paths) >= self.p.ransomware_burst_files:
            sample = paths[-10:]
            encrypted = sum(looks_encrypted(p) for p in sample)
            if encrypted >= max(3, len(sample) // 2):
                self._trigger(f"{len(paths)} file modificati in {self.p.ransomware_burst_seconds}s, "
                              f"{encrypted}/{len(sample)} sembrano cifrati", paths)

    def _trigger(self, reason: str, paths: list[str]) -> None:
        now = time.time()
        with self.lock:
            if now - self.last_alert < 60:      # niente raffica di notifiche
                return
            self.last_alert = now
        self.alert(reason, paths)

    def _default_alert(self, reason: str, paths: list[str]) -> None:
        from .notify import notify
        procs = top_writers() if IS_WINDOWS else ""
        log.critical("POSSIBILE RANSOMWARE: %s. File: %s. %s", reason, ", ".join(paths[:20]), procs)
        notify("PiumaAV: POSSIBILE RANSOMWARE IN AZIONE",
               f"{reason}.\nScollega la rete o spegni il PC subito. {procs}"[:250])


def top_writers() -> str:
    """Windows: i processi che hanno scritto piu' dati (indizio su chi sta cifrando)."""
    ps = ("Get-CimInstance Win32_Process | Sort-Object WriteTransferCount -Descending | "
          "Select-Object -First 3 | ForEach-Object { \"$($_.Name) (PID $($_.ProcessId))\" }")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                             timeout=20, creationflags=0x08000000).stdout.split()
        return "Processi piu' attivi in scrittura: " + " ".join(out) if out else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""
