"""Reputazione dei file su VirusTotal (facoltativa, disattivata per default).

Per i soli file "a rischio" (eseguibili, script, documenti con macro...) non
gia' riconosciuti dagli altri motori, PiumaAV calcola lo SHA-256 e chiede a
VirusTotal quanti dei ~70 antivirus del servizio lo considerano malevolo.
* Il file NON viene mai caricato: viaggia solo l'hash.
* Le risposte sono memorizzate (cache) per non ripetere le richieste.
* Rispetta i limiti del piano gratuito (4 richieste/minuto, 500/giorno).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from .config import ReputationConfig
from .engine import BaseEngine, ScanResult

log = logging.getLogger(__name__)

VT_URL = "https://www.virustotal.com/api/v3/files/{}"
CACHE_TTL_CLEAN = 3 * 24 * 3600     # un file "pulito" viene ricontrollato dopo 3 giorni
CACHE_TTL_UNKNOWN = 24 * 3600


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class _RateLimiter:
    def __init__(self, per_minute: int, per_day: int):
        self.per_minute, self.per_day = max(1, per_minute), per_day
        self.recent: list[float] = []
        self.day, self.day_count = time.strftime("%Y-%m-%d"), 0
        self.lock = threading.Lock()

    def try_acquire(self) -> bool:
        with self.lock:
            now = time.time()
            today = time.strftime("%Y-%m-%d")
            if today != self.day:
                self.day, self.day_count = today, 0
            self.recent = [t for t in self.recent if now - t < 60]
            if len(self.recent) >= self.per_minute or self.day_count >= self.per_day:
                return False
            self.recent.append(now)
            self.day_count += 1
            return True


class VirusTotalEngine(BaseEngine):
    name = "virustotal"

    def __init__(self, cfg: ReputationConfig, cache_file: Path, fetch=None):
        self.cfg = cfg
        self.cache_file = cache_file
        self.limiter = _RateLimiter(cfg.requests_per_minute, cfg.daily_limit)
        self._fetch = fetch or self._fetch_vt
        self._lock = threading.Lock()
        try:
            self.cache: dict = json.loads(cache_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.cache = {}

    def available(self) -> bool:
        return self.cfg.enabled and bool(self.cfg.virustotal_api_key)

    def version(self) -> str:
        return f"VirusTotal (soglia {self.cfg.min_detections} motori)"

    # ---------------------------------------------------------------- rete
    def _fetch_vt(self, digest: str) -> dict | None:
        """Restituisce le statistiche di analisi, None se l'hash e' sconosciuto."""
        req = urllib.request.Request(VT_URL.format(digest), headers={
            "x-apikey": self.cfg.virustotal_api_key, "User-Agent": "PiumaAV"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                attrs = json.loads(resp.read())["data"]["attributes"]
                return attrs.get("last_analysis_stats", {})
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    def _save_cache(self) -> None:
        try:
            tmp = self.cache_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.cache), encoding="utf-8")
            os.replace(tmp, self.cache_file)
        except OSError:
            pass

    # ---------------------------------------------------------------- scansione
    def scan_file(self, path: str) -> ScanResult:
        if os.path.splitext(path)[1].lower() not in self.cfg.extensions:
            return ScanResult(path, False)
        try:
            digest = sha256_file(path)
        except OSError as exc:
            return ScanResult(path, False, error=str(exc))

        with self._lock:
            hit = self.cache.get(digest)
        now = time.time()
        if hit and now - hit["t"] < (CACHE_TTL_CLEAN if hit.get("known") else CACHE_TTL_UNKNOWN) \
                and not hit.get("bad"):
            return ScanResult(path, False)
        if hit and hit.get("bad"):
            return self._verdict(path, hit)

        if not self.limiter.try_acquire():
            log.debug("VirusTotal: limite richieste raggiunto, salto %s", path)
            return ScanResult(path, False)
        try:
            stats = self._fetch(digest)
        except (OSError, ValueError, KeyError) as exc:
            log.debug("VirusTotal non raggiungibile: %s", exc)
            return ScanResult(path, False, error=f"VirusTotal: {exc}")

        if stats is None:
            entry = {"t": now, "known": False}
        else:
            malicious = int(stats.get("malicious", 0))
            total = sum(int(v) for v in stats.values() if isinstance(v, int))
            entry = {"t": now, "known": True, "mal": malicious, "tot": total,
                     "bad": malicious >= self.cfg.min_detections}
        with self._lock:
            self.cache[digest] = entry
            self._save_cache()
        return self._verdict(path, entry)

    @staticmethod
    def _verdict(path: str, entry: dict) -> ScanResult:
        if entry.get("bad"):
            return ScanResult(path, True, f"VirusTotal:{entry['mal']}/{entry['tot']}")
        return ScanResult(path, False)
