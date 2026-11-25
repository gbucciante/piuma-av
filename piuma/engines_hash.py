"""Motore a hash leggerissimo (usato soprattutto in modalita' leggera).

Gli hash SHA-256 dei malware di MalwareBazaar vengono salvati come file
binario ordinato (32 byte per hash). La ricerca avviene con una ricerca
binaria direttamente sul file mappato in memoria (mmap): anche con un milione
di hash si usano pochi MB di RAM e ogni controllo richiede microsecondi.
"""

from __future__ import annotations

import hashlib
import mmap
import os
import threading
from pathlib import Path

from .engine import BaseEngine, ScanResult

RECORD = 32
HASHES_BIN = "piuma_hashes.bin"


def write_hash_db(hex_hashes: set[str], dest: Path) -> int:
    digests = sorted(bytes.fromhex(h) for h in hex_hashes if len(h) == 64)
    tmp = dest.with_suffix(".tmp")
    with open(tmp, "wb") as fh:
        for d in digests:
            fh.write(d)
    os.replace(tmp, dest)
    return len(digests)


class HashEngine(BaseEngine):
    name = "hash"

    def __init__(self, db_file: Path, max_bytes: int = 100 * 1024 * 1024):
        self.db_file = Path(db_file)
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._mm: mmap.mmap | None = None
        self._fh = None
        self.count = 0
        self.reload()

    def available(self) -> bool:
        return self.count > 0

    def version(self) -> str:
        return f"{self.count} hash"

    def reload(self) -> None:
        with self._lock:
            if self._mm is not None:
                self._mm.close()
                self._fh.close()
                self._mm = self._fh = None
                self.count = 0
            if not self.db_file.exists() or self.db_file.stat().st_size < RECORD:
                return
            self._fh = open(self.db_file, "rb")
            self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
            self.count = len(self._mm) // RECORD

    def contains(self, digest: bytes) -> bool:
        with self._lock:
            mm, lo, hi = self._mm, 0, self.count - 1
            if mm is None:
                return False
            while lo <= hi:
                mid = (lo + hi) // 2
                rec = mm[mid * RECORD:(mid + 1) * RECORD]
                if rec == digest:
                    return True
                if rec < digest:
                    lo = mid + 1
                else:
                    hi = mid - 1
        return False

    def scan_file(self, path: str) -> ScanResult:
        try:
            if os.path.getsize(path) > self.max_bytes:
                return ScanResult(path, False)
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
        except OSError as exc:
            return ScanResult(path, False, error=str(exc))
        d = h.digest()
        if self.contains(d):
            return ScanResult(path, True, f"MalwareBazaar.{d.hex()[:12]}")
        return ScanResult(path, False)
