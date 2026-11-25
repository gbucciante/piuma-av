"""Motore Microsoft Defender (solo Windows).

Usa il motore di Defender, gia' presente in ogni Windows 10/11, in due modi:
  * AMSI (Antimalware Scan Interface): il contenuto del file viene passato
    in memoria all'antivirus di sistema. Velocissimo (millisecondi), con
    protezione cloud se attiva. Non restituisce il nome della minaccia.
  * MpCmdRun.exe -Scan: scansione classica da riga di comando, piu' lenta
    (~1 s per file), usata per i file grandi, quando AMSI non e' disponibile
    e per ricavare il nome della minaccia.

Nota: se sul PC c'e' un altro antivirus registrato come provider AMSI, e'
quello a rispondere tramite AMSI. Va benissimo: si usa il suo motore.
"""

from __future__ import annotations

import ctypes
import glob
import logging
import os
import re
import subprocess
import threading

from .config import IS_WINDOWS
from .engine import BaseEngine, ScanResult

log = logging.getLogger(__name__)

AMSI_RESULT_DETECTED = 32768
AMSI_BLOCKED_BY_ADMIN_START, AMSI_BLOCKED_BY_ADMIN_END = 0x4000, 0x4FFF
AMSI_MAX_BYTES = 32 * 1024 * 1024     # oltre questa dimensione si usa MpCmdRun
THREAT_RE = re.compile(r"^\s*Threat\s*:\s*(?P<name>\S.*?)\s*$", re.MULTILINE)


class _Amsi:
    """Wrapper minimale di amsi.dll tramite ctypes."""

    def __init__(self):
        dll = ctypes.WinDLL("amsi.dll")  # type: ignore[attr-defined]
        vp = ctypes.c_void_p
        dll.AmsiInitialize.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(vp)]
        dll.AmsiInitialize.restype = ctypes.c_long
        dll.AmsiOpenSession.argtypes = [vp, ctypes.POINTER(vp)]
        dll.AmsiOpenSession.restype = ctypes.c_long
        dll.AmsiCloseSession.argtypes = [vp, vp]
        dll.AmsiCloseSession.restype = None
        dll.AmsiScanBuffer.argtypes = [vp, vp, ctypes.c_ulong, ctypes.c_wchar_p, vp, ctypes.POINTER(ctypes.c_int)]
        dll.AmsiScanBuffer.restype = ctypes.c_long
        dll.AmsiUninitialize.argtypes = [vp]
        dll.AmsiUninitialize.restype = None
        self.dll = dll
        self.ctx = vp()
        hr = dll.AmsiInitialize("PiumaAV", ctypes.byref(self.ctx))
        if hr != 0:
            raise OSError(f"AmsiInitialize fallita (HRESULT {hr & 0xFFFFFFFF:#x})")
        self.lock = threading.Lock()

    def scan(self, data: bytes, name: str) -> int:
        """Restituisce il codice AMSI_RESULT (>= 32768 = malware)."""
        session = ctypes.c_void_p()
        result = ctypes.c_int(0)
        buf = ctypes.create_string_buffer(data, len(data))
        with self.lock:
            self.dll.AmsiOpenSession(self.ctx, ctypes.byref(session))
            try:
                hr = self.dll.AmsiScanBuffer(self.ctx, ctypes.cast(buf, ctypes.c_void_p), len(data),
                                             name, session, ctypes.byref(result))
            finally:
                self.dll.AmsiCloseSession(self.ctx, session)
        if hr != 0:
            raise OSError(f"AmsiScanBuffer fallita (HRESULT {hr & 0xFFFFFFFF:#x})")
        return result.value

    def close(self) -> None:
        self.dll.AmsiUninitialize(self.ctx)


def is_malware(code: int) -> bool:
    return code >= AMSI_RESULT_DETECTED or AMSI_BLOCKED_BY_ADMIN_START <= code <= AMSI_BLOCKED_BY_ADMIN_END


def find_mpcmdrun() -> str | None:
    if not IS_WINDOWS:
        return None
    # la versione aggiornata del motore sta in ProgramData\...\Platform\<versione>
    pd = os.environ.get("ProgramData", r"C:\ProgramData")
    platforms = sorted(glob.glob(os.path.join(pd, "Microsoft", "Windows Defender", "Platform", "*", "MpCmdRun.exe")))
    if platforms:
        return platforms[-1]
    legacy = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")
    return legacy if os.path.exists(legacy) else None


def parse_mpcmdrun(output: str) -> str | None:
    m = THREAT_RE.search(output)
    return m.group("name") if m else None


class DefenderEngine(BaseEngine):
    name = "defender"

    def __init__(self, max_file_size_mb: int = 100):
        self.max_bytes = max_file_size_mb * 1024 * 1024
        self.mpcmd = find_mpcmdrun()
        self.amsi: _Amsi | None = None
        if IS_WINDOWS:
            try:
                self.amsi = _Amsi()
            except OSError as exc:
                log.info("AMSI non disponibile (%s): uso solo MpCmdRun", exc)

    def available(self) -> bool:
        return bool(self.amsi or self.mpcmd)

    def version(self) -> str:
        return "AMSI + MpCmdRun" if self.amsi and self.mpcmd else ("AMSI" if self.amsi else "MpCmdRun")

    def _mpcmd_scan(self, path: str) -> ScanResult:
        try:
            proc = subprocess.run([self.mpcmd, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"],
                                  capture_output=True, text=True, errors="replace", timeout=300,
                                  creationflags=0x08000000)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ScanResult(path, False, error=str(exc))
        if proc.returncode == 2:
            return ScanResult(path, True, f"Defender:{parse_mpcmdrun(proc.stdout) or 'minaccia'}")
        if proc.returncode == 0:
            return ScanResult(path, False)
        return ScanResult(path, False, error=f"MpCmdRun codice {proc.returncode}")

    def scan_file(self, path: str) -> ScanResult:
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            # Defender in tempo reale puo' averlo gia' rimosso: per noi non e' un errore
            return ScanResult(path, False, error=str(exc))
        if self.amsi and size <= AMSI_MAX_BYTES:
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
                code = self.amsi.scan(data, path)
            except OSError as exc:
                if not self.mpcmd:
                    return ScanResult(path, False, error=str(exc))
            else:
                if not is_malware(code):
                    return ScanResult(path, False)
                # rilevato: chiediamo il nome a MpCmdRun (se il file c'e' ancora)
                name = None
                if self.mpcmd and os.path.exists(path):
                    name = self._mpcmd_scan(path).signature
                return ScanResult(path, True, name or "Defender:AMSI.Detected")
        if self.mpcmd:
            return self._mpcmd_scan(path)
        return ScanResult(path, False, error="Defender non disponibile")
