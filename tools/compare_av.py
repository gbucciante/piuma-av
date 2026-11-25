#!/usr/bin/env python3
"""Test comparativo SICURO tra PiumaAV/ClamAV e altri antivirus installati.

Non usa malware vero: genera sul posto file di prova innocui basati sullo
standard EICAR (riconosciuto da tutti gli antivirus) in varie "travestimenti"
(rinominato, compresso, archivi annidati...) piu' alcuni file di controllo che
NON devono essere segnalati. Poi chiede a ogni antivirus disponibile di
analizzarli e confronta i risultati, insieme alla velocita' su file puliti.

I file vengono generati dallo script (e non distribuiti gia' pronti) perche'
altrimenti l'antivirus del PC li cancellerebbe gia' durante il download.

Uso:
    python compare_av.py                      # cartella di prova temporanea
    python compare_av.py --kit C:\\AVTest     # cartella scelta
    python compare_av.py --speed C:\\Windows\\System32\\drivers   # anche test velocita'

Scanner riconosciuti automaticamente:
    - PiumaAV / ClamAV  (clamdscan se clamd e' attivo, altrimenti clamscan)
    - Microsoft Defender (MpCmdRun.exe, solo Windows)
    - ESET (ecls.exe), Avast/AVG (ashCmd.exe), Kaspersky (avp.com) se presenti
Risultati: tabella a schermo + file risultati_test_av.json
"""

from __future__ import annotations

import argparse
import base64
import bz2
import gzip
import io
import json
import lzma
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

IS_WIN = sys.platform.startswith("win")

# La stringa EICAR viene assemblata a runtime: cosi' questo script stesso non
# viene segnalato come "virus" da chi lo scarica.
_E = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"]
EICAR = ("".join(_E)).encode("ascii")


# ----------------------------------------------------------------- kit di prova
def _zip_bytes(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, data)
    return buf.getvalue()


def _tar_gz_bytes(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def build_kit() -> list[tuple[str, str, bytes, bool]]:
    """(nome file, descrizione, contenuto, deve_essere_rilevato)."""
    nested = EICAR
    for lvl in range(5, 0, -1):
        nested = _zip_bytes(f"livello{lvl}.{'zip' if lvl < 5 else 'com'}", nested)
    return [
        ("01_eicar.com", "EICAR originale (.com)", EICAR, True),
        ("02_eicar_rinominato.jpg", "EICAR con estensione falsa .jpg", EICAR, True),
        ("03_eicar.zip", "EICAR dentro uno ZIP", _zip_bytes("eicar.com", EICAR), True),
        ("04_eicar_annidato_5.zip", "ZIP dentro ZIP, 5 livelli", nested, True),
        ("05_eicar.tar.gz", "EICAR in archivio .tar.gz", _tar_gz_bytes("eicar.com", EICAR), True),
        ("06_eicar.com.gz", "EICAR compresso gzip", gzip.compress(EICAR), True),
        ("07_eicar.com.bz2", "EICAR compresso bzip2", bz2.compress(EICAR), True),
        ("08_eicar.com.xz", "EICAR compresso xz", lzma.compress(EICAR), True),
        ("09_eicar_coda_spazi.com", "EICAR + spazi finali (ammesso dallo standard)", EICAR + b" " * 64, True),
        # controlli: per lo standard EICAR NON vanno segnalati
        ("10_controllo_base64.txt", "EICAR codificato base64 (non eseguibile)", base64.b64encode(EICAR), False),
        ("11_controllo_dati_extra.bin", "EICAR + 4 KB di dati (fuori standard)", EICAR + os.urandom(4096), False),
        ("12_controllo_pulito.txt", "Testo pulito", "Ciao, sono un file innocuo.\n".encode() * 50, False),
        ("13_controllo_pulito.zip", "ZIP pulito", _zip_bytes("leggimi.txt", b"nessun virus qui\n" * 100), False),
    ]


def write_kit(folder: Path) -> list[dict]:
    folder.mkdir(parents=True, exist_ok=True)
    items = []
    for name, desc, data, expected in build_kit():
        p = folder / name
        try:
            p.write_bytes(data)
        except OSError:
            pass   # l'antivirus attivo puo' bloccarne la scrittura: conta come rilevato
        items.append({"file": name, "path": str(p), "descrizione": desc, "atteso": expected, "_data": data})
    return items


# ----------------------------------------------------------------- scanner
class Scanner:
    name = "?"

    def available(self) -> bool:
        return False

    def is_detected(self, path: str, data: bytes) -> bool | None:
        raise NotImplementedError

    def scan_dir_seconds(self, folder: str) -> float:
        t = time.perf_counter()
        self._scan_dir(folder)
        return time.perf_counter() - t

    def _scan_dir(self, folder: str) -> None:
        raise NotImplementedError


def _run(args, timeout=600, stdin: bytes | None = None):
    return subprocess.run(args, capture_output=True, input=stdin, timeout=timeout,
                          creationflags=0x08000000 if IS_WIN else 0)


def _which(*cands: str) -> str | None:
    for c in cands:
        if os.path.isfile(c):
            return c
        w = shutil.which(c)
        if w:
            return w
    return None


class ClamAV(Scanner):
    def __init__(self, database: str | None = None):
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        self.clamdscan = _which("clamdscan", os.path.join(pf, "ClamAV", "clamdscan.exe"))
        self.clamscan = _which("clamscan", os.path.join(pf, "ClamAV", "clamscan.exe"))
        self.database = database
        self.use_daemon = bool(self.clamdscan and not database and _run([self.clamdscan, "--ping", "1"]).returncode == 0) \
            if self.clamdscan else False
        self.name = "PiumaAV/ClamAV" + (" (clamd)" if self.use_daemon else " (clamscan)")

    def available(self):
        return bool(self.use_daemon or self.clamscan)

    def _args(self):
        if self.use_daemon:
            return [self.clamdscan, "--no-summary", "--stream"]
        a = [self.clamscan, "--no-summary", "--max-recursion=17"]
        return a + ([f"--database={self.database}"] if self.database else [])

    def is_detected(self, path, data):
        # Il contenuto viene passato in memoria (stdin): nessun file su disco,
        # cosi' l'antivirus in tempo reale del PC non interferisce.
        rc = _run(self._args() + ["-"], stdin=data).returncode
        return {0: False, 1: True}.get(rc)

    def _scan_dir(self, folder):
        _run(self._args() + (["--multiscan"] if self.use_daemon else ["-r"]) + [folder], timeout=7200)


class Defender(Scanner):
    name = "Microsoft Defender"

    def __init__(self):
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        self.exe = _which(os.path.join(pf, "Windows Defender", "MpCmdRun.exe"))

    def available(self):
        return IS_WIN and bool(self.exe)

    def is_detected(self, path, data):
        if not os.path.exists(path):
            return True                       # gia' rimosso/bloccato dalla protezione in tempo reale
        rc = _run([self.exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"]).returncode
        return {0: False, 2: True}.get(rc)

    def _scan_dir(self, folder):
        _run([self.exe, "-Scan", "-ScanType", "3", "-File", folder, "-DisableRemediation"], timeout=7200)


class GenericCLI(Scanner):
    """Altri antivirus con riga di comando: rc != 0 => rilevato (approssimazione)."""

    def __init__(self, name, exe_candidates, args_file, infected_codes):
        self.name, self.exe = name, _which(*exe_candidates)
        self.args_file, self.codes = args_file, infected_codes

    def available(self):
        return bool(self.exe)

    def is_detected(self, path, data):
        if not os.path.exists(path):
            return True                       # rimosso dalla sua protezione in tempo reale
        rc = _run([self.exe, *[a.format(path=path) for a in self.args_file]]).returncode
        return rc in self.codes

    def _scan_dir(self, folder):
        _run([self.exe, *[a.format(path=folder) for a in self.args_file]], timeout=7200)


def all_scanners(database: str | None) -> list[Scanner]:
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    return [s for s in [
        ClamAV(database),
        Defender(),
        GenericCLI("ESET", [os.path.join(pf, "ESET", "ESET Security", "ecls.exe")],
                   ["/no-quarantine", "/clean-mode=none", "{path}"], {1, 50}),
        GenericCLI("Avast/AVG", [os.path.join(pf, "Avast Software", "Avast", "ashCmd.exe"),
                                 os.path.join(pf, "AVG", "Antivirus", "ashCmd.exe")], ["{path}"], {1}),
        GenericCLI("Kaspersky", [os.path.join(pf86, "Kaspersky Lab", d, "avp.com") for d in
                                 ("Kaspersky Standard", "Kaspersky Plus", "Kaspersky Premium",
                                  "Kaspersky Internet Security 21.3")], ["SCAN", "{path}", "/i0"], {2, 3}),
    ] if s.available()]


# ----------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="Test comparativo sicuro tra antivirus (file EICAR innocui)")
    ap.add_argument("--kit", type=Path, help="cartella in cui creare i file di prova")
    ap.add_argument("--speed", type=Path, help="cartella di file PULITI per misurare la velocita'")
    ap.add_argument("--clamav-db", help="(sviluppo) cartella firme ClamAV alternativa")
    ap.add_argument("--out", type=Path, default=Path("risultati_test_av.json"))
    args = ap.parse_args()

    folder = args.kit or Path(tempfile.mkdtemp(prefix="avtest_"))
    print(f"Creo il kit di prova in {folder}")
    items = write_kit(folder)
    print("Attendo 5 secondi (le protezioni in tempo reale possono intervenire)...")
    time.sleep(5)
    for it in items:
        it["rimosso_in_tempo_reale"] = not os.path.exists(it["path"])

    scanners = all_scanners(args.clamav_db)
    if not scanners:
        print("Nessun antivirus con riga di comando trovato.")
        return 2
    print("Antivirus trovati:", ", ".join(s.name for s in scanners))

    for s in scanners:
        for it in items:
            it.setdefault("risultati", {})[s.name] = s.is_detected(it["path"], it["_data"])

    # ---- tabella
    w = max(len(i["descrizione"]) for i in items) + 2
    head = "".join(f"{s.name[:22]:>24}" for s in scanners)
    print("\n" + "File di prova".ljust(w) + "atteso " + head)
    score = {s.name: [0, 0] for s in scanners}
    for it in items:
        row = it["descrizione"].ljust(w) + ("SI   " if it["atteso"] else "no   ").ljust(7)
        for s in scanners:
            r = it["risultati"][s.name]
            cell = {True: "RILEVATO", False: "-", None: "errore"}[r]
            ok = (r is True) == it["atteso"]
            score[s.name][0] += ok
            score[s.name][1] += 1
            cell += "" if ok else " ✗"
            row += f"{cell:>24}"
        print(row)
    print("\nRisposte corrette (rilevati i positivi, ignorati i controlli):")
    for name, (ok, tot) in score.items():
        print(f"  {name:28} {ok}/{tot}")
    if any(i["rimosso_in_tempo_reale"] for i in items):
        print("\nNota: i file rimossi dalla protezione in tempo reale del PC contano come RILEVATI "
              "per quell'antivirus; ClamAV li analizza comunque in memoria.")
    for it in items:
        it.pop("_data", None)

    speed = {}
    if args.speed:
        print(f"\nVelocita' su {args.speed}:")
        n = sum(1 for _ in args.speed.rglob("*") if _.is_file())
        for s in scanners:
            secs = s.scan_dir_seconds(str(args.speed))
            speed[s.name] = {"secondi": round(secs, 2), "file": n}
            print(f"  {s.name:28} {secs:8.1f} s  ({n / secs:,.0f} file/s)" if secs else "")

    args.out.write_text(json.dumps({
        "sistema": platform.platform(), "data": time.strftime("%Y-%m-%d %H:%M"),
        "kit": items, "punteggio": score, "velocita": speed,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nRisultati salvati in {args.out.resolve()}")
    print(f"Ricorda di cancellare la cartella di prova: {folder}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
