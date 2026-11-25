"""Quarantena: isola i file infetti rendendoli innocui ma recuperabili.

Il file viene cifrato con un semplice XOR (non per segretezza, ma perche' non
sia piu' eseguibile ne' riconosciuto/aperto per errore) e spostato nella
cartella di quarantena insieme a un file .json con i metadati.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

KEY = b"PiumaAV-quarantena"


@dataclass
class QuarantineEntry:
    id: str
    original_path: str
    signature: str
    sha256: str
    size: int
    quarantined_at: float


def _xor_copy(src: Path, dst: Path) -> tuple[str, str]:
    """Copia src in dst applicando lo XOR; restituisce (sha256 ingresso, sha256 uscita)."""
    h_in, h_out = hashlib.sha256(), hashlib.sha256()
    block = 1 << 16
    stream = (KEY * (block // len(KEY) + 2))
    pos = 0
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while chunk := fi.read(block):
            off = pos % len(KEY)
            ks = stream[off:off + len(chunk)]
            out = (int.from_bytes(chunk, "big") ^ int.from_bytes(ks, "big")).to_bytes(len(chunk), "big")
            h_in.update(chunk)
            h_out.update(out)
            fo.write(out)
            pos += len(chunk)
    return h_in.hexdigest(), h_out.hexdigest()


class Quarantine:
    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def add(self, path: str, signature: str) -> QuarantineEntry:
        src = Path(path)
        qid = uuid.uuid4().hex[:12]
        blob = self.dir / f"{qid}.bin"
        size = src.stat().st_size
        digest, _ = _xor_copy(src, blob)
        entry = QuarantineEntry(qid, str(src), signature, digest, size, time.time())
        (self.dir / f"{qid}.json").write_text(json.dumps(asdict(entry), indent=2), encoding="utf-8")
        _force_remove(src)
        return entry

    def list(self) -> list[QuarantineEntry]:
        items = []
        for meta in sorted(self.dir.glob("*.json")):
            try:
                items.append(QuarantineEntry(**json.loads(meta.read_text(encoding="utf-8"))))
            except (ValueError, TypeError):
                continue
        return sorted(items, key=lambda e: e.quarantined_at)

    def _get(self, qid: str) -> QuarantineEntry:
        meta = self.dir / f"{qid}.json"
        if not meta.exists():
            raise KeyError(f"elemento di quarantena {qid!r} non trovato")
        return QuarantineEntry(**json.loads(meta.read_text(encoding="utf-8")))

    def restore(self, qid: str, target: str | None = None) -> str:
        entry = self._get(qid)
        dst = Path(target or entry.original_path)
        if dst.exists():
            dst = dst.with_name(dst.name + ".ripristinato")
        dst.parent.mkdir(parents=True, exist_ok=True)
        _, plain = _xor_copy(self.dir / f"{qid}.bin", dst)  # lo XOR e' simmetrico
        if plain != entry.sha256:
            dst.unlink(missing_ok=True)
            raise ValueError("ripristino non riuscito: hash non corrispondente")
        self.delete(qid)
        return str(dst)

    def delete(self, qid: str) -> None:
        self._get(qid)
        (self.dir / f"{qid}.bin").unlink(missing_ok=True)
        (self.dir / f"{qid}.json").unlink(missing_ok=True)


def _force_remove(path: Path) -> None:
    try:
        path.unlink()
    except PermissionError:
        # file in sola lettura (Windows): togli l'attributo e riprova
        os.chmod(path, stat.S_IWRITE)
        path.unlink()


def delete_file(path: str) -> None:
    p = Path(path)
    if p.is_dir():
        shutil.rmtree(p)
    else:
        _force_remove(p)
