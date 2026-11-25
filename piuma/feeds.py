"""Firme aggiuntive gratuite, scaricate e aggiornate automaticamente.

* MalwareBazaar (abuse.ch): hash SHA-256 di campioni di malware raccolti ogni
  giorno dalla comunita'. Convertiti nel formato ClamAV `.hsb` e caricati da
  clamd insieme alle firme ufficiali. Il dump completo viene riscaricato una
  volta a settimana, nel frattempo si aggiungono gli hash delle ultime 48 ore.
* YARA-Forge: regole YARA che riconoscono intere famiglie di malware.
* Feed ClamAV extra a scelta (es. SaneSecurity), dichiarati nella configurazione.

Autenticita' degli aggiornamenti:
* le firme ufficiali ClamAV (.cvd/.cld) sono firmate digitalmente da Cisco e
  freshclam rifiuta quelle con firma non valida;
* tutti i download avvengono SOLO in HTTPS con certificato verificato;
* lo zip di YARA-Forge viene confrontato con l'hash SHA-256 che GitHub
  pubblica per ogni file di release: se non coincide viene scartato;
* ogni file scaricato passa controlli di formato (e le regole YARA devono
  compilare) prima di sostituire quello vecchio, che resta in caso di errore.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import re
import shutil
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from . import __version__
from .config import Config

log = logging.getLogger(__name__)

# Dal 2025 abuse.ch richiede una chiave gratuita (https://auth.abuse.ch/) anche per
# gli export; i vecchi indirizzi /export/txt/sha256/... rispondono "410 Gone".
MB_FULL = "https://mb-api.abuse.ch/v2/files/exports/{key}/full.csv.zip"
MB_RECENT = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"
HSB_NAME = "piuma_malwarebazaar.hsb"
SHA256_RE = re.compile(rb"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
WEEK = 7 * 24 * 3600
SAFE_EXT = {".ndb", ".hdb", ".hsb", ".ldb", ".cdb", ".mdb", ".msb", ".ndu", ".ldu", ".yar", ".yara",
            ".hdu", ".hsu", ".mdu", ".msu", ".ign2", ".fp", ".sfp", ".cbc", ".ftm", ".pdb", ".wdb"}


class VerificationError(OSError):
    pass


def _download(url: str, auth_key: str = "", timeout: int = 300) -> bytes:
    if not url.lower().startswith("https://"):
        raise VerificationError(f"rifiutato: solo HTTPS e' ammesso ({url})")
    req = urllib.request.Request(url, headers={"User-Agent": f"PiumaAV/{__version__}"})
    if auth_key:
        req.add_header("Auth-Key", auth_key)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _unzip_if_needed(data: bytes) -> bytes:
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return b"\n".join(z.read(n) for n in z.namelist() if not n.endswith("/"))
    return data


def parse_sha256_list(data: bytes) -> set[str]:
    out = set()
    # elenco semplice (un hash per riga) oppure CSV: si prende il primo SHA-256 della riga
    for line in _unzip_if_needed(data).splitlines():
        line = line.strip()
        if not line or line.startswith(b"#"):
            continue
        m = SHA256_RE.search(line)
        if m:
            out.add(m.group().decode().lower())
    return out


def write_hsb(hashes: set[str], dest: Path) -> int:
    """Formato ClamAV: sha256:*:Nome:73  ('*' = dimensione qualsiasi, richiede livello motore 73+)."""
    tmp = dest.with_suffix(".tmp")
    with open(tmp, "w", encoding="ascii", newline="\n") as fh:
        for h in sorted(hashes):
            fh.write(f"{h}:*:MalwareBazaar.{h[:12]}:73\n")
    os.replace(tmp, dest)
    return len(hashes)


def read_hsb(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {line.split(":", 1)[0] for line in path.read_text(encoding="ascii", errors="ignore").splitlines() if line}


def read_hash_bin(path: Path) -> set[str]:
    if not path.exists():
        return set()
    data = path.read_bytes()
    return {data[i:i + 32].hex() for i in range(0, len(data) - 31, 32)}


def update_malwarebazaar(cfg: Config) -> bool:
    """Scrive gli hash per ClamAV (.hsb, modalita' completa) e/o per il motore hash (.bin, leggera)."""
    from .engines_hash import HASHES_BIN, write_hash_db
    db = Path(cfg.feeds.clamav_database_dir)
    hsb = db / HSB_NAME
    binf = cfg.data_dir / HASHES_BIN
    want_hsb = "clamav" in cfg.engine.engines
    want_bin = "hash" in cfg.engine.engines
    current = hsb if want_hsb else binf
    key = cfg.feeds.abusech_auth_key.strip()
    if not key:
        log.info("MalwareBazaar saltato: serve una chiave gratuita abuse.ch (abusech_auth_key in [feeds])")
        return False
    try:
        full_due = not current.exists() or time.time() - current.stat().st_mtime > WEEK
        old = set() if full_due else (read_hsb(hsb) if want_hsb else read_hash_bin(binf))
        new: set[str] = set()
        if full_due:
            try:
                new = parse_sha256_list(_download(MB_FULL.format(key=key), key))
            except urllib.error.HTTPError as exc:
                log.info("MalwareBazaar: export completo non disponibile (%s), uso quello recente", exc.code)
        if not new:
            new = parse_sha256_list(_download(MB_RECENT.format(key=key), key))
        hashes = old | new
        if len(hashes) < 100:
            log.warning("MalwareBazaar: risposta inattesa (%d hash), mantengo le firme attuali", len(hashes))
            return False
        if want_hsb:
            db.mkdir(parents=True, exist_ok=True)
            write_hsb(hashes, hsb)
        if want_bin:
            cfg.data_dir.mkdir(parents=True, exist_ok=True)
            write_hash_db(hashes, binf)
        log.info("MalwareBazaar: %d hash di malware attivi", len(hashes))
        return True
    except urllib.error.HTTPError as exc:
        hint = " (chiave abuse.ch non valida?)" if exc.code in (401, 403) else ""
        log.warning("MalwareBazaar non aggiornato: HTTP %s%s", exc.code, hint)
        return False
    except OSError as exc:
        log.warning("MalwareBazaar non aggiornato: %s", exc)
        return False


GITHUB_RELEASE_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/releases/(?:latest/download|download/[^/]+)/([^/]+)$")


def github_asset_digest(url: str, fetch=None) -> str | None:
    """Hash SHA-256 pubblicato da GitHub per un file di release (None se non disponibile)."""
    m = GITHUB_RELEASE_RE.match(url)
    if not m:
        return None
    repo, asset = m.groups()
    api = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        info = json.loads((fetch or _download)(api))
    except (OSError, ValueError):
        return None
    for a in info.get("assets", []):
        if a.get("name") == asset and str(a.get("digest", "")).startswith("sha256:"):
            return a["digest"].split(":", 1)[1].lower()
    return None


def verify_digest(data: bytes, expected: str | None, what: str) -> None:
    if expected is None:
        log.warning("%s: hash di verifica non pubblicato, mi affido solo a HTTPS", what)
        return
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise VerificationError(f"{what}: hash non corrispondente (atteso {expected[:16]}..., ottenuto {actual[:16]}...)")
    log.info("%s: autenticita' verificata (SHA-256)", what)


def update_yara_forge(cfg: Config) -> bool:
    from .engines_yara import backend, compile_rules
    if backend() is None:
        log.info("YARA-Forge saltato: libreria YARA non installata (yara-python o yara-x)")
        return False
    target = Path(cfg.engine.yara_rules_dir) if cfg.engine.yara_rules_dir else cfg.data_dir / "yara"
    try:
        data = _download(cfg.feeds.yara_forge_url)
        verify_digest(data, github_asset_digest(cfg.feeds.yara_forge_url), "YARA-Forge")
        staging = target.with_name(target.name + ".new")
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for member in z.namelist():
                if member.lower().endswith((".yar", ".yara")):
                    (staging / Path(member).name).write_bytes(z.read(member))
        compile_rules(staging)                 # se non compila, le vecchie regole restano
        shutil.rmtree(target, ignore_errors=True)
        os.replace(staging, target)
        return True
    except Exception as exc:  # zip corrotto, rete, regole non valide...
        log.warning("YARA-Forge non aggiornato: %s", exc)
        return False


def update_extra(cfg: Config) -> int:
    db = Path(cfg.feeds.clamav_database_dir)
    ok = 0
    for feed in cfg.feeds.extra:
        url, name = feed.get("url"), feed.get("file") or Path(feed.get("url", "")).name
        if not url or Path(name).suffix.lower() not in SAFE_EXT or Path(name).name != name:
            log.warning("feed extra ignorato (url/nome non valido): %s", feed)
            continue
        try:
            data = _download(url)
            tmp = db / (name + ".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, db / name)
            ok += 1
        except OSError as exc:
            log.warning("feed %s non aggiornato: %s", name, exc)
    return ok


def update_all(cfg: Config) -> bool:
    """Aggiorna tutti i feed attivi. True se almeno uno e' stato aggiornato."""
    if not cfg.feeds.enabled:
        return False
    changed = False
    if cfg.feeds.malwarebazaar and ("clamav" in cfg.engine.engines or "hash" in cfg.engine.engines):
        changed |= update_malwarebazaar(cfg)
    if cfg.feeds.yara_forge and "yara" in cfg.engine.engines:
        changed |= update_yara_forge(cfg)
    if cfg.feeds.extra:
        changed |= update_extra(cfg) > 0
    if changed and cfg.protection.integrity_check:
        # si aggiornano SOLO le voci delle firme, mai quelle del programma
        from .selfprotect import Integrity
        yara_dir = Path(cfg.engine.yara_rules_dir) if cfg.engine.yara_rules_dir else cfg.data_dir / "yara"
        from .engines_hash import HASHES_BIN
        Integrity(cfg).update_entries([yara_dir / "rules.yarc",
                                       Path(cfg.feeds.clamav_database_dir) / HSB_NAME,
                                       cfg.data_dir / HASHES_BIN])
    return changed
