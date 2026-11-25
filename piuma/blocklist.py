"""Blocco dei siti malevoli tramite il file hosts.

Scarica liste aggiornate di domini pericolosi (predefinita: URLhaus di
abuse.ch, domini che distribuiscono malware) e le scrive in una sezione
delimitata del file hosts, puntandoli a 0.0.0.0: il PC non riesce piu' a
contattarli, con qualsiasi browser o programma. Il resto del file hosts non
viene toccato; prima della prima modifica ne viene salvata una copia.
Richiede privilegi di amministratore/root.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import urllib.request
from pathlib import Path

from . import __version__
from .config import IS_WINDOWS, Config

log = logging.getLogger(__name__)

BEGIN = "# >>> PiumaAV blocklist - sezione gestita automaticamente, non modificare >>>"
END = "# <<< PiumaAV blocklist <<<"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
NEVER_BLOCK = {"localhost", "localhost.localdomain", "broadcasthost", "local", "0.0.0.0",
               "microsoft.com", "windowsupdate.com", "apple.com", "google.com", "github.com",
               "clamav.net", "abuse.ch", "virustotal.com"}
MAX_DOMAINS = 200_000


def default_hosts_path() -> Path:
    if IS_WINDOWS:
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def parse_list(text: str) -> set[str]:
    """Accetta formato hosts ('127.0.0.1 dominio') o un dominio per riga."""
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        parts = line.split()
        dom = parts[1] if len(parts) >= 2 and re.match(r"^[\d.:]+$", parts[0]) else parts[0]
        dom = dom.rstrip(".")
        if DOMAIN_RE.match(dom) and not re.match(r"^[\d.]+$", dom) and dom not in NEVER_BLOCK and not any(dom.endswith("." + s) for s in NEVER_BLOCK):
            out.add(dom)
    return out


def render_hosts(original: str, domains: set[str]) -> str:
    nl = "\r\n" if ("\r\n" in original or (IS_WINDOWS and not original)) else "\n"
    pattern = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END) + r"\r?\n?", re.S)
    base = pattern.sub("", original).rstrip("\r\n")
    base = base + nl if base else ""
    if not domains:
        return base
    lines = [BEGIN] + [f"0.0.0.0 {d}" for d in sorted(domains)] + [END]
    return base + nl.join(lines) + nl


def _download(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": f"PiumaAV/{__version__}"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read().decode("utf-8", "replace")


def apply(cfg: Config, domains: set[str]) -> int:
    hosts = Path(cfg.protection.hosts_file) if cfg.protection.hosts_file else default_hosts_path()
    original = hosts.read_text(encoding="utf-8", errors="replace") if hosts.exists() else ""
    backup = cfg.data_dir / "hosts.backup"
    if not backup.exists() and original:
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(hosts, backup)
    new = render_hosts(original, domains)
    if new != original:
        tmp = hosts.with_name(hosts.name + ".piuma.tmp")
        tmp.write_text(new, encoding="utf-8", newline="")
        os.replace(tmp, hosts)
    return len(domains)


def update(cfg: Config, fetch=_download) -> bool:
    if not cfg.protection.domain_blocking:
        return False
    domains: set[str] = set()
    ok = 0
    for url in cfg.protection.blocklists:
        try:
            got = parse_list(fetch(url))
        except OSError as exc:
            log.warning("lista %s non scaricata: %s", url, exc)
            continue
        if got:
            domains |= got
            ok += 1
    if not ok:
        return False        # nessuna lista valida: si lascia la sezione com'e'
    if len(domains) > MAX_DOMAINS:
        log.warning("liste troppo grandi (%d domini): uso i primi %d", len(domains), MAX_DOMAINS)
        domains = set(sorted(domains)[:MAX_DOMAINS])
    try:
        n = apply(cfg, domains)
    except PermissionError:
        log.warning("file hosts non modificabile: servono i privilegi di amministratore")
        return False
    log.info("blocco siti: %d domini malevoli", n)
    return True


def remove(cfg: Config) -> None:
    apply(cfg, set())
