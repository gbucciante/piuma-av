"""Motore YARA: regole che descrivono famiglie di malware (non solo file esatti).

Le regole vengono dalla raccolta gratuita YARA-Forge (pacchetto "core",
selezionato per avere pochi falsi positivi) e sono compilate una volta per
caricarle in un attimo. Funziona con `yara-python` oppure, se manca (per es.
con versioni di Python troppo nuove), con `yara-x`, il motore YARA di nuova
generazione che ha pacchetti pronti per ogni versione di Python.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path

from .engine import BaseEngine, ScanResult

log = logging.getLogger(__name__)

COMPILED = "rules.yarc"          # yara-python
COMPILED_X = "rules.yarx"        # yara-x
EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}


def backend() -> str | None:
    """'yara' (yara-python), 'yara_x' oppure None se nessuno dei due e' installato."""
    for mod in ("yara", "yara_x"):
        try:
            __import__(mod)
            return mod
        except ImportError:
            continue
    return None


def _sources(rules_dir: Path) -> list[Path]:
    sources = sorted([*rules_dir.rglob("*.yar"), *rules_dir.rglob("*.yara")])
    if not sources:
        raise FileNotFoundError(f"nessuna regola YARA in {rules_dir}")
    return sources


def compile_rules(rules_dir: Path, which: str | None = None) -> Path:
    """Compila tutti i .yar/.yara della cartella (salta le regole non valide)."""
    which = which or backend()
    if which == "yara_x":
        return _compile_x(rules_dir)
    import yara
    good = {}
    for i, src in enumerate(_sources(rules_dir)):
        try:
            text = _clean_for_yara(src.read_text(encoding="utf-8", errors="replace"), src.name)
        except yara.Error as exc:
            log.warning("regola YARA scartata %s: %s", src.name, exc)
            continue
        good[f"ns{i}"] = text
    if not good:
        raise ValueError(f"nessuna regola YARA compilabile in {rules_dir}")
    rules = yara.compile(sources=good, externals=EXTERNALS)
    tmp = rules_dir / (COMPILED + ".tmp")
    rules.save(str(tmp))
    os.replace(tmp, rules_dir / COMPILED)
    log.info("regole YARA compilate: %d file", len(good))
    return rules_dir / COMPILED


def _new_x_compiler():
    import yara_x
    try:
        compiler = yara_x.Compiler(relaxed_re_syntax=True)
    except TypeError:
        compiler = yara_x.Compiler()
    for k, v in EXTERNALS.items():
        compiler.define_global(k, v)
    return compiler


_RULE_START = None


def _drop_bad_rules(text: str, name: str, try_compile, error_cls, line_re: str,
                    what: str, max_drops: int = 300) -> str:
    """Toglie dal testo, una alla volta, le regole che il motore non riesce a compilare.

    YARA-Forge e' un unico file con migliaia di regole: senza questa pulizia una
    sola regola non supportata (per es. `pe.number_of_signatures` quando yara-python
    e' stato compilato senza OpenSSL, come succede su Windows) farebbe scartare
    tutto il file. La riga indicata dall'errore dice quale regola togliere.
    """
    import re
    global _RULE_START
    _RULE_START = _RULE_START or re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+\w+")
    rule_start = _RULE_START
    line_pat = re.compile(line_re)
    lines = text.splitlines()
    dropped = 0
    while True:
        try:
            try_compile("\n".join(lines))
            break
        except error_cls as exc:
            m = line_pat.search(str(exc))
            if not m or dropped >= max_drops:
                raise
            bad = min(int(m.group(1)) - 1, len(lines) - 1)
            start = bad
            while start > 0 and not rule_start.match(lines[start]):
                start -= 1
            if not rule_start.match(lines[start]):        # errore fuori da una regola
                raise
            end = start + 1
            while end < len(lines) and not rule_start.match(lines[end]):
                end += 1
            log.debug("YARA %s: scarto %s", name, lines[start].strip())
            del lines[start:end]
            dropped += 1
    if dropped:
        log.info("YARA %s: %d regole non supportate da %s scartate", name, dropped, what)
    return "\n".join(lines)


def _clean_for_yara(text: str, name: str) -> str:
    import yara
    return _drop_bad_rules(text, name, lambda t: yara.compile(source=t, externals=EXTERNALS),
                           yara.SyntaxError, r"line (\d+)", "yara-python")


def _clean_for_x(text: str, name: str) -> str:
    import yara_x
    # un errore lascia il compilatore inutilizzabile: ogni tentativo ne usa uno nuovo
    return _drop_bad_rules(text, name, lambda t: _new_x_compiler().add_source(t),
                           yara_x.CompileError, r"line:(\d+):", "yara-x")


def _compile_x(rules_dir: Path) -> Path:
    import yara_x
    compiler = _new_x_compiler()
    ok = 0
    for i, src in enumerate(_sources(rules_dir)):
        try:
            text = _clean_for_x(src.read_text(encoding="utf-8", errors="replace"), src.name)
        except yara_x.CompileError as exc:
            log.warning("regola YARA scartata %s: %s", src.name, str(exc).splitlines()[0])
            continue
        compiler.new_namespace(f"ns{i}")
        compiler.add_source(text)
        ok += 1
    if not ok:
        raise ValueError(f"nessuna regola YARA compilabile in {rules_dir}")
    rules = compiler.build()
    tmp = rules_dir / (COMPILED_X + ".tmp")
    with open(tmp, "wb") as fh:
        rules.serialize_into(fh)
    os.replace(tmp, rules_dir / COMPILED_X)
    log.info("regole YARA compilate con yara-x: %d file", ok)
    return rules_dir / COMPILED_X


class YaraEngine(BaseEngine):
    name = "yara"

    def __init__(self, rules_dir: Path, timeout: int = 30):
        self.dir = Path(rules_dir)
        self.timeout = timeout
        self.rules = None
        self._lock = threading.Lock()
        self._local = threading.local()
        self.backend = backend()
        if self.backend:
            self.reload()

    def available(self) -> bool:
        return self.rules is not None

    def reload(self) -> None:
        if not self.backend:
            return
        name = COMPILED_X if self.backend == "yara_x" else COMPILED
        compiled = self.dir / name
        try:
            if not compiled.exists() and self.dir.is_dir():
                compile_rules(self.dir, self.backend)
            if not compiled.exists():
                return
            if self.backend == "yara_x":
                import yara_x
                with open(compiled, "rb") as fh:
                    rules = yara_x.Rules.deserialize_from(fh)
            else:
                import yara
                rules = yara.load(str(compiled))
            with self._lock:
                self.rules = rules
                self._local = threading.local()      # scanner yara-x da ricreare
        except Exception as exc:  # noqa: BLE001 - regole rovinate: si continua senza YARA
            log.warning("regole YARA non caricate: %s", exc)

    def version(self) -> str:
        return f"{self.backend or 'nessuno'}, regole in {self.dir}"

    def scan_file(self, path: str) -> ScanResult:
        rules = self.rules
        if rules is None:
            return ScanResult(path, False, error="regole YARA non caricate")
        p = Path(path)
        ext = {"filename": p.name, "filepath": str(p.parent), "extension": p.suffix.lstrip(".").lower(),
               "filetype": "", "owner": ""}
        if self.backend == "yara_x":
            return self._scan_x(rules, path, ext)
        import yara
        try:
            matches = rules.match(path, externals=ext, timeout=self.timeout)
        except yara.Error as exc:
            return ScanResult(path, False, error=str(exc))
        if matches:
            return ScanResult(path, True, "YARA:" + matches[0].rule)
        return ScanResult(path, False)

    def _scan_x(self, rules, path: str, ext: dict) -> ScanResult:
        import yara_x
        scanner = getattr(self._local, "scanner", None)
        if scanner is None or getattr(self._local, "rules", None) is not rules:
            scanner = yara_x.Scanner(rules)
            scanner.set_timeout(self.timeout)
            self._local.scanner, self._local.rules = scanner, rules
        try:
            for k, v in ext.items():
                scanner.set_global(k, v)
            matches = scanner.scan_file(path).matching_rules
        except (yara_x.ScanError, yara_x.TimeoutError, OSError) as exc:
            return ScanResult(path, False, error=str(exc))
        if matches:
            return ScanResult(path, True, "YARA:" + matches[0].identifier)
        return ScanResult(path, False)
