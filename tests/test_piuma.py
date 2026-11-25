"""Test di PiumaAV. Usano un motore finto: non serve ClamAV installato.

Il test di integrazione con il vero clamscan parte solo se ClamAV e' presente.
"""

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from piuma.config import Config, load_config
from piuma.engine import BaseEngine, ScanResult, find_binary, _parse_clamd_reply, _parse_clamscan
from piuma.quarantine import Quarantine
from piuma.realtime import RealtimeProtection
from piuma.scanner import Scanner

# diviso in due pezzi: cosi' questo file non viene scambiato per un virus
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + rb"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class FakeEngine(BaseEngine):
    name = "fake"

    def scan_file(self, path):
        with open(path, "rb") as fh:
            data = fh.read()
        return ScanResult(path, EICAR in data, "Test.EICAR" if EICAR in data else None)


@pytest.fixture
def cfg(tmp_path):
    c = Config(data_dir=tmp_path / "data")
    c.notifications = False
    return c


def test_quarantine_roundtrip(tmp_path):
    f = tmp_path / "virus.exe"
    f.write_bytes(EICAR * 5000)              # > 64 KiB: verifica la cifratura a blocchi
    q = Quarantine(tmp_path / "q")
    entry = q.add(str(f), "Test")
    assert not f.exists()
    blob = (tmp_path / "q" / f"{entry.id}.bin").read_bytes()
    assert EICAR not in blob                 # in quarantena il file e' innocuo
    restored = q.restore(entry.id)
    assert Path(restored).read_bytes() == EICAR * 5000
    assert q.list() == []


def test_scan_paths_quarantines_and_excludes(tmp_path, cfg):
    root = tmp_path / "scan"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "bad.com").write_bytes(EICAR)
    (root / "good.txt").write_text("ciao")
    (root / "skipme").mkdir()
    (root / "skipme" / "bad2.com").write_bytes(EICAR)
    cfg.exclude = [str(root / "skipme")]
    s = Scanner(cfg, FakeEngine())
    rep = s.scan_paths([str(root)])
    assert rep.scanned == 2
    assert [t[0] for t in rep.threats] == [str(root / "sub" / "bad.com")]
    assert not (root / "sub" / "bad.com").exists()
    assert (root / "skipme" / "bad2.com").exists()
    assert len(s.quarantine.list()) == 1


def test_report_only_leaves_file(tmp_path, cfg):
    f = tmp_path / "x.com"
    f.write_bytes(EICAR)
    cfg.action = "report"
    rep = Scanner(cfg, FakeEngine()).scan_paths([str(f)])
    assert len(rep.threats) == 1 and f.exists()


def test_large_files_skipped(tmp_path, cfg):
    cfg.engine.max_file_size_mb = 1
    big = tmp_path / "big.bin"
    big.write_bytes(EICAR + b"\0" * (2 * 1024 * 1024))
    rep = Scanner(cfg, FakeEngine()).scan_paths([str(tmp_path)])
    assert rep.scanned == 0


def test_realtime_detects_new_file(tmp_path, cfg):
    watched = tmp_path / "watch"
    watched.mkdir()
    s = Scanner(cfg, FakeEngine())
    rt = RealtimeProtection(s, [str(watched)], settle_seconds=0.3)
    rt.start()
    try:
        time.sleep(0.5)
        (watched / "clean.txt").write_text("ok")
        (watched / "evil.exe").write_bytes(EICAR)
        deadline = time.time() + 10
        while time.time() < deadline and (watched / "evil.exe").exists():
            time.sleep(0.2)
    finally:
        rt.stop()
    assert not (watched / "evil.exe").exists()
    assert (watched / "clean.txt").exists()
    assert len(s.quarantine.list()) == 1


def test_parsers():
    assert _parse_clamd_reply("p", "stream: OK").infected is False
    r = _parse_clamd_reply("p", "stream: Win.Test.EICAR_HDB-1 FOUND")
    assert r.infected and r.signature == "Win.Test.EICAR_HDB-1"
    assert _parse_clamd_reply("p", "INSTREAM size limit exceeded. ERROR").error
    out = "C:\\Users\\a b\\x.exe: Win.Trojan.X FOUND\n/tmp/y: Eicar FOUND\n"
    assert _parse_clamscan(out) == {"C:\\Users\\a b\\x.exe": "Win.Trojan.X", "/tmp/y": "Eicar"}


def test_load_config(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[general]\naction = "report"\nexclude = ["~/vm"]\n'
                 '[update]\ninterval_hours = 0.1\n'
                 '[[scheduled_scan]]\nname = "settimanale"\npaths = ["/"]\ninterval_hours = 168\n')
    c = load_config(p)
    assert c.action == "report"
    assert c.update.interval_hours == 1.0          # minimo imposto
    assert c.exclude[0].startswith(os.path.expanduser("~"))
    assert c.scheduled_scans[0].interval_hours == 168


@pytest.mark.skipif(not find_binary("clamscan"), reason="ClamAV non installato")
def test_integration_clamscan(tmp_path, cfg):
    from piuma.engine import ClamscanEngine
    db = tmp_path / "db"
    db.mkdir()
    sample = tmp_path / "files" / "eicar.com"
    sample.parent.mkdir()
    sample.write_bytes(EICAR)
    (db / "test.hdb").write_text("44d88612fea8a8f36de82e1278abb02f:68:Test.EICAR\n")
    cfg.engine.database_dir = str(db)
    rep = Scanner(cfg, ClamscanEngine(cfg.engine)).scan_paths([str(sample.parent)])
    assert len(rep.threats) == 1 and "Test.EICAR" in rep.threats[0][1]


# ------------------------------------------------------------ multi-motore
class NameEngine(BaseEngine):
    """Rileva i file il cui nome contiene una parola chiave."""

    def __init__(self, word, sig):
        self.word, self.sig, self.calls = word, sig, 0
        self.name = sig

    def scan_file(self, path):
        self.calls += 1
        return ScanResult(path, self.word in os.path.basename(path), self.sig if self.word in path else None)


def test_composite_any_engine_detects(tmp_path, cfg):
    from piuma.engine import CompositeEngine
    for n in ("a_bad1.bin", "b_bad2.bin", "c_ok.bin"):
        (tmp_path / n).write_bytes(b"x")
    e1, e2 = NameEngine("bad1", "E1"), NameEngine("bad2", "E2")
    comp = CompositeEngine([e1, e2])
    res = {os.path.basename(r.path): r for r in comp.scan_files([str(tmp_path / n) for n in
                                                                 ("a_bad1.bin", "b_bad2.bin", "c_ok.bin")])}
    assert res["a_bad1.bin"].signature == "E1"
    assert res["b_bad2.bin"].signature == "E2"
    assert not res["c_ok.bin"].infected
    assert e2.calls == 2          # il secondo motore non rianalizza cio' che il primo ha gia' trovato


def test_composite_survives_broken_engine(tmp_path):
    from piuma.engine import CompositeEngine

    class Broken(BaseEngine):
        name = "rotto"

        def scan_file(self, path):
            raise RuntimeError("boom")
    f = tmp_path / "bad1"
    f.write_bytes(b"x")
    assert CompositeEngine([Broken(), NameEngine("bad1", "E1")]).scan_file(str(f)).infected


def test_yara_engine_and_report_only(tmp_path, cfg):
    pytest.importorskip("yara")
    from piuma.engines_yara import YaraEngine
    rules = tmp_path / "yara"
    rules.mkdir()
    (rules / "demo.yar").write_text('rule Demo_Ransom_Note { strings: $a = "I tuoi file sono stati cifrati" condition: $a }\n'
                                    'rule Usa_External { condition: extension == "zzz" }\n')
    (rules / "rotta.yar").write_text("rule rotta { condition: ")      # regola non valida: va scartata
    eng = YaraEngine(rules)
    assert eng.available()
    note = tmp_path / "LEGGIMI.txt"
    note.write_text("ATTENZIONE: I tuoi file sono stati cifrati! Paga 1 BTC")
    r = eng.scan_file(str(note))
    assert r.infected and r.signature == "YARA:Demo_Ransom_Note"
    ext = tmp_path / "x.zzz"
    ext.write_text("ciao")
    assert eng.scan_file(str(ext)).infected
    # le sole rilevazioni YARA vengono segnalate, non messe in quarantena
    rep = Scanner(cfg, eng).scan_paths([str(note)])
    assert rep.threats[0][2] == "solo segnalato" and note.exists()


def test_malwarebazaar_feed(tmp_path, cfg, monkeypatch):
    from piuma import feeds
    import hashlib, io as _io, zipfile as _zip
    sha = hashlib.sha256(EICAR).hexdigest()
    fake = [f"{i:064x}" for i in range(200)]
    body = ("# MalwareBazaar dump\n" + "\n".join([sha, *fake]) + "\n").encode()
    buf = _io.BytesIO()
    with _zip.ZipFile(buf, "w") as z:
        z.writestr("full_sha256.txt", body)
    monkeypatch.setattr(feeds, "_download", lambda url, key="", timeout=300: buf.getvalue())
    cfg.feeds.clamav_database_dir = str(tmp_path / "db")
    cfg.engine.engines = ["clamav"]
    cfg.feeds.abusech_auth_key = "test"
    cfg.feeds.yara_forge = False
    assert feeds.update_all(cfg)
    hsb = (tmp_path / "db" / feeds.HSB_NAME).read_text().splitlines()
    assert len(hsb) == 201 and f"{sha}:*:MalwareBazaar.{sha[:12]}:73" in hsb
    # risposta vuota/strana: le firme esistenti non vengono sovrascritte
    monkeypatch.setattr(feeds, "_download", lambda url, key="", timeout=300: b"<html>errore</html>")
    import os as _os, time as _time
    _os.utime(tmp_path / "db" / feeds.HSB_NAME, (0, 0))   # forza il dump completo
    assert not feeds.update_malwarebazaar(cfg)
    assert len((tmp_path / "db" / feeds.HSB_NAME).read_text().splitlines()) == 201


@pytest.mark.skipif(not find_binary("clamscan"), reason="ClamAV non installato")
def test_hsb_format_accepted_by_clamav(tmp_path, cfg):
    """Verifica con il vero ClamAV che il file .hsb generato funzioni."""
    from piuma import feeds
    from piuma.engine import ClamscanEngine
    import hashlib
    db = tmp_path / "db"
    db.mkdir()
    feeds.write_hsb({hashlib.sha256(EICAR).hexdigest(), "0" * 64}, db / feeds.HSB_NAME)
    sample = tmp_path / "f" / "sample.bin"
    sample.parent.mkdir()
    sample.write_bytes(EICAR)
    cfg.engine.database_dir = str(db)
    r = ClamscanEngine(cfg.engine).scan_file(str(sample))
    assert r.infected and "MalwareBazaar" in r.signature


def test_defender_helpers():
    from piuma.engines_defender import is_malware, parse_mpcmdrun
    assert is_malware(32768) and is_malware(0x4001) and not is_malware(1) and not is_malware(0)
    out = ("Scan starting...\nScan finished.\nScanning C:\\x found 1 threats.\n<===========================LIST OF DETECTED THREATS==========================>\n"
           "----------------------------- Threat information ------------------------------\n"
           "Threat                  : Virus:DOS/EICAR_Test_File\nResources               : 1 total\n    file                : C:\\x\\eicar.com\n")
    assert parse_mpcmdrun(out) == "Virus:DOS/EICAR_Test_File"


def test_create_engine_skips_unavailable(cfg, tmp_path):
    from piuma.engine import create_engine, EngineError
    cfg.engine.engines = ["defender"]          # su Linux non esiste
    with pytest.raises(EngineError):
        create_engine(cfg.engine, tmp_path)
