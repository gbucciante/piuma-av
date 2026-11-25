"""Test delle protezioni aggiuntive (0.3): nessun accesso a rete o a file di sistema."""

import json
import os
import time
from pathlib import Path

import pytest

from piuma.config import Config


@pytest.fixture
def cfg(tmp_path):
    c = Config(data_dir=tmp_path / "data")
    c.data_dir.mkdir()
    c.notifications = False
    c.feeds.clamav_database_dir = str(tmp_path / "db")
    return c


# ---------------------------------------------------------------- integrita'
def test_integrity_detects_tampering(cfg, tmp_path, monkeypatch):
    from piuma import selfprotect
    fake = tmp_path / "pkg"
    fake.mkdir()
    (fake / "a.py").write_text("print('ok')")
    (fake / "b.py").write_text("x = 1")
    monkeypatch.setattr(selfprotect, "PACKAGE_DIR", fake)
    integ = selfprotect.Integrity(cfg)
    assert integ.record() == 2
    assert integ.verify() == []
    (fake / "a.py").write_text("import os; os.system('malware')")
    (fake / "b.py").unlink()
    problems = integ.verify()
    assert any("modificato" in p for p in problems) and any("mancante" in p for p in problems)


def test_integrity_manifest_forgery_detected(cfg, tmp_path, monkeypatch):
    from piuma import selfprotect
    fake = tmp_path / "pkg"
    fake.mkdir()
    (fake / "a.py").write_text("ok")
    monkeypatch.setattr(selfprotect, "PACKAGE_DIR", fake)
    integ = selfprotect.Integrity(cfg)
    integ.record()
    # il malware cambia il file E l'elenco degli hash, ma non conosce la chiave HMAC
    (fake / "a.py").write_text("cattivo")
    data = json.loads(integ.manifest.read_text())
    data["files"][str(fake / "a.py")] = selfprotect._sha256(fake / "a.py")
    integ.manifest.write_text(json.dumps(data))
    assert "manomesso" in integ.verify()[0]


def test_feed_update_does_not_bless_program_files(cfg, tmp_path, monkeypatch):
    from piuma import selfprotect
    fake = tmp_path / "pkg"
    fake.mkdir()
    (fake / "a.py").write_text("ok")
    monkeypatch.setattr(selfprotect, "PACKAGE_DIR", fake)
    integ = selfprotect.Integrity(cfg)
    integ.record()
    (fake / "a.py").write_text("manomesso")
    db = Path(cfg.feeds.clamav_database_dir)
    db.mkdir()
    (db / "piuma_malwarebazaar.hsb").write_text("x")
    integ.update_entries([db / "piuma_malwarebazaar.hsb"])
    assert any("a.py" in p for p in integ.verify())


def test_watchdog_restarts_when_heartbeat_stale(cfg, monkeypatch):
    from piuma import selfprotect
    calls = []
    monkeypatch.setattr(selfprotect, "restart_service", lambda: calls.append(1) or True)
    selfprotect.write_heartbeat(cfg)
    assert selfprotect.watchdog(cfg) == 0 and not calls
    cfg.heartbeat_file.write_text(str(time.time() - 3600))
    assert selfprotect.watchdog(cfg) == 0 and calls == [1]


# ---------------------------------------------------------------- VirusTotal
def test_virustotal_hash_only_threshold_cache_and_limit(tmp_path):
    from piuma.config import ReputationConfig
    from piuma.reputation import VirusTotalEngine, sha256_file
    seen = []

    def fake_fetch(digest):
        seen.append(digest)
        return {"bad.exe": {"malicious": 12, "undetected": 58},
                "meh.exe": {"malicious": 1, "undetected": 69}}.get(names[digest])

    rc = ReputationConfig(enabled=True, virustotal_api_key="k", requests_per_minute=3)
    files = {}
    for n, body in (("bad.exe", b"MZbad"), ("meh.exe", b"MZmeh"), ("new.exe", b"MZnew"),
                    ("doc.txt", b"testo"), ("x.exe", b"MZx")):
        p = tmp_path / n
        p.write_bytes(body)
        files[n] = str(p)
    names = {sha256_file(p): n for n, p in files.items()}
    vt = VirusTotalEngine(rc, tmp_path / "cache.json", fetch=fake_fetch)
    r = vt.scan_file(files["bad.exe"])
    assert r.infected and r.signature == "VirusTotal:12/70"
    assert not vt.scan_file(files["meh.exe"]).infected          # 1 motore < soglia 3
    assert not vt.scan_file(files["new.exe"]).infected          # sconosciuto
    assert not vt.scan_file(files["doc.txt"]).infected          # tipo non a rischio: nessuna richiesta
    assert len(seen) == 3
    assert not vt.scan_file(files["x.exe"]).infected            # limite 3/minuto: saltato
    assert len(seen) == 3
    assert vt.scan_file(files["bad.exe"]).infected               # dalla cache, nessuna richiesta
    assert len(seen) == 3
    cache = json.loads((tmp_path / "cache.json").read_text())
    assert set(cache) <= set(names)                              # solo hash, nessun nome/percorso


# ---------------------------------------------------------------- avvio automatico
def test_autostart_detects_new_entry_and_scans_it(cfg, tmp_path):
    from piuma.autostart import AutostartMonitor, target_path
    evil = tmp_path / "evil.exe"
    evil.write_bytes(b"MZ")
    state = {"reg:HKCU\\Run\\OneDrive": "C:\\OneDrive.exe /background"}

    class FakeScanner:
        scanned = []

        def scan_file(self, path, source=""):
            self.scanned.append(path)
            from piuma.engine import ScanResult
            return ScanResult(path, True, "Trojan.Test")

    sc = FakeScanner()
    mon = AutostartMonitor(cfg, sc, collector=lambda: dict(state))
    assert mon.check() == []                       # primo giro: fotografia
    state["reg:HKCU\\Run\\Updater"] = f'"{evil}" --silent'
    changes = mon.check()
    assert changes == [("NUOVO", "reg:HKCU\\Run\\Updater", f'"{evil}" --silent')]
    assert sc.scanned == [str(evil)]
    assert mon.check() == []                       # gia' accettato
    del state["reg:HKCU\\Run\\OneDrive"]
    assert mon.check()[0][0] == "RIMOSSO"
    assert target_path(f"{evil} #abc123") == str(evil)


def test_autostart_collect_runs_on_this_os():
    from piuma.autostart import collect
    assert isinstance(collect(), dict)


# ---------------------------------------------------------------- ransomware
def test_ransomware_canary_triggers(cfg, tmp_path):
    from piuma.ransomware import RansomwareGuard
    alerts = []
    g = RansomwareGuard(cfg, [str(tmp_path)], alert=lambda r, p: alerts.append(r))
    g.plant_canaries()
    assert len(g.canaries) == 2
    canary = next(iter(g.canaries))
    assert os.path.exists(canary)
    g.on_event(canary, "modified")
    assert alerts and "esca" in alerts[0]


def test_ransomware_burst_of_encrypted_files(cfg, tmp_path):
    from piuma.ransomware import RansomwareGuard
    alerts = []
    cfg.protection.ransomware_burst_files = 20
    g = RansomwareGuard(cfg, [str(tmp_path)], alert=lambda r, p: alerts.append(r))
    for i in range(25):
        p = tmp_path / f"foto_{i}.dat"
        p.write_bytes(os.urandom(8192))                # contenuto "cifrato"
        g.on_event(str(p), "modified")
    assert alerts and "cifrati" in alerts[0]


def test_ransomware_ignores_normal_bulk_copy(cfg, tmp_path):
    from piuma.ransomware import RansomwareGuard
    alerts = []
    cfg.protection.ransomware_burst_files = 20
    g = RansomwareGuard(cfg, [str(tmp_path)], alert=lambda r, p: alerts.append(r))
    for i in range(60):
        p = tmp_path / f"doc_{i}.txt"
        p.write_text("testo normale " * 500)
        g.on_event(str(p), "created")
        j = tmp_path / f"img_{i}.jpg"
        j.write_bytes(os.urandom(4096))                 # jpg: alta entropia normale
        g.on_event(str(j), "created")
    assert alerts == []


def test_ransomware_extensions_and_notes(cfg, tmp_path):
    from piuma.ransomware import RansomwareGuard
    alerts = []
    g = RansomwareGuard(cfg, [str(tmp_path)], alert=lambda r, p: alerts.append(r))
    g.on_event(str(tmp_path / "HOW_TO_DECRYPT_FILES.txt"), "created")
    g.on_event(str(tmp_path / "a.docx"), "moved", str(tmp_path / "a.docx.locked"))
    g.on_event(str(tmp_path / "b.xlsx"), "moved", str(tmp_path / "b.xlsx.locked"))
    assert len(alerts) == 1


# ---------------------------------------------------------------- blocco siti
def test_blocklist_hosts_section(cfg, tmp_path):
    from piuma import blocklist
    hosts = tmp_path / "hosts"
    original = "127.0.0.1 localhost\n192.168.1.10 nas.casa\n"
    hosts.write_text(original)
    cfg.protection.hosts_file = str(hosts)
    feed = ("# URLhaus\n127.0.0.1\tmalware-dl.example\n127.0.0.1 evil.test\n"
            "127.0.0.1 1.2.3.4\n127.0.0.1 www.microsoft.com\n")
    assert blocklist.update(cfg, fetch=lambda url: feed)
    text = hosts.read_text()
    assert "0.0.0.0 malware-dl.example" in text and "0.0.0.0 evil.test" in text
    assert "1.2.3.4" not in text and "microsoft" not in text        # IP e domini protetti esclusi
    assert text.startswith(original)                                 # il resto non si tocca
    assert (cfg.data_dir / "hosts.backup").read_text() == original
    # aggiornamento: la sezione viene sostituita, non duplicata
    assert blocklist.update(cfg, fetch=lambda url: "127.0.0.1 nuovo.test\n")
    text = hosts.read_text()
    assert text.count(blocklist.BEGIN) == 1 and "evil.test" not in text and "nuovo.test" in text
    # lista irraggiungibile: nulla cambia
    def boom(url):
        raise OSError("rete giu'")
    assert not blocklist.update(cfg, fetch=boom)
    assert "nuovo.test" in hosts.read_text()
    blocklist.remove(cfg)
    assert hosts.read_text() == original


# ---------------------------------------------------------------- aggiornamenti verificati
def test_feeds_refuse_http_and_wrong_digest():
    from piuma import feeds
    import hashlib
    with pytest.raises(feeds.VerificationError):
        feeds._download("http://example.com/x.ndb")
    data = b"contenuto"
    feeds.verify_digest(data, hashlib.sha256(data).hexdigest(), "test")
    with pytest.raises(feeds.VerificationError):
        feeds.verify_digest(data, "0" * 64, "test")
    api = json.dumps({"assets": [{"name": "yara-forge-rules-core.zip", "digest": "sha256:" + "ab" * 32}]}).encode()
    url = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
    assert feeds.github_asset_digest(url, fetch=lambda u: api) == "ab" * 32
    assert feeds.github_asset_digest("https://example.com/x.zip", fetch=lambda u: api) is None
