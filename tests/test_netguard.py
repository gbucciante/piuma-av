"""Blocco Internet dei programmi sconosciuti: logica, senza toccare il firewall vero."""

import subprocess

from piuma.config import Config
from piuma.netguard import GROUP, NetGuard


class FakeRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, script):
        self.calls.append(script)
        return subprocess.CompletedProcess([], 0, "", "")


def make(tmp_path, monkeypatch, signed=False):
    home = tmp_path / "Utente"
    (home / "Downloads").mkdir(parents=True)
    monkeypatch.setenv("USERPROFILE", str(home))
    for v in ("TEMP", "TMP", "PUBLIC"):
        monkeypatch.delenv(v, raising=False)
    cfg = Config(data_dir=tmp_path / "data")
    cfg.notifications = False
    run = FakeRunner()
    return NetGuard(cfg, runner=run, signature_check=lambda p: signed), run, home


def test_blocks_new_unsigned_program_in_user_folder(tmp_path, monkeypatch):
    ng, run, home = make(tmp_path, monkeypatch)
    exe = home / "Downloads" / "strano's tool.exe"
    exe.write_bytes(b"MZ")
    assert ng.check(str(exe))
    assert "New-NetFirewallRule" in run.calls[0] and f"-Group '{GROUP}'" in run.calls[0]
    assert "'strano''s tool.exe'" in run.calls[0] or "strano''s tool.exe" in run.calls[0]   # apice protetto
    assert not ng.check(str(exe))            # una volta sola
    assert ng.blocked() and len(run.calls) == 1


def test_leaves_signed_and_system_programs_alone(tmp_path, monkeypatch):
    ng, run, home = make(tmp_path, monkeypatch, signed=True)
    exe = home / "Downloads" / "firmato.exe"
    exe.write_bytes(b"MZ")
    assert not ng.check(str(exe))
    ng2, run2, _ = make(tmp_path / "b", monkeypatch)
    outside = tmp_path / "Programmi" / "app.exe"
    outside.parent.mkdir()
    outside.write_bytes(b"MZ")
    assert not ng2.check(str(outside)) and not run.calls and not run2.calls


def test_allow_and_reset(tmp_path, monkeypatch):
    ng, run, home = make(tmp_path, monkeypatch)
    exe = home / "Downloads" / "gioco.exe"
    exe.write_bytes(b"MZ")
    ng.check(str(exe))
    # l'icona approva con un'altra istanza: il monitor non deve riattivare il blocco
    other = NetGuard(ng.cfg, runner=FakeRunner(), signature_check=lambda p: False)
    other.allow(str(exe))
    assert not ng.blocked() and not ng.should_block(str(exe))
    exe2 = home / "Downloads" / "altro.exe"
    exe2.write_bytes(b"MZ")
    assert ng.check(str(exe2))
    assert ng.reset() and not ng.blocked()
    assert any("Remove-NetFirewallRule" in c for c in run.calls)
