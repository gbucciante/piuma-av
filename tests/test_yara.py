"""Regole YARA: una regola non supportata non deve far scartare l'intero file.

YARA-Forge distribuisce migliaia di regole in un solo file. Su Windows
yara-python viene compilato senza OpenSSL e non conosce `pe.number_of_signatures`:
prima di questa correzione bastava una di quelle regole per perdere tutto (0 file).
Qui lo stesso caso si riproduce con un campo del modulo "pe" che non esiste.
"""

import pytest

from piuma.engines_yara import YaraEngine, compile_rules

# piccolo file "alla YARA-Forge": regole valide mescolate a regole non supportate
FORGE_LIKE = '''import "pe"

private rule Base_Pe {
    condition: uint16(0) == 0x5a4d
}

rule Firma_Non_Supportata {
    meta:
        description = "usa un campo che questo motore non conosce"
    condition:
        Base_Pe and for any i in (0 .. pe.campo_che_non_esiste) : (true)
}

rule Nota_Riscatto {
    strings:
        $a = "I tuoi file sono stati cifrati"
    condition:
        $a
}

private rule Privata_Rotta {
    condition: pe.altro_campo_inesistente == 1
}

rule Dipende_Da_Privata_Rotta {
    condition: Privata_Rotta
}

rule Nome_File {
    condition: extension == "zzz"
}
'''


@pytest.mark.parametrize("which", ["yara", "yara_x"])
def test_regole_non_supportate_scartate_una_per_una(tmp_path, which):
    pytest.importorskip(which)
    rules = tmp_path / "yara"
    rules.mkdir()
    (rules / "yara-rules-core.yar").write_text(FORGE_LIKE, encoding="utf-8")
    compile_rules(rules, which)

    eng = YaraEngine(rules)
    eng.backend = which
    eng.reload()
    assert eng.available()
    note = tmp_path / "LEGGIMI.txt"
    note.write_text("ATTENZIONE: I tuoi file sono stati cifrati!")
    r = eng.scan_file(str(note))
    assert r.infected and r.signature == "YARA:Nota_Riscatto"
    ext = tmp_path / "x.zzz"
    ext.write_text("ciao")
    assert eng.scan_file(str(ext)).signature == "YARA:Nome_File"


@pytest.mark.parametrize("which", ["yara", "yara_x"])
def test_nessuna_regola_valida_non_sovrascrive(tmp_path, which):
    """Se non si salva nulla, l'aggiornamento fallisce e restano le regole vecchie."""
    pytest.importorskip(which)
    rules = tmp_path / "yara"
    rules.mkdir()
    (rules / "rotta.yar").write_text("questo non e' YARA {", encoding="utf-8")
    with pytest.raises(Exception):
        compile_rules(rules, which)
    assert not any(rules.glob("rules.yar[cx]"))
