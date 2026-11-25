"""Prepara il pacchetto Windows di PiumaAV in modo riproducibile.

Usato dalla GitHub Action .github/workflows/release.yml (e utilizzabile a mano):

    python tools/build_release.py stage dist/pkg        # copia i file del pacchetto
    python tools/build_release.py zip dist/pkg dist/PiumaAV-0.5.2-Windows.zip

Lo zip e' deterministico: file in ordine alfabetico, data fissa, permessi fissi.
Lo stesso commit produce sempre lo stesso zip (stesso SHA-256), a parte le firme
Authenticode aggiunte da SignPath ai file .ps1.
"""

from __future__ import annotations

import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOP = "piuma-av"                       # cartella radice dentro lo zip
FIXED_DATE = (2020, 1, 1, 0, 0, 0)

FILES = [
    "LEGGIMI.txt", "INSTALLA.bat", "FIRMA.bat", "RIPARA.bat", "README.md", "LICENSE",
    "CODE_SIGNING_POLICY.md", "PRIVACY.md", "pyproject.toml", "config.example.toml",
    "tools/compare_av.py",
]
DIRS = {"piuma": "*.py", "install": "*"}


def version() -> str:
    text = (ROOT / "piuma" / "__init__.py").read_text(encoding="utf-8")
    v = re.search(r'__version__\s*=\s*"([^"]+)"', text).group(1)
    pv = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M).group(1)
    if v != pv:
        sys.exit(f"versione diversa: piuma/__init__.py={v} pyproject.toml={pv}")
    return v


def package_files() -> list[str]:
    out = [f for f in FILES if (ROOT / f).is_file()]
    for d, pattern in DIRS.items():
        out += [p.relative_to(ROOT).as_posix() for p in (ROOT / d).rglob(pattern)
                if p.is_file() and "__pycache__" not in p.parts]
    return sorted(set(out))


def stage(dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    for rel in package_files():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, target)
    print(f"{len(package_files())} file in {dest} (versione {version()})")


def make_zip(src: Path, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in src.rglob("*") if p.is_file())
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in files:
            info = zipfile.ZipInfo(f"{TOP}/{p.relative_to(src).as_posix()}", FIXED_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, p.read_bytes())
    print(f"creato {out} ({len(files)} file)")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "version":
        print(version())
    elif cmd == "stage" and len(sys.argv) == 3:
        stage(Path(sys.argv[2]))
    elif cmd == "zip" and len(sys.argv) == 4:
        make_zip(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        sys.exit(__doc__)
