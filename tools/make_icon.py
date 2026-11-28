"""Crea l'icona dell'installer (lo scudo verde dell'icona di PiumaAV) in formato .ico.

    python tools/make_icon.py dist/piuma.ico      (serve Pillow)
"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw

GREEN = (46, 160, 90)


def shield(size: int = 256) -> Image.Image:
    s = size / 64            # stesse coordinate di piuma/tray.py, scalate
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.polygon([(x * s, y * s) for x, y in [(32, 4), (58, 14), (54, 40), (32, 60), (10, 40), (6, 14)]], fill=GREEN)
    d.line([(20 * s, 33 * s), (29 * s, 42 * s), (45 * s, 22 * s)], fill="white", width=round(6 * s), joint="curve")
    return img


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "dist/piuma.ico")
    out.parent.mkdir(parents=True, exist_ok=True)
    shield().save(out, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print(f"creata {out}")
