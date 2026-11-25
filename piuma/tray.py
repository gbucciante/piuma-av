"""Icona nell'area di notifica (facoltativa: richiede `pystray` e `Pillow`)."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading

from .config import IS_MAC, IS_WINDOWS, Config
from .notify import notify

log = logging.getLogger(__name__)


def _open(path) -> None:
    if IS_WINDOWS:
        os.startfile(path)  # type: ignore[attr-defined]
    else:
        subprocess.Popen(["open" if IS_MAC else "xdg-open", str(path)])


def _icon_image(color=(46, 160, 90)):
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.polygon([(32, 4), (58, 14), (54, 40), (32, 60), (10, 40), (6, 14)], fill=color)   # scudo
    d.line([(20, 33), (29, 42), (45, 22)], fill="white", width=6)                       # spunta
    return img


def run_tray(cfg: Config) -> int:
    try:
        import pystray
    except ImportError:
        print("Per l'icona servono: pip install pystray Pillow", file=sys.stderr)
        return 2
    from .service import Service
    from .updater import update_signatures

    svc = Service(cfg)
    threading.Thread(target=svc.run, name="service", daemon=True).start()

    def bg(fn):
        return lambda icon, item: threading.Thread(target=fn, daemon=True).start()

    def quick_scan():
        notify("PiumaAV", "Scansione rapida avviata")
        rep = svc.scanner.scan_paths(cfg.quick_scan_paths, source="rapida")
        notify("PiumaAV", f"Scansione completata: {rep.scanned} file, {len(rep.threats)} minacce")

    def update_now():
        from .feeds import update_all
        ok = update_signatures(cfg.update, None)
        update_all(cfg)
        svc.engine.reload()
        notify("PiumaAV", "Firme aggiornate" if ok else "Aggiornamento non riuscito (vedi log)")

    def toggle_mode(icon, item):
        from .mode import set_mode
        new = "completa" if cfg.mode == "leggera" else "leggera"
        set_mode(cfg.data_dir, new)
        notify("PiumaAV", f"Modalita' {new}: riavvio della protezione...")
        svc.shutdown()
        icon.stop()
        # nuova istanza con la nuova modalita'
        subprocess.Popen([sys.executable, "-m", "piuma", "tray"],
                         creationflags=0x08000000 if IS_WINDOWS else 0)

    from . import pause as pz

    def pause_for(label, duration):
        def action(icon, item):
            def run():
                if not pz.confirm(f"Vuoi davvero disattivare la protezione {label}?\n"
                                  "Il PC restera' esposto finche' non si riattiva."):
                    return
                pz.pause(cfg.data_dir, duration)
                notify("PiumaAV", f"Protezione disattivata {label}")
                refresh(icon)
            threading.Thread(target=run, daemon=True).start()
        return action

    def resume_now(icon, item):
        pz.resume(cfg.data_dir)
        notify("PiumaAV", "Protezione riattivata")
        refresh(icon)

    def refresh(icon):
        paused = pz.is_paused(cfg.data_dir)
        icon.icon = _icon_image((150, 150, 150) if paused else (46, 160, 90))
        icon.title = "PiumaAV - " + pz.describe(pz.status(cfg.data_dir))
        icon.update_menu()

    def watch_pause(icon):
        icon.visible = True
        if cfg.notifications:
            notify("PiumaAV", "Protezione attiva. Se non vedi lo scudo, cercalo sotto la freccia ^ "
                              "vicino all'orologio (icone nascoste).")
        last = None
        while not svc.stop_event.wait(5):      # aggiorna icona allo scadere della pausa
            now = pz.is_paused(cfg.data_dir)
            if now != last:
                refresh(icon)
                last = now

    def is_paused_item(item):
        return pz.is_paused(cfg.data_dir)

    def quit_(icon, item):
        svc.shutdown()
        icon.stop()

    def firewall_items():
        from .netguard import NetGuard
        try:
            blocked = NetGuard(cfg, signature_check=lambda p: None).blocked()
        except Exception:  # noqa: BLE001
            blocked = []
        if not blocked:
            yield pystray.MenuItem("Nessun programma bloccato", None, enabled=False)
            return

        def allow(path):
            def _do(icon, item):
                NetGuard(cfg, signature_check=lambda p: None).allow(path)
                notify("PiumaAV", f"{os.path.basename(path)} ora puo' usare Internet")
            return _do
        for p in blocked[-15:]:
            yield pystray.MenuItem(f"Consenti {os.path.basename(p)}", allow(p))

    menu = pystray.Menu(
        pystray.MenuItem(lambda item: "Protezione " + pz.describe(pz.status(cfg.data_dir)), None, enabled=False),
        pystray.MenuItem("Disattiva protezione", pystray.Menu(
            pystray.MenuItem("Per 15 minuti", pause_for("per 15 minuti", 15 * 60)),
            pystray.MenuItem("Per 30 minuti", pause_for("per 30 minuti", 30 * 60)),
            pystray.MenuItem("Per 1 ora", pause_for("per 1 ora", 3600)),
            pystray.MenuItem("Fino al riavvio del PC", pause_for("fino al riavvio del PC", "reboot")),
        )),
        pystray.MenuItem("Riattiva ora", resume_now, visible=is_paused_item),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Scansione rapida", bg(quick_scan)),
        pystray.MenuItem("Aggiorna firme ora", bg(update_now)),
        pystray.MenuItem("Modalita' leggera (senza ClamAV, ~1 GB RAM in meno)", toggle_mode,
                         checked=lambda item: cfg.mode == "leggera"),
        pystray.MenuItem("Programmi bloccati da Internet", pystray.Menu(firewall_items),
                         visible=lambda item: IS_WINDOWS and cfg.protection.network_guard),
        pystray.MenuItem("Apri quarantena", lambda i, it: _open(cfg.quarantine_dir)),
        pystray.MenuItem("Apri log", lambda i, it: _open(cfg.log_dir / "piuma.log")),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Esci", quit_),
    )
    pystray.Icon("PiumaAV", _icon_image(), "PiumaAV - protetto", menu).run(setup=watch_pause)
    return 0
