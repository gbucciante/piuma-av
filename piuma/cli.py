"""Interfaccia a riga di comando di PiumaAV."""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import logging.handlers
import sys
from pathlib import Path

from . import APP_NAME, __version__
from .config import Config, default_config_path, load_config


def setup_logging(cfg: Config, verbose: bool) -> None:
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
    fh = logging.handlers.RotatingFileHandler(cfg.log_dir / "piuma.log", maxBytes=2_000_000,
                                              backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    if sys.stderr is not None:          # assente con pythonw / eseguibile senza console
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        root.addHandler(sh)


def cmd_scan(cfg: Config, args) -> int:
    from .engine import create_engine
    from .scanner import Scanner

    if args.processes:
        from .procscan import scan_processes
        if args.report_only:
            cfg.action = "report"
            cfg.processes.kill_infected = False
        scanner = Scanner(cfg, create_engine(cfg.engine, cfg.data_dir, cfg.reputation))
        prep = scan_processes(cfg, scanner, memory=args.memory or None)
        print(f"Processi: {prep.processes}, file in uso analizzati: {prep.files}")
        for path, sig, pids, action in prep.threats:
            print(f"  [!] {path}\n      {sig} (PID {pids}) -> {action}")
        for m in prep.memory:
            print(f"  [memoria] {m}")
        print("Nessuna minaccia nei processi." if not (prep.threats or prep.memory) else "")
        return 1 if prep.threats or prep.memory else 0
    paths = args.paths or (cfg.quick_scan_paths if args.quick else None)
    if not paths:
        print("Indica almeno una cartella/disco da scansionare, oppure usa --quick.", file=sys.stderr)
        return 2
    if args.report_only:
        cfg.action = "report"
    scanner = Scanner(cfg, create_engine(cfg.engine, cfg.data_dir, cfg.reputation))
    count = 0
    clr = "\r\033[K" if sys.stdout.isatty() else ""

    def progress(res):
        nonlocal count
        count += 1
        if res.infected:
            print(f"{clr}[!] {res.path}: {res.signature}")
        elif count % 50 == 0 and sys.stdout.isatty():
            print(f"{clr}{count} file analizzati... {res.path[-70:]}", end="", flush=True)

    report = scanner.scan_paths(paths, progress)
    print(f"{clr}\n=== Riepilogo ===\nFile analizzati: {report.scanned}\n"
          f"Minacce: {len(report.threats)}\nErrori/illeggibili: {report.errors}\n"
          f"Durata: {report.duration:.1f}s")
    for path, sig, action in report.threats:
        print(f"  - {path}\n    {sig} -> {action}")
    return 1 if report.threats else 0


def cmd_run(cfg: Config, args) -> int:
    from .service import Service
    Service(cfg).run()
    return 0


def cmd_update(cfg: Config, args) -> int:
    from .engine import ClamdEngine
    from .feeds import update_all
    from .updater import update_signatures
    clamd = ClamdEngine(cfg.engine)
    from . import blocklist
    ok = update_signatures(cfg.update, None)
    update_all(cfg)
    if cfg.protection.domain_blocking:
        blocklist.update(cfg)
    if clamd.ping():
        clamd.reload()
    return 0 if ok else 1


def cmd_quarantine(cfg: Config, args) -> int:
    from .quarantine import Quarantine
    q = Quarantine(cfg.quarantine_dir)
    if args.qaction == "list":
        items = q.list()
        if not items:
            print("La quarantena e' vuota.")
        for e in items:
            when = dt.datetime.fromtimestamp(e.quarantined_at).strftime("%Y-%m-%d %H:%M")
            print(f"{e.id}  {when}  {e.signature}\n    {e.original_path}")
    elif args.qaction == "restore":
        print("Ripristinato in:", q.restore(args.id, args.to))
    elif args.qaction == "delete":
        q.delete(args.id)
        print("Eliminato definitivamente.")
    return 0


def cmd_status(cfg: Config, args) -> int:
    import json
    from .engine import ClamdEngine, find_binary
    from .quarantine import Quarantine
    clamd = ClamdEngine(cfg.engine)
    print(f"{APP_NAME} {__version__}")
    print("Configurazione :", args.config or default_config_path())
    print("Cartella dati  :", cfg.data_dir)
    print("clamd          :", clamd.version() if clamd.ping() else "non attivo")
    print("clamscan       :", find_binary("clamscan", cfg.engine.clamscan_path) or "NON TROVATO")
    print("freshclam      :", find_binary("freshclam", cfg.update.freshclam_path) or "NON TROVATO")
    from . import pause
    print("Protezione     :", pause.describe(pause.status(cfg.data_dir)))
    print("Modalita'      :", cfg.mode)
    print("Motori attivi  :", ", ".join(cfg.engine.engines))
    print("Tempo reale    :", ", ".join(cfg.realtime.paths) if cfg.realtime.enabled else "disattivato")
    try:
        state = json.loads(cfg.state_file.read_text(encoding="utf-8"))
        last = state.get("update")
        print("Ultimo aggiornamento:", dt.datetime.fromtimestamp(last).strftime("%Y-%m-%d %H:%M") if last else "mai")
    except (OSError, ValueError):
        print("Ultimo aggiornamento: mai (servizio non ancora avviato)")
    print("In quarantena  :", len(Quarantine(cfg.quarantine_dir).list()))
    return 0


def cmd_watchdog(cfg: Config, args) -> int:
    from .selfprotect import watchdog
    return watchdog(cfg)


def cmd_integrity(cfg: Config, args) -> int:
    from .selfprotect import Integrity
    integ = Integrity(cfg)
    if args.record:
        print(f"Registrati {integ.record()} file come integri.")
        return 0
    problems = integ.verify()
    if not integ.manifest.exists():
        print("Nessun elenco d'integrita': eseguire 'piuma integrity --record'.")
        return 2
    for p in problems:
        print("  !", p)
    print("Tutto integro." if not problems else f"{len(problems)} problemi trovati.")
    return 1 if problems else 0


def cmd_autostart(cfg: Config, args) -> int:
    from .autostart import AutostartMonitor, collect
    mon = AutostartMonitor(cfg)
    if args.aaction == "list":
        for k, v in sorted(collect().items()):
            print(f"{k}\n    {v}")
    elif args.aaction == "accept":
        print(f"Fotografia aggiornata: {mon.accept()} voci considerate legittime.")
    else:
        changes = mon.check()
        for kind, k, v in changes:
            print(f"{kind:10} {k}\n           {v}")
        print("Nessuna modifica." if not changes else f"{len(changes)} modifiche (ora accettate).")
    return 0


def cmd_blocklist(cfg: Config, args) -> int:
    from . import blocklist
    if args.baction == "remove":
        blocklist.remove(cfg)
        print("Sezione PiumaAV rimossa dal file hosts.")
        return 0
    cfg.protection.domain_blocking = True
    return 0 if blocklist.update(cfg) else 1


def cmd_firewall(cfg: Config, args) -> int:
    from .netguard import NetGuard
    ng = NetGuard(cfg)
    if args.faction == "allow":
        if not args.path:
            print("Indica il percorso del programma da consentire.", file=sys.stderr)
            return 2
        ng.allow(args.path)
        print(f"Consentito: {args.path}")
    elif args.faction == "reset":
        ok = ng.reset()
        print("Tolte tutte le regole di blocco di PiumaAV." if ok else "Errore nel togliere le regole (serve l'amministratore).")
        return 0 if ok else 1
    else:
        items = ng.blocked()
        print("Programmi bloccati da Internet:" if items else "Nessun programma bloccato.")
        for p in items:
            print(f"  {p}")
    return 0


def cmd_mode(cfg: Config, args) -> int:
    from .mode import set_mode
    if not args.mode:
        print(f"Modalita' attuale: {cfg.mode} (motori: {', '.join(cfg.engine.engines)})")
        return 0
    if args.mode == cfg.mode:
        print(f"Gia' in modalita' {cfg.mode}.")
        return 0
    ok = set_mode(cfg.data_dir, args.mode)
    print(f"Modalita' {args.mode} impostata." + ("" if ok else " Attenzione: servizio clamd non modificato (serve un terminale da amministratore)."))
    if args.mode == "leggera":
        print("Scarico l'archivio hash per il motore leggero...")
        from .feeds import update_malwarebazaar
        update_malwarebazaar(load_config(args.config))
    from .selfprotect import restart_service
    print("Riavvio la protezione..." if restart_service() else "Riavvia PiumaAV per applicare la modifica.")
    return 0


def cmd_pause(cfg: Config, args) -> int:
    from . import pause
    try:
        dur = pause.parse_duration(args.duration)
    except ValueError as exc:
        print(exc)
        return 2
    try:
        pause.pause(cfg.data_dir, dur)
    except PermissionError:
        print("Servono i privilegi di amministratore per sospendere la protezione.")
        return 3
    print("Protezione", pause.describe(pause.status(cfg.data_dir)))
    return 0


def cmd_resume(cfg: Config, args) -> int:
    from . import pause
    pause.resume(cfg.data_dir)
    print("Protezione riattivata.")
    return 0


def cmd_tray(cfg: Config, args) -> int:
    from .tray import run_tray
    return run_tray(cfg)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="piuma", description=f"{APP_NAME} - antivirus leggero basato su ClamAV")
    p.add_argument("--config", type=Path, help="file di configurazione TOML")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scansiona cartelle, file o interi dischi")
    s.add_argument("paths", nargs="*", help=r"es. C:\  D:\Download  /home/utente")
    s.add_argument("--quick", action="store_true", help="scansione rapida delle cartelle a rischio")
    s.add_argument("--report-only", action="store_true", help="segnala soltanto, non spostare/eliminare")
    s.add_argument("--processes", action="store_true", help="controlla i processi in esecuzione e le librerie caricate")
    s.add_argument("--memory", action="store_true", help="con --processes: analizza anche la memoria (Windows)")
    s.set_defaults(func=cmd_scan)

    sub.add_parser("run", help="avvia il servizio (tempo reale + aggiornamenti + pianificazioni)").set_defaults(func=cmd_run)
    sub.add_parser("tray", help="avvia il servizio con icona nell'area di notifica").set_defaults(func=cmd_tray)
    sub.add_parser("update", help="aggiorna subito le firme").set_defaults(func=cmd_update)
    sub.add_parser("status", help="mostra lo stato").set_defaults(func=cmd_status)

    md = sub.add_parser("mode", help="modalita' completa (con ClamAV) o leggera (senza, ~1 GB di RAM in meno)")
    md.add_argument("mode", nargs="?", choices=["completa", "leggera"])
    md.set_defaults(func=cmd_mode)
    pa = sub.add_parser("pause", help="sospende la protezione: 15m, 30m, 1h o reboot (fino al riavvio)")
    pa.add_argument("duration")
    pa.set_defaults(func=cmd_pause)
    sub.add_parser("resume", help="riattiva subito la protezione").set_defaults(func=cmd_resume)
    sub.add_parser("watchdog", help="riavvia la protezione se si e' fermata (uso interno)").set_defaults(func=cmd_watchdog)
    ig = sub.add_parser("integrity", help="controlla che PiumaAV e le firme non siano stati manomessi")
    ig.add_argument("--record", action="store_true", help="registra lo stato attuale come integro")
    ig.set_defaults(func=cmd_integrity)
    au = sub.add_parser("autostart", help="programmi ad avvio automatico")
    au.add_argument("aaction", choices=["check", "list", "accept"], nargs="?", default="check")
    au.set_defaults(func=cmd_autostart)
    bl = sub.add_parser("blocklist", help="blocco dei siti malevoli (file hosts)")
    bl.add_argument("baction", choices=["update", "remove"], nargs="?", default="update")
    bl.set_defaults(func=cmd_blocklist)

    fw = sub.add_parser("firewall", help="programmi sconosciuti bloccati da Internet (Windows)")
    fw.add_argument("faction", choices=["list", "allow", "reset"], nargs="?", default="list")
    fw.add_argument("path", nargs="?")
    fw.set_defaults(func=cmd_firewall)

    q = sub.add_parser("quarantine", help="gestisce la quarantena")
    qs = q.add_subparsers(dest="qaction", required=True)
    qs.add_parser("list")
    r = qs.add_parser("restore")
    r.add_argument("id")
    r.add_argument("--to", help="percorso alternativo di ripristino")
    d = qs.add_parser("delete")
    d.add_argument("id")
    q.set_defaults(func=cmd_quarantine)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config(args.config)
    setup_logging(cfg, args.verbose)
    try:
        return args.func(cfg, args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # messaggio leggibile invece di uno stack trace
        logging.getLogger(__name__).error("%s", exc, exc_info=args.verbose)
        return 3
