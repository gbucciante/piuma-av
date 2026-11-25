"""Caricamento della configurazione (file TOML) con valori predefiniti per ogni sistema."""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

IS_WINDOWS = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"


def default_data_dir() -> Path:
    """Cartella dati dell'applicazione (quarantena, log, stato)."""
    if IS_WINDOWS:
        base = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        return Path(base) / "PiumaAV"
    if IS_MAC:
        return Path("/Library/Application Support/PiumaAV") if os.geteuid() == 0 \
            else Path.home() / "Library" / "Application Support" / "PiumaAV"
    return Path("/var/lib/piuma-av") if os.geteuid() == 0 \
        else Path.home() / ".local" / "share" / "piuma-av"


def default_config_path() -> Path:
    env = os.environ.get("PIUMA_CONFIG")
    if env:
        return Path(env)
    if IS_WINDOWS:
        return default_data_dir() / "config.toml"
    if IS_MAC:
        return default_data_dir() / "config.toml"
    return Path("/etc/piuma-av/config.toml") if os.geteuid() == 0 \
        else Path.home() / ".config" / "piuma-av" / "config.toml"


_FOLDERID_DOWNLOADS = "{374DE290-123F-4565-9164-39C4925E467B}"
_FOLDERID_DESKTOP = "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
_FOLDERID_DOCUMENTS = "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"


def _known_folder(guid: str) -> Path | None:
    """Percorso reale di una cartella speciale di Windows (SHGetKnownFolderPath)."""
    if not IS_WINDOWS:
        return None
    try:
        import ctypes
        import uuid
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                        ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

        u = uuid.UUID(guid)
        g = GUID(u.time_low, u.time_mid, u.time_hi_version,
                 (ctypes.c_ubyte * 8).from_buffer_copy(u.bytes[8:]))
        out = ctypes.c_wchar_p()
        shell32 = ctypes.windll.shell32
        if shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(out)) != 0:
            return None
        try:
            return Path(out.value)
        finally:
            ctypes.windll.ole32.CoTaskMemFree(out)
    except Exception:  # noqa: BLE001 - in caso di problemi si usa il percorso classico
        return None


def default_watch_paths() -> list[str]:
    """Cartelle monitorate in tempo reale per impostazione predefinita.

    Si sorvegliano i punti d'ingresso piu' comuni del malware (download, desktop,
    documenti, cartelle temporanee, avvio automatico) invece dell'intero disco:
    e' cio' che mantiene il programma leggero.
    """
    home = Path.home()
    paths = [home / "Downloads", home / "Desktop", home / "Documents"]
    if IS_WINDOWS:
        # Download/Desktop/Documenti possono essere spostati (altro disco, OneDrive):
        # si chiede a Windows dove sono davvero.
        paths = [_known_folder(guid) or fallback for guid, fallback in
                 ((_FOLDERID_DOWNLOADS, home / "Downloads"), (_FOLDERID_DESKTOP, home / "Desktop"),
                  (_FOLDERID_DOCUMENTS, home / "Documents"))]
        appdata = os.environ.get("APPDATA")
        temp = os.environ.get("TEMP")
        if appdata:
            paths.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
        if temp:
            paths.append(Path(temp))
    elif IS_MAC:
        paths.append(home / "Library" / "LaunchAgents")
    else:
        paths += [Path("/tmp"), home / ".config" / "autostart"]
    return [str(p) for p in paths]


def default_quick_scan_paths() -> list[str]:
    return default_watch_paths()


def default_engines() -> list[str]:
    return ["defender", "clamav", "yara", "heuristic"] if IS_WINDOWS else ["clamav", "yara", "heuristic"]


def default_clamav_db() -> str:
    if IS_WINDOWS:
        return str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClamAV" / "database")
    for p in ("/var/lib/clamav", "/opt/homebrew/var/lib/clamav", "/usr/local/var/lib/clamav"):
        if os.path.isdir(p):
            return p
    return "/var/lib/clamav"


@dataclass
class EngineConfig:
    # Motori usati, in ordine. Un file e' infetto se almeno uno lo rileva.
    engines: list[str] = field(default_factory=default_engines)
    # Le sole rilevazioni YARA (regole euristiche) vengono segnalate ma non
    # messe in quarantena, salvo che lo si chieda: riduce i falsi positivi.
    yara_quarantine: bool = False
    # Motore euristico PiumaHeur: punteggio 0-100. Da alert_score si avvisa,
    # da quarantine_score si mette in quarantena.
    heuristic_alert_score: int = 60
    heuristic_quarantine_score: int = 90
    yara_rules_dir: str = ""         # vuoto = <cartella dati>/yara
    # "auto": usa clamd se raggiungibile, altrimenti clamscan.
    mode: str = "auto"
    clamd_socket: str = "" if IS_WINDOWS else "/var/run/clamav/clamd.ctl"
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    clamscan_path: str = ""          # vuoto = cercalo nel PATH / cartelle note
    database_dir: str = ""           # vuoto = cartella firme predefinita di ClamAV
    clamdscan_timeout: float = 120.0
    max_file_size_mb: int = 100


@dataclass
class RealtimeConfig:
    enabled: bool = True
    paths: list[str] = field(default_factory=default_watch_paths)
    settle_seconds: float = 1.5      # attende che il file smetta di cambiare
    workers: int = 1


@dataclass
class UpdateConfig:
    enabled: bool = True
    interval_hours: float = 4.0      # ClamAV chiede di non scendere sotto 1 ora
    freshclam_path: str = ""
    freshclam_config: str = ""


@dataclass
class FeedsConfig:
    """Firme aggiuntive gratuite scaricate automaticamente."""
    enabled: bool = True
    clamav_database_dir: str = field(default_factory=default_clamav_db)
    malwarebazaar: bool = True       # hash SHA-256 di malware recenti (abuse.ch)
    abusech_auth_key: str = ""       # chiave gratuita abuse.ch, se richiesta
    yara_forge: bool = True          # regole YARA-Forge "core" (pochi falsi positivi)
    yara_forge_url: str = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
    # Feed ClamAV extra (.ndb/.hdb/.hsb/.ldb...): [{url = "...", file = "nome.ndb"}]
    extra: list[dict] = field(default_factory=list)


@dataclass
class ReputationConfig:
    """Controllo reputazione su VirusTotal (facoltativo). Invia SOLO l'hash SHA-256."""
    enabled: bool = False
    virustotal_api_key: str = ""
    min_detections: int = 3          # quanti antivirus devono segnalarlo
    requests_per_minute: int = 4     # limite del piano gratuito
    daily_limit: int = 500
    extensions: list[str] = field(default_factory=lambda: [
        ".exe", ".dll", ".scr", ".com", ".msi", ".msix", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
        ".wsf", ".hta", ".jar", ".lnk", ".iso", ".img", ".docm", ".xlsm", ".pptm", ".sh", ".app",
        ".dmg", ".pkg", ".elf", ".so", ".dylib", ".apk"])


@dataclass
class ProtectionConfig:
    autostart_monitor: bool = True
    autostart_interval_minutes: int = 5
    ransomware: bool = True
    ransomware_burst_files: int = 40      # file modificati...
    ransomware_burst_seconds: int = 15    # ...in questo intervallo => allarme
    canary_files: bool = True             # file esca nelle cartelle sorvegliate
    integrity_check: bool = True          # controlla che i file di PiumaAV non siano manomessi
    domain_blocking: bool = True          # blocca i siti malevoli tramite il file hosts
    blocklists: list[str] = field(default_factory=lambda: ["https://urlhaus.abuse.ch/downloads/hostfile/"])
    hosts_file: str = ""                  # vuoto = file hosts di sistema
    # Windows: i programmi nuovi senza firma nelle cartelle dell'utente non possono
    # collegarsi a Internet finche' non li approvi (vedi netguard.py)
    network_guard: bool = True


@dataclass
class BehaviorConfig:
    enabled: bool = True
    kill_critical: bool = True        # termina subito i processi con regole "critiche"
    scan_new_processes: bool = True   # analizza l'eseguibile di ogni nuovo processo


@dataclass
class UsbConfig:
    enabled: bool = True
    scan_already_connected: bool = False   # all'avvio, analizza anche i dischi gia' collegati


@dataclass
class ProcessesConfig:
    enabled: bool = True
    interval_hours: float = 12        # controllo periodico dei processi in esecuzione
    include_modules: bool = True      # anche DLL / librerie caricate
    kill_infected: bool = True
    memory_scan: bool = False         # Windows: anche la memoria (clamscan --memory + Defender rapida)


@dataclass
class ScheduledScan:
    name: str
    paths: list[str]
    interval_hours: float


@dataclass
class Config:
    data_dir: Path = field(default_factory=default_data_dir)
    action: str = "quarantine"       # "quarantine" | "report" | "delete"
    mode: str = "completa"           # "completa" | "leggera" (vedi mode.py)
    notifications: bool = True
    exclude: list[str] = field(default_factory=list)
    exclude_extensions: list[str] = field(default_factory=lambda: [".tmp.piuma", ".crdownload", ".part", ".partial", ".download"])
    quick_scan_paths: list[str] = field(default_factory=default_quick_scan_paths)
    engine: EngineConfig = field(default_factory=EngineConfig)
    realtime: RealtimeConfig = field(default_factory=RealtimeConfig)
    update: UpdateConfig = field(default_factory=UpdateConfig)
    feeds: FeedsConfig = field(default_factory=FeedsConfig)
    reputation: ReputationConfig = field(default_factory=ReputationConfig)
    protection: ProtectionConfig = field(default_factory=ProtectionConfig)
    behavior: BehaviorConfig = field(default_factory=BehaviorConfig)
    usb: UsbConfig = field(default_factory=UsbConfig)
    processes: ProcessesConfig = field(default_factory=ProcessesConfig)
    scheduled_scans: list[ScheduledScan] = field(default_factory=list)

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def heartbeat_file(self) -> Path:
        return self.data_dir / "heartbeat"

    @property
    def state_file(self) -> Path:
        return self.data_dir / "state.json"


def _expand(p: str) -> str:
    return os.path.expandvars(os.path.expanduser(p))


def load_config(path: Path | None = None) -> Config:
    path = path or default_config_path()
    cfg = Config()
    if not path.exists():
        return _apply_mode(cfg, None)
    # utf-8-sig: tollera il BOM che il Blocco note / PowerShell 5 aggiungono
    try:
        text = path.read_text(encoding="utf-8-sig")
    except PermissionError:
        raise SystemExit(f"PiumaAV: impossibile leggere {path} (accesso negato). "
                         "Avvialo da un prompt come amministratore oppure ripristina i permessi "
                         "rieseguendo INSTALLA.bat.") from None
    raw = tomllib.loads(text)

    general = raw.get("general", {})
    if "data_dir" in general:
        cfg.data_dir = Path(_expand(general["data_dir"]))
    cfg.action = general.get("action", cfg.action)
    toml_mode = general.get("mode")
    if cfg.action not in ("quarantine", "report", "delete"):
        raise ValueError(f"azione non valida: {cfg.action!r}")
    cfg.notifications = general.get("notifications", cfg.notifications)
    cfg.exclude = [_expand(p) for p in general.get("exclude", cfg.exclude)]
    cfg.exclude_extensions = [e.lower() for e in general.get("exclude_extensions", cfg.exclude_extensions)]
    if "quick_scan_paths" in general:
        cfg.quick_scan_paths = [_expand(p) for p in general["quick_scan_paths"]]

    for key, value in raw.get("engine", {}).items():
        if hasattr(cfg.engine, key):
            setattr(cfg.engine, key, value)

    rt = raw.get("realtime", {})
    for key, value in rt.items():
        if hasattr(cfg.realtime, key):
            setattr(cfg.realtime, key, value)
    cfg.realtime.paths = [_expand(p) for p in cfg.realtime.paths]

    for key, value in raw.get("update", {}).items():
        if hasattr(cfg.update, key):
            setattr(cfg.update, key, value)
    cfg.update.interval_hours = max(1.0, float(cfg.update.interval_hours))

    for key, value in raw.get("feeds", {}).items():
        if hasattr(cfg.feeds, key):
            setattr(cfg.feeds, key, value)

    for section, obj in (("reputation", cfg.reputation), ("protection", cfg.protection),
                         ("behavior", cfg.behavior), ("usb", cfg.usb), ("processes", cfg.processes)):
        for key, value in raw.get(section, {}).items():
            if hasattr(obj, key):
                setattr(obj, key, value)

    for item in raw.get("scheduled_scan", []):
        cfg.scheduled_scans.append(ScheduledScan(
            name=item.get("name", "pianificata"),
            paths=[_expand(p) for p in item["paths"]],
            interval_hours=max(1.0, float(item.get("interval_hours", 24))),
        ))
    return _apply_mode(cfg, toml_mode)


def _apply_mode(cfg: Config, toml_mode: str | None) -> Config:
    """La modalita' scelta con `piuma mode` (mode.json) prevale su quella del file TOML."""
    from .mode import MODES, engines_for, read_mode
    mode = read_mode(cfg.data_dir) or toml_mode or "completa"
    if mode not in MODES:
        raise ValueError(f"modalita' non valida: {mode!r}")
    cfg.mode = mode
    cfg.engine.engines = engines_for(mode, cfg.engine.engines)
    return cfg
