"""Motore euristico di PiumaAV ("PiumaHeur").

Non cerca virus GIA' NOTI (lo fanno Defender, ClamAV, gli hash), ma file che
"sembrano" malware: assegna un punteggio di rischio 0-100 sommando segnali.

File eseguibili Windows (PE: .exe .dll .scr ...), letti con un parser interno
senza dipendenze:
  * sezioni di packer noti (UPX, ASPack, MPRESS, Themida, VMProtect...)
  * sezioni con entropia molto alta (codice compresso/cifrato)
  * sezioni scrivibili ED eseguibili, punto d'ingresso fuori dal codice
  * pochissime importazioni + LoadLibrary/GetProcAddress (API nascoste)
  * combinazioni di API tipiche: iniezione in altri processi, keylogger,
    download+esecuzione, anti-debug, cifratura di massa dei file
  * grossi dati accodati al file (overlay) ad alta entropia
  * assenza di firma digitale (la presenza di una firma abbassa il punteggio;
    su Windows la firma viene anche VERIFICATA con WinVerifyTrust)
Nome del file:
  * doppia estensione ("fattura.pdf.exe"), carattere RTLO che inverte il testo
Script (.ps1 .js .vbs .hta .bat ...):
  * lunghi blocchi Base64, concatenazioni di caratteri, eval/Invoke-Expression,
    download + esecuzione

Soglie (configurabili): >= 60 "sospetto" -> avviso; >= 90 "molto probabile
malware" -> quarantena. Sotto il 60 nessuna segnalazione.
"""

from __future__ import annotations

import math
import os
import re
import struct
from collections import Counter
from dataclasses import dataclass, field

from .engine import BaseEngine, ScanResult

PE_EXT = {".exe", ".dll", ".scr", ".sys", ".cpl", ".ocx", ".com", ".pif", ".efi", ".drv", ".pyd"}
SCRIPT_EXT = {".ps1", ".psm1", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".bat", ".cmd"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt", "mp3", "mp4",
           "zip", "rar", "gif", "rtf", "csv", "odt"}
PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".mpress1": "MPRESS",
    ".mpress2": "MPRESS", ".themida": "Themida", ".winlice": "WinLicense", ".vmp0": "VMProtect",
    ".vmp1": "VMProtect", ".vmp2": "VMProtect", ".enigma1": "Enigma", ".enigma2": "Enigma", ".petite": "Petite",
    ".nsp0": "NsPack", ".nsp1": "NsPack", "pec2": "PECompact", ".pec": "PECompact", ".yp": "Y0da",
    ".packed": "packer", ".perplex": "Perplex", "mew": "MEW", ".boom": "Boom", ".spack": "SimplePack",
}
API_COMBOS = [
    ("iniezione di codice in altri processi", 30,
     [{"virtualallocex", "ntallocatevirtualmemory"}, {"writeprocessmemory", "ntwritevirtualmemory"},
      {"createremotethread", "ntcreatethreadex", "queueuserapc", "rtlcreateuserthread", "setthreadcontext"}]),
    ("svuotamento di processi (process hollowing)", 30,
     [{"ntunmapviewofsection", "zwunmapviewofsection"}, {"setthreadcontext", "wow64setthreadcontext"},
      {"resumethread"}]),
    ("registrazione dei tasti (keylogger)", 25,
     [{"setwindowshookexa", "setwindowshookexw"}, {"getasynckeystate", "getkeystate", "getkeyboardstate"}]),
    ("scarica ed esegue file da Internet", 20,
     [{"urldownloadtofilea", "urldownloadtofilew", "internetopenurla", "internetopenurlw",
       "winhttpopenrequest"}, {"winexec", "shellexecutea", "shellexecutew", "createprocessa", "createprocessw"}]),
    ("cifratura di massa dei file (ransomware)", 25,
     [{"cryptencrypt", "bcryptencrypt"}, {"findfirstfilew", "findfirstfilea", "findfirstfileexw"},
      {"movefileexw", "movefilew", "deletefilew", "setfileinformationbyhandle"}]),
    ("tecniche anti-analisi", 10,
     [{"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"},
      {"gettickcount", "queryperformancecounter", "outputdebugstringa"}]),
]


@dataclass
class Verdict:
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    def add(self, points: int, reason: str) -> None:
        self.score += points
        self.reasons.append(f"{reason} ({points:+d})")


_BYTES = [bytes([i]) for i in range(256)]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    if len(data) > 256 * 1024:              # campione: 64 blocchi da 4 KB distribuiti sul file
        step = len(data) // 64
        data = b"".join(data[i * step:i * step + 4096] for i in range(64))
    n = len(data)
    if n < 4096:
        counts = Counter(data).values()
    else:                                   # 256 conteggi in C: molto piu' veloce su dati grandi
        counts = [c for c in (data.count(b) for b in _BYTES) if c]
    return -sum(c / n * math.log2(c / n) for c in counts)


# ---------------------------------------------------------------- parser PE
@dataclass
class Section:
    name: str
    vaddr: int
    vsize: int
    raw_ptr: int
    raw_size: int
    chars: int
    entropy: float = 0.0

    @property
    def executable(self) -> bool:
        return bool(self.chars & 0x20000000)

    @property
    def writable(self) -> bool:
        return bool(self.chars & 0x80000000)


@dataclass
class PEInfo:
    is_dll: bool
    machine: int
    entry: int
    sections: list[Section]
    imports: dict[str, set[str]]
    has_signature: bool
    overlay_size: int
    overlay_entropy: float
    file_size: int


def _rva_to_off(rva: int, sections: list[Section]) -> int | None:
    for s in sections:
        if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size):
            return rva - s.vaddr + s.raw_ptr
    return None


def _cstr(data: bytes, off: int, limit: int = 256) -> str:
    end = data.find(b"\0", off, off + limit)
    return data[off:end if end != -1 else off + limit].decode("latin-1", "replace")


def parse_pe(data: bytes) -> PEInfo | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
        return None
    machine, nsec, _ts, _p, _n, opt_size, chars = struct.unpack_from("<HHIIIHH", data, pe_off + 4)
    opt = pe_off + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32plus = magic == 0x20B
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    dd_off = opt + (112 if pe32plus else 96)
    ndirs = struct.unpack_from("<I", data, dd_off - 4)[0]

    def directory(i):
        if i >= ndirs or dd_off + 8 * i + 8 > len(data):
            return 0, 0
        return struct.unpack_from("<II", data, dd_off + 8 * i)

    sections = []
    sec_off = opt + opt_size
    for i in range(min(nsec, 96)):
        o = sec_off + 40 * i
        if o + 40 > len(data):
            break
        name = data[o:o + 8].rstrip(b"\0").decode("latin-1", "replace")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, o + 8)
        sc = struct.unpack_from("<I", data, o + 36)[0]
        s = Section(name, vaddr, vsize, rptr, rsize, sc)
        s.entropy = entropy(data[rptr:rptr + min(rsize, 4 * 1024 * 1024)])
        sections.append(s)

    imports: dict[str, set[str]] = {}
    imp_rva, _ = directory(1)
    off = _rva_to_off(imp_rva, sections) if imp_rva else None
    count = 0
    while off is not None and off + 20 <= len(data) and count < 512:
        oft, _t, _f, name_rva, ft = struct.unpack_from("<IIIII", data, off)
        if name_rva == 0:
            break
        noff = _rva_to_off(name_rva, sections)
        dll = _cstr(data, noff).lower() if noff is not None else "?"
        funcs: set[str] = set()
        toff = _rva_to_off(oft or ft, sections)
        step, flag = (8, 1 << 63) if pe32plus else (4, 1 << 31)
        n = 0
        while toff is not None and toff + step <= len(data) and n < 4096:
            val = struct.unpack_from("<Q" if pe32plus else "<I", data, toff)[0]
            if val == 0:
                break
            if not val & flag:
                hoff = _rva_to_off(val & 0x7FFFFFFF, sections)
                if hoff is not None:
                    funcs.add(_cstr(data, hoff + 2).lower())
            toff += step
            n += 1
        imports.setdefault(dll, set()).update(funcs)
        off += 20
        count += 1

    sec_rva, sec_size = directory(4)      # firma Authenticode: e' un offset nel file, non un RVA
    has_sig = sec_size > 8 and sec_rva + sec_size <= len(data) + 8
    end_sections = max((s.raw_ptr + s.raw_size for s in sections if s.raw_size), default=len(data))
    if has_sig and sec_rva >= end_sections:
        overlay = data[end_sections:sec_rva]          # i dati della firma non contano come overlay
    else:
        overlay = data[end_sections:]
    return PEInfo(bool(chars & 0x2000), machine, entry, sections, imports, has_sig,
                  len(overlay), entropy(overlay[:4 * 1024 * 1024]), len(data))


# ---------------------------------------------------------------- firma (Windows)
def verify_signature_windows(path: str) -> bool | None:
    """True se la firma Authenticode e' valida (WinVerifyTrust). None se non verificabile."""
    import sys
    if not sys.platform.startswith("win"):
        return None
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("a", wintypes.DWORD), ("b", wintypes.WORD), ("c", wintypes.WORD), ("d", ctypes.c_ubyte * 8)]

    class FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

    class TRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(FILE_INFO)), ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    action = GUID(0xAAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    fi = FILE_INFO(ctypes.sizeof(FILE_INFO), path, None, None)
    td = TRUST_DATA()
    td.cbStruct = ctypes.sizeof(TRUST_DATA)
    td.dwUIChoice = 2            # WTD_UI_NONE
    td.fdwRevocationChecks = 0   # WTD_REVOKE_NONE (nessun accesso a Internet)
    td.dwUnionChoice = 1         # WTD_CHOICE_FILE
    td.pFile = ctypes.pointer(fi)
    td.dwProvFlags = 0x1000      # WTD_CACHE_ONLY_URL_RETRIEVAL
    try:
        res = ctypes.windll.wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(td))  # type: ignore[attr-defined]
    except OSError:
        return None
    return res == 0


# ---------------------------------------------------------------- analisi
def analyze_name(path: str, v: Verdict) -> None:
    name = os.path.basename(path)
    if "‮" in name:
        v.add(60, "nome con carattere che inverte il testo (RTLO)")
    parts = name.lower().split(".")
    if len(parts) >= 3 and parts[-2] in DOC_EXT and "." + parts[-1] in (PE_EXT | SCRIPT_EXT):
        v.add(50, f"doppia estensione ingannevole (.{parts[-2]}.{parts[-1]})")
    if re.search(r"\s{8,}\.\w{2,4}$", name):
        v.add(30, "estensione nascosta da molti spazi")


PACKING_CAP = 50   # i segnali di compressione sono correlati: insieme valgono al massimo 50


def analyze_pe(pe: PEInfo, path: str, signature_check=verify_signature_windows) -> Verdict:
    v = Verdict()
    pk = Verdict()      # segnali legati a compressione/offuscamento (sommati con un tetto)
    secs = pe.sections
    packers = {PACKER_SECTIONS[s.name.lower()] for s in secs if s.name.lower() in PACKER_SECTIONS}
    if packers:
        pk.add(25, f"compresso con {', '.join(sorted(packers))}")
    high = [s for s in secs if s.raw_size > 1024 and s.entropy > 7.2 and s.name.lower() not in (".rsrc", ".reloc")]
    if high:
        pk.add(20 if any(s.executable for s in high) else 10,
              f"sezioni ad alta entropia: {', '.join(s.name or '?' for s in high[:3])}")
    wx = [s for s in secs if s.executable and s.writable]
    if wx:
        pk.add(15, f"sezione scrivibile ed eseguibile: {wx[0].name or '?'}")
    ep_sec = next((s for s in secs if s.vaddr <= pe.entry < s.vaddr + max(s.vsize, s.raw_size)), None)
    if pe.entry and ep_sec is None:
        v.add(20, "punto d'ingresso fuori da ogni sezione")
    elif ep_sec is not None and not ep_sec.executable:
        v.add(15, "punto d'ingresso in una sezione non eseguibile")
    elif ep_sec is not None and secs and ep_sec is secs[-1] and len(secs) > 2 and not pe.is_dll:
        pk.add(10, "punto d'ingresso nell'ultima sezione (tipico dei packer)")
    if any(s.raw_size == 0 and s.vsize > 256 * 1024 and s.executable for s in secs):
        pk.add(10, "sezione eseguibile vuota nel file ma grande in memoria (si decomprime)")
    if not secs or len(secs) > 12:
        v.add(10, f"numero di sezioni anomalo ({len(secs)})")
    weird = [s.name for s in secs if s.name and not re.fullmatch(r"[.\w$/-]{1,8}", s.name)]
    if weird:
        v.add(10, f"nomi di sezione anomali: {', '.join(weird[:3])}")

    funcs = set().union(*pe.imports.values()) if pe.imports else set()
    if not pe.is_dll:
        if not funcs:
            v.add(15, "nessuna funzione importata")
        elif len(funcs) <= 8 and {"loadlibrarya", "loadlibraryw"} & funcs and "getprocaddress" in funcs:
            pk.add(20, "importa quasi solo LoadLibrary/GetProcAddress (API nascoste)")
    for desc, pts, groups in API_COMBOS:
        if all(g & funcs for g in groups):
            v.add(pts, desc)

    if pe.overlay_size > 64 * 1024 and pe.overlay_entropy > 7.5 and pe.overlay_size > pe.file_size * 0.3:
        pk.add(10, f"{pe.overlay_size // 1024} KB di dati cifrati/compressi accodati")

    if pk.score:
        capped = min(pk.score, PACKING_CAP)
        v.score += capped
        v.reasons += pk.reasons + ([f"(segnali di compressione limitati a {PACKING_CAP})"] if capped < pk.score else [])
    combos = sum(1 for desc, _, groups in API_COMBOS
                 if desc != "tecniche anti-analisi" and all(g & funcs for g in groups))
    if combos >= 2:
        v.add(10, "piu' comportamenti sospetti insieme")

    if pe.has_signature:
        valid = signature_check(path) if signature_check else None
        if valid is True:
            v.add(-60, "firma digitale valida")
        elif valid is False:
            v.add(25, "firma digitale NON valida o manomessa")
        else:
            v.add(-25, "firmato digitalmente (firma non verificata su questo sistema)")
    elif not pe.is_dll:
        v.add(10, "eseguibile senza firma digitale")
    return v


SCRIPT_SIGNS = [
    (re.compile(r"[A-Za-z0-9+/]{400,}={0,2}"), 20, "lungo blocco Base64"),
    (re.compile(r"(\[char\]\s*\d+\s*\+\s*){8,}|(chr\(\d+\)\s*[&+]\s*){8,}|(String\.fromCharCode\([\d,\s]{40,}\))", re.I),
     25, "testo nascosto con codici carattere"),
    (re.compile(r"\b(iex|invoke-expression|eval|execute(global)?)\b", re.I), 10, "esegue codice generato al volo"),
    (re.compile(r"(downloadstring|downloadfile|invoke-webrequest|net\.webclient|msxml2\.xmlhttp|winhttp\.winhttprequest|"
                r"bitstransfer|urldownloadtofile)", re.I), 15, "scarica dati da Internet"),
    (re.compile(r"(frombase64string|atob\(|base64\s+-d)", re.I), 10, "decodifica Base64"),
    (re.compile(r"(-w(indowstyle)?\s+hidden|\.run\s*\(.{0,80},\s*0\s*[,)])", re.I), 15, "esecuzione in finestra nascosta"),
    (re.compile(r"(vssadmin.{0,20}delete|shadowcopy.{0,20}delete|bcdedit.{0,40}recoveryenabled)", re.I), 40,
     "cancella i backup di Windows"),
    (re.compile(r"(set-mppreference.{0,60}disable|add-mppreference.{0,30}exclusion)", re.I), 35, "disattiva Defender"),
    (re.compile(r"(\^.){12,}|(`.){12,}"), 15, "offuscamento con caratteri di escape"),
]


def analyze_script(text: str) -> Verdict:
    v = Verdict()
    for rx, pts, desc in SCRIPT_SIGNS:
        if rx.search(text):
            v.add(pts, desc)
    lines = text.splitlines() or [""]
    if max(len(line) for line in lines) > 5000 and len(lines) < 20:
        v.add(10, "riga lunghissima (codice compattato/offuscato)")
    return v


# ---------------------------------------------------------------- motore
class HeuristicEngine(BaseEngine):
    name = "piuma-heur"

    def __init__(self, alert_score: int = 60, max_bytes: int = 50 * 1024 * 1024, signature_check=verify_signature_windows):
        self.alert_score = alert_score
        self.max_bytes = max_bytes
        self.signature_check = signature_check

    def available(self) -> bool:
        return True

    def version(self) -> str:
        return f"PiumaHeur (soglia {self.alert_score})"

    def analyze(self, path: str) -> Verdict:
        v = Verdict()
        analyze_name(path, v)
        ext = os.path.splitext(path)[1].lower()
        try:
            size = os.path.getsize(path)
            if size > self.max_bytes or size < 64:
                return v
            with open(path, "rb") as fh:
                head = fh.read(2)
                if head == b"MZ":
                    fh.seek(0)
                    data = fh.read()
                    try:
                        pe = parse_pe(data)
                    except (struct.error, IndexError, ValueError):
                        v.add(15, "struttura PE danneggiata/anomala")
                        return v
                    if pe:
                        pv = analyze_pe(pe, path, self.signature_check)
                        v.score += pv.score
                        v.reasons += pv.reasons
                        if ext.lstrip(".") in DOC_EXT:
                            v.add(50, f"eseguibile travestito da file {ext}")
                        elif ext and ext not in PE_EXT:
                            v.add(15, f"eseguibile con estensione insolita {ext}")
                elif ext in SCRIPT_EXT and size <= 5 * 1024 * 1024:
                    fh.seek(0)
                    text = fh.read().decode("utf-8", "replace")
                    sv = analyze_script(text)
                    v.score += sv.score
                    v.reasons += sv.reasons
        except OSError:
            return v
        v.score = max(0, min(100, v.score))
        return v

    def scan_file(self, path: str) -> ScanResult:
        v = self.analyze(path)
        if v.score >= self.alert_score:
            top = "; ".join(r for r in v.reasons if "(+" in r)[:300]
            return ScanResult(path, True, f"PiumaHeur:{v.score}:{top}")
        return ScanResult(path, False)


def heur_score(signature: str | None) -> int | None:
    if signature and signature.startswith("PiumaHeur:"):
        try:
            return int(signature.split(":", 2)[1])
        except (IndexError, ValueError):
            return None
    return None
