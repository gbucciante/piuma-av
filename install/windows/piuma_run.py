"""Avvio di PiumaAV su Windows senza ambiente virtuale.

Si usa il python.exe / pythonw.exe ufficiale (firmato digitalmente) e si
aggiunge la cartella "lib" accanto a questo file, dove l'installer ha messo
PiumaAV e le sue dipendenze. I lanciatori .exe di venv e pip non sono
firmati e Windows (Smart App Control, criteri aziendali) puo' bloccarli.
"""
import os
import sys

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib")
sys.path.insert(0, LIB)
# anche i processi figli (es. riavvio dell'icona con "python -m piuma") la trovano
os.environ["PYTHONPATH"] = LIB + os.pathsep + os.environ.get("PYTHONPATH", "")


def _crash_log(text: str) -> None:
    """Con pythonw non c'e' console: gli errori di avvio finiscono in un file."""
    import time
    base = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "PiumaAV", "logs")
    for folder in (base, os.path.join(os.environ.get("TEMP", "."), "PiumaAV")):
        try:
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, "avvio-errori.log"), "a", encoding="utf-8") as fh:
                fh.write(time.strftime("%Y-%m-%d %H:%M:%S ") + " ".join(sys.argv[1:]) + "\n" + text + "\n")
            return
        except OSError:
            continue


if __name__ == "__main__":
    try:
        from piuma.cli import main
        code = main()
    except SystemExit as exc:
        if exc.code not in (None, 0) and not isinstance(exc.code, int):
            _crash_log(str(exc.code))
        raise
    except BaseException:
        import traceback
        _crash_log(traceback.format_exc())
        if sys.stderr is not None:
            traceback.print_exc()
        code = 1
    raise SystemExit(code)
