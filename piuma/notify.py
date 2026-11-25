"""Notifiche desktop native, senza dipendenze esterne."""

from __future__ import annotations

import logging
import shutil
import subprocess

from .config import IS_MAC, IS_WINDOWS

log = logging.getLogger(__name__)

_PS_TOAST = r"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
$t = [Security.SecurityElement]::Escape($env:PIUMA_TITLE)
$m = [Security.SecurityElement]::Escape($env:PIUMA_MSG)
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$m</text></binding></visual></toast>")
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
"""


def notify(title: str, message: str) -> None:
    try:
        if IS_WINDOWS:
            import os
            env = dict(os.environ, PIUMA_TITLE=title, PIUMA_MSG=message)
            subprocess.Popen(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", _PS_TOAST],
                             env=env, creationflags=0x08000000)
        elif IS_MAC:
            esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
            subprocess.Popen(["osascript", "-e", f'display notification "{esc(message)}" with title "{esc(title)}"'])
        elif shutil.which("notify-send"):
            subprocess.Popen(["notify-send", "-u", "critical", "-a", "PiumaAV", title, message])
    except OSError as exc:
        log.debug("notifica non inviata: %s", exc)
