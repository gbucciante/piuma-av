#!/usr/bin/env bash
# Installazione di PiumaAV su Linux (Debian/Ubuntu, Fedora, Arch, openSUSE)
# Uso:  sudo ./install/linux/install.sh
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Eseguire con sudo"; exit 1; }
PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_DIR=/opt/piuma-av
CONF_DIR=/etc/piuma-av
TARGET_USER="${SUDO_USER:-root}"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"

echo "==> Installazione di ClamAV"
if command -v apt-get >/dev/null; then
    apt-get update -qq
    apt-get install -y clamav clamav-daemon clamav-freshclam python3 python3-venv
    CLAMD_SVC=clamav-daemon; FRESHCLAM_SVC=clamav-freshclam
    SOCKET=/var/run/clamav/clamd.ctl
elif command -v dnf >/dev/null; then
    dnf install -y clamav clamd clamav-update python3
    sed -i 's/^Example/#Example/; s|^#LocalSocket .*|LocalSocket /run/clamd.scan/clamd.sock|' /etc/clamd.d/scan.conf
    sed -i 's/^Example/#Example/' /etc/freshclam.conf
    CLAMD_SVC=clamd@scan; FRESHCLAM_SVC=clamav-freshclam
    SOCKET=/run/clamd.scan/clamd.sock
elif command -v pacman >/dev/null; then
    pacman -Sy --noconfirm clamav python
    CLAMD_SVC=clamav-daemon; FRESHCLAM_SVC=clamav-freshclam
    SOCKET=/run/clamav/clamd.ctl
elif command -v zypper >/dev/null; then
    zypper -n install clamav python3
    CLAMD_SVC=clamd; FRESHCLAM_SVC=freshclam
    SOCKET=/run/clamav/clamd-socket
else
    echo "Gestore pacchetti non riconosciuto: installare ClamAV manualmente"; exit 1
fi

echo "==> Primo download delle firme"
systemctl stop "$FRESHCLAM_SVC" 2>/dev/null || true
freshclam || echo "(freshclam: riprovera' piu' tardi)"
systemctl enable --now "$CLAMD_SVC"

echo "==> Installazione di PiumaAV in $INSTALL_DIR"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -q "$PROJECT_DIR[yara]"
ln -sf "$INSTALL_DIR/venv/bin/piuma" /usr/local/bin/piuma

mkdir -p "$CONF_DIR"
if [[ ! -f $CONF_DIR/config.toml ]]; then
    # il servizio gira come root: le cartelle "~" vanno riferite all'utente reale
    sed -e "s|~/|$TARGET_HOME/|g" \
        -e "s|^# clamd_socket = .*|clamd_socket = \"$SOCKET\"|" \
        -e "s|^# paths = .*|paths = [\"$TARGET_HOME/Downloads\", \"$TARGET_HOME/Desktop\", \"$TARGET_HOME/Documents\", \"/tmp\"]|" \
        "$PROJECT_DIR/config.example.toml" > "$CONF_DIR/config.toml"
fi

echo "==> Firme extra (MalwareBazaar, YARA-Forge)"
"$INSTALL_DIR/venv/bin/piuma" update || true

echo "==> Servizio systemd"
cat > /etc/systemd/system/piuma-av.service <<EOF
[Unit]
Description=PiumaAV - protezione in tempo reale
After=network-online.target $CLAMD_SVC.service
Wants=$CLAMD_SVC.service

[Service]
ExecStart=$INSTALL_DIR/venv/bin/piuma run
Restart=always
RestartSec=5
Nice=10
IOSchedulingClass=idle
# limiti per restare leggero
MemoryMax=300M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF
# inotify: alza il limite di cartelle sorvegliabili
echo "fs.inotify.max_user_watches=524288" > /etc/sysctl.d/60-piuma-av.conf
sysctl -q --system || true

# watchdog: ogni 5 minuti controlla il "battito" del servizio
cat > /etc/systemd/system/piuma-av-watchdog.service <<UNIT
[Unit]
Description=PiumaAV watchdog
[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/venv/bin/piuma watchdog
UNIT
cat > /etc/systemd/system/piuma-av-watchdog.timer <<UNIT
[Unit]
Description=PiumaAV watchdog ogni 5 minuti
[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
UNIT

echo "==> Autoprotezione: permessi e integrita'"
chown -R root:root "$INSTALL_DIR" "$CONF_DIR"
chmod -R go-w "$INSTALL_DIR" "$CONF_DIR"
mkdir -p /var/lib/piuma-av && chmod 700 /var/lib/piuma-av
"$INSTALL_DIR/venv/bin/piuma" integrity --record

systemctl daemon-reload
systemctl enable --now piuma-av piuma-av-watchdog.timer
echo
echo "Fatto. Stato: systemctl status piuma-av   |   piuma status"
echo "Scansione di un disco: sudo piuma scan /media/$TARGET_USER/USB"
