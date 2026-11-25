#!/usr/bin/env bash
# Installazione di PiumaAV su macOS (richiede Homebrew: https://brew.sh)
# Uso (come utente normale, NON con sudo):  ./install/macos/install.sh
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
APP_DIR="$HOME/Library/Application Support/PiumaAV"
AGENTS="$HOME/Library/LaunchAgents"

command -v brew >/dev/null || { echo "Installare prima Homebrew: https://brew.sh"; exit 1; }
BREW="$(brew --prefix)"

echo "==> Installazione di ClamAV e Python"
brew install clamav python@3.12

ETC="$BREW/etc/clamav"
DB="$BREW/var/lib/clamav"
mkdir -p "$DB" "$BREW/var/log"
if [[ ! -f $ETC/freshclam.conf ]]; then
    printf 'DatabaseDirectory %s\nDatabaseMirror database.clamav.net\n' "$DB" > "$ETC/freshclam.conf"
fi
if [[ ! -f $ETC/clamd.conf ]]; then
    cat > "$ETC/clamd.conf" <<EOF
DatabaseDirectory $DB
TCPSocket 3310
TCPAddr 127.0.0.1
Foreground yes
SelfCheck 600
StreamMaxLength 100M
MaxFileSize 100M
LogFile $BREW/var/log/clamd.log
EOF
fi

echo "==> Primo download delle firme"
"$BREW/bin/freshclam" --config-file="$ETC/freshclam.conf" || true

echo "==> Installazione di PiumaAV"
mkdir -p "$APP_DIR"
"$BREW/bin/python3.12" -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q "$PROJECT_DIR[tray,yara]"
mkdir -p "$HOME/.local/bin"
ln -sf "$APP_DIR/venv/bin/piuma" "$HOME/.local/bin/piuma"
[[ -f $APP_DIR/config.toml ]] || \
    sed "s|^# freshclam_config = .*|freshclam_config = \"$ETC/freshclam.conf\"|" \
        "$PROJECT_DIR/config.example.toml" > "$APP_DIR/config.toml"

echo "==> Firme extra (MalwareBazaar, YARA-Forge)"
"$APP_DIR/venv/bin/piuma" update || true

echo "==> Avvio automatico (LaunchAgent)"
mkdir -p "$AGENTS"
cat > "$AGENTS/com.piuma-av.clamd.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.piuma-av.clamd</string>
  <key>ProgramArguments</key><array>
    <string>$BREW/sbin/clamd</string><string>--config-file=$ETC/clamd.conf</string>
  </array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
EOF
cat > "$AGENTS/com.piuma-av.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.piuma-av</string>
  <key>ProgramArguments</key><array>
    <string>$APP_DIR/venv/bin/python</string><string>-m</string><string>piuma</string><string>tray</string>
  </array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
</dict></plist>
EOF
cat > "$AGENTS/com.piuma-av.watchdog.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.piuma-av.watchdog</string>
  <key>ProgramArguments</key><array>
    <string>$APP_DIR/venv/bin/python</string><string>-m</string><string>piuma</string><string>watchdog</string>
  </array>
  <key>StartInterval</key><integer>300</integer>
</dict></plist>
PLIST
chmod 700 "$APP_DIR"
"$APP_DIR/venv/bin/piuma" integrity --record

for p in com.piuma-av.clamd com.piuma-av com.piuma-av.watchdog; do
    launchctl bootout "gui/$(id -u)/$p" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$AGENTS/$p.plist"
done

echo
echo "Fatto. IMPORTANTE: per sorvegliare Scrivania, Documenti e Download concedi"
echo "'Accesso completo al disco' a: $APP_DIR/venv/bin/python"
echo "(Impostazioni di Sistema > Privacy e sicurezza > Accesso completo al disco)"
echo "Blocco siti malevoli (chiede la password di amministratore una volta):"
echo "  sudo $APP_DIR/venv/bin/piuma blocklist update"
echo "Comandi: piuma status | piuma scan ~/Downloads | piuma scan /Volumes/USB"
