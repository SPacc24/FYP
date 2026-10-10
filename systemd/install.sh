#!/usr/bin/env bash
# Installs and enables the PenPilot auto-start services. Run with sudo:
#   sudo bash /home/kali/Documents/IHL/FYP/systemd/install.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run this with sudo: sudo bash $HERE/install.sh" >&2
  exit 1
fi

echo "[1/6] Stopping any manually-started instances (ignore errors if none)..."
pkill -f msfrpcd 2>/dev/null || true
pkill -f "server.py --insecure" 2>/dev/null || true
pkill -f "python app.py" 2>/dev/null || true
sleep 2

echo "[2/6] Installing the msfrpcd helper script..."
install -m 0755 "$HERE/penpilot-msfrpcd.sh" /usr/local/bin/penpilot-msfrpcd.sh

echo "[3/6] Installing the browser launcher script..."
install -m 0755 "$HERE/penpilot-open-browser.sh" /usr/local/bin/penpilot-open-browser.sh

echo "[4/6] Installing systemd unit files..."
install -m 0644 "$HERE/penpilot-msfrpcd.service" /etc/systemd/system/penpilot-msfrpcd.service
install -m 0644 "$HERE/penpilot-caldera.service" /etc/systemd/system/penpilot-caldera.service
install -m 0644 "$HERE/penpilot-app.service"     /etc/systemd/system/penpilot-app.service

echo "[5/6] Installing the login autostart entry (opens the browser at login)..."
# The autostart entry must live in the desktop user's home, owned by that user.
DESKTOP_USER="${SUDO_USER:-kali}"
USER_HOME="$(getent passwd "$DESKTOP_USER" | cut -d: -f6)"
if [[ -n "$USER_HOME" ]]; then
  install -d -o "$DESKTOP_USER" -g "$DESKTOP_USER" "$USER_HOME/.config/autostart"
  install -m 0644 -o "$DESKTOP_USER" -g "$DESKTOP_USER" \
    "$HERE/penpilot-browser.desktop" "$USER_HOME/.config/autostart/penpilot-browser.desktop"
  echo "      Installed for user '$DESKTOP_USER' at $USER_HOME/.config/autostart/"
else
  echo "      WARNING: could not resolve home for '$DESKTOP_USER'; skipped autostart entry." >&2
fi

echo "[6/6] Reloading systemd and enabling services on boot..."
systemctl daemon-reload
systemctl enable --now penpilot-msfrpcd.service
systemctl enable --now penpilot-caldera.service
systemctl enable --now penpilot-app.service

echo
echo "Done. Current status:"
sleep 3
systemctl --no-pager --lines=0 status penpilot-msfrpcd.service penpilot-caldera.service penpilot-app.service || true

echo
echo "The browser will auto-open PenPilot + Caldera at your next graphical login."
echo "To open them now without logging out:  /usr/local/bin/penpilot-open-browser.sh &"
echo
echo "If a service shows 'failed', inspect it with:"
echo "  journalctl -u penpilot-<name>.service -n 50 --no-pager"
