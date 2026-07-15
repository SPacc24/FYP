#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run with sudo: sudo ./setup_diagnostics.sh" >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WEB_ROOT="/var/www/html"
BACKUP_DIR="/var/backups/autopentest-diagnostics-$(date +%Y%m%d-%H%M%S)"

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 php libapache2-mod-php

mkdir -p "$BACKUP_DIR"
for file in index.html index.php diagnostics.php; do
  if [[ -e "$WEB_ROOT/$file" ]]; then
    cp -a "$WEB_ROOT/$file" "$BACKUP_DIR/$file"
  fi
done

install -o root -g root -m 0644 "$SCRIPT_DIR/diagnostics.php" "$WEB_ROOT/diagnostics.php"
install -o root -g root -m 0644 "$SCRIPT_DIR/index.php" "$WEB_ROOT/index.php"
rm -f "$WEB_ROOT/index.html"

cat > /etc/apache2/conf-available/autopentest-lab.conf <<'EOF'
<Directory /var/www/html>
    Options -Indexes
    AllowOverride None
    Require all granted
</Directory>

DirectoryIndex index.php index.html
ServerTokens Prod
ServerSignature Off
EOF

a2enconf autopentest-lab >/dev/null
apache2ctl configtest
systemctl enable --now apache2
systemctl reload apache2

echo "Installed AutoPenTest diagnostics target."
echo "Backup: $BACKUP_DIR"
echo "Test locally: curl -i http://127.0.0.1/diagnostics.php"
