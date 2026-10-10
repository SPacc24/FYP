#!/usr/bin/env bash
# Waits for PenPilot (5000) and Caldera (8888) to answer, then opens both in a browser.
# Runs in the user's graphical session via an autostart entry (see install.sh).

APP_URL="http://127.0.0.1:5000/"
CALDERA_URL="http://127.0.0.1:8888/"

# Poll a URL until it returns any HTTP response (up to ~2.5 minutes).
wait_for() {
    local url="$1"
    local tries=75
    for ((i = 0; i < tries; i++)); do
        if curl -s -o /dev/null -m 2 "$url"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

wait_for "$APP_URL"
# Caldera takes longer to load plugins/compile Sandcat after boot.
wait_for "$CALDERA_URL"

# Small settle delay so the pages are fully served before the browser hits them.
sleep 2

if command -v firefox >/dev/null 2>&1; then
    exec firefox --new-window "$APP_URL" "$CALDERA_URL"
elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$APP_URL"
    sleep 1
    exec xdg-open "$CALDERA_URL"
elif command -v sensible-browser >/dev/null 2>&1; then
    exec sensible-browser "$APP_URL"
fi
