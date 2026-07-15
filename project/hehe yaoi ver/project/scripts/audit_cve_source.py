from pathlib import Path
import sys, json
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scanners.mitre_cve import OFFICIAL_CVE_SOURCE, INDEX

print({
    "accepted_source": OFFICIAL_CVE_SOURCE,
    "index_exists": INDEX.exists(),
    "index_file": str(INDEX),
})
if INDEX.exists():
    checked = 0
    bad = 0
    with INDEX.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if checked >= 1000:
                break
            checked += 1
            try:
                row = json.loads(line)
            except Exception:
                continue
            if row.get("source") != OFFICIAL_CVE_SOURCE:
                bad += 1
    if bad:
        raise SystemExit(f"Non-official CVE source rows found in first {checked} records: {bad}")
    print(f"OK: first {checked} indexed records use the accepted official source only.")
