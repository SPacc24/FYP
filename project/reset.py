import shutil
from pathlib import Path

TARGETS = [
    "storage/scans",
    "storage/logs",
    "storage/reports"
]

def reset():
    print("[RESET] Cleaning project artifacts...")
    for t in TARGETS:
        path = Path(t)
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True, exist_ok=True)
    print("[RESET] Done.")

if __name__ == "__main__":
    reset()