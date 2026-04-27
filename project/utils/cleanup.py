import os
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def remove_pycache(root=PROJECT_ROOT):
    for path in root.rglob("__pycache__"):
        try:
            shutil.rmtree(path)
            print(f"[CLEANUP] Removed: {path}")
        except Exception as e:
            print(f"[CLEANUP ERROR] {path}: {e}")

def remove_pyc_files(root=PROJECT_ROOT):
    for path in root.rglob("*.pyc"):
        try:
            path.unlink()
            print(f"[CLEANUP] Removed: {path}")
        except Exception as e:
            print(f"[CLEANUP ERROR] {path}: {e}")

def clean_storage():
    dirs_to_clean = [
        PROJECT_ROOT / "storage" / "logs",
        PROJECT_ROOT / "storage" / "scans"
    ]

    for d in dirs_to_clean:
        if d.exists():
            for item in d.iterdir():
                try:
                    if item.is_file():
                        item.unlink()
                    else:
                        shutil.rmtree(item)
                    print(f"[CLEANUP] Removed: {item}")
                except Exception as e:
                    print(f"[CLEANUP ERROR] {item}: {e}")

def full_cleanup():
    print("\n[INFO] Running cleanup...")
    remove_pycache()
    remove_pyc_files()
    clean_storage()
    print("[INFO] Cleanup complete.\n")