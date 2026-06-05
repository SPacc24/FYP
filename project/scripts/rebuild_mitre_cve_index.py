from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scanners.mitre_cve import INDEX, build_index, status

# Force a clean rebuild so CVSS fields added by newer code are included.
if INDEX.exists():
    INDEX.unlink()
print(build_index())
print(status())
