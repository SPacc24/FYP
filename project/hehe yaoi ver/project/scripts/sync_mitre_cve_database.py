
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scanners.mitre_cve import build_index
print(build_index())
