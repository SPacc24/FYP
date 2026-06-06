
from pathlib import Path
import sys, json
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scanners.mitre_cve import status
print(json.dumps(status(), indent=2))
