import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanners.nvd_repository import status

print(json.dumps(status(), indent=2))
