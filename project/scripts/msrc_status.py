#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanners.msrc_client import status


if __name__ == "__main__":
    print(json.dumps(status(), indent=2, ensure_ascii=False))
