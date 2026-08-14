#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from scanners.windows_advisory import build_index


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a local Microsoft MSRC Windows advisory index."
    )
    parser.add_argument(
        "--start-year",
        type=int,
        default=None,
        help="Earliest MSRC release year to include; defaults to the last ten years.",
    )
    args = parser.parse_args()
    print(json.dumps(build_index(args.start_year), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
