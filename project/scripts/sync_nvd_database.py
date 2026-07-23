import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanners.nvd_repository import sync


parser = argparse.ArgumentParser(description="Synchronise the complete official NVD CVE repository.")
parser.add_argument("--full", action="store_true", help="Re-run complete offset-paginated population.")
args = parser.parse_args()
print(json.dumps(sync(full=args.full), indent=2))
