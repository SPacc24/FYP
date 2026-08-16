from __future__ import annotations

import glob
import json
import os
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scanners.mitre_cve import status


def main() -> int:
    print('=== CVE pipeline status ===')
    print(json.dumps(status(), indent=2, default=str))
    files = [Path(p) for p in glob.glob(str(PROJECT_ROOT / 'storage/results/*.json'))]
    files = [p for p in files if not p.name.endswith(('_handoff.json','_knowledge_graph.json','_evidence_manifest.json','_operational_maturity.json','_enumeration_intelligence.json'))]
    if not files:
        print('\nNo scan result JSON found.')
        return 1
    latest = max(files, key=os.path.getmtime)
    data = json.loads(latest.read_text(encoding='utf-8'))
    print(f'\nLatest result: {latest}')
    print('Services:', len(data.get('service_inventory') or []))
    matches = list(data.get('baseline_cves') or data.get('cve_matches') or [])
    print('Baseline CVE references:', len(matches))
    print('Matcher diagnostics:', len(data.get('cve_matcher_diagnostics') or []))
    skipped = data.get('cve_skipped_services') or []
    print('Skipped services:', len(skipped))
    reasons = Counter(str(x.get('reason') or 'unknown') for x in (data.get('cve_matcher_diagnostics') or []))
    if reasons:
        print('Matcher diagnostics:')
        for reason, count in reasons.most_common():
            print(f'  {count} x {reason}')
    if skipped:
        print('\nFirst skipped services:')
        for row in skipped[:10]:
            print(f"  {row.get('host')}:{row.get('port')} {row.get('product') or row.get('service')} {row.get('version')} confidence={row.get('confidence_score')}")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
