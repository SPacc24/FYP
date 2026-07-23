from pathlib import Path
import sys
import shutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scanners.mitre_cve import BASE, INDEX, status as cve_status, _search_cached

SEED = BASE / 'lab_cve_seed.jsonl'


def install_seed() -> dict[str, str]:
    BASE.mkdir(parents=True, exist_ok=True)
    if not SEED.exists():
        return {'error': f'Lab seed file not found: {SEED}'}
    if INDEX.exists() and INDEX.stat().st_size > 0:
        return {
            'status': 'existing_index_preserved',
            'index_file': str(INDEX),
            'seed_file': str(SEED),
        }
    shutil.copy2(SEED, INDEX)
    _search_cached.cache_clear()
    return {
        'status': 'lab_seed_installed',
        'index_file': str(INDEX),
        'seed_file': str(SEED),
        'cve_status': cve_status(),
    }


if __name__ == '__main__':
    import json
    print(json.dumps(install_seed(), indent=2, default=str))
