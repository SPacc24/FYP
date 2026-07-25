
from pathlib import Path
forbidden = ['risk score','priority score','severity score','exploitability score','manual validation required','exploitation candidate']
roots = [Path('templates'), Path('policies'), Path('static')]
fail=[]
for root in roots:
    if not root.exists(): continue
    for path in root.rglob('*'):
        if path.is_file():
            text=path.read_text(encoding='utf-8', errors='ignore').lower()
            for term in forbidden:
                if term in text: fail.append((str(path), term))
if fail:
    print('Forbidden wording found:')
    for p,t in fail: print(f'{p}: {t}')
    raise SystemExit(1)
print('No forbidden recon-boundary wording found in templates/policies/static.')
