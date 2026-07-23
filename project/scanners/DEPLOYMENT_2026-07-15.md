# Kali Deployment — 2026-07-15

Run from a Kali terminal after copying the ZIP to the Desktop:

```bash
cd ~
mkdir -p "$HOME/AutoPenTest_Complete_Kali_2026-07-15"
unzip -o "$HOME/Desktop/AutoPenTest_Complete_Kali_Scanner_Accuracy_2026-07-15.zip" -d "$HOME"
cd "$HOME/AutoPenTest_Complete_Kali_2026-07-15"
bash install.sh
project/.venv/bin/python -m compileall -q project/scanners
cd project
.venv/bin/python -m unittest -v scanners.tests.test_scanner_hardening
cd ..
APP_HOST=127.0.0.1 bash start.sh
```

Expected validation result:

```text
Ran 19 tests
OK
```

Open `http://127.0.0.1:5000`. Retrieve the current operator token locally with:

```bash
sed -n 's/^OPERATOR_TOKEN=//p' project/.env
```

Do not paste the token into logs, reports, source control, or screenshots. The installer creates/reuses local runtime secrets. The release ZIP intentionally excludes `.env`, previous scan results, caches, and compiled Python artifacts.

If the official CVE index needs rebuilding:

```bash
cd "$HOME/AutoPenTest_Complete_Kali_2026-07-15/project"
.venv/bin/python scripts/rebuild_mitre_cve_index.py
.venv/bin/python scripts/mitre_cve_status.py
```

Operate only against explicitly authorized cyber-range targets and retain the default policy stop conditions.
