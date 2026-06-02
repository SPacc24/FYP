# v32.8 GitHub Commit Summary

This build is prepared as the team handoff version for the recon module. It keeps the recon boundary intact: evidence collection, evidence normalisation, official CVE List matching, report/PDF output, and JSON handoff generation only.

## Included fixes

- Hydra combo files are sanitized before execution. Comments, blank lines, and non `username:password` entries are removed.
- Command output is decoded safely so Python byte-string representations such as `b"..."` do not appear in the UI/report.
- Gobuster output is parsed even when the process times out after producing useful paths.
- Gobuster timeout with discovered paths is reported as `Partial Results Captured`, not `0 paths`.
- Gobuster-discovered web paths are added to Web Evidence.
- Key Exposure Indicator port rendering is fixed for both HTML and PDF output.
- UnrealIRCd banner/script parsing extracts `Unreal3.2.8.1` where available and supports official CVE review for CVE-2010-2075.
- Anonymous FTP access is added as a Key Exposure Indicator when `ftp-anon` evidence is collected.
- Samba TCP/UDP evidence is merged into a single SMB service card.
- NFS/RPC exposure text and candidate CVE headings are deduplicated.
- Empty service-check headings are hidden from the report.
- Samba CVE wording avoids claiming configuration proof that recon evidence did not collect.
- Repeated Hydra rows are consolidated in the report; invalid Hydra input is labelled `Input Invalid`.
- CVE metadata status warns when an older CVE index is missing CVSS fields and provides the rebuild helper command.
- PDF appendix tables are simplified for readability.
- Pentester Summary is displayed near the top of the report.

## Validation commands

Run from repository root:

```bash
python -m py_compile project/app.py project/config.py project/storage/*.py project/scanners/*.py project/scripts/*.py
pytest -q
python project/scripts/audit_no_scoring.py
python project/scripts/audit_cve_source.py
```

## Runtime setup on Kali

```bash
cd /home/kali/Desktop/AutoPenTest_Recon_Autonomous_Update_v32_8_from_v31
chmod +x install.sh
sudo ./install.sh
cd project
source .venv/bin/activate
python scripts/rebuild_mitre_cve_index.py
sudo .venv/bin/python app.py
```

## Git hygiene

The `.gitignore` keeps runtime scan evidence, local virtual environments, local CVE indexes, and cache files out of source control. The recon output remains available through generated reports and handoff JSON at runtime, not as committed artefacts.
