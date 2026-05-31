## Do run this inside  kali after placing the zip file in the desktop:#

```bash
cd /home/kali/Desktop
unzip AutoPenTest_Recon_Autonomous_Update_v32_8_from_v31.zip
cd AutoPenTest_Recon_Autonomous_Update_v32_8_from_v31
chmod +x install.sh
sudo ./install.sh
cd project
sudo .venv/bin/python app.py
```

## Click on the 2nd option as the first option is for internally in Kali

```text
http://<kali-ip>:5000
```

## (Optional) Only run if CVE not syncing

```bash
cd /home/kali/Desktop/AutoPenTest_Recon_Autonomous_Update_v32_8_from_v31/project
source .venv/bin/activate
python scripts/sync_mitre_cve_database.py
python scripts/mitre_cve_status.py
python scripts/audit_cve_source.py
```

## Report boundaries

This module performs:

```text
footprinting
enumeration
evidence normalisation
official CVE List strict matching
service-level exposure checks
JSON/PDF handoff generation
```

