# AutoPenTest v1.6.0 Full Package - Fresh Kali Setup

This is a standalone project archive. It does not require any older AutoPenTest
ZIP or hotfix overlay.

## Install

```bash
cd ~/Desktop
unzip -o ~/Desktop/AutoPenTest_v1.6.0_FULL_Project_Kali.zip
cd ~/Desktop/FYP-hehe
chmod +x install.sh start.sh
bash install.sh
```

The installer creates `project/.venv`, installs the Python and Kali tool
dependencies, generates `project/.env`, and synchronises the official CVE
List. Do not interrupt the CVE synchronisation.

## Optional MySQL setup

The web application can start without a working MySQL connection, but database
features require MariaDB/MySQL and credentials in `project/.env`.

```bash
sudo apt update
sudo apt install -y mariadb-server
sudo systemctl enable --now mariadb
sudo mariadb
```

In the MariaDB prompt, replace `CHOOSE_A_STRONG_PASSWORD` and run:

```sql
CREATE DATABASE autopentest;
CREATE USER 'autopentest'@'localhost' IDENTIFIED BY 'Admin123#@!';
GRANT ALL PRIVILEGES ON autopentest.* TO 'autopentest'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Then append the same configuration to `project/.env`:

```bash
cd ~/Desktop/FYP-hehe/project
nano .env
```

```text
MYSQL_HOST=127.0.0.1
MYSQL_USER=autopentest
MYSQL_PASS=CHOOSE_A_STRONG_PASSWORD
MYSQL_DB=autopentest
```

## Start

```bash
cd ~/Desktop/FYP-hehe
bash start.sh
```

Open `http://127.0.0.1:5000` in Kali. Show the generated operator token with:

```bash
cd ~/Desktop/FYP-hehe
project/.venv/bin/python project/scripts/bootstrap_env.py --show-secrets
```

The CVSS v3.1/v4.0 selector appears immediately below the target field.

The installer downloads the official CVE List V5 repository once and builds local
indexes under `storage/mitre_cve/`. Later updates retrieve only changed CVE records.
Check or refresh the local data with:

```bash
cd ~/Desktop/FYP-hehe/project
source .venv/bin/activate
python scripts/mitre_cve_status.py
python scripts/sync_mitre_cve_database.py
```

No API key is required. The installer builds local index schema v4. Machine-readable
CVE List V5 affected data decides whether a CVE becomes a Candidate. CVE prose is
never used as matching proof. Confirmed requires separate target-specific validation
evidence, and no other CVE finding value exists.
CVSS metrics use the operator-selected published version only, with no score
conversion, estimation, or cross-version fallback.
