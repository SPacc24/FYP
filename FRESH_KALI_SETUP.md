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
CREATE USER 'autopentest'@'localhost' IDENTIFIED BY 'CHOOSE_A_STRONG_PASSWORD';
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

The installer builds the complete CVE List index and then performs the NVD API's
offset-paginated initial population into `storage/mitre_cve/nvd_repository.sqlite3`.
Without an NVD API key, NVD's documented public rate limit makes the first sync take
roughly 20 minutes or longer. It is resumable. Check or resume it with:

```bash
cd ~/Desktop/FYP-hehe/project
source .venv/bin/activate
python scripts/nvd_status.py
python scripts/sync_nvd_database.py
```

An NVD API key is optional; add `NVD_API_KEY=...` to `project/.env` only if you have
one. NVD CPE/configuration data decides applicability. CVE prose is never used as
matching proof. CVSS metrics use the selected published version only, with no score
conversion or cross-version fallback.
