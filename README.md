# Set up on a fresh Kali

sudo apt update

sudo apt install -y 
python3 
python3-pip 
python3-venv 
git 
curl 
wget 
unzip 
nmap 
tshark 
rpcbind 
nfs-common 
smbclient 
enum4linux-ng 
dnsutils 
postgresql-client 
default-mysql-client

cd ~/Desktop

unzip (INPUT NAME).zip

cd (INPUT NAME)

chmod +x install.sh

sudo ./install.sh

cd project

source .venv/bin/activate

pip install --upgrade pip

pip install -r requirements.txt

python -m compileall .

pytest -v

python scripts/mitre_cve_status.py

python scripts/sync_mitre_cve_database.py

python scripts/mitre_cve_status.py

python scripts/audit_cve_source.py

ip addr

sudo .venv/bin/python app.py

Open:

http://<kali-ip>:5000

Use second option.

If CVE sync required later:

cd ~/Desktop/(INPUT NAME)/project

source .venv/bin/activate

python scripts/sync_mitre_cve_database.py # Installs from cve database

python scripts/mitre_cve_status.py # Checker

python scripts/audit_cve_source.py

Stop application:

CTRL+C

Deactivate:

deactivate

