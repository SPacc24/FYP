
import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'change-me')
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    CALDERA_URL = os.getenv('CALDERA_URL', 'http://127.0.0.1:8888')
    CALDERA_KEY = os.getenv('CALDERA_API_KEY', '')
    ENABLE_CALDERA_EXECUTION = os.getenv('ENABLE_CALDERA_EXECUTION', '0') == '1'
    MAX_EXPANDED_TARGETS = int(os.getenv('MAX_EXPANDED_TARGETS', '256'))
    # Essential profile defaults keep recon fast and avoid noisy/overlapping checks.
    ENABLE_CONTEXT_FOOTPRINTING = os.getenv('ENABLE_CONTEXT_FOOTPRINTING', '0') == '1'
    ENABLE_ARP_SCAN = os.getenv('ENABLE_ARP_SCAN', '0') == '1'
    ENABLE_HTTPX = os.getenv('ENABLE_HTTPX', '0') == '1'
    ENABLE_DEEP_WEB_DISCOVERY = os.getenv('ENABLE_DEEP_WEB_DISCOVERY', '0') == '1'
    ENABLE_SMBMAP = os.getenv('ENABLE_SMBMAP', '0') == '1'
    ENABLE_HYDRA = os.getenv('ENABLE_HYDRA', '0') == '1'
    GOBUSTER_WORDLIST = os.getenv('GOBUSTER_WORDLIST', '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt')
    HYDRA_CREDENTIAL_FILE = os.getenv('HYDRA_CREDENTIAL_FILE', '')
    MITRE_CVE_REPO = os.getenv('MITRE_CVE_REPO', 'https://github.com/CVEProject/cvelistV5.git')
