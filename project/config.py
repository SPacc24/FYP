import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'change-me')
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    OPERATOR_TOKEN = os.getenv('OPERATOR_TOKEN', '')
    ALLOW_INSECURE_OPERATOR_ACCESS = os.getenv('ALLOW_INSECURE_OPERATOR_ACCESS', '0') == '1'

    CALDERA_URL = os.getenv('CALDERA_URL', 'http://127.0.0.1:8888')
    CALDERA_KEY = os.getenv('CALDERA_API_KEY', '')
    ENABLE_CALDERA_EXECUTION = os.getenv('ENABLE_CALDERA_EXECUTION', '0') == '1'
    MAX_EXPANDED_TARGETS = int(os.getenv('MAX_EXPANDED_TARGETS', '256'))

    ENABLE_METASPLOIT = os.getenv('ENABLE_METASPLOIT', '0') == '1'
    ENABLE_METASPLOIT_EXPLOITS = os.getenv('ENABLE_METASPLOIT_EXPLOITS', '0') == '1'
    METASPLOIT_RPC_URL = os.getenv('METASPLOIT_RPC_URL', 'https://127.0.0.1:55552')
    METASPLOIT_RPC_USER = os.getenv('METASPLOIT_RPC_USER', 'msf')
    METASPLOIT_RPC_PASS = os.getenv('METASPLOIT_RPC_PASS', '')
    METASPLOIT_RPC_VERIFY_SSL = os.getenv('METASPLOIT_RPC_VERIFY_SSL', '0') == '1'
    METASPLOIT_RPC_TIMEOUT = int(os.getenv('METASPLOIT_RPC_TIMEOUT', '20'))
    METASPLOIT_RESULT_TIMEOUT = float(os.getenv('METASPLOIT_RESULT_TIMEOUT', '15'))
    METASPLOIT_POLL_INTERVAL = float(os.getenv('METASPLOIT_POLL_INTERVAL', '1'))

    AGENT_GROUP = os.getenv('AGENT_GROUP', 'red')
    KALI_IP = os.getenv('KALI_IP', '127.0.0.1')
    OPERATION_TIMEOUT = int(os.getenv('OPERATION_TIMEOUT', '180'))

    PROOF_OF_ACCESS_ENABLED = os.getenv(
        'PROOF_OF_ACCESS_ENABLED',
        'false',
    ).lower() == 'true'
    PROOF_OF_ACCESS_SECRET = os.getenv('PROOF_OF_ACCESS_SECRET', '')
    PROOF_OF_ACCESS_TTL = int(os.getenv('PROOF_OF_ACCESS_TTL', '300'))

    MYSQL_HOST = os.getenv('MYSQL_HOST', '127.0.0.1')
    MYSQL_USER = os.getenv('MYSQL_USER', 'autopentest')
    MYSQL_PASS = os.getenv('MYSQL_PASS', '')
    MYSQL_DB = os.getenv('MYSQL_DB', 'autopentest')

    ENABLE_CONTEXT_FOOTPRINTING = os.getenv('ENABLE_CONTEXT_FOOTPRINTING', '0') == '1'
    ENABLE_ARP_SCAN = os.getenv('ENABLE_ARP_SCAN', '0') == '1'
    ENABLE_HTTPX = os.getenv('ENABLE_HTTPX', '0') == '1'
    ENABLE_DEEP_WEB_DISCOVERY = os.getenv('ENABLE_DEEP_WEB_DISCOVERY', '0') == '1'
    ENABLE_SMBMAP = os.getenv('ENABLE_SMBMAP', '0') == '1'
    ENABLE_HYDRA = os.getenv('ENABLE_HYDRA', '0') == '1'
    GOBUSTER_WORDLIST = os.getenv('GOBUSTER_WORDLIST', '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt')
    HYDRA_CREDENTIAL_FILE = os.getenv('HYDRA_CREDENTIAL_FILE', '')
    MITRE_CVE_REPO = os.getenv('MITRE_CVE_REPO', 'https://github.com/CVEProject/cvelistV5.git')

    PIVOT_CHISEL_BINARY = os.getenv('PIVOT_CHISEL_BINARY', '/usr/bin/chisel')
    PIVOT_DEFAULT_SOCKS_PORT = int(os.getenv('PIVOT_DEFAULT_SOCKS_PORT', '1080'))
    PIVOT_DEFAULT_CHISEL_PORT = int(os.getenv('PIVOT_DEFAULT_CHISEL_PORT', '8080'))

    NMAP_DEFAULT_PORTS = os.getenv('NMAP_DEFAULT_PORTS', '1-1024')
    NMAP_DEFAULT_INTENSITY = os.getenv('NMAP_DEFAULT_INTENSITY', '3')
    NMAP_DEFAULT_PROFILE = os.getenv('NMAP_DEFAULT_PROFILE', 'basic')

    ENABLE_WEB_VALIDATION = os.getenv('ENABLE_WEB_VALIDATION', '0') == '1'
    WEB_VALIDATION_TIMEOUT = int(os.getenv('WEB_VALIDATION_TIMEOUT', '5'))
    WEB_VALIDATION_MAX_RESPONSE_BYTES = int(
        os.getenv('WEB_VALIDATION_MAX_RESPONSE_BYTES', '65536')
    )
    WEB_VALIDATION_MAX_REDIRECTS = int(
        os.getenv('WEB_VALIDATION_MAX_REDIRECTS', '2')
    )
    LAB_WEB_OS = os.getenv('LAB_WEB_OS', 'windows')


