
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'change-me')
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'

    CALDERA_URL = os.getenv('CALDERA_URL', 'http://127.0.0.1:8888')
    CALDERA_KEY = os.getenv('CALDERA_API_KEY', '')
    AGENT_GROUP = os.getenv('AGENT_GROUP', 'red')
    KALI_IP = os.getenv('KALI_IP', '127.0.0.1')
    OPERATION_TIMEOUT = int(os.getenv('OPERATION_TIMEOUT', '180'))

    MYSQL_HOST = os.getenv('MYSQL_HOST', '127.0.0.1')
    MYSQL_USER = os.getenv('MYSQL_USER', 'autopentest')
    MYSQL_PASS = os.getenv('MYSQL_PASS', '')
    MYSQL_DB = os.getenv('MYSQL_DB', 'autopentest')

    NMAP_DEFAULT_PORTS = os.getenv('NMAP_DEFAULT_PORTS', '1-1024')
    NMAP_DEFAULT_INTENSITY = os.getenv('NMAP_DEFAULT_INTENSITY', '3')
    NMAP_DEFAULT_PROFILE = os.getenv('NMAP_DEFAULT_PROFILE', 'basic')