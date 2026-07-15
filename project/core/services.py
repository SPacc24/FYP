import logging

from config import Config

from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager
from caldera.coverage_checker import CoverageChecker
from caldera.risk_scorer import RiskScorer

from exploitation.validator import ExploitabilityValidator
from exploitation.metasploit_client import MetasploitRpcClient
from exploitation.metasploit_service import MetasploitService

from storage.db import Database

log = logging.getLogger(__name__)

caldera_client = CalderaClient(
    base_url=Config.CALDERA_URL,
    api_key=Config.CALDERA_KEY,
)

operation_manager = OperationManager(caldera_client)
coverage_checker = CoverageChecker(caldera_client)
risk_scorer = RiskScorer()
exploitability_validator = ExploitabilityValidator()

metasploit_client = MetasploitRpcClient(
    base_url=Config.METASPLOIT_RPC_URL,
    username=Config.METASPLOIT_RPC_USER,
    password=Config.METASPLOIT_RPC_PASS,
    verify_ssl=Config.METASPLOIT_RPC_VERIFY_SSL,
    timeout=Config.METASPLOIT_RPC_TIMEOUT,
    enabled=Config.ENABLE_METASPLOIT,
)

metasploit_service = MetasploitService(
    metasploit_client,
    exploit_execution_enabled=Config.ENABLE_METASPLOIT_EXPLOITS,
)

db = Database(
    host=Config.MYSQL_HOST,
    user=Config.MYSQL_USER,
    password=Config.MYSQL_PASS,
    database=Config.MYSQL_DB,
)

def init_services():
    try:
        db.init_schema()
    except Exception:
        log.exception("Database schema initialization skipped or failed")