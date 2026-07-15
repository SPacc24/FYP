import logging

from config import Config

from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager
from caldera.coverage_checker import CoverageChecker
from caldera.risk_scorer import RiskScorer

from exploitation.metasploit_client import MetasploitRpcClient
from exploitation.metasploit_service import MetasploitService
from exploitation.validator import ExploitabilityValidator
from proof_of_access import ProofTicketManager
from storage.db import Database
from exploitation.web_validator import WebValidationService
from exploitation.web_exploiter import WebExploiter

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
    result_timeout=Config.METASPLOIT_RESULT_TIMEOUT,
    poll_interval=Config.METASPLOIT_POLL_INTERVAL,
)
proof_ticket_manager = ProofTicketManager(
    secret=Config.PROOF_OF_ACCESS_SECRET,
    enabled=Config.PROOF_OF_ACCESS_ENABLED,
    ttl_seconds=Config.PROOF_OF_ACCESS_TTL,
)

if Config.PROOF_OF_ACCESS_ENABLED and not proof_ticket_manager.active:
    log.warning(
        "Proof-of-access is enabled but PROOF_OF_ACCESS_SECRET is shorter "
        "than 32 bytes; ticket issuance is disabled."
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

web_validation_service = WebValidationService(
    enabled=Config.ENABLE_WEB_VALIDATION,
    timeout=Config.WEB_VALIDATION_TIMEOUT,
    max_response_bytes=Config.WEB_VALIDATION_MAX_RESPONSE_BYTES,
    max_redirects=Config.WEB_VALIDATION_MAX_REDIRECTS,
    operating_system=Config.LAB_WEB_OS,
)

# Initialize web exploiter (actual reverse shell exploitation)
web_exploiter = WebExploiter(
    lhost=Config.KALI_IP,
    lport=4444,
)