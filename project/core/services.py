import logging

from config import Config

from caldera.api_client import CalderaClient
from caldera.coverage_checker import CoverageChecker
from caldera.operation_manager import OperationManager
from caldera.risk_scorer import RiskScorer

from exploitation.metasploit_client import MetasploitRpcClient
from exploitation.metasploit_service import MetasploitService
from exploitation.smb_exploiter import SmbExploiter
from exploitation.validator import ExploitabilityValidator
from exploitation.web_exploiter import WebExploiter
from exploitation.web_validator import WebValidationService

from proof_of_access import ProofTicketManager
from storage.db import Database


log = logging.getLogger(__name__)


# ── CALDERA services ──────────────────────────────────────────────────

caldera_client = CalderaClient(
    base_url=Config.CALDERA_URL,
    api_key=Config.CALDERA_KEY,
)

operation_manager = OperationManager(caldera_client)
coverage_checker = CoverageChecker(caldera_client)
risk_scorer = RiskScorer()


# ── Validation services ───────────────────────────────────────────────

exploitability_validator = ExploitabilityValidator()

web_validation_service = WebValidationService(
    enabled=Config.ENABLE_WEB_VALIDATION,
    timeout=Config.WEB_VALIDATION_TIMEOUT,
    max_response_bytes=Config.WEB_VALIDATION_MAX_RESPONSE_BYTES,
    max_redirects=Config.WEB_VALIDATION_MAX_REDIRECTS,
    operating_system=Config.LAB_WEB_OS,
)


# ── Controlled web lab service ────────────────────────────────────────

web_exploiter = WebExploiter(
    lhost=Config.WEB_CALLBACK_ADVERTISE_HOST,
    lport=Config.WEB_CALLBACK_PORT,
    bind_host=Config.WEB_CALLBACK_BIND_HOST,
    callback_host=Config.WEB_CALLBACK_ADVERTISE_HOST,
    callback_port=Config.WEB_CALLBACK_PORT,
    callback_timeout=Config.WEB_CALLBACK_TIMEOUT,
    callback_max_bytes=Config.WEB_CALLBACK_MAX_BYTES,
)


# ── Controlled SMB lab service ────────────────────────────────────────

smb_exploiter = SmbExploiter(
    enabled=Config.ENABLE_SMB_EXPLOITATION,
)


# ── Metasploit services ───────────────────────────────────────────────

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
    session_timeout=Config.METASPLOIT_SESSION_TIMEOUT,
    session_poll_interval=Config.METASPLOIT_SESSION_POLL_INTERVAL,
)


# ── Proof-of-access service ───────────────────────────────────────────

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


# ── Database ──────────────────────────────────────────────────────────

db = Database(
    host=Config.MYSQL_HOST,
    user=Config.MYSQL_USER,
    password=Config.MYSQL_PASS,
    database=Config.MYSQL_DB,
)


def init_services() -> None:
    """Initialize services that require startup-time actions."""

    try:
        db.init_schema()
    except Exception:
        log.exception(
            "Database schema initialization skipped or failed"
        )