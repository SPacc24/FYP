import logging

from config import Config

from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager
from caldera.coverage_checker import CoverageChecker
from caldera.risk_scorer import RiskScorer

from exploitation.validator import ExploitabilityValidator
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