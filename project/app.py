
from __future__ import annotations

import ipaddress
import logging
import os
import sys
from pathlib import Path

from flask import Flask


PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# Bootstrap local configuration before importing Config when the application is
# launched directly. Tests and WSGI servers can manage their own environment.
ENV_BOOTSTRAP_RESULT = None
if __name__ == "__main__":
    try:
        from runtime_env import ensure_env_file

        ENV_BOOTSTRAP_RESULT = ensure_env_file()
    except ImportError:
        ENV_BOOTSTRAP_RESULT = None


from config import Config
from core.filters import register_filters
from core.services import init_services
from routes.ai_routes import register_routes as register_ai_routes
from routes.caldera_routes import register_routes as register_caldera_routes
from routes.operator_routes import register_routes as register_operator_routes
from routes.pentest_routes import register_routes as register_pentest_routes
from routes.proof_routes import register_routes as register_proof_routes
from routes.results_routes import register_routes as register_results_routes
from routes.scan_routes import register_routes as register_scan_routes
from routes.pivot_routes import register_routes as register_pivot_routes
from routes.mission_routes import register_routes as register_mission_routes
from routes.smb_routes import register_routes as register_smb_routes
from routes.chain_routes import register_routes as register_chain_routes

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def _host_is_loopback(host: str) -> bool:
    value = str(host or "").strip().lower()
    if value in {"localhost", "::1"}:
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _validate_runtime_security(host: str) -> None:
    """Reject an unsafe non-loopback deployment before Flask starts."""

    if _host_is_loopback(host):
        return

    problems = []
    secret_key = str(getattr(Config, "SECRET_KEY", "") or "")
    if secret_key == "change-me" or len(secret_key) < 32:
        problems.append("SECRET_KEY must be a generated value of at least 32 characters")
    if not getattr(Config, "OPERATOR_TOKEN", "") and not getattr(
        Config,
        "ALLOW_INSECURE_OPERATOR_ACCESS",
        False,
    ):
        problems.append("OPERATOR_TOKEN must be configured")
    if getattr(Config, "DEBUG", False):
        problems.append("DEBUG must be false")

    if problems:
        raise RuntimeError(
            "Refusing non-loopback startup with unsafe settings: " + "; ".join(problems)
        )


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    app.secret_key = getattr(Config, "SECRET_KEY", "change-me")
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

    register_filters(app)
    init_services()

    # Keep the group member's split-route design. Operator routes also install
    # the shared authentication/CSRF guard used by every sensitive endpoint.
    register_operator_routes(app)
    register_proof_routes(app)
    register_ai_routes(app)
    register_scan_routes(app)
    register_caldera_routes(app)
    register_results_routes(app)
    register_pentest_routes(app)
    register_smb_routes(app)
    register_pivot_routes(app)
    register_mission_routes(app)
    register_chain_routes(app)
    return app


app = create_app()


if __name__ == "__main__":
    if ENV_BOOTSTRAP_RESULT is not None:
        try:
            from runtime_env import startup_messages

            for message in startup_messages(ENV_BOOTSTRAP_RESULT):
                print(message)
        except ImportError:
            pass

    port = int(os.getenv("PORT", "5000"))

    # Bind to all interfaces by default so the dashboard is reachable
    # from other laptops during the demo.
    host = os.getenv("APP_HOST", "0.0.0.0")

    _validate_runtime_security(host)

    app.run(
        host=host,
        port=port,
        debug=getattr(Config, "DEBUG", False),
    )