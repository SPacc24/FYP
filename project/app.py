# app.py
# Main Flask entrypoint for AutoPenTest

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from flask import Flask

# Ensure project root is on sys.path so local packages can be imported
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Load/create .env only when running app.py directly, if runtime_env exists
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

from routes.pentest_routes import register_routes as register_pentest_routes
from routes.operator_routes import register_routes as register_operator_routes
from routes.ai_routes import register_routes as register_ai_routes
from routes.scan_routes import register_routes as register_scan_routes
from routes.caldera_routes import register_routes as register_caldera_routes
from routes.results_routes import register_routes as register_results_routes


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    app.secret_key = getattr(Config, "SECRET_KEY", "change-me")
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

    # Jinja filters used by templates
    register_filters(app)

    # Shared services such as database schema, CALDERA clients, etc.
    init_services()

    # Register split route files
    register_operator_routes(app)
    register_ai_routes(app)
    register_scan_routes(app)
    register_caldera_routes(app)
    register_results_routes(app)
    register_pentest_routes(app)

    return app


app = create_app()


# ---------------------------------------------------
# RUN
# ---------------------------------------------------

if __name__ == "__main__":
    if ENV_BOOTSTRAP_RESULT is not None:
        try:
            from runtime_env import startup_messages

            for message in startup_messages(ENV_BOOTSTRAP_RESULT):
                print(message)
        except ImportError:
            pass

    port = int(os.getenv("PORT", "5000"))

    # Use APP_HOST=0.0.0.0 if you want to access it from host browser / lab VMs.
    host = os.getenv("APP_HOST", "0.0.0.0")

    app.run(host=host, port=port, debug=getattr(Config, "DEBUG", False))