# app.py
# Main Flask entrypoint for AutoPenTest

import os
import sys
from pathlib import Path
import logging

from flask import Flask

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import Config

from core.filters import register_filters
from core.services import init_services

from routes.ai_routes import register_routes as register_ai_routes
from routes.scan_routes import register_routes as register_scan_routes
from routes.caldera_routes import register_routes as register_caldera_routes
from routes.results_routes import register_routes as register_results_routes


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.secret_key = getattr(Config, "SECRET_KEY", "change-me")
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

    # Register Jinja filters
    register_filters(app)

    # Register route files
    register_ai_routes(app)
    register_scan_routes(app)
    register_caldera_routes(app)
    register_results_routes(app)

    # Initialise shared services such as database schema
    init_services()

    return app


app = create_app()


# ---------------------------------------------------
# RUN
# ---------------------------------------------------

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))

    # Bind to all interfaces by default so the dashboard is reachable from the
    # host browser and other lab VMs at http://<kali-ip>:5000.
    # Override with APP_HOST=127.0.0.1 if you only want local access.
    host = os.getenv("APP_HOST", "0.0.0.0")

    app.run(host=host, port=port, debug=True)