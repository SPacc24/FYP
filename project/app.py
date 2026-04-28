from flask import Flask, request, jsonify
from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager
import os
import atexit
import signal
import sys

app = Flask(__name__)


def get_operation_manager():
    client = CalderaClient()
    return OperationManager(client)


@app.route("/")
def index():
    return "AutoPenTest Flask app is running."


@app.route("/caldera/status", methods=["GET"])
def caldera_status():
    manager = get_operation_manager()
    return jsonify(manager.check_readiness())


@app.route("/caldera/run", methods=["POST"])
def caldera_run():
    data = request.get_json() or {}

    adversary_id = data.get("adversary_id")
    selected_techniques = data.get("selected_techniques", [])
    group = data.get("group", "red")
    planner_id = data.get("planner_id")

    if not adversary_id:
        return jsonify({
            "ok": False,
            "message": "Missing adversary_id."
        }), 400

    manager = get_operation_manager()

    result = manager.start_operation(
        adversary_id=adversary_id,
        selected_techniques=selected_techniques,
        group=group,
        planner_id=planner_id
    )

    status_code = 200 if result["ok"] else 400
    return jsonify(result), status_code


@app.route("/caldera/operation/<operation_id>", methods=["GET"])
def caldera_operation(operation_id):
    manager = get_operation_manager()
    return jsonify(manager.poll_operation(operation_id))


if __name__ == "__main__":
    app.run(debug=True)