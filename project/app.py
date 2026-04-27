from flask import Flask, request, jsonify
from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager
import os
import atexit
import signal
import sys
from utils.cleanup import full_cleanup

# register cleanup on exit
atexit.register(full_cleanup)

app = Flask(__name__)

# Initialize Caldera client
caldera_url = os.getenv("CALDERA_URL", "http://localhost:8888")
caldera_api_key = os.getenv("CALDERA_API_KEY", "ADMIN123")
caldera_client = CalderaClient(caldera_url, caldera_api_key)

def handle_exit(signum, frame):
    full_cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)   # Ctrl+C
signal.signal(signal.SIGTERM, handle_exit)  # kill

@app.route("/caldera/status")
def caldera_status():
    manager = OperationManager(caldera_client)
    return jsonify(manager.verify_agent_ready())

@app.route("/caldera/run", methods=["POST"])
def caldera_run():
    data = request.json
    adversary_id = data["adversary_id"]
    techniques = data.get("techniques", [])

    manager = OperationManager(caldera_client)
    result = manager.run_operation(adversary_id, techniques)
    return jsonify(result)

@app.route("/caldera/operation/<operation_id>")
def caldera_operation(operation_id):
    manager = OperationManager(caldera_client)
    return jsonify(manager.poll_operation(operation_id))

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)