"""One-time proof-of-access ticket redemption endpoint."""

from flask import jsonify, request

from core.services import proof_ticket_manager
from proof_of_access import ProofTicketError


def register_routes(app):
    @app.route("/proof-of-access/redeem", methods=["POST"])
    def redeem_proof_of_access():
        data = request.get_json(silent=True) or {}

        try:
            proof = proof_ticket_manager.redeem(
                ticket=data.get("ticket", ""),
                observed_host=data.get("observed_host", ""),
                observed_ip=request.remote_addr or "",
            )
        except ProofTicketError:
            return jsonify({
                "ok": False,
                "error": (
                    "Proof ticket is invalid, expired, already used, "
                    "or for another host."
                ),
            }), 400

        return jsonify({"ok": True, "proof": proof})
