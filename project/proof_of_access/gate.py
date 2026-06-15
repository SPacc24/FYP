import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import secrets
import threading
import time
from typing import Any, Callable


PURPOSE = "autopentest-proof-of-access"
QUALIFYING_TECHNIQUES = {
    "T1078",  # Valid Accounts
    "T1110",  # Brute Force / weak-credential validation
    "T1190",  # Exploit Public-Facing Application
}


class ProofTicketError(ValueError):
    """Raised when a proof ticket cannot be issued or redeemed safely."""


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (binascii.Error, ValueError, TypeError) as error:
        raise ProofTicketError("Invalid proof ticket encoding.") from error


def _normalise_host(value: Any) -> str:
    return str(value or "").strip().lower().split(".", 1)[0]


def _normalise_ip(value: Any) -> str:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def _qualifies(technique_id: Any) -> bool:
    base_id = str(technique_id or "").strip().upper().split(".", 1)[0]
    return base_id in QUALIFYING_TECHNIQUES


class ProofTicketManager:
    """
    Issues short-lived, one-time tickets only for successful access validation.

    The ticket is a bearer credential, but the signing secret stays on the
    controller. Target-side marker scripts redeem the ticket over HTTP and
    never receive the signing secret.
    """

    def __init__(
        self,
        secret: str,
        enabled: bool = False,
        ttl_seconds: int = 300,
        clock: Callable[[], float] = time.time,
    ):
        self.enabled = bool(enabled)
        self._secret = str(secret or "").encode("utf-8")
        self.ttl_seconds = max(30, min(int(ttl_seconds), 900))
        self._clock = clock
        self._issued: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    @property
    def active(self) -> bool:
        return self.enabled and len(self._secret) >= 32

    def issue_for_operation(self, operation_results: dict[str, Any]) -> list[dict[str, Any]]:
        if not self.active:
            return []

        if not operation_results.get("success") or operation_results.get("timed_out"):
            return []

        operation_id = str(operation_results.get("operation_id") or "").strip()
        agent_host = str(operation_results.get("agent_host") or "").strip()
        agent_ip_addrs = [
            normalised
            for normalised in (
                _normalise_ip(value)
                for value in operation_results.get("agent_ip_addrs", [])
            )
            if normalised
        ]

        if not operation_id or not agent_host:
            return []

        tickets = []
        now = int(self._clock())

        with self._lock:
            self._cleanup_locked(now)

            for step in operation_results.get("techniques_run", []):
                if step.get("status") != "success":
                    continue
                if not _qualifies(step.get("technique_id")):
                    continue

                link_id = str(step.get("link_id") or "").strip()
                completed_at = str(step.get("timestamp") or "").strip()
                if not link_id or not completed_at:
                    continue

                nonce = secrets.token_urlsafe(18)
                expires_at = now + self.ttl_seconds
                payload = {
                    "version": 1,
                    "purpose": PURPOSE,
                    "nonce": nonce,
                    "operation_id": operation_id,
                    "link_id": link_id,
                    "technique_id": str(step.get("technique_id") or ""),
                    "technique_name": str(step.get("technique_name") or ""),
                    "tactic": str(step.get("tactic") or ""),
                    "agent_host": agent_host,
                    "agent_ip_addrs": agent_ip_addrs,
                    "completed_at": completed_at,
                    "issued_at": now,
                    "expires_at": expires_at,
                }
                token = self._encode(payload)
                self._issued[nonce] = {
                    "expires_at": expires_at,
                    "redeemed": False,
                }
                tickets.append({
                    "ticket": token,
                    "expires_at": expires_at,
                    "operation_id": operation_id,
                    "link_id": link_id,
                    "technique_id": payload["technique_id"],
                    "agent_host": agent_host,
                })

        return tickets

    def redeem(
        self,
        ticket: str,
        observed_host: str,
        observed_ip: str = "",
    ) -> dict[str, Any]:
        if not self.active:
            raise ProofTicketError("Proof-of-access ticketing is disabled.")

        payload = self._decode(ticket)
        now = int(self._clock())
        nonce = str(payload.get("nonce") or "")
        expires_at = int(payload.get("expires_at") or 0)

        if payload.get("purpose") != PURPOSE or payload.get("version") != 1:
            raise ProofTicketError("Invalid proof ticket purpose.")
        if not nonce or now > expires_at:
            raise ProofTicketError("Proof ticket has expired.")
        if _normalise_host(observed_host) != _normalise_host(payload.get("agent_host")):
            raise ProofTicketError("Proof ticket is not valid for this host.")

        expected_ips = {
            normalised
            for normalised in (
                _normalise_ip(value)
                for value in payload.get("agent_ip_addrs", [])
            )
            if normalised
        }
        if expected_ips and _normalise_ip(observed_ip) not in expected_ips:
            raise ProofTicketError("Proof ticket is not valid for this source address.")

        with self._lock:
            self._cleanup_locked(now)
            issued = self._issued.get(nonce)
            if not issued or issued.get("expires_at") != expires_at:
                raise ProofTicketError("Proof ticket was not issued by this controller.")
            if issued.get("redeemed"):
                raise ProofTicketError("Proof ticket has already been redeemed.")
            issued["redeemed"] = True

        return payload

    def _encode(self, payload: dict[str, Any]) -> str:
        raw = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        body = _b64url_encode(raw)
        signature = hmac.new(
            self._secret,
            body.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return f"{body}.{signature}"

    def _decode(self, ticket: str) -> dict[str, Any]:
        try:
            body, supplied_signature = str(ticket or "").split(".", 1)
        except ValueError as error:
            raise ProofTicketError("Invalid proof ticket format.") from error

        expected_signature = hmac.new(
            self._secret,
            body.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ProofTicketError("Invalid proof ticket signature.")

        try:
            payload = json.loads(_b64url_decode(body).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProofTicketError("Invalid proof ticket payload.") from error

        if not isinstance(payload, dict):
            raise ProofTicketError("Invalid proof ticket payload.")
        return payload

    def _cleanup_locked(self, now: int) -> None:
        expired = [
            nonce
            for nonce, state in self._issued.items()
            if int(state.get("expires_at") or 0) < now
        ]
        for nonce in expired:
            self._issued.pop(nonce, None)
