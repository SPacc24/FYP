#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def redeem_ticket(
    validator_url: str,
    ticket: str,
    observed_host: str,
    timeout: int = 10,
) -> dict[str, Any]:
    body = json.dumps({
        "ticket": ticket,
        "observed_host": observed_host,
    }).encode("utf-8")
    request = Request(
        validator_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
        raise RuntimeError("The controller rejected or could not validate the proof ticket.") from error

    proof = result.get("proof") if isinstance(result, dict) else None
    if not result.get("ok") or not isinstance(proof, dict):
        raise RuntimeError("The controller did not return a valid proof authorization.")
    return proof


def write_marker(
    proof: dict[str, Any],
    output_dir: Path,
    observed_host: str,
) -> Path:
    required = {
        "nonce",
        "operation_id",
        "link_id",
        "technique_id",
        "agent_host",
        "completed_at",
    }
    if not required.issubset(proof):
        raise ValueError("Proof authorization is missing required fields.")

    output_dir = output_dir.expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_dir.is_symlink():
        raise ValueError("Refusing to write proof into a symbolic-link directory.")

    evidence = {
        "proof_type": "controlled-access-validation",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "observed_host": observed_host,
        "operation_id": proof["operation_id"],
        "link_id": proof["link_id"],
        "technique_id": proof["technique_id"],
        "technique_name": proof.get("technique_name", ""),
        "tactic": proof.get("tactic", ""),
        "agent_host": proof["agent_host"],
        "completed_at": proof["completed_at"],
        "nonce": proof["nonce"],
    }
    canonical = json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    evidence["sha256"] = hashlib.sha256(canonical).hexdigest()

    safe_operation = re.sub(r"[^A-Za-z0-9_.-]", "_", str(proof["operation_id"]))
    safe_nonce = re.sub(r"[^A-Za-z0-9_.-]", "_", str(proof["nonce"]))
    marker_path = output_dir / f"proof_{safe_operation}_{safe_nonce}.json"

    descriptor = os.open(
        marker_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as marker_file:
        json.dump(evidence, marker_file, indent=2)
        marker_file.write("\n")

    return marker_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Write a harmless proof marker only after the AutoPenTest controller "
            "redeems a short-lived success ticket."
        )
    )
    parser.add_argument("--ticket-file", required=True, type=Path)
    parser.add_argument("--validator-url", required=True)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("proof-of-access"),
    )
    parser.add_argument("--timeout", type=int, default=10)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        ticket = args.ticket_file.read_text(encoding="utf-8").strip()
        if not ticket:
            raise ValueError("Ticket file is empty.")

        observed_host = socket.gethostname()
        proof = redeem_ticket(
            validator_url=args.validator_url,
            ticket=ticket,
            observed_host=observed_host,
            timeout=max(1, min(args.timeout, 30)),
        )
        marker_path = write_marker(
            proof=proof,
            output_dir=args.output_dir,
            observed_host=observed_host,
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Proof-of-access refused: {error}", file=sys.stderr)
        return 1

    print(f"Proof-of-access recorded: {marker_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
