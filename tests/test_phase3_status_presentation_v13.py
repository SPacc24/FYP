from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "project"


def _scan_store_module():
    import sys

    project_text = str(PROJECT)
    if project_text not in sys.path:
        sys.path.insert(0, project_text)
    from storage import scan_store

    return scan_store


def test_progress_summary_omits_raw_evidence_and_full_results():
    scan_store = _scan_store_module()
    scan_id = scan_store.new_scan("192.0.2.10")
    scan_store.append_tasks(scan_id, ["One", "Two"], phase="assessment")
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_ASSESSMENT_RUNNING,
        workflow_stage="assessment",
        assessment_started_at=scan_store.now(),
        results={
            "hosts": ["192.0.2.10"],
            "service_inventory": [],
            "large_private_result": "Y" * 50_000,
        },
    )
    scan_store.log_command(
        scan_id,
        command="example-tool --target 192.0.2.10",
        purpose="existing command evidence",
        output="X" * 50_000,
        output_summary="completed",
        status="Completed Successfully",
    )

    summary = scan_store.progress_summary(scan_id)
    serialized = json.dumps(summary)

    assert "results" not in summary
    assert "output" not in summary["command_log"][0]
    assert summary["command_log"][0]["command_index"] == 0
    assert "X" * 100 not in serialized
    assert "Y" * 100 not in serialized
    assert len(serialized) < 10_000


def test_progress_summary_surfaces_only_already_published_findings():
    scan_store = _scan_store_module()
    scan_id = scan_store.new_scan("192.0.2.20")
    scan_store.append_tasks(scan_id, ["One", "Two"], phase="assessment")
    scan_store.set_task(scan_id, "One", scan_store.STATUS_SUCCESS, summary="done")
    scan_store.set_task(scan_id, "Two", scan_store.STATUS_RUNNING)
    scan_store.update(
        scan_id,
        status=scan_store.STATUS_ASSESSMENT_RUNNING,
        workflow_stage="assessment",
        assessment_started_at=scan_store.now(),
        results={
            "hosts": ["192.0.2.20"],
            "service_inventory": [
                {
                    "host": "192.0.2.20",
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "product": "example-httpd",
                    "version": "1.0",
                },
                {
                    "host": "192.0.2.20",
                    "port": 53,
                    "protocol": "udp",
                    "state": "open",
                    "service": "domain",
                    "product": "example-dns",
                    "version": "",
                },
            ],
            "cve_matches": [{"cve_id": "CVE-EXAMPLE-0001"}],
        },
    )

    summary = scan_store.progress_summary(scan_id)
    findings = summary["live_findings"]

    assert summary["assessment_task_done"] == 1
    assert summary["assessment_task_total"] == 2
    assert summary["assessment_task_percent"] == 50.0
    assert findings["host_count"] == 1
    assert findings["tcp_service_count"] == 1
    assert findings["udp_service_count"] == 1
    assert findings["product_count"] == 2
    assert findings["versioned_endpoint_count"] == 1
    assert findings["cve_reference_count"] == 1
    assert findings["recent_services"][0]["service"] == "http"


def test_phase3_template_uses_lightweight_polling_and_on_demand_raw_evidence():
    source = (PROJECT / "templates" / "scanning.html").read_text(encoding="utf-8")

    assert "/scan/status-lite/" in source
    assert "/scan/command-evidence/" in source
    assert "Live Findings" in source
    assert "Phase 3 elapsed" in source
    assert "Last activity" in source
    assert "Intl.DateTimeFormat" in source
    assert "resolvedOptions().timeZone" in source
    assert "modalRecordedAt" in source
    assert "Raw tool output is preserved exactly as emitted" in source
    assert "Service Discovery (TCP/UDP)" in source
    assert "read-only" not in source.lower()


def test_existing_status_contract_is_preserved_and_new_routes_are_additive():
    source = (PROJECT / "routes" / "scan_routes.py").read_text(encoding="utf-8")

    assert '@app.route("/scan/status/<scan_id>")' in source
    assert "data = scan_store.progress(scan_id)" in source
    assert '@app.route("/scan/status-lite/<scan_id>")' in source
    assert "data = scan_store.progress_summary(scan_id)" in source
    assert '@app.route("/scan/command-evidence/<scan_id>/<int:command_index>")' in source
