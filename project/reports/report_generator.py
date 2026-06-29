import os
from datetime import datetime
from pathlib import Path
from typing import Any

REPORT_DIR = Path(__file__).resolve().parent.parent / "storage" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def _safe_text(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) if value else "None"
    return str(value)


def _section(title: str, lines: list[str]) -> str:
    border = "=" * max(len(title), 4)
    return f"{title}\n{border}\n" + "\n".join(lines) + "\n\n"


def _summarize_vulnerabilities(mapping: dict[str, Any]) -> list[str]:
    lines = []
    vulnerabilities = mapping.get("vulnerabilities", [])
    top = vulnerabilities[:5]

    if not vulnerabilities:
        return ["No vulnerability findings were mapped."]

    lines.append(f"Total mapped findings: {len(vulnerabilities)}")
    lines.append("Top findings:")
    for vuln in top:
        lines.append(
            f"- {vuln.get('host', 'Unknown')}:{vuln.get('port', 'N/A')} {vuln.get('service', 'unknown')} "
            f"[{vuln.get('severity', 'Unknown')}] {vuln.get('title', '')}"
        )
    if mapping.get("top_risks"):
        lines.append("\nRecommended focus areas:")
        for risk in mapping.get("top_risks", [])[:3]:
            lines.append(
                f"- {risk.get('host', 'Unknown')}:{risk.get('port', 'N/A')} "
                f"{risk.get('service', 'unknown')} - {risk.get('title', '')}"
            )
    return lines


def _summarize_scan_findings(scan: dict[str, Any]) -> list[str]:
    lines = [
        f"Target IP: {_safe_text(scan.get('target_ip', 'Unknown'))}",
        f"Detected OS: {_safe_text(scan.get('os', 'Unknown'))}",
        f"Port range: {_safe_text(scan.get('port_range', '1-1024'))}",
        f"Scan output: {_safe_text(scan.get('output_file', 'Not saved'))}",
    ]
    ports = scan.get("ports", []) or []
    if ports:
        lines.append("Open/reported services:")
        for port in ports[:20]:
            lines.append(
                f"- {port.get('port', 'N/A')}/{port.get('protocol', 'tcp')} "
                f"{port.get('state', 'unknown')} {port.get('service', 'unknown')} "
                f"{port.get('product', '')} {port.get('version', '')}".strip()
            )
    return lines


def _summarize_attack_plan(mapping: dict[str, Any]) -> list[str]:
    lines = []
    plan = mapping.get("caldera_plan", {})
    if not plan:
        return ["No planned Caldera techniques available."]

    lines.append(f"Selection reason: {plan.get('selection_reason', 'Not available')}")
    lines.append("Selected techniques:")
    for tech in plan.get("selected_techniques", []):
        lines.append(
            f"- {tech.get('id', 'N/A')} {tech.get('name', '')} "
            f"[{tech.get('attack_path_stage', 'Validation')}] ({tech.get('max_severity', '')})"
        )
    return lines


def _summarize_operation(operation: dict[str, Any]) -> list[str]:
    if not operation:
        return ["No Caldera operation has been executed yet."]

    lines = [
        f"Operation ID: {operation.get('operation_id', 'N/A')}",
        f"Operation name: {operation.get('operation_name', 'N/A')}",
        f"State: {operation.get('state', 'N/A')}",
        f"Total techniques executed: {operation.get('total', 0)}",
        f"Successful: {operation.get('success_count', 0)}",
        f"Failed: {operation.get('fail_count', 0)}",
        f"Timed out: {operation.get('timed_out', False)}",
    ]

    if operation.get("techniques_run"):
        lines.append("\nTechnique execution summary:")
        for step in operation.get("techniques_run", []):
            lines.append(
                f"- {step.get('technique_id', 'N/A')} {step.get('technique_name', '')} "
                f"[{step.get('tactic', 'unknown')}] - {step.get('status', 'unknown')}"
            )
            if step.get("command"):
                lines.append(f"  Command: {step.get('command')}")
            if step.get("evidence_summary"):
                lines.append(f"  Evidence summary: {step.get('evidence_summary')}")
            if step.get("parsed_evidence"):
                for evidence in step.get("parsed_evidence", [])[:6]:
                    lines.append(f"  - {evidence}")
            elif step.get("output"):
                output = str(step.get("output", "")).strip()
                lines.append(f"  Raw output: {output[:500]}")
            else:
                lines.append("  Execution completed but no evidence returned.")
    return lines


def _summarize_validation(validation: dict[str, Any]) -> list[str]:
    if not validation:
        return ["No lab exploitability validation has been executed yet."]

    lines = [
        f"Mode: {validation.get('mode', 'lab_safe_validation')}",
        f"Target: {validation.get('target', 'Unknown')}",
        f"Checks executed: {validation.get('total_checked', 0)}",
        f"Confirmed findings: {validation.get('confirmed', 0)}",
        f"Potential exposures: {validation.get('potential', 0)}",
        f"Failed checks: {validation.get('failed', 0)}",
        f"Summary: {validation.get('narrative', 'N/A')}",
    ]

    if validation.get("findings"):
        lines.append("\nValidation evidence:")
        for finding in validation.get("findings", []):
            lines.append(
                f"- {finding.get('status', 'unknown').upper()} "
                f"{finding.get('service', 'unknown')}:{finding.get('port', 'N/A')} "
                f"{finding.get('title', '')}"
            )
            lines.append(f"  Evidence: {finding.get('evidence', '')}")
            lines.append(f"  Next step: {finding.get('next_step', '')}")
    return lines


def _summarize_risk(risk: dict[str, Any]) -> list[str]:
    if not risk:
        return ["Risk score has not been calculated."]

    return [
        f"Final risk score: {risk.get('score', 'N/A')} / 10",
        f"Label: {risk.get('label', 'N/A')}",
        f"Badge: {risk.get('badge', 'N/A')}",
        f"Colour: {risk.get('colour', 'N/A')}",
        f"Breakdown: {risk.get('breakdown', {})}",
    ]


def _summarize_remediations(remediations: list[dict[str, Any]]) -> list[str]:
    if not remediations:
        return ["No remediation guidance is available."]

    lines: list[str] = []
    for advice in remediations:
        if advice.get("type") == "vulnerability":
            lines.append(
                f"- [VULN] {advice.get('severity', 'Unknown')} {advice.get('title', '')} "
                f"on {advice.get('affected_host', 'Unknown')}:{advice.get('affected_port', 'N/A')}"
            )
            lines.append(f"  Summary: {advice.get('summary', '')}")
            lines.append(f"  Fix: {advice.get('fixes', ['No fix available'])[0]}")
        else:
            lines.append(
                f"- [TECH] {advice.get('technique_id', 'N/A')} {advice.get('technique_name', '')} "
                f"({advice.get('tactic', 'unknown')})"
            )
            lines.append(f"  Summary: {advice.get('summary', '')}")
            fixes = advice.get('fixes', [])
            for fix in fixes[:3]:
                lines.append(f"    • {fix}")
            if advice.get('mitre_url'):
                lines.append(f"  MITRE ATT&CK: {advice.get('mitre_url')}")
    return lines


def build_report_summary(
    scan: dict[str, Any],
    mapping: dict[str, Any],
    operation: dict[str, Any],
    risk: dict[str, Any],
    remediations: list[dict[str, Any]],
    validation: dict[str, Any] | None = None,
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"AutoPenTest Report", f"Generated: {now}", ""]

    lines.append(_section("Target Summary", _summarize_scan_findings(scan)))

    lines.append(_section("Vulnerability Mapping", _summarize_vulnerabilities(mapping)))
    lines.append(_section("Attack Plan", _summarize_attack_plan(mapping)))
    lines.append(_section("Lab Exploitability Validation", _summarize_validation(validation or {})))
    lines.append(_section("Operation Results", _summarize_operation(operation)))
    lines.append(_section("Risk Summary", _summarize_risk(risk)))
    lines.append(_section("Remediation Guidance", _summarize_remediations(remediations)))

    return "\n".join(lines).strip() + "\n"


def generate_text_report(
    scan: dict[str, Any],
    mapping: dict[str, Any],
    operation: dict[str, Any],
    risk: dict[str, Any],
    remediations: list[dict[str, Any]],
    validation: dict[str, Any] | None = None,
) -> str:
    report_text = build_report_summary(scan, mapping, operation, risk, remediations, validation)
    path = REPORT_DIR / f"autopentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    path.write_text(report_text, encoding="utf-8")
    return str(path)


def generate_pdf_report(
    scan_id=None,
    scan=None,
    mapping=None,
    validation=None,
    operation=None,
    risk=None,
    remediations=None,
) -> str:
    if scan is None:
        scan = {}
    if mapping is None:
        mapping = {}
    if validation is None:
        validation = {}
    if operation is None:
        operation = {}
    if risk is None:
        risk = {}
    if remediations is None:
        remediations = []

    return generate_text_report(scan, mapping, operation, risk, remediations, validation)
