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

    advice = validation.get("attack_advice") or {}
    if advice.get("attack_paths"):
        lines.append("\nOllama attack-path advice:")
        lines.append(f"Source: {advice.get('source', 'unknown')}")
        lines.append(f"Summary: {advice.get('summary', 'N/A')}")
        for path in advice.get("attack_paths", [])[:5]:
            lines.append(
                f"- {path.get('title', 'Safe validation path')} "
                f"({path.get('confidence', 'low')}) via {path.get('recommended_validation', 'manual_review')}"
            )
            lines.append(f"  Techniques: {_safe_text(path.get('technique_ids', []))}")
            lines.append(f"  Reasoning: {path.get('reasoning', '')}")
            lines.append(f"  Next step: {path.get('next_step', '')}")

    metasploit = validation.get("metasploit_results") or {}
    if metasploit.get("runs"):
        lines.append("\nMetasploit RPC execution records:")
        lines.append(f"Last summary: {metasploit.get('last_summary', 'N/A')}")
        for run in metasploit.get("runs", [])[:5]:
            action = run.get("action") or {}
            lines.append(
                f"- {run.get('timestamp', 'N/A')} "
                f"{action.get('module_type', 'module')}/{action.get('module_name', 'unknown')} "
                f"against {action.get('target', 'Unknown')}:{action.get('port', 'N/A')}"
            )
            lines.append(f"  Policy: {action.get('policy_key', 'N/A')} ({action.get('risk', 'unknown')} risk)")
            lines.append(f"  Result: {run.get('summary', 'N/A')}")
    return lines


def _summarize_pivot(pivot: dict[str, Any]) -> list[str]:
    if not pivot:
        return ["No pivot assessment has been performed."]

    lines = [
        f"Status: {_safe_text(pivot.get('status'))}",
        f"Summary: {_safe_text(pivot.get('summary'))}",
        f"Generated at: {_safe_text(pivot.get('generated_at'))}",
        f"Entry host: {_safe_text(pivot.get('entry_host'))}",
        f"CALDERA operation successful: {pivot.get('operation_success', False)}",
        f"Pivot possible: {pivot.get('pivot_possible', False)}",
        f"Post-pivot candidates: {pivot.get('candidate_count', 0)}",
        f"Pivot risk component: {pivot.get('risk_component', 0.0)}",
    ]

    # Future tunnel fields—displayed automatically when the backend provides them.
    tunnel_status = pivot.get("tunnel_status")
    if tunnel_status:
        lines.extend([
            "",
            "Tunnel details:",
            f"- Status: {_safe_text(tunnel_status)}",
            f"- Established at: {_safe_text(pivot.get('tunnel_started_at'))}",
            f"- Closed at: {_safe_text(pivot.get('tunnel_closed_at'))}",
        ])

    ai_plan = pivot.get("ai_plan") or {}
    if ai_plan:
        lines.append("\nPivot AI findings:")
        lines.append(
            f"- Summary: "
            f"{_safe_text(ai_plan.get('summary') or ai_plan.get('selection_reason'))}"
        )
        lines.append(
            f"- Selected techniques: "
            f"{_safe_text(ai_plan.get('selected_technique_ids', []))}"
        )

    pivot_mapping = pivot.get("mapping") or {}
    mitre_techniques = (
        pivot_mapping.get("recommended_techniques", []) or []
    )

    if mitre_techniques:
        lines.append("\nPivot MITRE ATT&CK findings:")

        for technique in mitre_techniques:
            lines.append(
                f"- {technique.get('id') or technique.get('technique_id', 'N/A')} "
                f"{technique.get('name') or technique.get('technique_name', '')} "
                f"[{technique.get('tactic', 'unknown')}]"
            )

            if technique.get("reason"):
                lines.append(
                    f"  Evidence: {technique.get('reason')}"
                )

    targets = pivot.get("reachable_targets", []) or []
    if targets:
        lines.append("\nDiscovered post-pivot targets:")

        for target in targets:
            host = target.get("host", "Unknown")
            hostname = target.get("hostname") or "N/A"

            lines.append(
                f"- {host} ({hostname}) | "
                f"OS: {target.get('os', 'Unknown')} | "
                f"Segment: {target.get('segment', 'unknown')} | "
                f"Relation: {target.get('segment_relation', 'unknown')} | "
                f"Live agent: {target.get('has_live_agent', False)}"
            )

            services = target.get("services", []) or []
            if services:
                lines.append("  Services:")

                for service in services:
                    lines.append(
                        f"  - {service.get('port', 'N/A')}/"
                        f"{service.get('protocol', 'tcp')} "
                        f"{service.get('state', 'unknown')} "
                        f"{service.get('service', 'unknown')} "
                        f"{service.get('product', '')} "
                        f"{service.get('version', '')}".strip()
                    )

            reasons = target.get("reasons", []) or []
            if reasons:
                lines.append("  Evidence:")

                for reason in reasons:
                    lines.append(f"  - {reason}")

    paths = pivot.get("paths", []) or []
    if paths:
        lines.append("\nAttack path / network topology:")

        for path in paths:
            relation = str(
                path.get("relation", "unknown")
            ).replace("_", " ")

            lines.append(
                f"- {path.get('from', 'Unknown')} "
                f"-> {path.get('to', 'Unknown')} "
                f"[{relation}]"
            )

            if path.get("reason"):
                lines.append(f"  Evidence: {path.get('reason')}")

    limitations = pivot.get("limitations", []) or []
    if limitations:
        lines.append("\nLimitations:")

        for limitation in limitations:
            lines.append(f"- {limitation}")

    return lines

def _summarize_missions(missions: list[dict[str, Any]]) -> list[str]:
    if not missions:
        return ["No mission has been orchestrated for this assessment."]

    lines: list[str] = []
    lines.append(f"Total missions: {len(missions)}")
    for mission in missions:
        lines.append(f"\n  Mission {mission.get('mission_id', 'N/A')}")
        lines.append(f"  Status: {_safe_text(mission.get('status'))}")
        lines.append(f"  Playbook: {_safe_text(mission.get('playbook_id'))}")
        lines.append(f"  Risk posture: {_safe_text(mission.get('risk_posture'))}")
        debrief = mission.get("debrief") or {}
        if debrief:
            lines.append(f"  Outcome: {_safe_text(debrief.get('reason'))}")
            lines.append(f"  Goal met: {_safe_text(debrief.get('goal_met'))}")
            lines.append(f"  Total actions: {debrief.get('total_actions', '?')}")
            lines.append(f"  Successful: {debrief.get('successful_actions', 0)}")
            lines.append(f"  Failed: {debrief.get('failed_actions', 0)}")
        queue = mission.get("action_queue") or []
        if queue:
            lines.append(f"  Action queue ({len(queue)} items):")
            for a in queue[:10]:
                lines.append(
                    f"    - {a.get('title') or a.get('catalog_key', '?')} "
                    f"[{a.get('status', '?')}] "
                    f"{a.get('target', '')}:{a.get('port', '')}"
                )
        proofs = mission.get("proofs") or []
        if proofs:
            lines.append(f"  Proofs ({len(proofs)}):")
            for p in proofs[:5]:
                lines.append(
                    f"    - {p.get('proof_type', '?')} "
                    f"{p.get('catalog_key', '')} "
                    f"({p.get('target', '')})"
                )
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


def _fallback_remediations(scan: dict[str, Any], mapping: dict[str, Any]) -> list[dict[str, Any]]:
    """Produce actionable baseline guidance when CALDERA-specific advice is absent."""
    ports = scan.get("ports") or scan.get("service_inventory") or []
    text = " ".join(str(x) for x in ports).lower() + " " + str(mapping).lower()
    fixes: list[str] = []
    if any(token in text for token in ("445", "139", "smb", "microsoft-ds", "netbios")):
        fixes += [
            "Disable SMBv1 where operationally possible and apply all supported Microsoft security updates.",
            "Restrict TCP 139/445 to trusted management and file-server segments only.",
            "Require SMB signing, strong unique credentials, and remove unnecessary administrative shares.",
        ]
    if any(token in text for token in ("3389", "rdp", "ms-wbt-server")):
        fixes += [
            "Restrict RDP to a VPN or management network, enable Network Level Authentication, and enforce MFA where supported.",
            "Review RDP account lockout, logging, and permitted user groups.",
        ]
    if any(token in text for token in ("5985", "winrm", "wsman")):
        fixes += [
            "Restrict WinRM to approved administration hosts and prefer HTTPS transport with strong authentication.",
        ]
    if any(token in text for token in ("windows xp", "server 2003")):
        fixes.insert(0, "Migrate the unsupported legacy Windows host to a currently supported operating system.")
    fixes.append("Re-run the assessment after remediation and compare the new evidence with this baseline.")
    unique=[]
    for fix in fixes:
        if fix not in unique: unique.append(fix)
    return [{
        "type": "baseline",
        "technique_id": "HARDENING",
        "technique_name": "Evidence-based hardening",
        "tactic": "remediation",
        "summary": "Baseline remediation generated from observed services and platform evidence.",
        "fixes": unique,
    }]


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
    pivot: dict[str, Any] | None = None,
    missions: list[dict[str, Any]] | None = None,
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"AutoPenTest Report", f"Generated: {now}", ""]

    lines.append(_section("Target Summary", _summarize_scan_findings(scan)))

    lines.append(_section("Vulnerability Mapping", _summarize_vulnerabilities(mapping)))
    lines.append(_section("Attack Plan", _summarize_attack_plan(mapping)))
    lines.append(_section("Lab Exploitability Validation", _summarize_validation(validation or {})))
    lines.append(_section("Operation Results", _summarize_operation(operation)))
    lines.append(
    _section(
        "Lateral Movement / Pivot Assessment",
        _summarize_pivot(pivot or {}),
        )
    )
    lines.append(_section("Risk Summary", _summarize_risk(risk)))
    lines.append(_section("Mission Orchestration", _summarize_missions(missions or [])))
    effective_remediations = remediations or _fallback_remediations(scan, mapping)
    lines.append(_section("Remediation Guidance", _summarize_remediations(effective_remediations)))

    return "\n".join(lines).strip() + "\n"


def generate_text_report(
    scan: dict[str, Any],
    mapping: dict[str, Any],
    operation: dict[str, Any],
    risk: dict[str, Any],
    remediations: list[dict[str, Any]],
    validation: dict[str, Any] | None = None,
    pivot: dict[str, Any] | None = None,
    missions: list[dict[str, Any]] | None = None,
) -> str:
    report_text = build_report_summary(scan, mapping, operation, risk, remediations, validation, pivot, missions)
    path = REPORT_DIR / f"autopentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    path.write_text(report_text, encoding="utf-8")
    return str(path)


def generate_pdf_report(
    scan_id: str = "",
    scan: dict[str, Any] | None = None,
    mapping: dict[str, Any] | None = None,
    validation: dict[str, Any] | None = None,
    operation: dict[str, Any] | None = None,
    risk: dict[str, Any] | None = None,
    remediations: list[dict[str, Any]] | None = None,
    pivot: dict[str, Any] | None = None,
    missions: list[dict[str, Any]] | None = None,
) -> str:
    """Generate a real PDF when ReportLab is available; otherwise a .txt fall-back.

    Never wrote binary-looking .pdf files that were actually plain text.
    """
    if scan is None:
        scan = {}
    if mapping is None:
        mapping = {}
    if validation is None:
        validation = {}
    if pivot is None:
        pivot = {}
    if operation is None:
        operation = {}
    if risk is None:
        risk = {}
    if remediations is None:
        remediations = []

    report_text = build_report_summary(
        scan, mapping, operation, risk, remediations, validation, pivot, missions
    )
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
        from reportlab.lib.units import mm
        from xml.sax.saxutils import escape

        path = REPORT_DIR / f"autopentest_report_{stamp}.pdf"
        doc = SimpleDocTemplate(
            str(path),
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=16 * mm,
            bottomMargin=16 * mm,
        )
        styles = getSampleStyleSheet()
        body = styles["BodyText"]
        body.fontSize = 9
        body.leading = 12
        story: list[Any] = []
        for line in report_text.splitlines():
            if not line.strip():
                story.append(Spacer(1, 4))
                continue
            story.append(Paragraph(escape(line).replace(" ", "&nbsp;"), body))
        doc.build(story)
        return str(path)
    except Exception:
        path = REPORT_DIR / f"autopentest_report_{stamp}.txt"
        path.write_text(report_text, encoding="utf-8")
        return str(path)