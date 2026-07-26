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

    # report_text = build_report_summary(
    #        scan, mapping, operation, risk, remediations, validation, pivot, missions
    # )
     
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
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

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#6D5DFC"),
            spaceAfter=8,
        )

        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#666666"),
            spaceAfter=20,
        )

        section_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#2E2559"),
            spaceBefore=14,
            spaceAfter=8,
        )

        body = ParagraphStyle(
            "ReportBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#222222"),
            spaceAfter=3,
        )

        story: list[Any] = []
        story.append(Spacer(1, 35))

        story.append(Paragraph("AutoPenTest", title_style))
        story.append(Paragraph("Automated Penetration Testing Report", subtitle_style))

        story.append(
            Paragraph(
                f"<b>Generated:</b> {datetime.now().strftime('%d %B %Y %H:%M')}",
                subtitle_style,
            )
        )

        if scan_id:
            story.append(
                Paragraph(
                    f"<b>Scan ID:</b> {escape(scan_id)}",
                    subtitle_style,
                )
            )

        story.append(Spacer(1, 30))
        info_data = [
            ["Target", _safe_text(scan.get("target_ip", "Unknown"))],
            ["Operating System", _safe_text(scan.get("os", "Unknown"))],
            ["Report Generated", datetime.now().strftime("%d %B %Y %H:%M")],
        ]

        info_table = Table(info_data, colWidths=[55 * mm, 105 * mm])

        info_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F0FF")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ])
        )

        story.append(info_table)
        story.append(PageBreak())

        story.append(Paragraph("Executive Summary", section_style))
        story.append(Spacer(1, 6))

        story.append(
            Paragraph(
                "This report summarises the findings from the automated penetration testing assessment, "
                "including discovered services, identified vulnerabilities, MITRE ATT&CK mappings, "
                "adversary emulation results, and remediation recommendations.",
                body,
            )
        )

        story.append(Spacer(1, 12))

        # =========================================================
        # HELPER FOR SAFE, WRAPPING TABLE CELLS
        # =========================================================
        def pdf_cell(value):
            """
            Convert any value into a ReportLab Paragraph.

            Paragraph cells wrap automatically instead of overflowing
            into neighbouring columns.
            """
            return Paragraph(
                escape(_safe_text(value)),
                body,
            )


        # =========================================================
        # OPEN SERVICES
        # =========================================================
        story.append(Paragraph("Open Services", section_style))
        story.append(Spacer(1, 6))

        ports = scan.get("ports", []) or []

        if ports:
            port_data = [
                ["Port", "Protocol", "State", "Service", "Product", "Version"]
            ]

            for port in ports:
                port_data.append([
                    pdf_cell(port.get("port", "N/A")),
                    pdf_cell(
                        _safe_text(port.get("protocol", "tcp")).upper()
                    ),
                    pdf_cell(port.get("state", "unknown")),
                    pdf_cell(port.get("service", "unknown")),
                    pdf_cell(port.get("product", "")),
                    pdf_cell(port.get("version", "")),
                ])

            port_table = Table(
                port_data,
                colWidths=[
                    15 * mm,
                    19 * mm,
                    18 * mm,
                    30 * mm,
                    48 * mm,
                    30 * mm,
                ],
                repeatRows=1,
            )

            port_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E2559")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FAFAFA")),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )

            story.append(port_table)

        else:
            story.append(
                Paragraph(
                    "No open or reported services were found.",
                    body,
                )
            )

        story.append(Spacer(1, 14))


        # =========================================================
        # VULNERABILITY FINDINGS
        # =========================================================
        story.append(Paragraph("Vulnerability Findings", section_style))
        story.append(Spacer(1, 6))

        vulnerabilities = mapping.get("vulnerabilities", []) or []

        if vulnerabilities:
            vulnerability_data = [
                ["Severity", "Host", "Port", "Service", "Finding"]
            ]

            for vulnerability in vulnerabilities:
                vulnerability_data.append([
                    pdf_cell(
                        _safe_text(
                            vulnerability.get("severity", "Unknown")
                        ).title()
                    ),
                    pdf_cell(vulnerability.get("host", "Unknown")),
                    pdf_cell(vulnerability.get("port", "N/A")),
                    pdf_cell(vulnerability.get("service", "unknown")),
                    pdf_cell(
                        vulnerability.get("title", "Untitled finding")
                    ),
                ])

            vulnerability_table = Table(
                vulnerability_data,
                colWidths=[
                    21 * mm,
                    29 * mm,
                    15 * mm,
                    27 * mm,
                    68 * mm,
                ],
                repeatRows=1,
            )

            vulnerability_style = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E2559")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]

            for row_number, vulnerability in enumerate(
                vulnerabilities,
                start=1,
            ):
                severity = str(
                    vulnerability.get("severity", "")
                ).lower()

                if severity == "critical":
                    background = colors.HexColor("#FDE8E8")
                elif severity == "high":
                    background = colors.HexColor("#FFF0E0")
                elif severity == "medium":
                    background = colors.HexColor("#FFF8D8")
                elif severity == "low":
                    background = colors.HexColor("#E8F5E9")
                else:
                    background = colors.HexColor("#F5F5F5")

                vulnerability_style.append(
                    (
                        "BACKGROUND",
                        (0, row_number),
                        (-1, row_number),
                        background,
                    )
                )

            vulnerability_table.setStyle(
                TableStyle(vulnerability_style)
            )

            story.append(vulnerability_table)

        else:
            story.append(
                Paragraph(
                    "No vulnerability findings were mapped.",
                    body,
                )
            )

        story.append(Spacer(1, 14))


        # =========================================================
        # MITRE ATT&CK MAPPING
        # =========================================================
        story.append(Paragraph("MITRE ATT&CK Mapping", section_style))
        story.append(Spacer(1, 6))

        plan = mapping.get("caldera_plan", {}) or {}
        techniques = plan.get("selected_techniques", []) or []

        if techniques:
            mitre_data = [
                ["Technique ID", "Technique", "Stage", "Severity"]
            ]

            for technique in techniques:
                mitre_data.append([
                    pdf_cell(technique.get("id", "N/A")),
                    pdf_cell(technique.get("name", "Unknown technique")),
                    pdf_cell(
                        technique.get(
                            "attack_path_stage",
                            "N/A",
                        )
                    ),
                    pdf_cell(
                        technique.get(
                            "max_severity",
                            "N/A",
                        )
                    ),
                ])

            mitre_table = Table(
                mitre_data,
                colWidths=[
                    27 * mm,
                    63 * mm,
                    48 * mm,
                    22 * mm,
                ],
                repeatRows=1,
            )

            mitre_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E2559")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FAFAFA")),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )

            story.append(mitre_table)

        else:
            story.append(
                Paragraph(
                    "No MITRE ATT&CK techniques were selected.",
                    body,
                )
            )

        story.append(Spacer(1, 14))


        # =========================================================
        # CALDERA OPERATION RESULTS
        # =========================================================
        story.append(
            Paragraph(
                "CALDERA Operation Results",
                section_style,
            )
        )
        story.append(Spacer(1, 6))

        if operation:
            operation_data = [
                [
                    "Operation ID",
                    pdf_cell(operation.get("operation_id", "N/A")),
                ],
                [
                    "Operation Name",
                    pdf_cell(operation.get("operation_name", "N/A")),
                ],
                [
                    "State",
                    pdf_cell(operation.get("state", "N/A")),
                ],
                [
                    "Techniques Executed",
                    pdf_cell(operation.get("total", 0)),
                ],
                [
                    "Successful",
                    pdf_cell(operation.get("success_count", 0)),
                ],
                [
                    "Failed",
                    pdf_cell(operation.get("fail_count", 0)),
                ],
                [
                    "Timed Out",
                    pdf_cell(operation.get("timed_out", False)),
                ],
            ]

            operation_table = Table(
                operation_data,
                colWidths=[
                    45 * mm,
                    115 * mm,
                ],
            )

            operation_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F0FF")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )

            story.append(operation_table)

            techniques_run = operation.get("techniques_run", []) or []

            if techniques_run:
                story.append(Spacer(1, 10))

                execution_data = [
                    ["Technique ID", "Technique", "Tactic", "Status"]
                ]

                for technique in techniques_run:
                    execution_data.append([
                        pdf_cell(
                            technique.get("technique_id", "N/A")
                        ),
                        pdf_cell(
                            technique.get("technique_name", "")
                        ),
                        pdf_cell(
                            technique.get("tactic", "unknown")
                        ),
                        pdf_cell(
                            _safe_text(
                                technique.get("status", "unknown")
                            ).title()
                        ),
                    ])

                execution_table = Table(
                    execution_data,
                    colWidths=[
                        27 * mm,
                        66 * mm,
                        39 * mm,
                        28 * mm,
                    ],
                    repeatRows=1,
                )

                execution_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E2559")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FAFAFA")),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ])
                )

                story.append(execution_table)

        else:
            story.append(
                Paragraph(
                    "No CALDERA operation has been executed yet.",
                    body,
                )
            )

        story.append(Spacer(1, 14))


        # =========================================================
        # RISK SUMMARY
        # =========================================================
        story.append(Paragraph("Risk Summary", section_style))
        story.append(Spacer(1, 6))

        risk_score = _safe_text(risk.get("score", "N/A"))
        risk_label = _safe_text(
            risk.get("label", "N/A")
        ).title()

        risk_data = [
            [
                "Overall Risk Score",
                pdf_cell(f"{risk_score} / 10"),
            ],
            [
                "Risk Level",
                pdf_cell(risk_label),
            ],
        ]

        risk_table = Table(
            risk_data,
            colWidths=[
                45 * mm,
                115 * mm,
            ],
        )

        risk_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F0FF")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )

        story.append(risk_table)
        story.append(Spacer(1, 14))


        # =========================================================
        # LAB EXPLOITABILITY VALIDATION
        # =========================================================
        story.append(
            Paragraph(
                "Lab Exploitability Validation",
                section_style,
            )
        )
        story.append(Spacer(1, 6))

        validation = validation or {}

        validation_data = [
            [
                "Mode",
                pdf_cell(validation.get("mode", "N/A")),
            ],
            [
                "Target",
                pdf_cell(validation.get("target", "N/A")),
            ],
            [
                "Checks Executed",
                pdf_cell(validation.get("total_checked", 0)),
            ],
            [
                "Confirmed",
                pdf_cell(validation.get("confirmed", 0)),
            ],
            [
                "Potential",
                pdf_cell(validation.get("potential", 0)),
            ],
            [
                "Failed",
                pdf_cell(validation.get("failed", 0)),
            ],
        ]

        validation_table = Table(
            validation_data,
            colWidths=[
                45 * mm,
                115 * mm,
            ],
        )

        validation_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F0FF")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )

        story.append(validation_table)
        story.append(Spacer(1, 14))


        # =========================================================
        # PIVOT ASSESSMENT
        # =========================================================
        story.append(Paragraph("Pivot Assessment", section_style))
        story.append(Spacer(1, 6))

        pivot = pivot or {}

        pivot_data = [
            [
                "Status",
                pdf_cell(pivot.get("status", "N/A")),
            ],
            [
                "Entry Host",
                pdf_cell(pivot.get("entry_host", "N/A")),
            ],
            [
                "Pivot Possible",
                pdf_cell(pivot.get("pivot_possible", False)),
            ],
            [
                "Reachable Targets",
                pdf_cell(pivot.get("candidate_count", 0)),
            ],
        ]

        pivot_table = Table(
            pivot_data,
            colWidths=[
                45 * mm,
                115 * mm,
            ],
        )

        pivot_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F0FF")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )

        story.append(pivot_table)
        story.append(Spacer(1, 14))


        # =========================================================
        # REMEDIATION RECOMMENDATIONS
        # =========================================================
        story.append(
            Paragraph(
                "Remediation Recommendations",
                section_style,
            )
        )
        story.append(Spacer(1, 6))

        if remediations:
            remediation_data = [
                ["Type", "Recommendation"]
            ]

            for item in remediations:
                fixes = item.get("fixes", []) or []

                if fixes:
                    fixes_text = "<br/>".join(
                        f"• {escape(_safe_text(fix))}"
                        for fix in fixes[:3]
                    )
                else:
                    fixes_text = "No recommendation provided."

                remediation_data.append([
                    pdf_cell(
                        _safe_text(
                            item.get("type", "General")
                        ).title()
                    ),
                    Paragraph(
                        fixes_text,
                        body,
                    ),
                ])

            remediation_table = Table(
                remediation_data,
                colWidths=[
                    35 * mm,
                    125 * mm,
                ],
                repeatRows=1,
            )

            remediation_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E2559")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FAFAFA")),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )

            story.append(remediation_table)

        else:
            story.append(
                Paragraph(
                    "No remediation recommendations available.",
                    body,
                )
            )

        story.append(Spacer(1, 14))

        
        doc.build(story)
        return str(path)
    
    except Exception:
        report_text = build_report_summary(
            scan,
            mapping,
            operation,
            risk,
            remediations,
            validation,
            pivot,
            missions,
        )

        path = REPORT_DIR / f"autopentest_report_{stamp}.txt"
        path.write_text(report_text, encoding="utf-8")
        return str(path)