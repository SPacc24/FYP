import os
from datetime import datetime
from pathlib import Path
from typing import Any

REPORT_DIR = Path(__file__).resolve().parent.parent / "storage" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def _safe_text(value: Any, default: str = "N/A") -> str:
    if value is None:
        return default
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) if value else "None"
    if isinstance(value, dict):
        return ", ".join(f"{key}: {value}" for key, value in value.items())
    return str(value)


def _section(title: str, lines: list[str]) -> str:
    border = "=" * len(title)
    return f"{title}\n{border}\n" + "\n".join(lines) + "\n\n"


def _summarize_scan(scan: dict[str, Any]) -> list[str]:
    lines = [
        f"Target IP: {_safe_text(scan.get('target_ip'), 'Unknown')}",
        f"Detected OS: {_safe_text(scan.get('os'), 'Unknown')}",
        f"Port range: {_safe_text(scan.get('port_range'), '1-1024')}",
        f"Scan output: {_safe_text(scan.get('output_file'), 'Not saved')}",
    ]

    ports = scan.get("ports") or scan.get("service_inventory") or []
    if not ports:
        lines.append("Open/reported services: None")
        return lines

    lines.append("Open/reported services:")
    for port in ports:
        service = " ".join(
            str(value)
            for value in (
                port.get("service", ""),
                port.get("product", ""),
                port.get("version", ""),
            )
            if value
        ).strip()

        lines.append(
            f"- {port.get('port', 'N/A')}/"
            f"{port.get('protocol', 'tcp')} "
            f"{port.get('state', 'unknown')} "
            f"{service or 'unknown'}"
        )

    return lines


def _summarize_vulnerabilities(mapping: dict[str, Any]) -> list[str]:
    vulnerabilities = mapping.get("vulnerabilities") or []

    if not vulnerabilities:
        return ["No vulnerability findings were mapped."]

    lines = [f"Total mapped findings: {len(vulnerabilities)}", "Findings:"]

    for vulnerability in vulnerabilities:
        lines.append(
            f"- {vulnerability.get('host', 'Unknown')}:"
            f"{vulnerability.get('port', 'N/A')} "
            f"{vulnerability.get('service', 'unknown')} "
            f"[{vulnerability.get('severity', 'Unknown')}] "
            f"{vulnerability.get('title', 'Untitled finding')}"
        )

    top_risks = mapping.get("top_risks") or []
    if top_risks:
        lines.append("")
        lines.append("Recommended focus areas:")
        for risk in top_risks:
            lines.append(
                f"- {risk.get('host', 'Unknown')}:"
                f"{risk.get('port', 'N/A')} "
                f"{risk.get('service', 'unknown')} - "
                f"{risk.get('title', 'Untitled finding')}"
            )

    return lines


def _summarize_attack_plan(mapping: dict[str, Any]) -> list[str]:
    plan = mapping.get("caldera_plan") or {}

    if not plan:
        return ["No planned MITRE ATT&CK techniques are available."]

    lines = [
        f"Selection reason: "
        f"{_safe_text(plan.get('selection_reason'), 'Not available')}"
    ]

    techniques = plan.get("selected_techniques") or []
    if not techniques:
        lines.append("Selected techniques: None")
        return lines

    lines.append("Selected techniques:")
    for technique in techniques:
        lines.append(
            f"- {technique.get('id', 'N/A')} "
            f"{technique.get('name', 'Unknown technique')} "
            f"[{technique.get('attack_path_stage', 'Validation')}] "
            f"({technique.get('max_severity', 'N/A')})"
        )

    return lines


def _summarize_validation(validation: dict[str, Any]) -> list[str]:
    if not validation:
        return ["No lab exploitability validation has been executed yet."]

    lines = [
        f"Mode: {_safe_text(validation.get('mode'), 'lab_safe_validation')}",
        f"Target: {_safe_text(validation.get('target'), 'Unknown')}",
        f"Checks executed: {validation.get('total_checked', 0)}",
        f"Confirmed findings: {validation.get('confirmed', 0)}",
        f"Potential exposures: {validation.get('potential', 0)}",
        f"Failed checks: {validation.get('failed', 0)}",
        f"Summary: {_safe_text(validation.get('narrative'))}",
    ]

    findings = validation.get("findings") or []
    if findings:
        lines.append("")
        lines.append("Validation evidence:")
        for finding in findings:
            lines.append(
                f"- {str(finding.get('status', 'unknown')).upper()} "
                f"{finding.get('service', 'unknown')}:"
                f"{finding.get('port', 'N/A')} "
                f"{finding.get('title', 'Untitled finding')}"
            )
            if finding.get("evidence"):
                lines.append(f"  Evidence: {finding['evidence']}")
            if finding.get("next_step"):
                lines.append(f"  Next step: {finding['next_step']}")

    advice = validation.get("attack_advice") or {}
    attack_paths = advice.get("attack_paths") or []
    if attack_paths:
        lines.extend(
            [
                "",
                "Ollama attack-path advice:",
                f"Source: {_safe_text(advice.get('source'), 'unknown')}",
                f"Summary: {_safe_text(advice.get('summary'))}",
            ]
        )

        for path in attack_paths:
            lines.append(
                f"- {path.get('title', 'Safe validation path')} "
                f"({path.get('confidence', 'low')}) via "
                f"{path.get('recommended_validation', 'manual_review')}"
            )
            lines.append(
                f"  Techniques: "
                f"{_safe_text(path.get('technique_ids', []))}"
            )
            if path.get("reasoning"):
                lines.append(f"  Reasoning: {path['reasoning']}")
            if path.get("next_step"):
                lines.append(f"  Next step: {path['next_step']}")

    metasploit = validation.get("metasploit_results") or {}
    runs = metasploit.get("runs") or []
    if runs:
        lines.extend(
            [
                "",
                "Metasploit RPC execution records:",
                f"Last summary: {_safe_text(metasploit.get('last_summary'))}",
            ]
        )

        for run in runs:
            action = run.get("action") or {}
            lines.append(
                f"- {_safe_text(run.get('timestamp'))} "
                f"{action.get('module_type', 'module')}/"
                f"{action.get('module_name', 'unknown')} "
                f"against {action.get('target', 'Unknown')}:"
                f"{action.get('port', 'N/A')}"
            )
            lines.append(
                f"  Policy: {action.get('policy_key', 'N/A')} "
                f"({action.get('risk', 'unknown')} risk)"
            )
            lines.append(
                f"  Result: {_safe_text(run.get('summary'))}"
            )

    return lines


def _summarize_operation(operation: dict[str, Any]) -> list[str]:
    if not operation:
        return ["No CALDERA operation has been executed yet."]

    lines = [
        f"Operation ID: {_safe_text(operation.get('operation_id'))}",
        f"Operation name: {_safe_text(operation.get('operation_name'))}",
        f"State: {_safe_text(operation.get('state'))}",
        f"Total techniques executed: {operation.get('total', 0)}",
        f"Successful: {operation.get('success_count', 0)}",
        f"Failed: {operation.get('fail_count', 0)}",
        f"Timed out: {operation.get('timed_out', False)}",
    ]

    techniques = operation.get("techniques_run") or []
    if not techniques:
        return lines

    lines.extend(["", "Technique execution summary:"])

    for technique in techniques:
        lines.append(
            f"- {technique.get('technique_id', 'N/A')} "
            f"{technique.get('technique_name', '')} "
            f"[{technique.get('tactic', 'unknown')}] - "
            f"{technique.get('status', 'unknown')}"
        )

        if technique.get("command"):
            lines.append(f"  Command: {technique['command']}")

        if technique.get("evidence_summary"):
            lines.append(
                f"  Evidence summary: {technique['evidence_summary']}"
            )

        parsed = technique.get("parsed_evidence") or []
        if parsed:
            for evidence in parsed[:6]:
                lines.append(f"  - {evidence}")
        elif technique.get("output"):
            output = str(technique["output"]).strip()
            lines.append(f"  Raw output: {output[:500]}")
        else:
            lines.append("  Execution completed but no evidence returned.")

    return lines

def _summarize_risk(risk: dict[str, Any]) -> list[str]:
    if not risk:
        return ["Risk score has not been calculated."]

    return [
        f"Final risk score: {_safe_text(risk.get('score'))} / 10",
        f"Label: {_safe_text(risk.get('label'))}",
        f"Breakdown: {_safe_text(risk.get('breakdown'))}",
    ]


def _fallback_remediations(
    scan: dict[str, Any],
    mapping: dict[str, Any],
) -> list[dict[str, Any]]:
    ports = scan.get("ports") or scan.get("service_inventory") or []
    text = f"{ports} {mapping}".lower()

    fixes: list[str] = []

    if any(token in text for token in (
        "445", "139", "smb", "microsoft-ds", "netbios"
    )):
        fixes.extend(
            [
                "Disable SMBv1 where operationally possible and apply supported Microsoft security updates.",
                "Restrict TCP 139/445 to trusted management and file-server segments.",
                "Require SMB signing, strong unique credentials, and remove unnecessary administrative shares.",
            ]
        )

    if any(token in text for token in (
        "3389", "rdp", "ms-wbt-server"
    )):
        fixes.extend(
            [
                "Restrict RDP to approved management networks or VPN access.",
                "Enable Network Level Authentication and enforce MFA where supported.",
                "Review RDP account lockout, logging, and permitted user groups.",
            ]
        )

    if any(token in text for token in (
        "5985", "5986", "winrm", "wsman"
    )):
        fixes.append(
            "Restrict WinRM to approved administration hosts and prefer HTTPS transport with strong authentication."
        )

    if any(token in text for token in (
        "windows xp", "server 2003"
    )):
        fixes.insert(
            0,
            "Migrate unsupported legacy Windows hosts to a currently supported operating system.",
        )

    fixes.append(
        "Re-run the assessment after remediation and compare the new evidence with the baseline."
    )

    unique_fixes = list(dict.fromkeys(fixes))

    return [
        {
            "type": "baseline",
            "technique_id": "HARDENING",
            "technique_name": "Evidence-based hardening",
            "tactic": "remediation",
            "summary": (
                "Baseline remediation generated from observed services "
                "and platform evidence."
            ),
            "fixes": unique_fixes,
        }
    ]


def _summarize_remediations(
    remediations: list[dict[str, Any]],
) -> list[str]:
    if not remediations:
        return ["No remediation guidance is available."]

    lines: list[str] = []

    for advice in remediations:
        if advice.get("type") == "vulnerability":
            lines.append(
                f"- [VULN] {advice.get('severity', 'Unknown')} "
                f"{advice.get('title', '')} on "
                f"{advice.get('affected_host', 'Unknown')}:"
                f"{advice.get('affected_port', 'N/A')}"
            )
            lines.append(
                f"  Summary: {_safe_text(advice.get('summary'))}"
            )

            fixes = advice.get("fixes") or []
            if fixes:
                lines.append(f"  Fix: {fixes[0]}")
        else:
            lines.append(
                f"- [TECH] {advice.get('technique_id', 'N/A')} "
                f"{advice.get('technique_name', '')} "
                f"({advice.get('tactic', 'unknown')})"
            )
            lines.append(
                f"  Summary: {_safe_text(advice.get('summary'))}"
            )

            for fix in (advice.get("fixes") or [])[:3]:
                lines.append(f"  - {fix}")

            if advice.get("mitre_url"):
                lines.append(
                    f"  MITRE ATT&CK: {advice['mitre_url']}"
                )

    return lines


def build_report_summary(
    scan: dict[str, Any],
    mapping: dict[str, Any],
    operation: dict[str, Any],
    risk: dict[str, Any],
    remediations: list[dict[str, Any]],
    validation: dict[str, Any] | None = None,
    results: dict[str, Any] | None = None,
) -> str:
    """Build the plain-text AutoPenTest report."""

    del results  # Reserved for PDF-specific enrichment.

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sections = [
        _section(
            "AutoPenTest Report",
            [
                f"Generated: {generated}",
                f"Target: {_safe_text(scan.get('target_ip'), 'Unknown')}",
            ],
        ),
        _section("Target Summary", _summarize_scan(scan)),
        _section(
            "Vulnerability Mapping",
            _summarize_vulnerabilities(mapping),
        ),
        _section("Attack Plan", _summarize_attack_plan(mapping)),
        _section(
            "Lab Exploitability Validation",
            _summarize_validation(validation or {}),
        ),
        _section(
            "CALDERA Operation Results",
            _summarize_operation(operation),
        ),
        _section("Risk Summary", _summarize_risk(risk)),
        _section(
            "Remediation Guidance",
            _summarize_remediations(
                remediations or _fallback_remediations(scan, mapping)
            ),
        ),
    ]

    return "".join(sections).rstrip() + "\n"


def generate_text_report(
    scan: dict[str, Any],
    mapping: dict[str, Any],
    operation: dict[str, Any],
    risk: dict[str, Any],
    remediations: list[dict[str, Any]],
    validation: dict[str, Any] | None = None,
    results: dict[str, Any] | None = None,
) -> str:
    """Generate and save a plain-text report."""

    report_text = build_report_summary(
        scan=scan,
        mapping=mapping,
        operation=operation,
        risk=risk,
        remediations=remediations,
        validation=validation,
        results=results,
    )

    path = REPORT_DIR / (
        f"autopentest_report_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )
    path.write_text(report_text, encoding="utf-8")
    return str(path)


def generate_pdf_report(
    scan_id: str = "",
    scan: dict[str, Any] | None = None,
    results: dict[str, Any] | None = None,
    mapping: dict[str, Any] | None = None,
    validation: dict[str, Any] | None = None,
    operation: dict[str, Any] | None = None,
    risk: dict[str, Any] | None = None,
    remediations: list[dict[str, Any]] | None = None,
) -> str:
    """Generate the AutoPenTest PDF report.
    """

    scan = scan or {}
    results = results or {}
    mapping = mapping or {}
    validation = validation or {}
    operation = operation or {}
    risk = risk or {}
    remediations = remediations or []

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
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
            title="AutoPenTest Report",
            author="AutoPenTest",
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
            spaceAfter=10,
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

        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#222222"),
            spaceAfter=3,
        )

        small_style = ParagraphStyle(
            "ReportSmall",
            parent=body_style,
            fontSize=7.5,
            leading=10,
        )

        story: list[Any] = []

        def cell(value: Any, small: bool = False) -> Paragraph:
            style = small_style if small else body_style
            return Paragraph(escape(_safe_text(value)), style)

        def table_style(
            header: bool = True,
            background: str = "#FAFAFC",
        ) -> TableStyle:
            commands = [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
                ("BACKGROUND", (0, 1 if header else 0), (-1, -1),
                 colors.HexColor(background)),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]

            if header:
                commands.extend(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0),
                         colors.HexColor("#2E2559")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ]
                )

            return TableStyle(commands)

        # ---------------------------------------------------------
        # Cover / executive summary
        # ---------------------------------------------------------
        story.extend(
            [
                Spacer(1, 35),
                Paragraph("AutoPenTest", title_style),
                Paragraph(
                    "Automated Penetration Testing Report",
                    subtitle_style,
                ),
                Paragraph(
                    f"<b>Generated:</b> "
                    f"{datetime.now().strftime('%d %B %Y %H:%M')}",
                    subtitle_style,
                ),
            ]
        )

        if scan_id:
            story.append(
                Paragraph(
                    f"<b>Scan ID:</b> {escape(scan_id)}",
                    subtitle_style,
                )
            )

        story.append(Spacer(1, 25))

        overview = Table(
            [
                ["Target", cell(scan.get("target_ip"), True)],
                ["Operating System", cell(scan.get("os"), True)],
                ["Port Range", cell(scan.get("port_range", "1-1024"), True)],
                [
                    "Risk",
                    cell(
                        f"{_safe_text(risk.get('score'))} / 10 "
                        f"({_safe_text(risk.get('label'))})",
                        True,
                    ),
                ],
            ],
            colWidths=[45 * mm, 115 * mm],
        )
        overview.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1),
                     colors.HexColor("#F3F0FF")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5,
                     colors.HexColor("#CCCCCC")),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(overview)

        story.append(Paragraph("Executive Summary", section_style))
        story.append(
            Paragraph(
                "This report presents the results of the AutoPenTest "
                "assessment, covering reconnaissance, vulnerability "
                "intelligence, exploitability validation, MITRE ATT&CK "
                "planning, CALDERA execution, risk "
                "evaluation, and remediation guidance.",
                body_style,
            )
        )

        # ---------------------------------------------------------
        # Open services
        # ---------------------------------------------------------
        story.append(Paragraph("Open Services", section_style))

        ports = scan.get("ports") or scan.get("service_inventory") or []

        if ports:
            data = [
                ["Port", "Protocol", "State", "Service", "Product", "Version"]
            ]

            for port in ports:
                data.append(
                    [
                        cell(port.get("port"), True),
                        cell(
                            _safe_text(
                                port.get("protocol", "tcp")
                            ).upper(),
                            True,
                        ),
                        cell(port.get("state", "unknown"), True),
                        cell(port.get("service", "unknown"), True),
                        cell(port.get("product", ""), True),
                        cell(port.get("version", ""), True),
                    ]
                )

            table = Table(
                data,
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
            table.setStyle(table_style())
            story.append(table)
        else:
            story.append(
                Paragraph(
                    "No open or reported services were found.",
                    body_style,
                )
            )

        # ---------------------------------------------------------
        # Vulnerability intelligence
        # ---------------------------------------------------------
        story.append(
            Paragraph("Vulnerability Intelligence", section_style)
        )

        mitre_source = results.get("mitre_source") or {}
        nvd_source = (
            results.get("nvd_source")
            or mitre_source.get("nvd_enrichment")
            or {}
        )
        msrc_source = results.get("msrc_source") or {}

        cvss_versions = (
            mitre_source.get(
                "records_with_cvss_metadata_by_version"
            )
            or {}
        )

        index_age_seconds = mitre_source.get("index_age_seconds")
        if index_age_seconds is not None:
            try:
                index_age = (
                    f"{float(index_age_seconds) / 3600:.1f} hours"
                )
            except (TypeError, ValueError):
                index_age = _safe_text(index_age_seconds)
        else:
            index_age = "Unknown"

        data = [
            [
                cell("CVE Source"),
                cell(mitre_source.get("source", "Unavailable")),
                cell("Records Indexed"),
                cell(mitre_source.get("records_indexed", "N/A")),
            ],
            [
                cell("Index Updated"),
                cell(mitre_source.get("index_updated_at", "Unknown")),
                cell("Index Age"),
                cell(index_age),
            ],
            [
                cell("CVSS 3.1 Records"),
                cell(cvss_versions.get("3.1", "N/A")),
                cell("CVSS 4.0 Records"),
                cell(cvss_versions.get("4.0", "N/A")),
            ],
            [
                cell("NVD Enrichment"),
                cell(
                    "Enabled"
                    if nvd_source.get("enabled")
                    else "Disabled / unavailable"
                ),
                cell("CVE Repository Head"),
                cell(mitre_source.get("repo_head_at", "Unknown")),
            ],
            [
                cell("Microsoft Remediation Source"),
                cell(
                    "Available"
                    if msrc_source.get("available")
                    else (
                        "Enabled; cache empty"
                        if msrc_source.get("enabled")
                        else "Disabled"
                    )
                ),
                cell("Cached MSRC Lookups"),
                cell(msrc_source.get(
                    "cached_cve_remediation_queries", 0
                )),
            ],
        ]

        table = Table(
            data,
            colWidths=[31 * mm, 49 * mm, 31 * mm, 49 * mm],
        )
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4,
                     colors.HexColor("#CCCCCC")),
                    ("BACKGROUND", (0, 0), (0, -1),
                     colors.HexColor("#F3F0FF")),
                    ("BACKGROUND", (2, 0), (2, -1),
                     colors.HexColor("#F3F0FF")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(table)

        # ---------------------------------------------------------
        # Candidate CVEs
        # ---------------------------------------------------------
        story.append(
            Paragraph("Candidate CVE Review", section_style)
        )

        review = results.get("cve_review_summary") or {}
        generation_state = review.get(
            "candidate_generation_state",
            (
                "available"
                if mitre_source.get("local_index_available")
                else "unavailable"
            ),
        )

        candidates = (
            results.get("cve_review_candidates")
            or results.get("cve_matches")
            or []
        )

        if candidates:
            data = [
                [
                    "CVE",
                    "Affected Asset",
                    "Evidence / Match Basis",
                    "Validation",
                    "Potential Outcome",
                ]
            ]

            for cve in candidates:
                product = (
                    cve.get("product")
                    or cve.get("service")
                    or "Observed identity"
                )
                version = cve.get("version") or ""
                asset = f"{product} {version}".strip()

                host = cve.get("host") or "Unknown"
                port = cve.get("port")
                protocol = cve.get("protocol") or "tcp"
                asset += (
                    f"\n{host} · {port}/{protocol}"
                    if port
                    else f"\n{host}"
                )

                evidence = (
                    cve.get("display_match_reason")
                    or cve.get("match_reason")
                    or cve.get("match_basis")
                    or cve.get("candidate_basis")
                    or "Evidence-linked product/version correlation"
                )

                validation_state = (
                    cve.get("validation_state") or "not_performed"
                )

                outcome = (
                    cve.get("attacker_outcome")
                    or "Potential impact requires validation."
                )

                data.append(
                    [
                        cell(cve.get("cve_id", "Unknown"), True),
                        cell(asset, True),
                        cell(evidence, True),
                        cell(
                            str(validation_state)
                            .replace("_", " ")
                            .title(),
                            True,
                        ),
                        cell(outcome, True),
                    ]
                )

            table = Table(
                data,
                colWidths=[
                    24 * mm,
                    32 * mm,
                    46 * mm,
                    23 * mm,
                    35 * mm,
                ],
                repeatRows=1,
            )
            table.setStyle(table_style(font_size=7.5) if False else table_style())
            story.append(table)
        else:
            message = (
                "Candidate CVE generation was unavailable."
                if generation_state == "unavailable"
                else "No candidate CVEs were generated from the observed software identities."
            )
            story.append(Paragraph(message, body_style))

        # ---------------------------------------------------------
        # Published CVSS
        # ---------------------------------------------------------
        story.append(
            Paragraph("Published CVSS Severity", section_style)
        )

        if candidates:
            data = [
                [
                    "CVE ID",
                    "Affected Service",
                    "CVSS 3.1",
                    "Severity",
                    "CVSS 4.0",
                    "Severity",
                ]
            ]

            for cve in candidates:
                metrics = (
                    cve.get("effective_cvss_metrics")
                    or cve.get("source_cvss_metrics")
                    or {}
                )

                metric_31 = metrics.get("3.1") or {}
                metric_40 = metrics.get("4.0") or {}

                service = (
                    cve.get("product")
                    or cve.get("service")
                    or "Unknown"
                )

                version = cve.get("version")
                if version:
                    service = f"{service} {version}"

                score_31 = metric_31.get("cvss_score")
                score_40 = metric_40.get("cvss_score")

                cvss_31 = (
                    f"{float(score_31):.1f}\n"
                    f"{metric_31.get('cvss_vector', '')}"
                    if score_31 is not None
                    else "Not published"
                )

                cvss_40 = (
                    f"{float(score_40):.1f}\n"
                    f"{metric_40.get('cvss_vector', '')}"
                    if score_40 is not None
                    else "Not published"
                )

                data.append(
                    [
                        cell(cve.get("cve_id", "Unknown"), True),
                        cell(service, True),
                        cell(cvss_31, True),
                        cell(metric_31.get("cvss_severity", "—"), True),
                        cell(cvss_40, True),
                        cell(metric_40.get("cvss_severity", "—"), True),
                    ]
                )

            table = Table(
                data,
                colWidths=[
                    24 * mm,
                    38 * mm,
                    31 * mm,
                    18 * mm,
                    31 * mm,
                    18 * mm,
                ],
                repeatRows=1,
            )
            table.setStyle(table_style())
            story.append(table)
        else:
            story.append(
                Paragraph(
                    "No published CVSS records are available.",
                    body_style,
                )
            )

        # ---------------------------------------------------------
        # Vulnerability findings
        # ---------------------------------------------------------
        story.append(
            Paragraph("Vulnerability Findings", section_style)
        )

        vulnerabilities = mapping.get("vulnerabilities") or []

        if vulnerabilities:
            data = [
                ["Severity", "Host", "Port", "Service", "Finding"]
            ]

            for vulnerability in vulnerabilities:
                data.append(
                    [
                        cell(
                            _safe_text(
                                vulnerability.get(
                                    "severity", "Unknown"
                                )
                            ).title()
                        ),
                        cell(vulnerability.get("host", "Unknown")),
                        cell(vulnerability.get("port", "N/A")),
                        cell(vulnerability.get("service", "unknown")),
                        cell(
                            vulnerability.get(
                                "title", "Untitled finding"
                            )
                        ),
                    ]
                )

            table = Table(
                data,
                colWidths=[21 * mm, 29 * mm, 15 * mm, 27 * mm, 68 * mm],
                repeatRows=1,
            )

            commands = table_style()
            for row, vulnerability in enumerate(
                vulnerabilities, start=1
            ):
                severity = str(
                    vulnerability.get("severity", "")
                ).lower()

                background = {
                    "critical": "#FDE8E8",
                    "high": "#FFF0E0",
                    "medium": "#FFF8D8",
                    "low": "#E8F5E9",
                }.get(severity, "#F5F5F5")

                commands.add(
                    "BACKGROUND",
                    (0, row),
                    (-1, row),
                    colors.HexColor(background),
                )

            table.setStyle(commands)
            story.append(table)
        else:
            story.append(
                Paragraph(
                    "No vulnerability findings were mapped.",
                    body_style,
                )
            )

        # ---------------------------------------------------------
        # MITRE ATT&CK
        # ---------------------------------------------------------
        story.append(
            Paragraph("MITRE ATT&CK Mapping", section_style)
        )

        plan = mapping.get("caldera_plan") or {}
        techniques = plan.get("selected_techniques") or []

        if techniques:
            data = [
                ["Technique ID", "Technique", "Stage", "Severity"]
            ]

            for technique in techniques:
                data.append(
                    [
                        cell(technique.get("id", "N/A")),
                        cell(
                            technique.get(
                                "name", "Unknown technique"
                            )
                        ),
                        cell(
                            technique.get(
                                "attack_path_stage", "N/A"
                            )
                        ),
                        cell(
                            technique.get(
                                "max_severity", "N/A"
                            )
                        ),
                    ]
                )

            table = Table(
                data,
                colWidths=[27 * mm, 63 * mm, 48 * mm, 22 * mm],
                repeatRows=1,
            )
            table.setStyle(table_style())
            story.append(table)
        else:
            story.append(
                Paragraph(
                    "No MITRE ATT&CK techniques were selected.",
                    body_style,
                )
            )

        # ---------------------------------------------------------
        # CALDERA operation
        # ---------------------------------------------------------
        story.append(
            Paragraph("CALDERA Operation Results", section_style)
        )

        if operation:
            data = [
                ["Operation ID", cell(operation.get("operation_id"))],
                ["Operation Name", cell(operation.get("operation_name"))],
                ["State", cell(operation.get("state"))],
                ["Techniques Executed", cell(operation.get("total", 0))],
                ["Successful", cell(operation.get("success_count", 0))],
                ["Failed", cell(operation.get("fail_count", 0))],
                ["Timed Out", cell(operation.get("timed_out", False))],
            ]

            table = Table(data, colWidths=[45 * mm, 115 * mm])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1),
                         colors.HexColor("#F3F0FF")),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.4,
                         colors.HexColor("#CCCCCC")),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(table)

            executed = operation.get("techniques_run") or []
            if executed:
                story.append(Spacer(1, 10))

                data = [
                    ["Technique ID", "Technique", "Tactic", "Status"]
                ]

                for technique in executed:
                    data.append(
                        [
                            cell(technique.get("technique_id", "N/A"), True),
                            cell(technique.get("technique_name", ""), True),
                            cell(technique.get("tactic", "unknown"), True),
                            cell(
                                _safe_text(
                                    technique.get(
                                        "status", "unknown"
                                    )
                                ).title(),
                                True,
                            ),
                        ]
                    )

                table = Table(
                    data,
                    colWidths=[27 * mm, 66 * mm, 39 * mm, 28 * mm],
                    repeatRows=1,
                )
                table.setStyle(table_style())
                story.append(table)
        else:
            story.append(
                Paragraph(
                    "No CALDERA operation has been executed yet.",
                    body_style,
                )
            )

        # ---------------------------------------------------------
        # Risk
        # ---------------------------------------------------------
        story.append(
            Paragraph("Risk Summary", section_style)
        )

        data = [
            [
                "Overall Risk Score",
                cell(f"{_safe_text(risk.get('score'))} / 10"),
            ],
            [
                "Risk Level",
                cell(_safe_text(risk.get("label")).title()),
            ],
        ]

        table = Table(data, colWidths=[45 * mm, 115 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1),
                     colors.HexColor("#F3F0FF")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5,
                     colors.HexColor("#CCCCCC")),
                    ("TOPPADDING", (0, 0), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)

        # ---------------------------------------------------------
        # Validation
        # ---------------------------------------------------------
        story.append(
            Paragraph("Lab Exploitability Validation", section_style)
        )

        data = [
            ["Mode", cell(validation.get("mode", "N/A"))],
            ["Target", cell(validation.get("target", "N/A"))],
            ["Checks Executed", cell(validation.get("total_checked", 0))],
            ["Confirmed", cell(validation.get("confirmed", 0))],
            ["Potential", cell(validation.get("potential", 0))],
            ["Failed", cell(validation.get("failed", 0))],
        ]

        table = Table(data, colWidths=[45 * mm, 115 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1),
                     colors.HexColor("#F3F0FF")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.4,
                     colors.HexColor("#CCCCCC")),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)

        # ---------------------------------------------------------
        # Remediation
        # ---------------------------------------------------------
        story.append(
            Paragraph("Remediation Recommendations", section_style)
        )

        effective_remediations = (
            remediations
            or _fallback_remediations(scan, mapping)
        )

        if effective_remediations:
            data = [["Type", "Recommendation"]]

            for item in effective_remediations:
                fixes = item.get("fixes") or []

                if fixes:
                    recommendation = "<br/>".join(
                        f"• {escape(_safe_text(fix))}"
                        for fix in fixes[:5]
                    )
                else:
                    recommendation = "No recommendation provided."

                data.append(
                    [
                        cell(
                            _safe_text(
                                item.get("type", "General")
                            ).title()
                        ),
                        Paragraph(recommendation, body_style),
                    ]
                )

            table = Table(
                data,
                colWidths=[35 * mm, 125 * mm],
                repeatRows=1,
            )
            table.setStyle(table_style())
            story.append(table)
        else:
            story.append(
                Paragraph(
                    "No remediation recommendations are available.",
                    body_style,
                )
            )

        doc.build(story)
        return str(path)

    except Exception:
        report_text = build_report_summary(
            scan=scan,
            mapping=mapping,
            operation=operation,
            risk=risk,
            remediations=remediations,
            validation=validation,
            results=results,
        )

        path = REPORT_DIR / f"autopentest_report_{stamp}.txt"
        path.write_text(report_text, encoding="utf-8")
        return str(path)
