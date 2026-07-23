from __future__ import annotations

from io import BytesIO
from html import escape
from typing import Any


def _p(value: Any) -> str:
    text = '' if value is None else str(value)
    return escape(text).replace('\n', '<br/>')


def _para(value: Any, style):
    from reportlab.platypus import Paragraph
    return Paragraph(_p(value), style)


def _small_para(value: Any, style):
    return _para(value, style)


def _minimal_pdf(scan: dict[str, Any], results: dict[str, Any]) -> bytes:
    target = results.get('target_input') or scan.get('target') or 'Unknown target'
    profile = (results.get('scan_options') or scan.get('scan_options') or {}).get('profile_label', 'Scan')
    lines = [
        'Reconnaissance Evidence Report',
        f'Target: {target}',
        f'Scan Profile: {profile}',
        f"Hosts: {len(results.get('hosts') or [])}",
        f"TCP Services: {results.get('tcp_service_count', 0)}",
        f"UDP Services: {results.get('udp_service_count', 0)}",
        f"CVE Findings: {len(results.get('cve_matches') or [])}",
    ]
    escaped_lines = [str(line).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)') for line in lines]
    text_ops = ['BT', '/F1 14 Tf', '72 760 Td']
    for idx, line in enumerate(escaped_lines):
        if idx:
            text_ops.append('0 -22 Td')
        text_ops.append(f'({line}) Tj')
    text_ops.append('ET')
    stream = '\n'.join(text_ops).encode('latin-1', errors='replace')
    objects = [
        b'1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n',
        b'2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n',
        b'3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n',
        b'4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n',
        b'5 0 obj << /Length ' + str(len(stream)).encode('ascii') + b' >> stream\n' + stream + b'\nendstream endobj\n',
    ]
    out = BytesIO()
    out.write(b'%PDF-1.4\n')
    offsets = [0]
    for obj in objects:
        offsets.append(out.tell())
        out.write(obj)
    xref_offset = out.tell()
    out.write(f'xref\n0 {len(objects) + 1}\n'.encode('ascii'))
    out.write(b'0000000000 65535 f \n')
    for offset in offsets[1:]:
        out.write(f'{offset:010d} 00000 n \n'.encode('ascii'))
    out.write(f'trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n'.encode('ascii'))
    return out.getvalue()


def build_pdf_report(scan: dict[str, Any], results: dict[str, Any]) -> bytes:
    """Create a readable PDF without depending on browser/CSS rendering.

    This is a fallback for environments where WeasyPrint or its native
    rendering dependencies fail at runtime.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, CondPageBreak
    except ModuleNotFoundError:
        return _minimal_pdf(scan, results)

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=10 * mm,
        bottomMargin=10 * mm,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='SmallWrap', parent=styles['BodyText'], fontSize=7.2, leading=8.6))
    styles.add(ParagraphStyle(name='Cell', parent=styles['BodyText'], fontSize=7.8, leading=9.4))
    styles.add(ParagraphStyle(name='Muted', parent=styles['BodyText'], fontSize=8.4, leading=10.2, textColor=colors.HexColor('#555555')))
    story = []
    target = results.get('target_input') or scan.get('target') or ''
    story.append(Paragraph(f'Reconnaissance Evidence Report - {_p(target)}', styles['Title']))
    profile = (results.get('scan_options') or scan.get('scan_options') or {}).get('profile_label', 'Scan')
    story.append(Paragraph(f'Scan Profile: {_p(profile)}', styles['Muted']))
    story.append(Paragraph('Candidate findings require a reliable observed product/version and a structured official CVE List V5 affected-version match. They are not target-specific vulnerability detections. Published CVSS metrics are copied with their exact vector and provider; this module does not generate, convert, fall back, or substitute them.', styles['Muted']))
    story.append(Spacer(1, 6))

    summary = [[_para('Hosts', styles['Cell']), _para('TCP Services', styles['Cell']), _para('UDP Services', styles['Cell']), _para('CVE Findings', styles['Cell'])],
               [_para(len(results.get('hosts') or []), styles['Cell']), _para(results.get('tcp_service_count', 0), styles['Cell']), _para(results.get('udp_service_count', 0), styles['Cell']), _para(len(results.get('cve_matches') or []), styles['Cell'])]]
    t = Table(summary, repeatRows=1, colWidths=[45*mm, 45*mm, 45*mm, 65*mm])
    t.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
    story.append(t)
    story.append(Spacer(1, 8))

    policy = results.get('scan_options') or {}
    policy_rows = [
        ['Policy status', policy.get('policy_status', '')],
        ['Policy SHA-256', policy.get('effective_policy_sha256', '')],
        ['Policy conflict resolution', policy.get('policy_resolution', '')],
        ['Disabled conflicting collectors', ', '.join(policy.get('policy_conflicts') or []) or 'None'],
    ]
    story.append(Paragraph('Effective Scan Policy', styles['Heading2']))
    policy_table = Table([[_para(a, styles['Cell']), _para(b, styles['SmallWrap'])] for a, b in policy_rows], colWidths=[55*mm, 213*mm])
    policy_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(0,-1),colors.HexColor('#f3f3f3')),('VALIGN',(0,0),(-1,-1),'TOP')]))
    story.append(policy_table)
    story.append(Spacer(1, 6))

    coverage = results.get('scan_coverage') or {}
    if coverage:
        coverage_rows = [[_para(x, styles['Cell']) for x in ['Host', 'TCP requested', 'TCP open', 'UDP requested', 'UDP open']]]
        tcp_rows = coverage.get('tcp') or {}
        udp_rows = coverage.get('udp') or {}
        for host in sorted(set(tcp_rows) | set(udp_rows)):
            tcp = tcp_rows.get(host) or {}
            udp = udp_rows.get(host) or {}
            coverage_rows.append([
                _para(host, styles['SmallWrap']),
                _para(tcp.get('explicit_port_count', 0), styles['SmallWrap']),
                _para(tcp.get('open_port_count', 0), styles['SmallWrap']),
                _para(udp.get('requested_port_count', 0), styles['SmallWrap']),
                _para(len(udp.get('open_ports_observed') or []), styles['SmallWrap']),
            ])
        story.append(Paragraph('Port Coverage and Limitations', styles['Heading2']))
        coverage_table = Table(coverage_rows, repeatRows=1, colWidths=[68*mm,50*mm,50*mm,50*mm,50*mm])
        coverage_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(coverage_table)
        for limitation in coverage.get('limitations') or []:
            story.append(Paragraph('• ' + _p(limitation), styles['Muted']))
        story.append(Spacer(1, 6))

    if results.get('pentester_summary'):
        story.append(Paragraph('Pentester Summary', styles['Heading2']))
        for item in results.get('pentester_summary') or []:
            story.append(Paragraph('• ' + _p(item), styles['BodyText']))
        story.append(Spacer(1, 6))
    if (results.get('mitre_source') or {}).get('cvss_metadata_warning'):
        story.append(Paragraph('CVE metadata notice: ' + _p((results.get('mitre_source') or {}).get('cvss_metadata_warning')), styles['Muted']))
        story.append(Spacer(1, 6))
    if (results.get('mitre_source') or {}).get('selected_cvss_warning'):
        story.append(Paragraph('Selected CVSS notice: ' + _p((results.get('mitre_source') or {}).get('selected_cvss_warning')), styles['Muted']))
        story.append(Spacer(1, 6))

    scoring = results.get('vulnerability_scoring') or {}
    story.append(Paragraph(
        'Vulnerability severity standard: ' + _p(scoring.get('label') or 'Not recorded for this scan')
        + '. Published source metrics only; no conversion or cross-version fallback. CVSS severity is separate from target applicability and client risk.',
        styles['Muted'],
    ))
    story.append(Spacer(1, 6))
    source_status = results.get('mitre_source') or {}
    story.append(Paragraph(
        f"CVE List V5 local index: records={source_status.get('records_indexed', 0)}; "
        f"source={source_status.get('source') or 'Official CVE List V5'}.",
        styles['Muted'],
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph('Candidate and Confirmed CVE Findings', styles['Heading2']))
    cves = list(results.get('cve_matches') or [])
    cve_source_ready = bool((results.get('mitre_source') or {}).get('available'))
    if not cve_source_ready:
        story.append(Paragraph('CVE correlation was unavailable because the official index was not ready. A zero count is not a successful no-match result.', styles['BodyText']))
    elif cves:
        rows = [[_para(value, styles['Cell']) for value in ['Port', 'Service', 'CVE', 'Severity', 'Score', 'Description']]]
        for c in cves:
            selected_version = c.get('source_cvss_version') or scoring.get('version') or 'unknown'
            if c.get('cvss_status') == 'published':
                severity = str(c.get('source_cvss_severity') or '')
                score = (
                    f"{c.get('source_cvss_score')} (v{selected_version})\n"
                    f"{c.get('source_cvss_vector') or ''}\n"
                    f"Provider: {c.get('source_cvss_source') or ''}"
                )
            else:
                severity = f"Not provided for CVSS v{selected_version}"
                score = severity
            ports = ', '.join(c.get('observed_ports') or [
                str(c.get('port') or '') + '/' + str(c.get('protocol') or '')
            ])
            service = ' '.join(value for value in [
                str(c.get('service') or ''),
                str(c.get('product') or ''),
                str(c.get('version') or ''),
            ] if value)
            cve_cell = f"{c.get('cve_id') or ''}\n{c.get('classification') or 'Evidence-linked CVE'}"
            description = str(c.get('vulnerability') or '')
            if c.get('classification_reason'):
                description += f"\nApplicability: {c.get('classification_reason')}"
            rows.append([
                _para(ports, styles['SmallWrap']),
                _para(service, styles['SmallWrap']),
                _para(cve_cell, styles['SmallWrap']),
                _para(severity, styles['SmallWrap']),
                _para(score, styles['SmallWrap']),
                _para(description, styles['SmallWrap']),
            ])
        table = Table(rows, repeatRows=1, colWidths=[25*mm, 42*mm, 48*mm, 34*mm, 55*mm, 64*mm])
        table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(table)
        story.append(Spacer(1, 6))
    else:
        story.append(Paragraph('No CVE satisfied the Candidate or Confirmed requirements.', styles['BodyText']))

    observations = results.get('key_exposure_indicators') or results.get('security_relevant_observations') or []
    if observations:
        story.append(Paragraph('Key Exposure Indicators', styles['Heading2']))
        data = [[_para(x, styles['Cell']) for x in ['Host','Ports','Service','Observation','Evidence']]]
        for o in observations[:60]:
            ports = ', '.join(o.get('ports') or []) or (str(o.get('port') or '') + (('/' + str(o.get('protocol'))) if o.get('protocol') else ''))
            data.append([_para(o.get('host',''), styles['SmallWrap']), _para(ports, styles['SmallWrap']), _para(o.get('service',''), styles['SmallWrap']), _para(o.get('observation',''), styles['SmallWrap']), _para(o.get('evidence',''), styles['SmallWrap'])])
        table = Table(data, repeatRows=1, colWidths=[32*mm,34*mm,28*mm,78*mm,96*mm])
        table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(table)

    diagnostics = results.get('cve_matcher_diagnostics') or []
    if diagnostics:
        story.append(CondPageBreak(40 * mm))
        story.append(Paragraph('CVE Matcher Diagnostics', styles['Heading2']))
        data = [[_para(x, styles['Cell']) for x in ['Host / Port', 'Operational Event', 'Detail']]]
        for row in diagnostics[:100]:
            detail = row.get('error') or row.get('detail') or row.get('rebuild_command') or row.get('product') or row.get('product_identity') or ''
            data.append([
                _para(f"{row.get('host','')}:{row.get('port','')}", styles['SmallWrap']),
                _para(row.get('event',''), styles['SmallWrap']),
                _para(detail, styles['SmallWrap']),
            ])
        table = Table(data, repeatRows=1, colWidths=[58*mm,70*mm,140*mm])
        table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(table)

    story.append(Paragraph('Service Inventory', styles['Heading2']))
    inv = results.get('service_summary') or results.get('service_inventory') or []
    data = [[_para(x, styles['Cell']) for x in ['Host','Port','Proto','Service','Product','Version','Status']]]
    for s in inv[:80]:
        data.append([_para(s.get('host',''), styles['SmallWrap']), _para(s.get('port',''), styles['SmallWrap']), _para(s.get('protocol',''), styles['SmallWrap']), _para(s.get('service',''), styles['SmallWrap']), _para(s.get('product',''), styles['SmallWrap']), _para(s.get('version',''), styles['SmallWrap']), _para(s.get('status') or ', '.join(s.get('missing_information') or []), styles['SmallWrap'])])
    table = Table(data, repeatRows=1, colWidths=[32*mm,18*mm,16*mm,32*mm,52*mm,42*mm,48*mm])
    table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
    story.append(table)

    story.append(PageBreak())
    story.append(Paragraph('Evidence Collection Summary', styles['Heading2']))
    cov = results.get('tool_coverage') or []
    data = [[_para(x, styles['Cell']) for x in ['Check','Status','Evidence Summary','Reference']]]
    for r in cov[:120]:
        summary = str(r.get('evidence_type') or r.get('information_added') or '')
        if r.get('note'):
            summary += '\n' + str(r.get('note'))
        ref = str(r.get('output_file','')).split('/')[-1] if r.get('output_file') else ''
        data.append([_para(r.get('tool',''), styles['SmallWrap']), _para(r.get('status',''), styles['SmallWrap']), _para(summary, styles['SmallWrap']), _para(ref, styles['SmallWrap'])])
    table = Table(data, repeatRows=1, colWidths=[50*mm,42*mm,116*mm,60*mm])
    table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
    story.append(table)

    def page_footer(canvas, document):
        canvas.saveState()
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(colors.HexColor('#666666'))
        canvas.drawRightString(document.pagesize[0] - 12 * mm, 6 * mm, f'Page {document.page}')
        canvas.restoreState()

    doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
    return buffer.getvalue()
