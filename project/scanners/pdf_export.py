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
    cve_rows = list(results.get('cve_matches') or []) + list(results.get('relevant_cve_information') or [])
    cve_reference_count = len({str(row.get('cve_id')) for row in cve_rows if row.get('cve_id')})
    lines = [
        'Reconnaissance Evidence Report',
        f'Target: {target}',
        f'Scan Profile: {profile}',
        f"Hosts: {len(results.get('hosts') or [])}",
        f"TCP Services: {results.get('tcp_service_count', 0)}",
        f"UDP Services: {results.get('udp_service_count', 0)}",
        f"CVE References: {cve_reference_count}",
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
    cve_rows = list(results.get('cve_matches') or []) + list(results.get('relevant_cve_information') or [])
    cve_reference_count = len({str(row.get('cve_id')) for row in cve_rows if row.get('cve_id')})
    story.append(Paragraph(f'Scan Configuration: {_p(profile)}', styles['Muted']))
    story.append(Paragraph('CVE findings are linked from collected product, version, and supporting service evidence. The recon module does not score, rank, prioritise, or make execution decisions.', styles['Muted']))
    story.append(Spacer(1, 6))

    summary = [[_para('Hosts', styles['Cell']), _para('TCP Services', styles['Cell']), _para('UDP Services', styles['Cell']), _para('CVE References', styles['Cell'])],
               [_para(len(results.get('hosts') or []), styles['Cell']), _para(results.get('tcp_service_count', 0), styles['Cell']), _para(results.get('udp_service_count', 0), styles['Cell']), _para(cve_reference_count, styles['Cell'])]]
    t = Table(summary, repeatRows=1, colWidths=[50*mm, 50*mm, 50*mm, 80*mm])
    t.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
    story.append(t)
    story.append(Spacer(1, 8))

    policy = results.get('scan_options') or {}
    port_selection = policy.get('port_selection') or {}
    advanced = policy.get('advanced_settings') or {}
    tcp_selection = port_selection.get('tcp') or {}
    udp_selection = port_selection.get('udp') or {}
    execution_mode = (
        f"Parallel x{advanced.get('parallel_workers', 1)}"
        if advanced.get('parallel_scanning') else 'Sequential'
    )
    policy_rows = [
        ['TCP coverage', tcp_selection.get('display', tcp_selection.get('mode', ''))],
        ['UDP coverage', udp_selection.get('display', udp_selection.get('mode', ''))],
        ['Ports per batch', advanced.get('ports_per_batch', '')],
        ['Batch timeout (seconds)', advanced.get('command_timeout_seconds', '')],
        ['Retry failed batches', f"{advanced.get('retry_failed_batches', False)} (max retries: {advanced.get('retry_count', 0)})"],
        ['Batch execution', execution_mode],
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

    # CVE/CVSS report is deliberately separated into three views:
    # reference/applicability, severity/triage, and full technical context.
    cve_rows = []
    seen_cve_rows = set()
    for c in list(results.get('cve_matches') or []) + list(results.get('relevant_cve_information') or []):
        if not isinstance(c, dict) or not c.get('cve_id'):
            continue
        key = (
            str(c.get('cve_id') or ''), str(c.get('host') or ''),
            str(c.get('port') or ''), str(c.get('protocol') or ''),
            str(c.get('product') or ''), str(c.get('version') or ''),
        )
        if key in seen_cve_rows:
            continue
        seen_cve_rows.add(key)
        cve_rows.append(c)

    def _metric(cve, version):
        metrics = cve.get('source_cvss_metrics') or cve.get('cvss_metrics') or {}
        metric = metrics.get(version) if isinstance(metrics, dict) else None
        return metric if isinstance(metric, dict) else {}

    def _service_label(cve):
        identity = ' '.join(x for x in [str(cve.get('product') or '').strip(), str(cve.get('version') or '').strip()] if x).strip()
        if not identity:
            identity = str(cve.get('service') or 'Unknown')
        port = cve.get('port')
        proto = cve.get('protocol') or 'tcp'
        endpoint = f'{port}/{proto}' if port not in (None, '') else 'port unknown'
        return f'{identity} ({endpoint})'

    story.append(Paragraph('Table 1 - CVE References', styles['Heading2']))
    story.append(Paragraph('Reference and applicability view: identifier, affected service, why it matched, CVE publisher, and verification links.', styles['Muted']))
    if cve_rows:
        data = [[_para(x, styles['Cell']) for x in ['Identifier','Affected Service','Why It Matched','Published By','Links']]]
        for c in cve_rows:
            data.append([
                _para(c.get('cve_id',''), styles['SmallWrap']),
                _para(_service_label(c), styles['SmallWrap']),
                _para(c.get('classification_reason') or c.get('match_reason') or c.get('match_basis') or '', styles['SmallWrap']),
                _para(c.get('cve_publisher') or 'CVE Program CNA', styles['SmallWrap']),
                _para(f"CVE.org: https://www.cve.org/CVERecord?id={c.get('cve_id','')}\nNVD: https://nvd.nist.gov/vuln/detail/{c.get('cve_id','')}", styles['SmallWrap']),
            ])
        table = Table(data, repeatRows=1, colWidths=[28*mm,54*mm,84*mm,43*mm,64*mm])
        table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(table)
    else:
        story.append(Paragraph('No CVE references matched the observed service evidence.', styles['BodyText']))
    story.append(Spacer(1, 8))

    story.append(Paragraph('Table 2 - Severity & Triage', styles['Heading2']))
    story.append(Paragraph('CVSS 3.1 and CVSS 4.0 are independent published metrics. Missing versions are shown as Not published and are never converted.', styles['Muted']))
    if cve_rows:
        severity_rows = []
        for c in cve_rows:
            m31, m40 = _metric(c, '3.1'), _metric(c, '4.0')
            scores = []
            for m in (m31, m40):
                try:
                    scores.append(float(m.get('cvss_score')))
                except (TypeError, ValueError):
                    pass
            severity_rows.append((-(max(scores) if scores else -1.0), c, m31, m40))
        severity_rows.sort(key=lambda item: (item[0], str(item[1].get('cve_id') or '')))
        data = [[_para(x, styles['Cell']) for x in ['Identifier','Affected Service','CVSS 3.1','Severity','CVSS 4.0','Severity','Score Source','Vector','Verified']]]
        for _, c, m31, m40 in severity_rows:
            score31 = f"{float(m31.get('cvss_score')):.1f}" if m31.get('cvss_score') is not None else 'Not published'
            score40 = f"{float(m40.get('cvss_score')):.1f}" if m40.get('cvss_score') is not None else 'Not published'
            sev31 = m31.get('cvss_severity') or ('—' if not m31 else '')
            sev40 = m40.get('cvss_severity') or ('—' if not m40 else '')
            sources = []
            vectors = []
            verified = []
            for version, metric in (('3.1', m31), ('4.0', m40)):
                if metric:
                    sources.append(f"{version}: {metric.get('cvss_source') or 'Published source'}")
                    vectors.append(f"{version}: {metric.get('cvss_vector') or 'Not published'}")
                    verified.append(f"{version}: {'Verified' if metric.get('cvss_verified') else 'Not verified'}")
                else:
                    sources.append(f'{version}: Not published')
                    vectors.append(f'{version}: Not published')
                    verified.append(f'{version}: Not published')
            data.append([
                _para(c.get('cve_id',''), styles['SmallWrap']), _para(_service_label(c), styles['SmallWrap']),
                _para(score31, styles['SmallWrap']), _para(sev31, styles['SmallWrap']),
                _para(score40, styles['SmallWrap']), _para(sev40, styles['SmallWrap']),
                _para('\n'.join(sources), styles['SmallWrap']), _para('\n'.join(vectors), styles['SmallWrap']),
                _para('\n'.join(verified), styles['SmallWrap']),
            ])
        table = Table(data, repeatRows=1, colWidths=[24*mm,43*mm,18*mm,18*mm,18*mm,18*mm,37*mm,70*mm,27*mm])
        table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(table)
    else:
        story.append(Paragraph('No CVSS triage rows are available.', styles['BodyText']))
    story.append(Spacer(1, 8))

    story.append(Paragraph('Table 3 - Information Dump', styles['Heading2']))
    story.append(Paragraph('Technical context retained for traceability. This section intentionally favours evidence detail over compact presentation.', styles['Muted']))
    if cve_rows:
        data = [[_para(x, styles['Cell']) for x in ['Identifier','Target / Service','State','Description','Matching / Observed Evidence','Published Affected Data','CVSS / References']]]
        for c in cve_rows:
            m31, m40 = _metric(c, '3.1'), _metric(c, '4.0')
            observed = [
                f"Match basis: {c.get('match_basis') or ''}",
                f"Product basis: {c.get('product_match_basis') or ''}",
                f"Reason: {c.get('classification_reason') or c.get('match_reason') or ''}",
                f"Product tokens: {', '.join(map(str, c.get('matched_product_tokens') or []))}",
                f"Version tokens: {', '.join(map(str, c.get('matched_version_tokens') or []))}",
                f"Evidence sources: {', '.join(map(str, c.get('evidence_sources') or []))}",
            ]
            published = [
                f"Publisher: {c.get('cve_publisher') or 'CVE Program CNA'}",
                f"Vendors: {', '.join(map(str, c.get('affected_vendors') or []))}",
                f"Products: {', '.join(map(str, c.get('affected_products') or []))}",
                f"Versions/ranges: {', '.join(map(str, c.get('affected_versions') or []))}",
                f"CPEs: {', '.join(map(str, c.get('affected_cpes') or []))}",
            ]
            cvss_ref = []
            for version, metric in (('3.1', m31), ('4.0', m40)):
                if metric:
                    cvss_ref.append(f"CVSS {version}: {metric.get('cvss_score')} {metric.get('cvss_severity','')} | {metric.get('cvss_vector','')} | {metric.get('cvss_verification','')}")
                else:
                    cvss_ref.append(f'CVSS {version}: Not published')
            refs = list(c.get('references') or [])
            if refs:
                cvss_ref.append('References: ' + ', '.join(map(str, refs)))
            data.append([
                _para(c.get('cve_id',''), styles['SmallWrap']),
                _para(f"{c.get('host','')} | {_service_label(c)}", styles['SmallWrap']),
                _para(c.get('classification') or 'Candidate', styles['SmallWrap']),
                _para(c.get('vulnerability') or c.get('description') or '', styles['SmallWrap']),
                _para('\n'.join(x for x in observed if not x.endswith(': ')), styles['SmallWrap']),
                _para('\n'.join(x for x in published if not x.endswith(': ')), styles['SmallWrap']),
                _para('\n'.join(cvss_ref), styles['SmallWrap']),
            ])
        table = Table(data, repeatRows=1, colWidths=[24*mm,39*mm,27*mm,52*mm,48*mm,43*mm,40*mm])
        table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(table)
    else:
        story.append(Paragraph('No CVE information is available for this assessment.', styles['BodyText']))
    story.append(Spacer(1, 8))

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

    groups = results.get('candidate_cve_groups') or []
    if groups:
        story.append(CondPageBreak(45 * mm))
        story.append(Paragraph('Candidate CVE References', styles['Heading2']))
        data = [[_para(x, styles['Cell']) for x in ['Host','Ports','Service','Product / Version','References','Reason']]]
        for g in groups[:60]:
            refs = ', '.join(str(r.get('cve_id','')) for r in g.get('references') or [])
            reason = (g.get('references') or [{}])[0].get('reason','')
            data.append([_para(g.get('host',''), styles['SmallWrap']), _para(', '.join(g.get('ports') or []), styles['SmallWrap']), _para(g.get('service',''), styles['SmallWrap']), _para(f"{g.get('product','')} {g.get('version','')}", styles['SmallWrap']), _para(refs, styles['SmallWrap']), _para(reason, styles['SmallWrap'])])
        table = Table(data, repeatRows=1, colWidths=[32*mm,32*mm,28*mm,56*mm,58*mm,62*mm])
        table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(table)

    diagnostics = results.get('cve_matcher_diagnostics') or []
    if diagnostics:
        story.append(CondPageBreak(40 * mm))
        story.append(Paragraph('CVE Matcher Diagnostics', styles['Heading2']))
        data = [[_para(x, styles['Cell']) for x in ['Host / Port', 'Status', 'Reason', 'Detail']]]
        for row in diagnostics[:100]:
            detail = row.get('error') or row.get('rebuild_command') or row.get('product') or ''
            data.append([
                _para(f"{row.get('host','')}:{row.get('port','')}", styles['SmallWrap']),
                _para(row.get('matcher_status',''), styles['SmallWrap']),
                _para(row.get('reason',''), styles['SmallWrap']),
                _para(detail, styles['SmallWrap']),
            ])
        table = Table(data, repeatRows=1, colWidths=[48*mm,36*mm,72*mm,112*mm])
        table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(table)

    story.append(Paragraph('Service Inventory', styles['Heading2']))
    inv = results.get('service_summary') or results.get('service_inventory') or []
    data = [[_para(x, styles['Cell']) for x in ['Host','Port','Proto','Service','Product','Version','Evidence']]]
    for s in inv[:80]:
        evidence = ' · '.join(s.get('evidence_sources') or []) or s.get('evidence') or s.get('source') or s.get('status') or ', '.join(s.get('missing_information') or [])
        data.append([_para(s.get('host',''), styles['SmallWrap']), _para(s.get('port',''), styles['SmallWrap']), _para(s.get('protocol',''), styles['SmallWrap']), _para(s.get('service',''), styles['SmallWrap']), _para(s.get('product',''), styles['SmallWrap']), _para(s.get('version',''), styles['SmallWrap']), _para(evidence, styles['SmallWrap'])])
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
