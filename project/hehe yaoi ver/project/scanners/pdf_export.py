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
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
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
    story.append(Paragraph('CVE findings are linked from collected product, version, and supporting service evidence. The recon module does not score, rank, prioritise, or make execution decisions.', styles['Muted']))
    story.append(Spacer(1, 6))

    summary = [[_para('Hosts', styles['Cell']), _para('TCP Services', styles['Cell']), _para('UDP Services', styles['Cell']), _para('CVE Findings', styles['Cell']), _para('Candidate Groups', styles['Cell'])],
               [_para(len(results.get('hosts') or []), styles['Cell']), _para(results.get('tcp_service_count', 0), styles['Cell']), _para(results.get('udp_service_count', 0), styles['Cell']), _para(len(results.get('cve_matches') or []), styles['Cell']), _para(len(results.get('candidate_cve_groups') or []), styles['Cell'])]]
    t = Table(summary, repeatRows=1, colWidths=[35*mm, 35*mm, 35*mm, 50*mm, 55*mm])
    t.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
    story.append(t)
    story.append(Spacer(1, 8))

    if results.get('pentester_summary'):
        story.append(Paragraph('Pentester Summary', styles['Heading2']))
        for item in results.get('pentester_summary') or []:
            story.append(Paragraph('• ' + _p(item), styles['BodyText']))
        story.append(Spacer(1, 6))
    if (results.get('mitre_source') or {}).get('cvss_metadata_warning'):
        story.append(Paragraph('CVE metadata notice: ' + _p((results.get('mitre_source') or {}).get('cvss_metadata_warning')), styles['Muted']))
        story.append(Spacer(1, 6))

    story.append(Paragraph('CVE Findings', styles['Heading2']))
    cves = results.get('cve_matches') or []
    if cves:
        for c in cves:
            title = f"{c.get('cve_id','')} - {c.get('product','')} {c.get('version','')}"
            story.append(Paragraph(_p(title), styles['Heading3']))
            rows = [
                ['Finding Type', c.get('finding_type','CVE Finding')],
                ['Host / Ports', f"{c.get('host','')} / {', '.join(c.get('observed_ports') or [str(c.get('port','')) + '/' + str(c.get('protocol',''))])}"],
                ['Vulnerability', c.get('vulnerability','')],
                ['Potential Outcome', c.get('attacker_outcome','')],
                ['Remediation', c.get('remediation_direction','')],
                ['Evidence Basis', str(c.get('classification_reason') or '')],
            ]
            table = Table([[ _para(a, styles['Cell']), _para(b, styles['SmallWrap'])] for a,b in rows], colWidths=[38*mm, 230*mm])
            table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(0,-1),colors.HexColor('#f3f3f3')),('VALIGN',(0,0),(-1,-1),'TOP')]))
            story.append(table)
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph('No confirmed CVE findings were linked from the collected evidence.', styles['BodyText']))

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
        story.append(Paragraph('Candidate CVE References', styles['Heading2']))
        data = [[_para(x, styles['Cell']) for x in ['Host','Ports','Service','Product / Version','References','Reason']]]
        for g in groups[:60]:
            refs = ', '.join(str(r.get('cve_id','')) for r in g.get('references') or [])
            reason = (g.get('references') or [{}])[0].get('reason','')
            data.append([_para(g.get('host',''), styles['SmallWrap']), _para(', '.join(g.get('ports') or []), styles['SmallWrap']), _para(g.get('service',''), styles['SmallWrap']), _para(f"{g.get('product','')} {g.get('version','')}", styles['SmallWrap']), _para(refs, styles['SmallWrap']), _para(reason, styles['SmallWrap'])])
        table = Table(data, repeatRows=1, colWidths=[32*mm,32*mm,28*mm,56*mm,58*mm,62*mm])
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

    doc.build(story)
    return buffer.getvalue()
