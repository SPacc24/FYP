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


def build_pdf_report(scan: dict[str, Any], results: dict[str, Any]) -> bytes:
    """Create a readable PDF without depending on browser/CSS rendering.

    This is a fallback for environments where WeasyPrint or its native
    rendering dependencies fail at runtime.
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

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
