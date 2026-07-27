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
    scan_summary = results.get('scan_summary') or {}
    cve_ids = {
        str(row.get('cve_id') or '').upper()
        for row in list(results.get('cve_matches') or []) + list(results.get('relevant_cve_information') or [])
        if isinstance(row, dict) and row.get('cve_id')
    }
    lines = [
        'Reconnaissance Evidence Report',
        f'Target: {target}',
        f'Scan Configuration: {profile}',
        f"Hosts reached/requested: {(scan_summary.get('targets') or {}).get('reached', len(results.get('hosts') or []))}/{(scan_summary.get('targets') or {}).get('requested', len(results.get('hosts') or []))}",
        f"TCP scanned/requested: {(scan_summary.get('tcp') or {}).get('scanned', 0)}/{(scan_summary.get('tcp') or {}).get('requested', 0)}",
        f"UDP scanned/requested: {(scan_summary.get('udp') or {}).get('scanned', 0)}/{(scan_summary.get('udp') or {}).get('requested', 0)}",
        f"Observed service endpoints: {(scan_summary.get('services') or {}).get('observed_endpoints', len(results.get('service_inventory') or []))}",
        f"CVE References: {(scan_summary.get('cve_review') or {}).get('unique_references', len(cve_ids))}",
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
    story.append(Paragraph(f'Scan Configuration: {_p(profile)}', styles['Muted']))
    story.append(Paragraph('CVE findings are linked from collected product, version, and supporting service evidence. The recon module does not score, rank, prioritise, or make execution decisions.', styles['Muted']))
    story.append(Spacer(1, 6))

    assurance = results.get('scan_summary') or {}
    assurance_targets = assurance.get('targets') or {}
    assurance_services = assurance.get('services') or {}
    assurance_cves = assurance.get('cve_review') or {}
    summary = [[_para('Targets Reached', styles['Cell']), _para('TCP Services', styles['Cell']), _para('UDP Services', styles['Cell']), _para('Observed Endpoints', styles['Cell']), _para('CVE References', styles['Cell'])],
               [_para(assurance_targets.get('reached', len(results.get('hosts') or [])), styles['Cell']), _para(results.get('tcp_service_count', 0), styles['Cell']), _para(results.get('udp_service_count', 0), styles['Cell']), _para(assurance_services.get('observed_endpoints', len(results.get('service_inventory') or [])), styles['Cell']), _para(assurance_cves.get('unique_references', 0), styles['Cell'])]]
    t = Table(summary, repeatRows=1, colWidths=[35*mm, 35*mm, 35*mm, 50*mm, 55*mm])
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
        ['Selected TCP scope', tcp_selection.get('display', tcp_selection.get('mode', ''))],
        ['Full TCP range', 'Selected' if str(tcp_selection.get('mode') or '').lower() == 'full' else 'Not selected'],
        ['Selected UDP scope', udp_selection.get('display', udp_selection.get('mode', ''))],
        ['Ports per batch', advanced.get('ports_per_batch', '')],
        ['Batch timeout (seconds)', advanced.get('command_timeout_seconds', '')],
        ['Retry failed batches', f"{advanced.get('retry_failed_batches', False)} (max retries: {advanced.get('retry_count', 0)})"],
        ['Batch execution', execution_mode],
        ['Evidence collection preset', policy.get('collection_preset_label', policy.get('collection_preset', ''))],
        ['Evidence collectors requested / permitted / blocked', f"{(policy.get('collector_counts') or {}).get('requested', 0)} / {(policy.get('collector_counts') or {}).get('permitted', 0)} / {(policy.get('collector_counts') or {}).get('blocked', 0)}"],
        ['Host discovery requested', ', '.join(k for k, v in ((policy.get('host_discovery') or {}).get('requested') or {}).items() if v) or 'None'],
        ['Host discovery effective', ', '.join(k for k, v in ((policy.get('host_discovery') or {}).get('effective') or {}).items() if v) or 'None'],
        ['Service identity controls', str(policy.get('service_identity') or {})],
        ['Policy status', policy.get('policy_status', '')],
        ['Policy SHA-256', policy.get('effective_policy_sha256', '')],
        ['Policy conflict resolution', policy.get('policy_resolution', '')],
        ['Disabled conflicting collectors', ', '.join(policy.get('policy_conflicts') or []) or 'None'],
    ]
    story.append(Paragraph('Effective Scan Configuration', styles['Heading2']))
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
                _para(tcp.get('configured_port_count', tcp.get('scanned_port_count', 0)), styles['SmallWrap']),
                _para(tcp.get('open_port_count', 0), styles['SmallWrap']),
                _para(udp.get('configured_port_count', udp.get('scanned_port_count', 0)), styles['SmallWrap']),
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

    mitre_source = results.get('mitre_source') or {}
    nvd_source = results.get('nvd_source') or mitre_source.get('nvd_enrichment') or {}
    msrc_source = results.get('msrc_source') or {}
    story.append(Paragraph('Vulnerability Intelligence - Data Freshness', styles['Heading2']))
    freshness_rows = [
        ['CVE source', mitre_source.get('source', 'Unavailable')],
        ['Local index', 'Available' if mitre_source.get('local_index_available') else 'Unavailable'],
        ['Index updated (UTC)', mitre_source.get('index_updated_at') or 'Unknown'],
        ['Index age at assessment', (f"{float(mitre_source.get('index_age_seconds')) / 3600:.1f} hours" if mitre_source.get('index_age_seconds') is not None else 'Unknown')],
        ['Records indexed', mitre_source.get('records_indexed', 'N/A')],
        ['CVSS 3.1 / 4.0 records', f"{(mitre_source.get('records_with_cvss_metadata_by_version') or {}).get('3.1','N/A')} / {(mitre_source.get('records_with_cvss_metadata_by_version') or {}).get('4.0','N/A')}"],
        ['CVE repository head', mitre_source.get('repo_head_at') or 'Unknown'],
        ['NVD enrichment', 'Enabled' if nvd_source.get('enabled') else 'Disabled / unavailable'],
        ['NVD cached CVE metrics', nvd_source.get('cached_cve_metric_queries', 0)],
        ['NVD cache age', (f"{float(nvd_source.get('cache_age_seconds')) / 3600:.1f} hours" if nvd_source.get('cache_age_seconds') is not None else 'No successful cache timestamp')],
        ['Microsoft remediation intelligence', ('Available' if msrc_source.get('available') else ('Enabled; cache empty' if msrc_source.get('enabled') else 'Disabled'))],
        ['MSRC cached month / CVE queries', f"{msrc_source.get('cached_month_documents', 0)} / {msrc_source.get('cached_cve_remediation_queries', 0)}"],
    ]
    freshness_table = Table([[_para(a, styles['Cell']), _para(b, styles['SmallWrap'])] for a, b in freshness_rows], colWidths=[68*mm, 200*mm])
    freshness_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(0,-1),colors.HexColor('#f3f3f3')),('VALIGN',(0,0),(-1,-1),'TOP')]))
    story.append(freshness_table)
    story.append(Spacer(1, 8))

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
        metrics = cve.get('effective_cvss_metrics') or cve.get('source_cvss_metrics') or cve.get('cvss_metrics') or {}
        metric = metrics.get(version) if isinstance(metrics, dict) else None
        return metric if isinstance(metric, dict) else {}

    def _service_label(cve):
        identity = ' '.join(x for x in [str(cve.get('product') or '').strip(), str(cve.get('version') or '').strip()] if x).strip()
        if not identity:
            identity = str(cve.get('service') or 'Unknown')
        port = cve.get('port')
        proto = cve.get('protocol') or 'tcp'
        if str(port).lower() == 'host' or str(proto).lower() == 'host' or cve.get('match_scope') == 'host_os':
            endpoint = 'host operating system'
        else:
            endpoint = f'{port}/{proto}' if port not in (None, '') else 'port unknown'
        return f'{identity} ({endpoint})'

    def _publisher(cve):
        raw = str(cve.get('cve_publisher') or 'CVE Program CNA').strip()
        raw_norm = ''.join(ch for ch in raw.lower() if ch.isalnum())
        for vendor in cve.get('affected_vendors') or []:
            vendor = str(vendor).strip()
            vendor_norm = ''.join(ch for ch in vendor.lower() if ch.isalnum())
            if raw_norm and (raw_norm == vendor_norm or raw_norm in vendor_norm or vendor_norm in raw_norm):
                return vendor
        return raw

    def _metric_source(cve, metric):
        if not metric:
            return 'Not published'
        name = str(metric.get('cvss_provider_name') or '').strip()
        raw = str(metric.get('cvss_source') or '').strip()
        role = str(metric.get('cvss_provider_role') or '').strip().upper()
        if name:
            return name + (f' ({role})' if role and role.lower() not in name.lower() else '')
        if raw.lower() == 'nvd' or 'nist.gov' in raw.lower():
            return 'NVD'
        if raw and raw == str(cve.get('cve_publisher_id') or ''):
            return _publisher(cve) + (f' ({role})' if role else '')
        import re as _re
        if _re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}', raw):
            return f'{role} provider' if role else 'Published provider'
        return raw or (f'{role} provider' if role else 'Published source')

    story.append(Paragraph('Host & Operating System Identity', styles['Heading2']))
    story.append(Paragraph('Cross-platform OS identity is derived from retained collector evidence. Broad or conflicting observations remain explicit rather than being converted into an assumed release.', styles['Muted']))
    host_inventory = results.get('host_identity_inventory') or []
    if host_inventory:
        host_rows = [[_para(x, styles['Cell']) for x in ['Host','Vendor','Family','Product','Release','Build / Version','Quality','Evidence']]]
        for host_row in host_inventory:
            for ident in host_row.get('identities') or []:
                sources = ', '.join(map(str, ident.get('sources') or []))
                cpes = ', '.join(map(str, ident.get('cpe') or []))
                evidence = sources + (("\n" + cpes) if cpes else '')
                host_rows.append([
                    _para(host_row.get('host',''), styles['SmallWrap']),
                    _para(ident.get('vendor') or 'Not established', styles['SmallWrap']),
                    _para(ident.get('family') or 'Not established', styles['SmallWrap']),
                    _para(ident.get('product') or ident.get('name') or 'Not established', styles['SmallWrap']),
                    _para(ident.get('release') or '—', styles['SmallWrap']),
                    _para(ident.get('build') or ident.get('version') or '—', styles['SmallWrap']),
                    _para(ident.get('quality') or 'Incomplete identity', styles['SmallWrap']),
                    _para(evidence or '—', styles['SmallWrap']),
                ])
        host_table = Table(host_rows, repeatRows=1, colWidths=[32*mm,28*mm,25*mm,48*mm,30*mm,35*mm,38*mm,58*mm])
        host_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(host_table)
    else:
        story.append(Paragraph('No host operating-system identity was established; service evidence remains independent.', styles['BodyText']))
    host_gaps = results.get('host_identity_gaps') or []
    if host_gaps:
        host_gap_rows = [[_para(x, styles['Cell']) for x in ['Host','Observed Identity','Remaining Gap','Quality']]]
        for gap in host_gaps:
            host_gap_rows.append([_para(gap.get('host',''), styles['SmallWrap']), _para(gap.get('observed_identity',''), styles['SmallWrap']), _para(gap.get('remaining_gap',''), styles['SmallWrap']), _para(gap.get('quality',''), styles['SmallWrap'])])
        gap_table = Table(host_gap_rows, repeatRows=1, colWidths=[45*mm,70*mm,100*mm,55*mm])
        gap_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(Spacer(1,4)); story.append(gap_table)
    story.append(Spacer(1, 8))

    windows_patch_inventory = results.get('windows_patch_inventory') or []
    if windows_patch_inventory:
        story.append(Paragraph('Windows Authenticated Patch Evidence', styles['Heading2']))
        story.append(Paragraph('Read-only Windows build and installed-update evidence. The collector uses an already-approved cached credential; missing KB identifiers alone never establish vulnerability.', styles['Muted']))
        patch_rows = [[_para(x, styles['Cell']) for x in ['Host','Product','Release','Version','Build / UBR','Installed KBs','Registry','Lifecycle']]]
        for row in windows_patch_inventory:
            build = str(row.get('build') or '—')
            if row.get('ubr'):
                build += '.' + str(row.get('ubr'))
            kbs = list(row.get('installed_kbs') or [])
            kb_text = f"{row.get('hotfix_count', len(kbs))} observed"
            if kbs:
                kb_text += '\n' + ', '.join(map(str, kbs[:20])) + (' …' if len(kbs) > 20 else '')
            patch_rows.append([
                _para(row.get('host',''), styles['SmallWrap']),
                _para(row.get('product') or 'Not established', styles['SmallWrap']),
                _para(row.get('release') or '—', styles['SmallWrap']),
                _para(row.get('version') or '—', styles['SmallWrap']),
                _para(build, styles['SmallWrap']),
                _para(kb_text, styles['SmallWrap']),
                _para(row.get('registry_evidence_status') or 'not attempted', styles['SmallWrap']),
                _para(row.get('lifecycle_state') or row.get('status') or 'unknown', styles['SmallWrap']),
            ])
        patch_table = Table(patch_rows, repeatRows=1, colWidths=[28*mm,48*mm,24*mm,30*mm,32*mm,60*mm,24*mm,27*mm])
        patch_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(patch_table)
        assessments = results.get('windows_patch_assessments') or []
        if assessments:
            story.append(Spacer(1,4)); story.append(Paragraph('Microsoft Remediation Assessments', styles['Heading3']))
            assess_rows = [[_para(x, styles['Cell']) for x in ['Host','CVE','Patch State','Evidence Basis','Observed KB','Fixed Builds']]]
            for row in assessments:
                assess_rows.append([
                    _para(row.get('host',''), styles['SmallWrap']),
                    _para(row.get('cve_id',''), styles['SmallWrap']),
                    _para(row.get('patch_state',''), styles['SmallWrap']),
                    _para(row.get('patch_basis',''), styles['SmallWrap']),
                    _para(', '.join(map(str,row.get('observed_remediation_kbs') or [])) or '—', styles['SmallWrap']),
                    _para(', '.join(map(str,row.get('vendor_fixed_builds') or [])) or '—', styles['SmallWrap']),
                ])
            assess_table = Table(assess_rows, repeatRows=1, colWidths=[28*mm,25*mm,34*mm,82*mm,38*mm,44*mm])
            assess_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
            story.append(assess_table)
        story.append(Spacer(1, 8))

    story.append(Paragraph('Platform & Connector Identity', styles['Heading2']))
    story.append(Paragraph('Distinct component layers are retained only when directly observed and remain separate from host OS and primary application identity.', styles['Muted']))
    components = results.get('platform_component_identities') or []
    if components:
        component_rows = [[_para(x, styles['Cell']) for x in ['Host','Endpoint','Kind','Product','Version','Evidence']]]
        for row in components:
            evidence = ', '.join(map(str, row.get('sources') or []))
            cpes = ', '.join(map(str, row.get('cpe') or []))
            if cpes:
                evidence += ('\n' if evidence else '') + cpes
            component_rows.append([
                _para(row.get('host',''), styles['SmallWrap']),
                _para(f"{row.get('port','')}/{row.get('protocol','')}", styles['SmallWrap']),
                _para(str(row.get('kind') or '').replace('_',' '), styles['SmallWrap']),
                _para(row.get('product') or 'Not established', styles['SmallWrap']),
                _para(row.get('version') or '—', styles['SmallWrap']),
                _para(evidence or '—', styles['SmallWrap']),
            ])
        component_table = Table(component_rows, repeatRows=1, colWidths=[38*mm,30*mm,35*mm,55*mm,30*mm,82*mm])
        component_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(component_table)
    else:
        story.append(Paragraph('No distinct platform/component identity was directly observed.', styles['BodyText']))
    story.append(Spacer(1, 8))

    story.append(Paragraph('Table 1 - CVE References', styles['Heading2']))
    story.append(Paragraph('Reference and applicability view: identifier, affected host/service identity, why it matched, CVE publisher, and verification links.', styles['Muted']))
    if cve_rows:
        data = [[_para(x, styles['Cell']) for x in ['Identifier','Affected Service','Why It Matched','Published Prerequisites','Published By','Links']]]
        for c in cve_rows:
            data.append([
                _para(c.get('cve_id',''), styles['SmallWrap']),
                _para(_service_label(c), styles['SmallWrap']),
                _para(c.get('display_match_reason') or c.get('match_reason') or c.get('match_basis') or '', styles['SmallWrap']),
                _para((lambda ctx: ('; '.join(
                    [f"Module: {x}" for x in (ctx.get('published',{}).get('modules') or [])] +
                    [f"Platform: {x}" for x in (ctx.get('published',{}).get('platforms') or [])] +
                    ([f"Package: {ctx.get('published',{}).get('package_name')}"] if ctx.get('published',{}).get('package_name') else [])
                ) + (f" | evidence: {ctx.get('status','').replace('_',' ')}" if ctx.get('status') and ctx.get('status') != 'not_published' else '')) or 'No structured prerequisite published')(c.get('applicability_context') or {}), styles['SmallWrap']),
                _para(_publisher(c), styles['SmallWrap']),
                _para(f"CVE.org: https://www.cve.org/CVERecord?id={c.get('cve_id','')}\nNVD: https://nvd.nist.gov/vuln/detail/{c.get('cve_id','')}", styles['SmallWrap']),
            ])
        table = Table(data, repeatRows=1, colWidths=[25*mm,45*mm,70*mm,52*mm,34*mm,48*mm])
        table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(table)
    else:
        story.append(Paragraph('No CVE references matched the observed host/platform or service evidence.', styles['BodyText']))
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
        data = [[_para(x, styles['Cell']) for x in ['Identifier','Affected Service','CVSS 3.1','Severity','CVSS 4.0','Severity','Score Source','Vector','CVSS Integrity']]]
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
                    sources.append(f"{version}: {_metric_source(c, metric)}")
                    vectors.append(f"{version}: {metric.get('cvss_vector') or 'Not published'}")
                    verified.append(f"{version}: {metric.get('cvss_verification') or 'Published metric retained'}")
                else:
                    sources.append(f'{version}: Not published')
                    vectors.append(f'{version}: Not published')
                    verified.append(f'{version}: Not published')
            nvd_state = c.get('nvd_cvss_enrichment') or {}
            if nvd_state:
                nvd_label = str(nvd_state.get('status') or 'not queried').replace('_', ' ')
                versions = ', '.join(map(str, nvd_state.get('versions') or []))
                sources.append(f"NVD enrichment: {nvd_label}" + (f" (CVSS {versions})" if versions else ''))
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

    # Evidence-derived coverage assurance. Older scans may not have this block.
    scan_summary = results.get('scan_summary') or {}
    story.append(Paragraph('Scan Summary - Selected Scope Coverage & Assurance', styles['Heading2']))
    story.append(Paragraph('Actual executed coverage is reported separately from untested scope; untested ports are never represented as closed or secure.', styles['Muted']))
    if scan_summary:
        tcp = scan_summary.get('tcp') or {}
        udp = scan_summary.get('udp') or {}
        targets_summary = scan_summary.get('targets') or {}
        services_summary = scan_summary.get('services') or {}
        checks = scan_summary.get('evidence_checks') or {}
        cve_summary = scan_summary.get('cve_review') or {}
        overview = [
            ['Targets reached / requested', f"{targets_summary.get('reached', 0)} / {targets_summary.get('requested', 0)}"],
            ['TCP endpoints re-probed / open endpoints', f"{services_summary.get('tcp_reprobed', services_summary.get('tcp_fingerprinted', 0))} / {services_summary.get('tcp_open_endpoints', 0)}"],
            ['Observed service endpoints', services_summary.get('observed_endpoints', 0)],
            ['Versioned service endpoints', services_summary.get('versioned_service_endpoints', services_summary.get('versioned_products', 0))],
            ['Evidence actions', f"{checks.get('executed', 0)} executed; {checks.get('produced_evidence', 0)} produced evidence; {checks.get('no_evidence', 0)} completed with no evidence; {checks.get('failed', 0)} failed; {checks.get('not_executed', checks.get('skipped', 0))} not executed"],
            ['Not executed breakdown', f"{checks.get('not_applicable', 0)} not applicable; {checks.get('disabled', 0)} disabled; {checks.get('unavailable', 0)} unavailable/input missing; {checks.get('deferred', 0)} deferred; {checks.get('skipped_policy', 0)} policy-skipped; {checks.get('not_executed_unspecified', 0)} unspecified"],
            ['Unique CVE references', cve_summary.get('unique_references', 0)],
        ]
        overview_table = Table([[_para(a, styles['Cell']), _para(b, styles['SmallWrap'])] for a, b in overview], colWidths=[68*mm, 200*mm])
        overview_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(0,-1),colors.HexColor('#f3f3f3')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(overview_table)
        story.append(Spacer(1, 5))
        coverage_data = [[_para(x, styles['Cell']) for x in ['Selected Scope','Selected','Scanned','Open','Closed','Filtered','Unknown / No Response','Untested']]]
        for label, row in (('TCP', tcp), ('UDP', udp)):
            coverage_data.append([_para(v, styles['SmallWrap']) for v in [
                label, row.get('requested', 0), row.get('scanned', 0), row.get('open', 0), row.get('closed', 0),
                row.get('filtered', 0), row.get('unknown', 0), row.get('untested', 0)
            ]])
        coverage_table = Table(coverage_data, repeatRows=1, colWidths=[28*mm,28*mm,28*mm,23*mm,23*mm,23*mm,55*mm,28*mm])
        coverage_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(coverage_table)
    else:
        story.append(Paragraph('Coverage assurance data is unavailable for this older scan.', styles['BodyText']))
    story.append(Spacer(1, 8))

    matrix = results.get('collector_coverage_matrix') or {}
    matrix_summary = matrix.get('summary') or {}
    story.append(Paragraph('Collector Coverage Matrix - Assurance Summary', styles['Heading2']))
    story.append(Paragraph('Operator intent, applicability and execution are distinct states. The detailed matrix below records what ran and why a requested collector did not run.', styles['Muted']))
    matrix_overview = [
        ['Service endpoints evaluated', matrix_summary.get('endpoints', 0)],
        ['Applicable collector actions', matrix_summary.get('applicable_actions', 0)],
        ['Actions retaining evidence', matrix_summary.get('evidence_actions', 0)],
        ['Failed actions', matrix_summary.get('failed_actions', 0)],
        ['Not executed actions', matrix_summary.get('not_executed_actions', 0)],
        ['Host-level lifecycle records', matrix_summary.get('host_lifecycle_actions', 0)],
    ]
    matrix_table = Table([[_para(a, styles['Cell']), _para(b, styles['SmallWrap'])] for a, b in matrix_overview], colWidths=[75*mm, 193*mm])
    matrix_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(0,-1),colors.HexColor('#f3f3f3')),('VALIGN',(0,0),(-1,-1),'TOP')]))
    story.append(matrix_table)
    host_lifecycle = matrix.get('host_lifecycle') or []
    if host_lifecycle:
        host_data = [[_para(x, styles['Cell']) for x in ['Host-level Check','Status','Reason / Result']]]
        for row in host_lifecycle[:40]:
            host_data.append([_para(row.get('tool',''), styles['SmallWrap']), _para(row.get('status',''), styles['SmallWrap']), _para(row.get('note',''), styles['SmallWrap'])])
        host_table = Table(host_data, repeatRows=1, colWidths=[48*mm,48*mm,172*mm])
        host_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(Spacer(1,4)); story.append(host_table)
    endpoint_rows = matrix.get('endpoint_rows') or []
    if endpoint_rows:
        endpoint_data = [[_para(x, styles['Cell']) for x in ['Endpoint','Service','Collector','Mode','Policy','Outcome']]]
        for row in endpoint_rows[:180]:
            endpoint_data.append([
                _para(f"{row.get('host','')} {row.get('endpoint','')}", styles['SmallWrap']),
                _para(row.get('service') or 'Unknown', styles['SmallWrap']),
                _para(str(row.get('collector') or '').replace('_',' ').title(), styles['SmallWrap']),
                _para(row.get('requested_mode') or '', styles['SmallWrap']),
                _para(row.get('policy_state') or '', styles['SmallWrap']),
                _para(row.get('outcome') or '', styles['SmallWrap']),
            ])
        endpoint_table = Table(endpoint_data, repeatRows=1, colWidths=[48*mm,35*mm,55*mm,30*mm,30*mm,70*mm])
        endpoint_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(Spacer(1,4)); story.append(endpoint_table)
    story.append(Spacer(1, 8))

    gaps = results.get('unresolved_identity_queue') or []
    host_gaps = results.get('host_identity_gaps') or []
    story.append(Paragraph('Evidence Gaps - Unresolved Identity Queue', styles['Heading2']))
    story.append(Paragraph('Missing host and service identity information is preserved as unresolved rather than guessed.', styles['Muted']))
    if gaps or host_gaps:
        gap_data = [[_para(x, styles['Cell']) for x in ['Host','Endpoint','Observed Service','Product','Version','Remaining Gap','Recovery']]]
        for row in host_gaps[:50]:
            gap_data.append([
                _para(row.get('host',''), styles['SmallWrap']), _para('HOST', styles['SmallWrap']),
                _para('Operating system', styles['SmallWrap']), _para(row.get('observed_identity') or 'Not established', styles['SmallWrap']),
                _para('Not established', styles['SmallWrap']), _para(row.get('remaining_gap') or '', styles['SmallWrap']),
                _para('Where applicable', styles['SmallWrap']),
            ])
        for row in gaps[:100]:
            gap_data.append([
                _para(row.get('host',''), styles['SmallWrap']),
                _para(f"{row.get('port','')}/{row.get('protocol','')}", styles['SmallWrap']),
                _para(row.get('service') or 'Unknown', styles['SmallWrap']),
                _para(row.get('product') or 'Not established', styles['SmallWrap']),
                _para(row.get('version') or 'Not established', styles['SmallWrap']),
                _para('; '.join(row.get('gaps') or []), styles['SmallWrap']),
                _para('Attempted' if row.get('recovery_attempted') else 'Not attempted', styles['SmallWrap']),
            ])
        gap_table = Table(gap_data, repeatRows=1, colWidths=[35*mm,25*mm,38*mm,45*mm,35*mm,65*mm,25*mm])
        gap_table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(gap_table)
    else:
        story.append(Paragraph('No unresolved identity gaps were retained.', styles['BodyText']))
    story.append(Spacer(1, 8))

    conditions = results.get('observed_security_conditions') or []
    story.append(Paragraph('Observed Security Conditions', styles['Heading2']))
    story.append(Paragraph('Direct protocol/configuration evidence from collectors. No CVE or CVSS value is inferred by this table.', styles['Muted']))
    if conditions:
        data = [[_para(x, styles['Cell']) for x in ['Host','Endpoint','Check','Observed Evidence','Source']]]
        for row in conditions[:100]:
            data.append([
                _para(row.get('host') or 'Unknown', styles['SmallWrap']),
                _para(f"{row.get('port') or '—'}/{row.get('protocol') or 'tcp'}" if row.get('port') else '—', styles['SmallWrap']),
                _para(row.get('condition') or row.get('check') or '', styles['SmallWrap']),
                _para(row.get('evidence') or '', styles['SmallWrap']),
                _para(row.get('source') or '', styles['SmallWrap']),
            ])
        table = Table(data, repeatRows=1, colWidths=[34*mm,28*mm,48*mm,112*mm,46*mm])
        table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(table)
    else:
        story.append(Paragraph('No structured security-condition evidence was retained.', styles['BodyText']))
    story.append(Spacer(1, 8))

    story.append(Paragraph('Table 3 - Scan Findings', styles['Heading2']))
    story.append(Paragraph('Evidence-derived network and service findings observed during the scan. Missing products, versions, and evidence labels remain missing rather than being inferred.', styles['Muted']))
    inventory = results.get('service_inventory') or []
    if inventory:
        data = [[_para(x, styles['Cell']) for x in ['Host','Port / Protocol','State','Service','Product','Version','Fingerprint Context','Evidence']]]
        for row in inventory:
            evidence = row.get('evidence') or row.get('source')
            if not evidence:
                evidence = ' · '.join(str(source).replace('_', ' ').title() for source in (row.get('evidence_sources') or [])) or 'Evidence source not labelled'
            data.append([
                _para(row.get('host') or 'Unknown', styles['SmallWrap']),
                _para(f"{row.get('port', '—')}/{row.get('protocol') or '—'}", styles['SmallWrap']),
                _para(row.get('state') or 'Observed', styles['SmallWrap']),
                _para(row.get('service') or 'Unknown', styles['SmallWrap']),
                _para(row.get('product') or '—', styles['SmallWrap']),
                _para(row.get('version') or '—', styles['SmallWrap']),
                _para('\n'.join(x for x in [str(row.get('extra') or row.get('extrainfo') or '').strip(), str(row.get('identity_context') or '').strip()] if x) or '—', styles['SmallWrap']),
                _para(evidence, styles['SmallWrap']),
            ])
        table = Table(data, repeatRows=1, colWidths=[29*mm,24*mm,18*mm,26*mm,43*mm,30*mm,43*mm,54*mm])
        table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eeeeee')),('VALIGN',(0,0),(-1,-1),'TOP')]))
        story.append(table)
    else:
        story.append(Paragraph('No service findings were retained for this scan.', styles['BodyText']))
    story.append(Spacer(1, 8))

    # Client PDF uses the canonical Observed Security Conditions and CVE tables above.
    # Legacy exposure/candidate/matcher-status sections are intentionally omitted.

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
