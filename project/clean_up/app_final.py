
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, send_file
import logging

from config import Config
from mapping.technique_mapper import map_vulnerabilities, select_attack_mode
from scanners.nmap_parser import NmapParseError, parse_nmap_xml
from scanners.nmap_runner import NmapScanError, run_nmap_scan
from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager
from caldera.risk_scorer import RiskScorer
from storage.db import Database

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = getattr(Config, 'SECRET_KEY', 'change-me')

caldera_client = CalderaClient(
    base_url=Config.CALDERA_URL,
    api_key=Config.CALDERA_KEY,
)
operation_manager = OperationManager(caldera_client)
risk_scorer = RiskScorer()
db = Database(
    host=Config.MYSQL_HOST,
    user=Config.MYSQL_USER,
    password=Config.MYSQL_PASS,
    database=Config.MYSQL_DB,
)
try:
    db.init_schema()
except Exception:
    log.exception('Database schema initialization skipped or failed')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    ports = request.form.get('ports')
    intensity = request.form.get('intensity')
    profile = request.form.get('profile')
    try:
        scan_result = run_nmap_scan(target, ports, intensity, profile)
        parsed_results = parse_nmap_xml(scan_result['output_file'])
        mapping_results = map_vulnerabilities(parsed_results)
        session['target_ip'] = target
        session['port_range'] = ports or '1-1024'
        return render_template('results.html', scan=scan_result, results=parsed_results, mapping=mapping_results)
    except (NmapScanError, NmapParseError, ValueError) as error:
        return render_template('error.html', error_message=str(error)), 400


@app.route('/confirm-plan', methods=['POST'])
def confirm_attack_plan():
    scan_file = request.form.get('scan_file')
    mode = request.form.get('mode')
    selected_ids = request.form.getlist('selected_techniques')
    try:
        parsed_results = parse_nmap_xml(scan_file)
        mapping_results = map_vulnerabilities(parsed_results)
        attack_plan = select_attack_mode(mapping_results, mode=mode, selected_ids=selected_ids)
        return render_template('attack_plan.html', mapping=mapping_results, attack_plan=attack_plan)
    except (NmapParseError, ValueError) as error:
        return render_template('error.html', error_message=str(error)), 400


@app.route('/caldera/status', methods=['GET'])
def caldera_status():
    return jsonify(operation_manager.check_readiness())


@app.route('/caldera/run', methods=['POST'])
def caldera_run():
    data = request.get_json(silent=True) or {}
    adversary_id = data.get('adversary_id')
    selected_techniques = data.get('selected_techniques', [])
    group = data.get('group', Config.AGENT_GROUP)
    planner_id = data.get('planner_id')
    if not adversary_id:
        return jsonify({'ok': False, 'message': 'Missing adversary_id.'}), 400
    result = operation_manager.start_operation(
        adversary_id=adversary_id,
        selected_techniques=selected_techniques,
        group=group,
        planner_id=planner_id,
    )
    return jsonify(result), (200 if result.get('ok') else 400)


@app.route('/caldera/operation/<operation_id>', methods=['GET'])
def caldera_operation(operation_id):
    return jsonify(operation_manager.poll_operation(operation_id))


@app.route('/scan/save', methods=['POST'])
def save_scan():
    scan_results = request.get_json(silent=True) or {}
    target_ip = session.get('target_ip')
    port_range = session.get('port_range', '1-1024')
    if not target_ip:
        return jsonify({'success': False, 'error': 'No target_ip in session'}), 400
    scan_id = db.save_scan(target_ip, scan_results, port_range)
    session['scan_id'] = scan_id
    return jsonify({'success': True, 'scan_id': scan_id})


@app.route('/vulnerabilities/save', methods=['POST'])
def save_vulnerabilities():
    data = request.get_json(silent=True) or {}
    vulns = data.get('vulnerabilities', [])
    scan_id = session.get('scan_id')
    if not scan_id:
        return jsonify({'success': False, 'error': 'No scan_id in session'}), 400
    db.save_vulnerabilities(scan_id, vulns)
    session['vulnerabilities'] = vulns
    return jsonify({'success': True, 'count': len(vulns)})


@app.route('/agent/check', methods=['GET'])
def check_agent():
    available, info = operation_manager.check_agent(Config.AGENT_GROUP)
    if available:
        return jsonify({'agent_ready': True, 'host': info.get('host', 'unknown'), 'paw': info.get('paw', '')})
    deploy_cmd = operation_manager.get_deploy_command(kali_ip=Config.KALI_IP, group=Config.AGENT_GROUP)
    return jsonify({'agent_ready': False, 'error': info, 'deploy_command': deploy_cmd})


@app.route('/attack/execute', methods=['POST'])
def execute_attack():
    data = request.get_json(silent=True) or {}
    technique_ids = data.get('technique_ids', [])
    scan_id = session.get('scan_id')
    vulns = session.get('vulnerabilities', [])
    if not scan_id:
        return jsonify({'success': False, 'error': 'No scan_id found'}), 400
    if not technique_ids:
        return jsonify({'success': False, 'error': 'No techniques selected'}), 400
    op_results = operation_manager.run_operation(
        technique_ids=technique_ids,
        group=Config.AGENT_GROUP,
        timeout=Config.OPERATION_TIMEOUT,
    )
    if not op_results.get('success'):
        return jsonify(op_results), 500
    risk = risk_scorer.calculate(vulns, op_results)
    remediations = risk_scorer.get_all_remediations(op_results)
    db.save_operation(scan_id, op_results, risk['score'])
    session['operation_results'] = op_results
    session['risk_score'] = risk
    session['remediations'] = remediations
    return jsonify({
        'success': True,
        'operation_id': op_results['operation_id'],
        'total': op_results['total'],
        'success_count': op_results['success_count'],
        'fail_count': op_results['fail_count'],
        'risk_score': risk['score'],
        'risk_label': risk['label'],
        'risk_colour': risk['colour'],
        'techniques': op_results['techniques_run'],
        'remediations': remediations,
    })


@app.route('/attack/status', methods=['GET'])
def attack_status():
    op_id = request.args.get('operation_id')
    op = operation_manager.client.get_operation(op_id) if op_id else {}
    return jsonify({'state': op.get('state', 'unknown'), 'chain': op.get('chain', [])})


@app.route('/results')
def results():
    op_results = session.get('operation_results')
    risk = session.get('risk_score')
    remediations = session.get('remediations', [])
    if not op_results:
        return redirect(url_for('index'))
    return render_template('results.html', operation=op_results, risk=risk, remediations=remediations)


@app.route('/report/export', methods=['GET'])
def export_report():
    from reports.report_generator import generate_pdf_report
    scan_id = session.get('scan_id')
    op_results = session.get('operation_results')
    risk = session.get('risk_score')
    remediations = session.get('remediations', [])
    if not op_results:
        return 'No results to export', 400
    pdf_path = generate_pdf_report(scan_id=scan_id, operation=op_results, risk=risk, remediations=remediations)
    return send_file(pdf_path, as_attachment=True)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
