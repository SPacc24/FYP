from flask import Flask, render_template, request, jsonify

from mapping.technique_mapper import map_vulnerabilities, select_attack_mode
from scanners.nmap_parser import NmapParseError, parse_nmap_xml
from scanners.nmap_runner import NmapScanError, run_nmap_scan

from caldera.api_client import CalderaClient
from caldera.operation_manager import OperationManager

app = Flask(__name__)


def get_operation_manager():
    client = CalderaClient()
    return OperationManager(client)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target")
    ports = request.form.get("ports")
    intensity = request.form.get("intensity")
    profile = request.form.get("profile")

    try:
        scan_result = run_nmap_scan(target, ports, intensity, profile)
        parsed_results = parse_nmap_xml(scan_result["output_file"])
        mapping_results = map_vulnerabilities(parsed_results)

        return render_template(
            "results.html",
            scan=scan_result,
            results=parsed_results,
            mapping=mapping_results,
        )
    except (NmapScanError, NmapParseError, ValueError) as error:
        return render_template("error.html", error_message=str(error))


@app.route("/confirm-plan", methods=["POST"])
def confirm_attack_plan():
    scan_file = request.form.get("scan_file")
    mode = request.form.get("mode")
    selected_ids = request.form.getlist("selected_techniques")

    try:
        parsed_results = parse_nmap_xml(scan_file)
        mapping_results = map_vulnerabilities(parsed_results)

        attack_plan = select_attack_mode(
            mapping_results,
            mode=mode,
            selected_ids=selected_ids,
        )

        return render_template(
            "attack_plan.html",
            mapping=mapping_results,
            attack_plan=attack_plan,
        )
    except (NmapParseError, ValueError) as error:
        return render_template("error.html", error_message=str(error))


@app.route("/caldera/status", methods=["GET"])
def caldera_status():
    manager = get_operation_manager()
    return jsonify(manager.check_readiness())


@app.route("/caldera/run", methods=["POST"])
def caldera_run():
    data = request.get_json() or {}

    adversary_id = data.get("adversary_id")
    selected_techniques = data.get("selected_techniques", [])
    group = data.get("group", "red")
    planner_id = data.get("planner_id")

    if not adversary_id:
        return jsonify({
            "ok": False,
            "message": "Missing adversary_id."
        }), 400

    manager = get_operation_manager()
    result = manager.start_operation(
        adversary_id=adversary_id,
        selected_techniques=selected_techniques,
        group=group,
        planner_id=planner_id
    )

    status_code = 200 if result.get("ok") else 400
    return jsonify(result), status_code


@app.route("/caldera/operation/<operation_id>", methods=["GET"])
def caldera_operation(operation_id):
    manager = get_operation_manager()
    return jsonify(manager.poll_operation(operation_id))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

"""# app.py
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from config import Config
 
# ── P4 imports ──
from caldera.operation_manager import OperationManager
from caldera.risk_scorer import RiskScorer
from storage.db import Database
 
import logging
 
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)
 
app = Flask(__name__)
app.config.from_object(Config)
 
# ── Initialize P4 components (do this once at startup) ──
operation_manager = OperationManager(
    base_url=Config.CALDERA_URL,
    api_key=Config.CALDERA_KEY
)
 
risk_scorer = RiskScorer()
 
db = Database(
    host=Config.MYSQL_HOST,
    user=Config.MYSQL_USER,
    password=Config.MYSQL_PASS,
    database=Config.MYSQL_DB
)
 
# Initialize database schema on first run
db.init_schema()
 
# ═══════════════════════════════════════════════════════════════════════════
# STEP 3 — Flask Routes That Use P4
# ═══════════════════════════════════════════════════════════════════════════
 
"""
P1 creates these routes. P4 components are called inside them.
"""
 
 
# ── Route 1: After Nmap scan completes (P2 finished scanning) ──────────────
 
@app.route('/scan/save', methods=['POST'])
def save_scan():
    """
    Called after P2's Nmap scan finishes.
    Saves scan results to MySQL and stores scan_id in session.
    """
    scan_results = request.json  # P2 sends scan results as JSON
    target_ip    = session.get('target_ip')
    port_range   = session.get('port_range', '1-1024')
    
    # Save to MySQL
    scan_id = db.save_scan(target_ip, scan_results, port_range)
    session['scan_id'] = scan_id
    
    log.info(f"Scan saved: id={scan_id} target={target_ip}")
    return jsonify({'success': True, 'scan_id': scan_id})
 
 
# ── Route 2: After vulnerability mapping (P3 finished CVE lookup) ───────────
 
@app.route('/vulnerabilities/save', methods=['POST'])
def save_vulnerabilities():
    """
    Called after P3's vulnerability mapper finishes.
    Saves CVE findings to MySQL linked to the current scan.
    """
    vulns   = request.json.get('vulnerabilities', [])
    scan_id = session.get('scan_id')
    
    if not scan_id:
        return jsonify({'success': False, 'error': 'No scan_id in session'}), 400
    
    db.save_vulnerabilities(scan_id, vulns)
    session['vulnerabilities'] = vulns  # store for risk scoring later
    
    log.info(f"Saved {len(vulns)} vulnerabilities for scan {scan_id}")
    return jsonify({'success': True, 'count': len(vulns)})
 
 
# ── Route 3: Check if Caldera agent is ready ────────────────────────────────
 
@app.route('/agent/check', methods=['GET'])
def check_agent():
    """
    Checks if a Sandcat agent is online and returns status.
    If no agent, returns the PowerShell deployment command.
    """
    available, info = operation_manager.check_agent(Config.AGENT_GROUP)
    
    if available:
        return jsonify({
            'agent_ready': True,
            'host':        info.get('host', 'unknown'),
            'paw':         info.get('paw', '')
        })
    else:
        # No agent — return deployment command
        deploy_cmd = operation_manager.get_deploy_command(
            kali_ip=Config.KALI_IP,
            group=Config.AGENT_GROUP
        )
        return jsonify({
            'agent_ready':   False,
            'error':         info,
            'deploy_command': deploy_cmd
        })
 
 
# ── Route 4: Run Caldera operation (main P4 flow) ───────────────────────────
 
@app.route('/attack/execute', methods=['POST'])
def execute_attack():
    """
    Main P4 entry point.
    
    Receives:
    - technique_ids: list of ATT&CK technique IDs from P3's mapper
    
    Does:
    1. Run Caldera operation via operation_manager
    2. Calculate risk score
    3. Save results to MySQL
    4. Return results to frontend
    """
    technique_ids = request.json.get('technique_ids', [])
    scan_id       = session.get('scan_id')
    vulns         = session.get('vulnerabilities', [])
    
    if not scan_id:
        return jsonify({'success': False, 'error': 'No scan_id found'}), 400
    
    if not technique_ids:
        return jsonify({'success': False, 'error': 'No techniques selected'}), 400
    
    log.info(f"Starting operation with {len(technique_ids)} techniques")
    
    # ── Step 1: Run Caldera operation ──
    op_results = operation_manager.run_operation(
        technique_ids=technique_ids,
        group=Config.AGENT_GROUP,
        timeout=Config.OPERATION_TIMEOUT
    )
    
    if not op_results['success']:
        return jsonify(op_results), 500
    
    log.info(
        f"Operation complete: {op_results['success_count']}/{op_results['total']} "
        f"techniques succeeded"
    )
    
    # ── Step 2: Calculate risk score ──
    risk = risk_scorer.calculate(vulns, op_results)
    
    # ── Step 3: Get remediation advice ──
    remediations = risk_scorer.get_all_remediations(op_results)
    
    # ── Step 4: Save to MySQL ──
    db.save_operation(scan_id, op_results, risk['score'])
    
    log.info(f"Risk score: {risk['score']}/10 — {risk['label']}")
    
    # ── Step 5: Store results in session for report page ──
    session['operation_results'] = op_results
    session['risk_score']        = risk
    session['remediations']      = remediations
    
    # ── Step 6: Return to frontend ──
    return jsonify({
        'success':      True,
        'operation_id': op_results['operation_id'],
        'total':        op_results['total'],
        'success_count': op_results['success_count'],
        'fail_count':   op_results['fail_count'],
        'risk_score':   risk['score'],
        'risk_label':   risk['label'],
        'risk_colour':  risk['colour'],
        'techniques':   op_results['techniques_run'],
        'remediations': remediations
    })
 
# ── Route 5: Results page (displays operation results) ──────────────────────
 
@app.route('/results')
def results():
    """
    Displays the final results page after operation completes.
    P5 builds the results.html template using data from session.
    """
    op_results   = session.get('operation_results')
    risk         = session.get('risk_score')
    remediations = session.get('remediations', [])
    
    if not op_results:
        return redirect(url_for('index'))
    
    return render_template(
        'results.html',
        operation=op_results,
        risk=risk,
        remediations=remediations
    )
 
 
# ── Route 6: Export PDF report (P5 builds report generator) ─────────────────
 
@app.route('/report/export', methods=['GET'])
def export_report():
    """
    Generates and downloads a PDF report.
    P5 implements reports/report_generator.py.
    """
    from reports.report_generator import generate_pdf_report
    
    scan_id      = session.get('scan_id')
    op_results   = session.get('operation_results')
    risk         = session.get('risk_score')
    remediations = session.get('remediations', [])
    
    if not op_results:
        return "No results to export", 400
    
    pdf_path = generate_pdf_report(
        scan_id=scan_id,
        operation=op_results,
        risk=risk,
        remediations=remediations
    )
    
    return send_file(pdf_path, as_attachment=True)
 
 
# ═══════════════════════════════════════════════════════════════════════════
# STEP 4 — Frontend JavaScript (optional polling for live updates)
# ═══════════════════════════════════════════════════════════════════════════
 
"""
File: templates/results.html (P5 owns the template)
 
If you want live status updates while Caldera operation runs, use AJAX polling.
This is optional — simpler approach is to just show a loading spinner for 2-3 mins.
"""
 
# In results.html <script> section (optional):
 
"""
// Poll operation status every 5 seconds while running
let operationId = "{{ operation.operation_id }}";
let pollInterval = setInterval(async () => {
    const res = await fetch(`/attack/status?operation_id=${operationId}`);
    const data = await res.json();
    
    if (data.state === 'finished' || data.state === 'complete') {
        clearInterval(pollInterval);
        location.reload();  // refresh page to show final results
    } else {
        // Update status indicator
        document.getElementById('status').innerText = data.state;
    }
}, 5000);
"""
 
# And add this route to app.py:
 
"""
@app.route('/attack/status', methods=['GET'])
def attack_status():
    op_id = request.args.get('operation_id')
    from caldera.api_client import CalderaClient
    
    client = CalderaClient(Config.CALDERA_URL, Config.CALDERA_KEY)
    op = client.get_operation(op_id)
    
    return jsonify({
        'state': op.get('state', 'unknown'),
        'chain': op.get('chain', [])
    })
"""
 
 
# ═══════════════════════════════════════════════════════════════════════════
# STEP 5 — Error Handling Best Practices
# ═══════════════════════════════════════════════════════════════════════════
 
"""
Wrap P4 calls in try-except to handle failures gracefully.
"""
 
@app.route('/attack/execute-safe', methods=['POST'])
def execute_attack_safe():
    """Example with proper error handling."""
    try:
        technique_ids = request.json.get('technique_ids', [])
        scan_id = session.get('scan_id')
        
        if not scan_id:
            raise ValueError("No scan_id in session")
        
        # Check agent first
        available, info = operation_manager.check_agent()
        if not available:
            return jsonify({
                'success': False,
                'error': 'No agent available',
                'deploy_command': operation_manager.get_deploy_command(Config.KALI_IP)
            }), 503
        
        # Run operation
        op_results = operation_manager.run_operation(
            technique_ids=technique_ids,
            timeout=Config.OPERATION_TIMEOUT
        )
        
        if not op_results['success']:
            raise RuntimeError(op_results.get('error', 'Operation failed'))
        
        # Calculate risk
        vulns = session.get('vulnerabilities', [])
        risk = risk_scorer.calculate(vulns, op_results)
        
        # Save to DB
        db.save_operation(scan_id, op_results, risk['score'])
        
        return jsonify({
            'success': True,
            'operation_id': op_results['operation_id'],
            'risk_score': risk['score']
        })
        
    except ValueError as e:
        log.error(f"Validation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400
    
    except RuntimeError as e:
        log.error(f"Operation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    
    except Exception as e:
        log.exception("Unexpected error in attack execution")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
 
 
# ═══════════════════════════════════════════════════════════════════════════
# STEP 6 — Session Data Flow (what P1 needs to track)
# ═══════════════════════════════════════════════════════════════════════════
 
"""
Session variables that P1 needs to manage across the flow:
 
Step 1 (Input):
    session['target_ip']    = '192.168.56.101'
    session['port_range']   = '1-1024'
    
Step 2 (After Nmap scan - P2):
    session['scan_id']      = 123
    session['scan_results'] = {...}
    
Step 3 (After vuln mapping - P3):
    session['vulnerabilities'] = [...]
    session['technique_ids']   = ['T1082', 'T1087', ...]
    
Step 4 (After Caldera operation - P4):
    session['operation_results'] = {...}
    session['risk_score']        = {...}
    session['remediations']      = [...]
    
Step 5 (Results page - P5):
    All of the above gets passed to results.html template
"""
 
 
# ═══════════════════════════════════════════════════════════════════════════
# STEP 7 — Testing the Integration
# ═══════════════════════════════════════════════════════════════════════════
 
"""
After P1 integrates the routes above, test end-to-end:
 
1. Start Flask app:
   python3 app.py
   
2. Start Caldera:
   cd ~/caldera && python3 server.py --insecure
   
3. Deploy Sandcat on Windows VM (if not already done)
 
4. Test flow manually via curl:
   
   # Save scan
   curl -X POST http://localhost:5000/scan/save \
     -H "Content-Type: application/json" \
     -d '{"target_ip":"192.168.56.101","os":"Windows 10","ports":[...]}'
   
   # Save vulnerabilities
   curl -X POST http://localhost:5000/vulnerabilities/save \
     -H "Content-Type: application/json" \
     -d '{"vulnerabilities":[{"cve_id":"CVE-2017-0144","cve_score":9.8,...}]}'
   
   # Check agent
   curl http://localhost:5000/agent/check
   
   # Execute attack
   curl -X POST http://localhost:5000/attack/execute \
     -H "Content-Type: application/json" \
     -d '{"technique_ids":["T1082","T1087"]}'
   
5. Or test via the web UI — full user flow
"""
 
 
# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY — What P1 Needs To Do
# ═══════════════════════════════════════════════════════════════════════════
 
"""
✅ Create config.py with all settings
✅ Import P4 modules in app.py
✅ Initialize operation_manager, risk_scorer, db at startup
✅ Add routes that call P4:
   - /scan/save (after P2 finishes)
   - /vulnerabilities/save (after P3 finishes)
   - /agent/check (show Sandcat deploy command if needed)
   - /attack/execute (main P4 entry point)
   - /results (display page using session data)
✅ Pass session data between steps
✅ Handle errors gracefully
✅ Test end-to-end
 
P4 modules are ready to use — just wire them in as shown above!
"""
 
 
if __name__ == '__main__':
    """
    P1 runs the Flask app like this:
    """
    app.run(
        host='0.0.0.0',  # accessible from other VMs
        port=5000,
        debug=True
    )
"""