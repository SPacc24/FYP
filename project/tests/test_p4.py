"""
test_p4.py
End-to-end test script for P4 (Caldera integration).
Run this to verify everything works BEFORE plugging into Flask.

Usage:
    python3 test_p4.py

Edit the CONFIG section below before running.
"""

import sys
import json

# ── CONFIG — edit these before running ──────────────────────────────────────
CALDERA_URL  = "http://localhost:8888"
CALDERA_KEY  = "redadmin"           # your plaintext key from default.yml
KALI_IP      = "192.168.86.128"       # your Kali IP (run: ip addr)
AGENT_GROUP  = "red"
TIMEOUT      = 120                  # seconds to wait for operation

MYSQL_HOST   = "192.168.67.1"
MYSQL_USER   = "autopentest"
MYSQL_PASS   = "Admin123#@!"       # your MySQL user password
MYSQL_DB     = "autopentest"
# ────────────────────────────────────────────────────────────────────────────


def separator(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def test_caldera_connection():
    separator("TEST 1 — Caldera Connection + API Key")
    from caldera.api_client import CalderaClient

    client = CalderaClient(CALDERA_URL, CALDERA_KEY)
    alive  = client.ping()

    if alive:
        print("✅ Caldera is reachable and API key is valid.")
    else:
        print("❌ Cannot connect to Caldera or API key is wrong.")
        print("   → Check: python3 server.py --insecure is running")
        print("   → Check: api_key_red in conf/default.yml matches CALDERA_KEY above")
        sys.exit(1)

    return client


def test_agents(client):
    separator("TEST 2 — Check Active Agents")
    agents = client.get_agents()
    print(f"Total agents found: {len(agents)}")

    if not agents:
        print("⚠️  No agents found. Deploy Sandcat on your Windows VM first.")
        print("\nRun this on your Windows 10 VM (PowerShell as Admin):")
        print(client.generate_sandcat_command(KALI_IP, AGENT_GROUP))
        print("\nThen wait 30 seconds and re-run this script.")
        sys.exit(1)

    for a in agents:
        status = "✅ Active" if a.get('trusted') else "⚠️  Not trusted"
        print(f"  {status} | Host: {a.get('host')} | Group: {a.get('group')} | Paw: {a.get('paw')}")

    return agents


def test_adversaries(client):
    separator("TEST 3 — Available Adversaries")
    adversaries = client.get_adversaries()
    print(f"Total adversaries: {len(adversaries)}")

    for adv in adversaries[:5]:  # show first 5
        print(f"  • {adv.get('name')} | ID: {adv.get('adversary_id')}")

    if len(adversaries) > 5:
        print(f"  ... and {len(adversaries) - 5} more")

    return adversaries


def test_abilities(client):
    separator("TEST 4 — Abilities for T1082 (System Discovery)")
    abilities = client.get_abilities_by_technique('T1082')
    print(f"Abilities matching T1082: {len(abilities)}")

    for ab in abilities[:3]:
        print(f"  • {ab.get('name')} | Platform: {list(ab.get('platforms', {}).keys())}")


def test_operation_manager():
    separator("TEST 5 — Full Operation Flow (Operation Manager)")
    from caldera.operation_manager import OperationManager

    manager   = OperationManager(CALDERA_URL, CALDERA_KEY)

    # Check agent first
    available, info = manager.check_agent(AGENT_GROUP)
    if not available:
        print(f"❌ {info}")
        return None

    print(f"✅ Agent ready: {info.get('host')}")
    print(f"\nRunning operation with techniques: T1082, T1087 (Discovery)")
    print(f"Timeout: {TIMEOUT}s — please wait...\n")

    results = manager.run_operation(
        technique_ids=['T1082', 'T1087'],
        group=AGENT_GROUP,
        timeout=TIMEOUT
    )

    if not results['success']:
        print(f"❌ Operation failed: {results.get('error')}")
        return None

    print(f"✅ Operation completed!")
    print(f"   ID:       {results['operation_id']}")
    print(f"   State:    {results['state']}")
    print(f"   Total:    {results['total']} techniques")
    print(f"   Success:  {results['success_count']}")
    print(f"   Failed:   {results['fail_count']}")
    print(f"   Agent:    {results['agent_host']}")
    print(f"\nTechnique details:")

    for t in results['techniques_run']:
        icon = "✅" if t['status'] == 'success' else "❌" if t['status'] == 'failed' else "⏳"
        print(f"  {icon} {t['technique_id']} — {t['technique_name']} ({t['tactic']})")

    return results


def test_risk_scorer(operation_results):
    separator("TEST 6 — Risk Scoring")
    from project.caldera.risk_scorer import RiskScorer

    scorer = RiskScorer()

    # Simulate some CVE findings
    mock_vulns = [
        {'cve_id': 'CVE-2017-0144', 'cve_score': 9.8, 'severity': 'critical',
         'port': 445, 'service': 'smb', 'description': 'EternalBlue SMB RCE'},
        {'cve_id': 'CVE-2019-0708', 'cve_score': 9.8, 'severity': 'critical',
         'port': 3389, 'service': 'rdp', 'description': 'BlueKeep RDP RCE'},
        {'cve_id': 'CVE-2021-34527', 'cve_score': 8.8, 'severity': 'high',
         'port': 445, 'service': 'smb', 'description': 'PrintNightmare'},
    ]

    risk = scorer.calculate(mock_vulns, operation_results or {'techniques_run': [], 'total': 0, 'success_count': 0})
    print(f"Risk Score: {risk['score']}/10 — {risk['label']}")
    print(f"Breakdown:  {json.dumps(risk['breakdown'], indent=10)}")

    # Test remediation
    print("\nRemediation advice for successful techniques:")
    if operation_results:
        remediations = scorer.get_all_remediations(operation_results)
        for r in remediations:
            print(f"\n  [{r['technique_id']}] {r['title']}")
            for fix in r['fixes'][:2]:
                print(f"    → {fix}")

    return risk


def test_mysql():
    separator("TEST 7 — MySQL Storage")
    try:
        from project.storage.db import Database

        db = Database(MYSQL_HOST, MYSQL_USER, MYSQL_PASS, MYSQL_DB)

        # Init schema
        print("Initialising schema...")
        ok = db.init_schema()
        if ok:
            print("✅ Schema created/verified.")
        else:
            print("❌ Schema init failed — check MySQL credentials.")
            return

        # Test connection
        connected, msg = db.test_connection()
        if connected:
            print(f"✅ MySQL connected: {msg}")
        else:
            print(f"❌ MySQL connection failed: {msg}")
            return

        # Test save scan
        mock_scan = {
            'target_ip': '192.168.56.101',
            'os': 'Windows 10',
            'ports': [
                {'port': 445, 'service': 'smb',  'state': 'open', 'version': '3.1.1'},
                {'port': 3389, 'service': 'rdp', 'state': 'open', 'version': ''},
            ]
        }
        scan_id = db.save_scan('192.168.56.101', mock_scan)
        if scan_id > 0:
            print(f"✅ Scan saved: id={scan_id}")
        else:
            print("❌ Scan save failed.")
            return

        # Test save vulnerabilities
        mock_vulns = [
            {'port': 445, 'service': 'smb', 'cve_id': 'CVE-2017-0144',
             'cve_score': 9.8, 'severity': 'critical', 'description': 'EternalBlue'},
        ]
        db.save_vulnerabilities(scan_id, mock_vulns)
        print("✅ Vulnerabilities saved.")

        print(f"\nAll MySQL tests passed! scan_id={scan_id}")

    except ImportError:
        print("❌ mysql-connector-python not installed.")
        print("   Run: pip3 install mysql-connector-python --break-system-packages")
    except Exception as e:
        print(f"❌ MySQL test failed: {e}")


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("\n🔥 AutoPenTest — P4 Test Suite")
    print("   SP DCDF Group 6 | AY2026/27 S1")

    try:
        client           = test_caldera_connection()
        test_agents(client)
        test_adversaries(client)
        test_abilities(client)
        op_results       = test_operation_manager()
        risk             = test_risk_scorer(op_results)
        test_mysql()

        separator("ALL TESTS COMPLETE")
        print("✅ P4 is fully operational and ready to integrate with Flask.")
        print("   Next step: wire caldera/operation_manager.py into app.py\n")

    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
