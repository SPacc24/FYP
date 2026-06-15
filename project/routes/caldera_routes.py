import logging
import time
from pathlib import Path
from types import SimpleNamespace

from flask import jsonify, request, session

from config import Config

from core.helpers import (
    _active_mapping_results,
    _active_operation_results,
    _active_validation_results,
    _caldera_agent_server_host,
    _current_target_context,
    _load_current_scan_results,
    _safe_risk_calculate,
    _save_active_scan_fields,
)

from core.services import (
    coverage_checker,
    exploitability_validator,
    operation_manager,
    risk_scorer,
)
from exploitation.lab_exploitation_runner import build_report, write_report

log = logging.getLogger(__name__)


def register_routes(app):
    @app.route("/caldera/status", methods=["GET"])
    def caldera_status():
        target_context = _current_target_context()

        status = operation_manager.check_readiness(
            target=target_context["target"]
        )

        status["target"] = target_context["target"]
        status["target_os"] = target_context["os"]

        if not status.get("agent_ready"):
            status["deploy_command"] = operation_manager.get_deploy_command(
                kali_ip=_caldera_agent_server_host(),
                group=getattr(Config, "AGENT_GROUP", "red"),
                platform=target_context["platform"],
            )

        return jsonify(status)

    @app.route("/caldera/deploy-command", methods=["GET"])
    def caldera_deploy_command():
        target_context = _current_target_context()

        return jsonify({
            "ok": True,
            "target": target_context["target"],
            "os": target_context["os"],
            "group": getattr(Config, "AGENT_GROUP", "red"),
            "deploy_command": operation_manager.get_deploy_command(
                kali_ip=_caldera_agent_server_host(),
                group=getattr(Config, "AGENT_GROUP", "red"),
                platform=target_context["platform"],
            ),
        })

    @app.route("/caldera/agent/delete", methods=["POST"])
    def caldera_agent_delete():
        try:
            data = request.get_json(silent=True) or {}
            paw = data.get("paw")

            result = operation_manager.delete_agent(paw)

            return jsonify(result), 200 if result.get("ok") else 400

        except Exception as e:
            log.error("Agent delete failed: %s", e)

            return jsonify({
                "ok": False,
                "error": str(e)
            }), 500

    @app.route("/caldera/agents/remove-stale", methods=["POST"])
    def caldera_agents_remove_stale():
        try:
            target_context = _current_target_context()

            result = operation_manager.remove_stale_agents(
                target=target_context["target"]
            )

            return jsonify(result), 200 if result.get("ok") else 500

        except Exception as e:
            log.error("Remove stale agents failed: %s", e)

            return jsonify({
                "ok": False,
                "error": str(e)
            }), 500

    @app.route("/caldera/agent/select", methods=["POST"])
    def caldera_agent_select():
        data = request.get_json(silent=True) or {}
        paw = data.get("paw")

        if not paw:
            return jsonify({
                "ok": False,
                "error": "Missing paw"
            }), 400

        session["selected_agent_paw"] = paw

        return jsonify({
            "ok": True,
            "selected_agent_paw": paw
        })

    @app.route("/caldera/operation/status", methods=["GET"])
    def operation_status():
        return jsonify(_active_operation_results())

    @app.route("/exploitation/run", methods=["POST"])
    def exploitation_run():
        try:
            parsed_results = _load_current_scan_results()

            if not parsed_results:
                return jsonify({
                    "ok": False,
                    "error": "No scan results available. Run a scan before validation."
                }), 400

            mapping_results = _active_mapping_results()

            validation_results = exploitability_validator.validate(
                parsed_results,
                mapping_results
            )

            session["validation_results"] = validation_results

            session["risk_score"] = _safe_risk_calculate(
                mapping_results.get("vulnerabilities", []),
                {
                    **(_active_operation_results() or {}),
                    "validation_results": validation_results,
                },
            )

            _save_active_scan_fields(
                validation_results=validation_results,
                risk=session["risk_score"],
            )

            return jsonify(validation_results)

        except Exception as e:
            log.error("Exploitability validation failed: %s", e)

            return jsonify({
                "ok": False,
                "error": str(e)
            }), 500

    @app.route("/exploitation/approved-run", methods=["POST"])
    def exploitation_approved_run():
        try:
            data = request.get_json(silent=True) or {}

            if not data.get("approved"):
                return jsonify({
                    "ok": False,
                    "error": "Explicit approval is required before running exploitation validation."
                }), 400

            target_context = _current_target_context()
            target = data.get("target") or target_context.get("target") or session.get("target_ip")

            if not target or target == "Unknown":
                return jsonify({
                    "ok": False,
                    "error": "No target is available. Run a scan before approved exploitation."
                }), 400

            scan_id = session.get("scan_id") or "manual"
            ts = time.strftime("%Y%m%d_%H%M%S")
            output_path = Path("storage/scans") / f"approved_exploitation_{scan_id}_{ts}.json"

            args = SimpleNamespace(
                target=target,
                cred_file=(data.get("cred_file") or "wordlists/default_credentials_autopentest.txt"),
                allow_credential_checks=bool(data.get("allow_credential_checks", True)),
                web_url=[url for url in (data.get("web_urls") or []) if str(url).strip()],
                sqli_url=(data.get("sqli_url") or "").strip() or None,
                sqli_param=(data.get("sqli_param") or "id").strip() or "id",
                cmdi_url=(data.get("cmdi_url") or "").strip() or None,
                cmdi_param=(data.get("cmdi_param") or "ip").strip() or "ip",
                allow_command_injection_probe=bool(data.get("allow_command_injection_probe")),
                ftp_port=int(data.get("ftp_port") or 21),
                ssh_port=int(data.get("ssh_port") or 22),
                smb_port=int(data.get("smb_port") or 445),
                winrm_port=int(data.get("winrm_port") or 5985),
                winrm_tls_port=int(data.get("winrm_tls_port") or 5986),
                timeout=float(data.get("timeout") or 5.0),
                output=str(output_path),
            )

            report = build_report(args)
            write_report(report, str(output_path))

            report["ok"] = True
            report["mode"] = "approved_controlled_exploitation"
            report["output_file"] = str(output_path)

            session["approved_exploitation_results"] = report

            mapping_results = _active_mapping_results()
            session["risk_score"] = _safe_risk_calculate(
                mapping_results.get("vulnerabilities", []),
                {
                    **(_active_operation_results() or {}),
                    "validation_results": _active_validation_results(),
                    "approved_exploitation_results": report,
                },
            )

            _save_active_scan_fields(
                approved_exploitation_results=report,
                risk=session["risk_score"],
            )

            return jsonify(report)

        except Exception as e:
            log.error("Approved exploitation run failed: %s", e)

            return jsonify({
                "ok": False,
                "error": str(e)
            }), 500

    @app.route("/api/caldera/check-coverage", methods=["POST"])
    def check_coverage():
        try:
            data = request.get_json(silent=True) or {}
            technique_ids = data.get("technique_ids", [])

            if not technique_ids:
                return jsonify({
                    "ok": False,
                    "error": "technique_ids list is required"
                }), 400

            coverage = coverage_checker.check_technique_coverage(
                technique_ids
            )

            return jsonify({
                "ok": True,
                **coverage,
            })

        except Exception as e:
            log.error("Coverage check failed: %s", e)

            return jsonify({
                "ok": False,
                "error": str(e)
            }), 500

    @app.route("/caldera/run", methods=["POST"])
    def caldera_run():
        try:
            data = request.get_json(silent=True) or {}

            selected_techniques = data.get("selected_techniques", [])

            if not selected_techniques:
                return jsonify({
                    "ok": False,
                    "error": "No techniques selected"
                }), 400

            coverage = coverage_checker.check_technique_coverage(
                selected_techniques
            )
            supported_techniques = coverage_checker.get_supported_techniques(
                selected_techniques
            )
            unsupported_count = coverage["unsupported"]

            if unsupported_count > 0:
                log.warning(
                    "User requested %s techniques; %s not supported by CALDERA. "
                    "Will execute only %s supported techniques.",
                    len(selected_techniques),
                    unsupported_count,
                    len(supported_techniques),
                )

            if not supported_techniques:
                mapping_results = _active_mapping_results()

                unsupported_results = operation_manager.build_unsupported_results(
                    selected_techniques,
                    {
                        "vulnerabilities": mapping_results.get("vulnerabilities", []),
                        "scan_context": {
                            "os": session.get("target_os", "Unknown")
                        },
                    },
                )

                result = {
                    "success": True,
                    "operation_id": "",
                    "operation_name": "No CALDERA operation created",
                    "state": "unsupported",
                    "techniques_run": unsupported_results,
                    "total": len(unsupported_results),
                    "success_count": 0,
                    "fail_count": 0,
                    "running_count": 0,
                    "discarded_count": 0,
                    "unsupported_count": len(unsupported_results),
                    "timed_out": False,
                    "agent_host": "",
                    "agent_paw": "",
                    "coverage": coverage,
                    "coverage_info": {
                        "requested": selected_techniques,
                        "supported": [],
                        "unsupported": selected_techniques,
                        "unsupported_count": len(selected_techniques),
                        "coverage_details": coverage,
                    },
                }

                result["validation_results"] = _active_validation_results()

                risk = _safe_risk_calculate(
                    mapping_results.get("vulnerabilities", []),
                    result
                )

                session["operation_results"] = result
                session["risk_score"] = risk

                _save_active_scan_fields(
                    operation_results=result,
                    risk=risk
                )

                return jsonify({
                    "ok": True,
                    **result,
                    "risk": risk,
                    "message": (
                        "No selected techniques are supported by CALDERA. "
                        "Unsupported techniques were recorded for external validation."
                    ),
                })

            result = operation_manager.run_operation(
                technique_ids=supported_techniques,
                group=data.get("group", getattr(Config, "AGENT_GROUP", "red")),
                timeout=getattr(Config, "OPERATION_TIMEOUT", 180),
                target=session.get("target_ip"),
                selected_paw=session.get("selected_agent_paw"),
                unsupported_techniques=[
                    technique_id
                    for technique_id in selected_techniques
                    if technique_id not in supported_techniques
                ],
                unsupported_context={
                    "vulnerabilities": _active_mapping_results().get("vulnerabilities", []),
                    "scan_context": {
                        "os": session.get("target_os", "Unknown")
                    },
                },
            )

            if not isinstance(result, dict):
                return jsonify({
                    "ok": False,
                    "error": "Invalid response from operation manager"
                }), 500

            if not result.get("success", True):
                return jsonify(result), 500

            mapping_results = _active_mapping_results()

            vulns = (
                data.get("vulnerabilities")
                or session.get("vulnerabilities")
                or mapping_results.get("vulnerabilities", [])
            )

            session["vulnerabilities"] = vulns

            result["validation_results"] = _active_validation_results()

            risk = _safe_risk_calculate(vulns, result)

            vulnerability_remediations = []

            try:
                vulnerability_remediations = (
                    risk_scorer.get_vulnerability_remediations(mapping_results)
                    or []
                )
            except Exception:
                vulnerability_remediations = []

            technique_remediations = []

            try:
                technique_remediations = (
                    risk_scorer.get_all_remediations(result)
                    or []
                )
            except Exception:
                technique_remediations = []

            remediations = vulnerability_remediations + technique_remediations

            result["coverage_info"] = {
                "requested": selected_techniques,
                "supported": supported_techniques,
                "unsupported": [
                    technique_id
                    for technique_id in selected_techniques
                    if technique_id not in supported_techniques
                ],
                "unsupported_count": unsupported_count,
                "coverage_details": coverage,
            }

            session["operation_results"] = result
            session["risk_score"] = risk
            session["remediations"] = remediations

            _save_active_scan_fields(
                operation_results=result,
                risk=risk,
                remediations=remediations,
            )

            return jsonify({
                "ok": True,
                "success": True,
                **result,
                "risk": risk,
                "remediations": remediations,
            })

        except Exception as e:
            log.error("CALDERA execution failed: %s", e)

            return jsonify({
                "ok": False,
                "error": str(e)
            }), 500

    @app.route("/caldera/operation/<operation_id>", methods=["GET"])
    def caldera_operation(operation_id):
        return jsonify(operation_manager.poll_operation(operation_id))
