import json

from pentest_ai.advisor import generate_attack_path_advice


def test_advisor_falls_back_to_safe_service_path_when_llm_unavailable():
    parsed_results = {
        "hosts": [{"address": {"primary": "192.168.56.20"}}],
        "ports": [
            {"port": "445", "state": "open", "service": "microsoft-ds", "product": "Windows SMB"},
        ],
    }
    mapping_results = {
        "recommended_techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1135", "name": "Network Share Discovery"},
            {"id": "T1210", "name": "Exploitation of Remote Services"},
            {"id": "T1021.002", "name": "SMB Admin Shares"},
        ],
        "vulnerabilities": [{"service": "smb", "title": "SMB exposure"}],
    }

    result = generate_attack_path_advice(
        parsed_results,
        mapping_results,
        ask_json=lambda prompt: "not json",
    )

    assert result["ok"] is True
    assert result["source"] == "deterministic_fallback"
    assert result["attack_paths"]
    assert result["attack_paths"][0]["recommended_validation"] == "tcp_reachability_check"
    assert result["attack_paths"][0]["safe_to_run_automatically"] is False
    assert result["attack_paths"][0]["requires_human_approval"] is True


def test_advisor_sanitizes_unapproved_module_and_invented_technique():
    parsed_results = {
        "target_ip": "192.168.56.30",
        "ports": [{"port": "80", "state": "open", "service": "http"}],
    }
    mapping_results = {
        "recommended_techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
        ],
        "vulnerabilities": [],
    }
    llm_response = {
        "summary": "Use the web evidence.",
        "attack_paths": [
            {
                "title": "Unsafe suggestion should be constrained",
                "target": "192.168.56.30",
                "service": "http",
                "port": 80,
                "technique_ids": ["T9999", "T1190"],
                "confidence": "high",
                "recommended_validation": "run_random_exploit",
                "reasoning": "msfconsole would be unsafe here",
                "evidence": ["HTTP service observed"],
                "requires_human_approval": False,
                "safe_to_run_automatically": True,
            }
        ],
        "limitations": [],
    }

    result = generate_attack_path_advice(
        parsed_results,
        mapping_results,
        ask_json=lambda prompt: json.dumps(llm_response),
    )

    path = result["attack_paths"][0]
    assert result["source"] == "ollama"
    assert path["recommended_validation"] == "manual_review"
    assert path["technique_ids"] == ["T1190"]
    assert path["reasoning"] == "Evidence supports safe validation review."
    assert path["safe_to_run_automatically"] is False
    assert path["requires_human_approval"] is True
