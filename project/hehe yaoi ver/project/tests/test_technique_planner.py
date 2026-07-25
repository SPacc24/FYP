import json

from ai import technique_planner as planner


def fake_mitre_info(technique_id):
    return {
        "id": technique_id,
        "name": f"Technique {technique_id}",
        "description": f"Description for {technique_id}",
        "tactics": ["Discovery"],
        "platforms": ["Windows"],
        "data_sources": [],
        "detection": "",
        "mitre_url": planner.build_mitre_url(technique_id),
    }


def test_safe_json_loads_handles_non_dict_json():
    parsed = planner.safe_json_loads('["T1046"]')

    assert parsed["selected_technique_ids"] == []
    assert "unexpected JSON shape" in parsed["reasoning"]


def test_planner_filters_invented_technique_ids(monkeypatch):
    mapping_result = {
        "recommended_techniques": [
            {
                "id": "T1046",
                "name": "Network Service Discovery",
                "count": 2,
                "max_severity": "High",
            }
        ],
        "vulnerabilities": [],
    }

    llm_response = {
        "selected_technique_ids": ["T9999", "T1046", "T1046"],
        "reasoning": "Use the mapped discovery technique.",
        "technique_explanations": [],
        "next_steps": ["Review safely."],
    }

    monkeypatch.setattr(planner, "get_mitre_technique_info", fake_mitre_info)
    monkeypatch.setattr(planner, "ask_llm_json", lambda prompt: json.dumps(llm_response))

    plan = planner.generate_ai_technique_plan(mapping_result)

    assert plan["selected_technique_ids"] == ["T1046"]
    assert "T9999" not in plan["selected_technique_ids"]


def test_planner_falls_back_when_llm_returns_bad_json(monkeypatch):
    mapping_result = {
        "recommended_techniques": [
            {
                "id": "T1046",
                "name": "Network Service Discovery",
                "count": 1,
                "max_severity": "Medium",
            },
            {
                "id": "T1021.002",
                "name": "SMB/Windows Admin Shares",
                "count": 1,
                "max_severity": "Critical",
            },
        ],
        "vulnerabilities": [],
    }

    monkeypatch.setattr(planner, "get_mitre_technique_info", fake_mitre_info)
    monkeypatch.setattr(planner, "ask_llm_json", lambda prompt: "not json")

    plan = planner.generate_ai_technique_plan(mapping_result)

    assert plan["selected_technique_ids"] == ["T1046", "T1021.002"]
    assert "could not be parsed" in plan["reasoning"]
    assert plan["technique_explanations"]

def test_cves_link_to_matching_attack_technique_only(monkeypatch):
    mapping_result = {
        "recommended_techniques": [
            {
                "id": "T1046",
                "name": "Network Service Discovery",
                "count": 1,
                "max_severity": "Medium",
            },
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "count": 1,
                "max_severity": "High",
            },
        ],
        "vulnerabilities": [
            {
                "title": "Apache CVE-2021-41773 exposure",
                "cve_ids": ["CVE-2021-41773"],
                "attack_techniques": [
                    {"id": "T1190", "name": "Exploit Public-Facing Application"}
                ],
            }
        ],
    }

    monkeypatch.setattr(planner, "get_mitre_technique_info", fake_mitre_info)
    monkeypatch.setattr(
        planner,
        "fetch_cve_from_nvd",
        lambda cve_id: {"id": cve_id, "cvss": {"severity": "High", "score": 7.5}},
    )

    allowed = planner.extract_allowed_techniques(mapping_result)
    by_id = {item["id"]: item for item in allowed}

    assert by_id["T1190"]["linked_cves"][0]["id"] == "CVE-2021-41773"
    assert by_id["T1046"]["linked_cves"] == []


def test_planner_expands_smb_to_attack_path(monkeypatch):
    mapping_result = {
        "recommended_techniques": [
            {"id": "T1046", "name": "Network Service Discovery", "count": 1, "max_severity": "High"},
            {"id": "T1135", "name": "Network Share Discovery", "count": 1, "max_severity": "High"},
            {"id": "T1210", "name": "Exploitation of Remote Services", "count": 1, "max_severity": "High"},
            {"id": "T1021.002", "name": "SMB Admin Shares", "count": 1, "max_severity": "High"},
        ],
        "vulnerabilities": [],
    }

    llm_response = {
        "selected_technique_ids": ["T1046", "T1135"],
        "reasoning": "Discovery first.",
        "technique_explanations": [],
        "next_steps": ["Review safely."],
    }

    monkeypatch.setattr(planner, "get_mitre_technique_info", fake_mitre_info)
    monkeypatch.setattr(planner, "ask_llm_json", lambda prompt: json.dumps(llm_response))

    plan = planner.generate_ai_technique_plan(mapping_result)

    assert plan["selected_technique_ids"] == ["T1046", "T1135", "T1210", "T1021.002"]
