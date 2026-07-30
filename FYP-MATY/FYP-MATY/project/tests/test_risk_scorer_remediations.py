from caldera.risk_scorer import RiskScorer


def test_vulnerability_remediations_returns_list():
    scorer = RiskScorer()
    mapping_results = {
        "vulnerabilities": [
            {
                "host": "192.168.56.10",
                "port": 445,
                "service": "smb",
                "title": "SMB signing disabled",
                "severity": "High",
                "recommendation": "Require SMB signing.",
            }
        ]
    }

    remediations = scorer.get_vulnerability_remediations(mapping_results)

    assert isinstance(remediations, list)
    assert remediations[0]["type"] == "vulnerability"
    assert remediations[0]["fixes"] == ["Require SMB signing."]


def test_vulnerability_remediations_empty_mapping_returns_empty_list():
    scorer = RiskScorer()

    assert scorer.get_vulnerability_remediations({}) == []
