"""RQ1–RQ3: three evidence conditions + naive baseline vs gated engine."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture()
def mission_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPENTEST_MISSIONS_DIR", str(tmp_path / "missions"))
    monkeypatch.setenv("AUTOPENTEST_PROOFS_DIR", str(tmp_path / "proofs"))
    from automation import mission_service as ms

    ms.reset_mission_service()
    yield tmp_path
    ms.reset_mission_service()


def _load_eval_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_orchestration_evaluation.py"
    spec = importlib.util.spec_from_file_location("run_orchestration_evaluation", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_three_conditions_three_path_signatures(mission_env):
    mod = _load_eval_module()
    report = mod.run_evaluation()
    assert report["distinct_path_signatures"] >= 3
    assert report["research_questions"]["RQ2_path_diversity"]["pass"] is True


def test_rq1_gated_beats_naive_on_patched_smb(mission_env):
    mod = _load_eval_module()
    report = mod.run_evaluation()
    rq1 = report["research_questions"]["RQ1_unsupported_exploit_pressure"]
    assert rq1["pass"] is True, rq1
    web = report["conditions"]["C_web_smb_no_cve"]
    assert web["gated"]["high_risk_auto_count"] == 0
    assert web["ms17_suppressed"] is True


def test_rq3_zero_high_risk_auto_all_conditions(mission_env):
    mod = _load_eval_module()
    report = mod.run_evaluation()
    assert report["research_questions"]["RQ3_zero_high_risk_auto"]["pass"] is True
    for name, row in report["conditions"].items():
        assert row["gated"]["high_risk_auto_count"] == 0, name


def test_unknown_surface_research_not_invented_exploit(mission_env):
    mod = _load_eval_module()
    report = mod.run_evaluation()
    unknown = report["conditions"]["C_unknown_surface"]
    assert unknown["unknown_research"] is True
    assert unknown["gated"]["high_risk_auto_count"] == 0


def test_evaluation_script_overall_pass(mission_env):
    mod = _load_eval_module()
    report = mod.run_evaluation()
    assert report["overall_pass"] is True
