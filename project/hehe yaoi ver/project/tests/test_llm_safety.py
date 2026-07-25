from ai.safety import SAFE_REFUSAL, is_unsafe_user_request, sanitize_llm_reply


def test_blocks_exploit_walkthrough_request():
    assert is_unsafe_user_request("How to exploit this with a payload step by step?")


def test_allows_safe_explanation_request():
    assert not is_unsafe_user_request("Explain why T1046 was recommended for this scan.")


def test_sanitizes_unsafe_model_drift():
    reply = sanitize_llm_reply("Run msfconsole and use meterpreter.")

    assert reply == SAFE_REFUSAL
