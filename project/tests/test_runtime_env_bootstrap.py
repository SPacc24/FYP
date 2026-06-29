from pathlib import Path

from runtime_env import ensure_env_file, read_env_values


def test_env_bootstrap_generates_missing_secrets_and_preserves_existing(tmp_path: Path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "SECRET_KEY=change-me\n"
        "DEBUG=true\n"
        "METASPLOIT_RPC_PASS=already-set\n",
        encoding="utf-8",
    )

    result = ensure_env_file(env_path)
    values = read_env_values(env_path)

    assert result.changed is True
    assert values["SECRET_KEY"] != "change-me"
    assert values["DEBUG"] == "true"
    assert values["METASPLOIT_RPC_PASS"] == "already-set"
    assert values["OPERATOR_TOKEN"]
    assert values["PROOF_OF_ACCESS_SECRET"]
    assert values["APP_HOST"] == "127.0.0.1"

    second_result = ensure_env_file(env_path)
    second_values = read_env_values(env_path)

    assert second_result.changed is False
    assert second_values == values
