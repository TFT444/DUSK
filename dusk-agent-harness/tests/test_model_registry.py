from models.registry import MODEL_PROFILES, get_model_profile

EXPECTED = {
    "moonshotai.kimi-k2.5": "kimi-k2-5",
    "zai.glm-5": "glm-5",
    "qwen.qwen3-32b": "qwen3-32b",
    "openai.gpt-oss-120b": "gpt-oss-120b",
}


def test_registry_explicitly_exports_its_public_contract() -> None:
    from models import registry

    assert set(registry.__all__) == {"MODEL_PROFILES", "ModelProfile", "get_model_profile"}


def test_registry_contains_exact_supported_model_set() -> None:
    assert {profile.model_id: profile.slug for profile in MODEL_PROFILES} == EXPECTED


def test_unknown_model_fails_closed() -> None:
    try:
        get_model_profile("unknown.model")
    except ValueError as exc:
        assert "Unsupported Bedrock Mantle model" in str(exc)
    else:
        raise AssertionError("unknown model must fail closed")


def test_every_model_profile_owns_its_complete_client_contract() -> None:
    profiles = {profile.model_id: profile for profile in MODEL_PROFILES}

    assert profiles["moonshotai.kimi-k2.5"].timeout_seconds == 180
    assert profiles["moonshotai.kimi-k2.5"].max_retries == 1
    for model_id in ("zai.glm-5", "qwen.qwen3-32b", "openai.gpt-oss-120b"):
        assert profiles[model_id].timeout_seconds == 120
        assert profiles[model_id].max_retries == 0
    assert all(profile.max_completion_tokens == 4096 for profile in profiles.values())
    assert profiles["qwen.qwen3-32b"].retry_on_token_limit is True
    assert profiles["openai.gpt-oss-120b"].retry_on_token_limit is False
    assert profiles["openai.gpt-oss-120b"].client_correction_prompt
    assert profiles["openai.gpt-oss-120b"].simulation_context
    assert profiles["openai.gpt-oss-120b"].force_single_tool_choice is True
    assert profiles["zai.glm-5"].client_correction_prompt is None


def test_runtime_uses_production_name() -> None:
    from pathlib import Path

    assert Path("runtime/bedrock_client.py").is_file()
    assert not Path("agent-demo").exists()
