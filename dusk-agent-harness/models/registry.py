from models.glm import PROFILE as GLM_PROFILE
from models.gpt_oss import PROFILE as GPT_OSS_PROFILE
from models.kimi import PROFILE as KIMI_PROFILE
from models.profile import ModelProfile
from models.qwen import PROFILE as QWEN_PROFILE

__all__ = ["MODEL_PROFILES", "ModelProfile", "get_model_profile"]

MODEL_PROFILES = (
    KIMI_PROFILE,
    GLM_PROFILE,
    QWEN_PROFILE,
    GPT_OSS_PROFILE,
)


def get_model_profile(model_id: str) -> ModelProfile:
    for profile in MODEL_PROFILES:
        if profile.model_id == model_id:
            return profile
    raise ValueError(f"Unsupported Bedrock Mantle model: {model_id}")
