from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ModelProfile:
    name: str
    slug: str
    model_id: str
    provider: str = "mantle"
    timeout_seconds: int = 120
    max_retries: int = 0
    max_completion_tokens: int = 4096
    retry_on_token_limit: bool = True
    client_correction_prompt: str | None = None
    simulation_context: str | None = None
    force_single_tool_choice: bool = False
