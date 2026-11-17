"""Target adapter factory and exports."""

from __future__ import annotations

import httpx

from redteam_harness.config import HarnessSettings
from redteam_harness.schemas import ProviderMode, TargetConfig
from redteam_harness.targets.base import (
    EgressPolicyError,
    TargetAdapter,
    TargetInvocationError,
    TargetResponse,
    validate_endpoint_url,
)
from redteam_harness.targets.mock import MockTargetAdapter
from redteam_harness.targets.openai_compat import OpenAICompatibleClient, OpenAICompatibleTarget


def build_target_adapter(
    config: TargetConfig,
    settings: HarnessSettings,
    *,
    allow_private_override: bool | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> TargetAdapter:
    """Construct a `TargetAdapter` from `TargetConfig` and runtime gateway settings."""
    if config.mode == ProviderMode.MOCK:
        return MockTargetAdapter(profile=config.mock_profile)

    base_url = (config.base_url or settings.default_target_base_url).strip()
    model = (config.model or settings.default_target_model).strip()
    api_key = (
        config.api_key.get_secret_value()
        if config.api_key is not None
        else settings.default_target_api_key
    )
    allow_private = (
        settings.allow_private_targets if allow_private_override is None else allow_private_override
    )
    client = OpenAICompatibleClient(
        base_url=base_url,
        model=model,
        api_key=api_key,
        timeout_seconds=config.timeout_seconds,
        max_retries=config.max_retries,
        extra_headers=config.extra_headers,
        allow_private=allow_private,
        allowed_hosts=settings.allowed_target_hosts,
        transport=transport,
    )
    return OpenAICompatibleTarget(
        client=client,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
    )


__all__ = [
    "EgressPolicyError",
    "MockTargetAdapter",
    "OpenAICompatibleClient",
    "OpenAICompatibleTarget",
    "TargetAdapter",
    "TargetInvocationError",
    "TargetResponse",
    "build_target_adapter",
    "validate_endpoint_url",
]
