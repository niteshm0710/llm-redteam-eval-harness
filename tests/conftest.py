"""Shared pytest fixtures and mock OpenAI-compatible HTTP transports."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from redteam_harness.api import create_app
from redteam_harness.attacks import AttackRegistry, create_default_registry
from redteam_harness.config import HarnessSettings


@pytest.fixture
def registry() -> AttackRegistry:
    """Fresh default AttackRegistry with all four built-in suites."""
    return create_default_registry()


@pytest.fixture
def client() -> TestClient:
    """Unauthenticated FastAPI TestClient using default secure settings."""
    settings = HarnessSettings(allow_private_targets=False, max_stored_runs=50)
    app = create_app(settings=settings)
    return TestClient(app)


@pytest.fixture
def authed_client() -> tuple[TestClient, str]:
    """FastAPI TestClient protected by a gateway Bearer token."""
    token = "rt-gateway-secret-token-998877"
    settings = HarnessSettings(api_token=token, allow_private_targets=False)
    app = create_app(settings=settings)
    return TestClient(app), token


def make_chat_completion_response(
    content: Any,
    *,
    model: str = "test-model-v1",
    status_code: int = 200,
    refusal: str | None = None,
) -> httpx.Response:
    """Build a synthetic OpenAI-compatible `/chat/completions` HTTP response."""
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if refusal is not None:
        message["refusal"] = refusal
    body = {
        "id": "chatcmpl-test123",
        "object": "chat.completion",
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 42, "completion_tokens": 18, "total_tokens": 60},
    }
    return httpx.Response(
        status_code=status_code,
        headers={"Content-Type": "application/json"},
        content=json.dumps(body).encode("utf-8"),
    )
