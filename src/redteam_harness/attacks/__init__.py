"""Built-in adversarial attack suites and default registry factory."""

from redteam_harness.attacks.base import (
    AttackPlugin,
    AttackRegistry,
    DuplicatePluginError,
    UnknownCaseError,
    UnknownSuiteError,
    apply_mutation,
    list_mutations,
)
from redteam_harness.attacks.jailbreak import JailbreakPlugin
from redteam_harness.attacks.pii_leakage import PIILeakagePlugin
from redteam_harness.attacks.prompt_injection import PromptInjectionPlugin
from redteam_harness.attacks.system_prompt_extraction import SystemPromptExtractionPlugin


def create_default_registry() -> AttackRegistry:
    """Instantiate an `AttackRegistry` populated with all four core attack suites."""
    registry = AttackRegistry()
    registry.register(PromptInjectionPlugin())
    registry.register(JailbreakPlugin())
    registry.register(SystemPromptExtractionPlugin())
    registry.register(PIILeakagePlugin())
    return registry


__all__ = [
    "AttackPlugin",
    "AttackRegistry",
    "DuplicatePluginError",
    "JailbreakPlugin",
    "PIILeakagePlugin",
    "PromptInjectionPlugin",
    "SystemPromptExtractionPlugin",
    "UnknownCaseError",
    "UnknownSuiteError",
    "apply_mutation",
    "create_default_registry",
    "list_mutations",
]
