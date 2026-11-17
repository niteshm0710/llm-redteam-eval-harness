"""Base target adapter abstraction and SSRF/egress endpoint policy validator."""

from __future__ import annotations

import ipaddress
from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from redteam_harness.schemas import SanitizedEndpointInfo

_BLOCKED_METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "metadata",
    }
)
_BLOCKED_METADATA_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud metadata
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
)


class TargetInvocationError(RuntimeError):
    """Raised when querying a target or judge LLM endpoint fails."""


class EgressPolicyError(ValueError):
    """Raised when a target or judge base URL violates gateway egress policy."""


def validate_endpoint_url(
    raw_url: str,
    *,
    allow_private: bool = False,
    allowed_hosts: tuple[str, ...] = (),
) -> str:
    """Validate and normalize an OpenAI-compatible base URL against SSRF rules."""
    if not raw_url or not raw_url.strip():
        raise EgressPolicyError("Endpoint base_url must not be empty.")

    candidate = raw_url.strip()
    if any(ch in candidate for ch in ("\r", "\n", "\x00", " ")):
        raise EgressPolicyError("Endpoint base_url contains illegal whitespace or control chars.")

    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise EgressPolicyError(
            f"Unsupported URL scheme '{parsed.scheme or '<empty>'}'; only http and https are allowed."
        )
    if parsed.username or parsed.password:
        raise EgressPolicyError("Embedded credentials in endpoint base_url are forbidden.")
    if not parsed.hostname:
        raise EgressPolicyError("Endpoint base_url must include a valid hostname.")
    if parsed.query or parsed.fragment:
        raise EgressPolicyError("Endpoint base_url must not contain query parameters or fragments.")

    hostname = parsed.hostname.lower().rstrip(".")
    if hostname in _BLOCKED_METADATA_HOSTS:
        raise EgressPolicyError(f"Host '{hostname}' is blocked (cloud instance metadata endpoint).")

    # Validate port parses cleanly if present.
    try:
        _ = parsed.port
    except ValueError as exc:
        raise EgressPolicyError(f"Invalid port in endpoint base_url: {exc}") from exc

    # Inspect IP literal if hostname is an IPv4/IPv6 address.
    parsed_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        parsed_ip = ipaddress.ip_address(hostname)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        check_ip = (
            parsed_ip.ipv4_mapped
            if isinstance(parsed_ip, ipaddress.IPv6Address) and parsed_ip.ipv4_mapped
            else parsed_ip
        )
        for net in _BLOCKED_METADATA_NETWORKS:
            if check_ip.version == net.version and check_ip in net:
                raise EgressPolicyError(
                    f"Address '{hostname}' is blocked (link-local/metadata range)."
                )
        if check_ip.is_multicast or check_ip.is_unspecified:
            raise EgressPolicyError(f"Address '{hostname}' is blocked (non-unicast address).")

    if allowed_hosts:
        normalized_allowlist = {host.lower().rstrip(".") for host in allowed_hosts}
        if hostname not in normalized_allowlist:
            raise EgressPolicyError(
                f"Host '{hostname}' is not in the configured target host allowlist."
            )

    if not allow_private:
        if hostname == "localhost" or hostname.endswith((".localhost", ".local")):
            raise EgressPolicyError(
                f"Private/loopback host '{hostname}' is blocked by egress policy. "
                "Set REDTEAM_ALLOW_PRIVATE_TARGETS=true for trusted local model servers."
            )
        if parsed_ip is not None:
            check_ip = (
                parsed_ip.ipv4_mapped
                if isinstance(parsed_ip, ipaddress.IPv6Address) and parsed_ip.ipv4_mapped
                else parsed_ip
            )
            if check_ip.is_private or check_ip.is_loopback or check_ip.is_reserved:
                raise EgressPolicyError(
                    f"Private/loopback IP '{hostname}' is blocked by egress policy. "
                    "Set REDTEAM_ALLOW_PRIVATE_TARGETS=true for trusted local model servers."
                )

    normalized_path = parsed.path.rstrip("/")
    return urlunsplit((scheme, parsed.netloc, normalized_path, "", ""))


@dataclass(frozen=True, slots=True)
class TargetResponse:
    """Normalized completion payload returned by a `TargetAdapter`."""

    content: str
    model: str
    latency_ms: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class TargetAdapter(ABC):
    """Abstract interface for invoking a target LLM endpoint."""

    @property
    @abstractmethod
    def endpoint_info(self) -> SanitizedEndpointInfo:
        """Return credential-free metadata describing this target endpoint."""

    @abstractmethod
    async def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        case_id: str | None = None,
    ) -> TargetResponse:
        """Execute a single prompt turn against the target model."""

    async def aclose(self) -> None:  # noqa: B027
        """Release any underlying network resources."""
