"""Shared helpers for bounded external threat-intelligence requests."""

import httpx

from backend.src.providers.models import ProviderFailure
from backend.src.tools.schemas import ToolError


def error(provider: str, error_type: str, message: str, retryable: bool = False) -> ProviderFailure:
    return ProviderFailure(error=ToolError(provider=provider, error_type=error_type, message=message, retryable=retryable))


def get_json(*, provider: str, url: str, timeout: int, headers: dict[str, str] | None = None, params: dict[str, object] | None = None) -> dict[str, object] | ProviderFailure | None:
    try:
        response = httpx.get(url, headers=headers, params=params, timeout=timeout)
    except httpx.TimeoutException:
        return error(provider, "timeout", f"{provider} request timed out.", True)
    except httpx.HTTPError as exc:
        return error(provider, "provider_error", f"{provider} request failed: {exc}", True)
    if response.status_code == 404:
        return None
    if response.status_code == 429:
        return error(provider, "rate_limit", f"{provider} rate limit was reached.", True)
    if response.status_code in {401, 403}:
        return error(provider, "authentication", f"{provider} rejected the API key or account permissions.")
    if response.is_error:
        return error(provider, "provider_error", f"{provider} returned HTTP {response.status_code}.", response.status_code >= 500)
    payload = response.json()
    return payload if isinstance(payload, dict) else error(provider, "invalid_response", f"{provider} returned an unexpected response.")
