"""Shared helpers for bounded external threat-intelligence requests."""

import atexit

import httpx

from backend.src.providers.models import ProviderFailure
from backend.src.tools.schemas import ToolError


_CLIENT = httpx.Client(
    limits=httpx.Limits(max_connections=20, max_keepalive_connections=10, keepalive_expiry=30.0),
    follow_redirects=True,
)
atexit.register(_CLIENT.close)


def error(provider: str, error_type: str, message: str, retryable: bool = False) -> ProviderFailure:
    return ProviderFailure(error=ToolError(provider=provider, error_type=error_type, message=message, retryable=retryable))


def get_json(
    *,
    provider: str,
    url: str,
    timeout: int,
    connect_timeout: float = 3.0,
    write_timeout: float = 5.0,
    pool_timeout: float = 3.0,
    headers: dict[str, str] | None = None,
    params: dict[str, object] | None = None,
) -> dict[str, object] | ProviderFailure | None:
    request_timeout = httpx.Timeout(
        connect=connect_timeout,
        read=float(timeout),
        write=write_timeout,
        pool=pool_timeout,
    )
    try:
        response = _CLIENT.get(url, headers=headers, params=params, timeout=request_timeout)
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
