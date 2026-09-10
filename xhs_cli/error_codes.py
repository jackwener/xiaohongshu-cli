"""Stable error-code mapping for structured CLI output."""

from __future__ import annotations

from .exceptions import (
    IpBlockedError,
    NeedVerifyError,
    NoCookieError,
    RateLimitedError,
    SessionExpiredError,
    SignatureError,
    UnsupportedOperationError,
    XhsApiError,
)


def error_code_for_exception(exc: Exception) -> str:
    """Map domain exceptions to stable structured error codes."""
    if isinstance(exc, (NoCookieError, SessionExpiredError)):
        return "not_authenticated"
    if isinstance(exc, NeedVerifyError):
        return "verification_required"
    if isinstance(exc, IpBlockedError):
        return "ip_blocked"
    if isinstance(exc, SignatureError):
        return "signature_error"
    if isinstance(exc, UnsupportedOperationError):
        return "unsupported_operation"
    if isinstance(exc, RateLimitedError):
        return "rate_limited"
    if isinstance(exc, XhsApiError):
        if exc.code in {
            "not_authenticated",
            "verification_required",
            "ip_blocked",
            "signature_error",
            "unsupported_operation",
            "rate_limited",
            "api_error",
        }:
            return str(exc.code)
        return "api_error"
    return "unknown_error"
