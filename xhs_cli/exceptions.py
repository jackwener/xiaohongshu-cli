"""Custom exceptions for XHS API client."""


class XhsApiError(Exception):
    """Base exception for XHS API errors."""

    def __init__(self, message: str, code: int | str | None = None, response: dict | None = None):
        super().__init__(message)
        self.code = code
        self.response = response


class NeedVerifyError(XhsApiError):
    """Raised when XHS requires captcha verification."""

    def __init__(self, verify_type: str, verify_uuid: str):
        super().__init__(f"Captcha required: type={verify_type}, uuid={verify_uuid}")
        self.verify_type = verify_type
        self.verify_uuid = verify_uuid


class SessionExpiredError(XhsApiError):
    """Raised when the session has expired."""

    def __init__(self):
        super().__init__("Session expired — please re-login with: xhs login", code=-100)


class IpBlockedError(XhsApiError):
    """Raised when IP is blocked by XHS."""

    def __init__(self):
        super().__init__("IP blocked by XHS — try a different network", code=300012)


class SignatureError(XhsApiError):
    """Raised when signature verification fails."""

    def __init__(self):
        super().__init__("Signature verification failed", code=300015)


class UnsupportedOperationError(XhsApiError):
    """Raised when the current web API no longer supports an exposed CLI action."""

    def __init__(self, message: str):
        super().__init__(message, code="unsupported_operation")


class NoCookieError(XhsApiError):
    """Raised when no valid cookies are found."""

    def __init__(self, source: str, details: str = ""):
        if source == "cookiecloud":
            msg = "No usable Xiaohongshu cookies were found in CookieCloud."
        elif source == "auto":
            msg = "No 'a1' cookie found for xiaohongshu.com in any installed browser."
        else:
            msg = f"No 'a1' cookie found for xiaohongshu.com in {source}."
        if details:
            msg += f"\n{details}"
        msg += "\n\nTroubleshooting:\n"
        if source == "cookiecloud":
            msg += "  1. Check COOKIECLOUD_HOST, COOKIECLOUD_UUID, and COOKIECLOUD_PASSWORD\n"
            msg += "  2. Confirm CookieCloud contains xiaohongshu.com cookies with a valid a1\n"
            msg += "  3. Try: xhs login --cookie-source cookiecloud"
        else:
            msg += "  1. Open a browser and visit https://www.xiaohongshu.com/\n"
            msg += "  2. Make sure you are logged in\n"
            msg += "  3. Try: xhs login --cookie-source <browser>"
        super().__init__(msg)
