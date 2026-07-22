"""
XHS API client transport, signing, and retry primitives.

Domain-specific endpoint methods live in ``client_mixins.py``.
"""

from __future__ import annotations

import json
import logging
import random
import time
from typing import Any

import httpx

from .client_mixins import (
    AuthEndpointsMixin,
    CreatorEndpointsMixin,
    InteractionEndpointsMixin,
    NotificationEndpointsMixin,
    ReadingEndpointsMixin,
    SocialEndpointsMixin,
)
from .constants import CHROME_VERSION, CREATOR_HOST, EDITH_HOST, HOME_URL, USER_AGENT
from .cookies import cookies_to_string
from .creator_signing import sign_creator
from .exceptions import (
    IpBlockedError,
    NeedVerifyError,
    SessionExpiredError,
    SignatureError,
    XhsApiError,
)
from .signing import build_get_uri, sign_main_api

logger = logging.getLogger(__name__)


class XhsClient(
    ReadingEndpointsMixin,
    InteractionEndpointsMixin,
    CreatorEndpointsMixin,
    SocialEndpointsMixin,
    NotificationEndpointsMixin,
    AuthEndpointsMixin,
):
    """Xiaohongshu API client with automatic signing, rate limiting, and retry."""

    def __init__(
        self,
        cookies: dict[str, str],
        timeout: float = 30.0,
        request_delay: float = 1.0,
        max_retries: int = 3,
    ):
        self.cookies = cookies
        self._http = httpx.Client(timeout=timeout, follow_redirects=True)
        self._request_delay = request_delay
        self._base_request_delay = request_delay
        self._max_retries = max_retries
        self._last_request_time = 0.0
        self._verify_count = 0
        self._request_count = 0

    def close(self) -> None:
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _rate_limit_delay(self) -> None:
        """Enforce minimum delay with Gaussian jitter to mimic human browsing."""
        if self._request_delay <= 0:
            return
        elapsed = time.time() - self._last_request_time
        if elapsed < self._request_delay:
            jitter = max(0, random.gauss(0.3, 0.15))
            if random.random() < 0.05:
                jitter += random.uniform(2.0, 5.0)
            sleep_time = self._request_delay - elapsed + jitter
            logger.debug("Rate-limit delay: %.2fs", sleep_time)
            time.sleep(sleep_time)

    def _mark_request(self) -> None:
        self._last_request_time = time.time()
        self._request_count += 1

    def _base_headers(self) -> dict[str, str]:
        return {
            "user-agent": USER_AGENT,
            "content-type": "application/json;charset=UTF-8",
            "cookie": cookies_to_string(self.cookies),
            "origin": HOME_URL,
            "referer": f"{HOME_URL}/",
            "sec-ch-ua": f'"Not:A-Brand";v="99", "Google Chrome";v="{CHROME_VERSION}", "Chromium";v="{CHROME_VERSION}"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "accept": "application/json, text/plain, */*",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
            "dnt": "1",
            "priority": "u=1, i",
        }

    def _handle_response(self, resp: httpx.Response) -> Any:
        if resp.status_code in (461, 471):
            self._verify_count += 1
            cooldown = min(30, 5 * (2 ** (self._verify_count - 1)))
            logger.warning(
                "Captcha triggered (count=%d), cooling down %.0fs before raising",
                self._verify_count, cooldown,
            )
            self._request_delay = max(self._request_delay, self._base_request_delay * 2)
            time.sleep(cooldown)
            raise NeedVerifyError(
                verify_type=resp.headers.get("verifytype", "unknown"),
                verify_uuid=resp.headers.get("verifyuuid", "unknown"),
            )

        self._verify_count = 0
        text = resp.text
        if not text:
            return None

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            raise XhsApiError(f"Non-JSON response: {text[:200]}") from None

        if data.get("success"):
            return data.get("data", data.get("success"))

        code = data.get("code")
        if code == 300012:
            raise IpBlockedError()
        if code == 300015:
            raise SignatureError()
        if code == -100:
            raise SessionExpiredError()

        raise XhsApiError(
            f"API error: {json.dumps(data)[:300]}",
            code=code,
            response=data,
        )

    def _merge_response_cookies(self, resp: httpx.Response) -> None:
        """Persist response cookies back into the in-memory session jar."""
        for name, value in resp.cookies.items():
            if not value:
                continue
            self.cookies[name] = value

    def _request_with_retry(self, method: str, url: str, **kwargs) -> httpx.Response:
        self._rate_limit_delay()
        last_exc: Exception | None = None
        idempotent = method.upper() in {"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}
        attempts = max(1, self._max_retries) if idempotent else 1

        for attempt in range(attempts):
            try:
                resp = self._http.request(method, url, **kwargs)
                self._merge_response_cookies(resp)
                self._mark_request()
                if resp.status_code in (429, 500, 502, 503, 504):
                    if attempt + 1 == attempts:
                        break
                    wait = (2 ** attempt) + random.uniform(0, 1)
                    logger.warning(
                        "HTTP %d from %s, retrying in %.1fs (attempt %d/%d)",
                        resp.status_code, url[:80], wait, attempt + 1, attempts,
                    )
                    time.sleep(wait)
                    continue
                return resp
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_exc = exc
                if attempt + 1 == attempts:
                    break
                wait = (2 ** attempt) + random.uniform(0, 1)
                logger.warning(
                    "Network error: %s, retrying in %.1fs (attempt %d/%d)",
                    exc, wait, attempt + 1, attempts,
                )
                time.sleep(wait)

        if last_exc:
            raise XhsApiError(f"Request failed after {attempts} attempt(s): {last_exc}") from last_exc
        raise XhsApiError(f"Request failed after {attempts} attempt(s): HTTP {resp.status_code}")

    def _main_api_get(
        self,
        uri: str,
        params: dict[str, str | int | list[str]] | None = None,
    ) -> Any:
        sign_headers = sign_main_api("GET", uri, self.cookies, params=params)
        full_uri = build_get_uri(uri, params)
        url = f"{EDITH_HOST}{full_uri}"
        logger.debug("GET %s", url)
        resp = self._request_with_retry("GET", url, headers={**self._base_headers(), **sign_headers})
        return self._handle_response(resp)

    def _main_api_post(
        self,
        uri: str,
        data: dict[str, Any],
        header_overrides: dict[str, str] | None = None,
    ) -> Any:
        sign_headers = sign_main_api("POST", uri, self.cookies, payload=data)
        url = f"{EDITH_HOST}{uri}"
        headers = {**self._base_headers(), **sign_headers}
        if header_overrides:
            headers.update(header_overrides)
        logger.debug("POST %s", url)
        body = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        resp = self._request_with_retry("POST", url, headers=headers, content=body)
        return self._handle_response(resp)

    def _creator_host(self, uri: str) -> str:
        return CREATOR_HOST if uri.startswith("/api/galaxy/") else EDITH_HOST

    def _creator_get(
        self,
        uri: str,
        params: dict[str, str | int] | None = None,
    ) -> Any:
        full_uri = build_get_uri(uri, params)
        sign = sign_creator(f"url={full_uri}", None, self.cookies["a1"])
        host = self._creator_host(uri)
        url = f"{host}{full_uri}"
        headers = {
            **self._base_headers(),
            "x-s": sign["x-s"],
            "x-t": sign["x-t"],
            "origin": CREATOR_HOST,
            "referer": f"{CREATOR_HOST}/",
        }
        logger.debug("Creator GET %s", url)
        resp = self._request_with_retry("GET", url, headers=headers)
        return self._handle_response(resp)

    def _creator_post(self, uri: str, data: dict[str, Any]) -> Any:
        sign = sign_creator(f"url={uri}", data, self.cookies["a1"])
        host = self._creator_host(uri)
        url = f"{host}{uri}"
        headers = {
            **self._base_headers(),
            "x-s": sign["x-s"],
            "x-t": sign["x-t"],
            "origin": CREATOR_HOST,
            "referer": f"{CREATOR_HOST}/",
        }
        logger.debug("Creator POST %s", url)
        body = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        resp = self._request_with_retry("POST", url, headers=headers, content=body)
        return self._handle_response(resp)
