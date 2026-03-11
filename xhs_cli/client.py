"""
XHS API Client

Handles all HTTP requests to edith.xiaohongshu.com and creator.xiaohongshu.com
with proper signing, headers, and error handling.

Ported from: ~/readers/redbook/src/lib/client.ts
"""

import json
import logging
import random
import time
from typing import Any

import httpx

from .constants import CHROME_VERSION, CREATOR_HOST, EDITH_HOST, HOME_URL, UPLOAD_HOST, USER_AGENT
from .cookies import cookies_to_string
from .creator_signing import sign_creator
from .exceptions import (
    IpBlockedError,
    NeedVerifyError,
    SessionExpiredError,
    SignatureError,
    UnsupportedOperationError,
    XhsApiError,
)
from .signing import build_get_uri, sign_main_api

logger = logging.getLogger(__name__)


def _generate_search_id() -> str:
    """Generate a unique search ID (base36 of timestamp << 64 + random)."""
    e = int(time.time() * 1000) << 64
    t = random.randint(0, 2147483646)
    num = e + t

    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if num == 0:
        return "0"
    result = ""
    while num > 0:
        result = alphabet[num % 36] + result
        num //= 36
    return result


class XhsClient:
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
        self._verify_count = 0  # NeedVerify cooldown tracker
        self._request_count = 0  # Total requests in session

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
            # Truncated Gaussian jitter — more natural than uniform
            jitter = max(0, random.gauss(0.3, 0.15))
            # ~5% chance of a longer pause (simulates reading/thinking)
            if random.random() < 0.05:
                jitter += random.uniform(2.0, 5.0)
            sleep_time = self._request_delay - elapsed + jitter
            logger.debug("Rate-limit delay: %.2fs", sleep_time)
            time.sleep(sleep_time)

    def _mark_request(self) -> None:
        """Record timestamp of last request."""
        self._last_request_time = time.time()
        self._request_count += 1

    def _base_headers(self) -> dict[str, str]:
        return {
            "user-agent": USER_AGENT,
            "content-type": "application/json",
            "cookie": cookies_to_string(self.cookies),
            "origin": HOME_URL,
            "referer": f"{HOME_URL}/",
            # Anti-detection: must match UA (macOS Chrome)
            "sec-ch-ua": f'"Chromium";v="{CHROME_VERSION}", "Google Chrome";v="{CHROME_VERSION}", "Not-A.Brand";v="8"',
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
        """Handle API response, raising appropriate errors.

        NeedVerify cooldown: on first captcha trigger, increase request delay
        and sleep to reduce risk. After 3 consecutive triggers, give up.
        """
        if resp.status_code in (461, 471):
            self._verify_count += 1
            cooldown = min(30, 5 * (2 ** (self._verify_count - 1)))  # 5s, 10s, 20s, 30s cap
            logger.warning(
                "Captcha triggered (count=%d), cooling down %.0fs before raising",
                self._verify_count, cooldown,
            )
            # Permanently increase delay after captcha
            self._request_delay = max(self._request_delay, self._base_request_delay * 2)
            time.sleep(cooldown)
            raise NeedVerifyError(
                verify_type=resp.headers.get("verifytype", "unknown"),
                verify_uuid=resp.headers.get("verifyuuid", "unknown"),
            )

        # Successful request resets verify counter
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

    def _request_with_retry(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Execute HTTP request with automatic retry on transient errors.

        Retries on:
        - httpx.TimeoutException / httpx.NetworkError
        - HTTP 429 (rate limited), 500, 502, 503, 504
        Does NOT retry on XhsApiError (business logic errors from _handle_response).
        """
        self._rate_limit_delay()
        last_exc: Exception | None = None

        for attempt in range(self._max_retries):
            try:
                if method == "GET":
                    resp = self._http.get(url, **kwargs)
                else:
                    resp = self._http.post(url, **kwargs)
                self._mark_request()

                # Retry on server errors and rate limits
                if resp.status_code in (429, 500, 502, 503, 504):
                    wait = (2 ** attempt) + random.uniform(0, 1)
                    logger.warning(
                        "HTTP %d from %s, retrying in %.1fs (attempt %d/%d)",
                        resp.status_code, url[:80], wait, attempt + 1, self._max_retries,
                    )
                    time.sleep(wait)
                    continue

                return resp
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_exc = exc
                wait = (2 ** attempt) + random.uniform(0, 1)
                logger.warning(
                    "Network error: %s, retrying in %.1fs (attempt %d/%d)",
                    exc, wait, attempt + 1, self._max_retries,
                )
                time.sleep(wait)

        # All retries exhausted
        if last_exc:
            raise XhsApiError(f"Request failed after {self._max_retries} retries: {last_exc}") from last_exc
        raise XhsApiError(f"Request failed after {self._max_retries} retries: HTTP {resp.status_code}")

    # ─── Main API Methods ──────────────────────────────────────────────────

    def _main_api_get(
        self,
        uri: str,
        params: dict[str, str | int | list[str]] | None = None,
    ) -> Any:
        """GET request to edith.xiaohongshu.com with signing."""
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
        """POST request to edith.xiaohongshu.com with signing."""
        sign_headers = sign_main_api("POST", uri, self.cookies, payload=data)
        url = f"{EDITH_HOST}{uri}"

        headers = {**self._base_headers(), **sign_headers}
        if header_overrides:
            headers.update(header_overrides)

        logger.debug("POST %s", url)
        resp = self._request_with_retry("POST", url, headers=headers, content=json.dumps(data, separators=(",", ":")))
        return self._handle_response(resp)

    # ─── Creator API Methods ───────────────────────────────────────────────

    def _creator_host(self, uri: str) -> str:
        return CREATOR_HOST if uri.startswith("/api/galaxy/") else EDITH_HOST

    def _creator_get(
        self,
        uri: str,
        params: dict[str, str | int] | None = None,
    ) -> Any:
        """GET request to creator API with signing."""
        api_str = f"url={uri}"
        if params:
            qs = "&".join(f"{k}={v}" for k, v in params.items())
            api_str = f"url={uri}?{qs}"

        sign = sign_creator(api_str, None, self.cookies["a1"])
        full_uri = f"{uri}?{'&'.join(f'{k}={v}' for k, v in params.items())}" if params else uri
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

    def _creator_post(
        self,
        uri: str,
        data: dict[str, Any],
    ) -> Any:
        """POST request to creator API with signing."""
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
        resp = self._request_with_retry("POST", url, headers=headers, content=json.dumps(data, separators=(",", ":")))
        return self._handle_response(resp)

    # ─── Reading Endpoints ─────────────────────────────────────────────────

    def get_self_info(self) -> dict[str, Any]:
        """Get current user's profile info."""
        return self._main_api_get("/api/sns/web/v2/user/me")

    def get_user_info(self, user_id: str) -> dict[str, Any]:
        """Get another user's profile info."""
        return self._main_api_get("/api/sns/web/v1/user/otherinfo", {
            "target_user_id": user_id,
        })

    def get_user_notes(self, user_id: str, cursor: str = "") -> dict[str, Any]:
        """Get a user's published notes."""
        return self._main_api_get("/api/sns/web/v1/user_posted", {
            "num": 30,
            "cursor": cursor,
            "user_id": user_id,
            "image_scenes": "FD_WM_WEBP",
        })

    def search_notes(
        self,
        keyword: str,
        page: int = 1,
        page_size: int = 20,
        sort: str = "general",
        note_type: int = 0,
    ) -> Any:
        """
        Search notes by keyword.

        Args:
            keyword: Search query
            page: Page number
            page_size: Results per page
            sort: "general", "popularity_descending", "time_descending"
            note_type: 0=all, 1=video, 2=image
        """
        search_id = _generate_search_id()
        return self._main_api_post("/api/sns/web/v1/search/notes", {
            "keyword": keyword,
            "page": page,
            "page_size": page_size,
            "search_id": search_id,
            "sort": sort,
            "note_type": note_type,
        })

    def get_note_by_id(
        self,
        note_id: str,
        xsec_token: str = "",
        xsec_source: str = "pc_feed",
    ) -> Any:
        """Get note details by ID."""
        return self._main_api_post("/api/sns/web/v1/feed", {
            "source_note_id": note_id,
            "image_formats": ["jpg", "webp", "avif"],
            "extra": {"need_body_topic": 1},
            "xsec_source": xsec_source,
            "xsec_token": xsec_token,
        })

    def get_home_feed(self, category: str = "homefeed_recommend") -> dict[str, Any]:
        """Get homepage recommendation feed."""
        return self._main_api_post("/api/sns/web/v1/homefeed", {
            "cursor_score": "",
            "num": 40,
            "refresh_type": 1,
            "note_index": 0,
            "unread_begin_note_id": "",
            "unread_end_note_id": "",
            "unread_note_count": 0,
            "category": category,
            "search_key": "",
            "need_num": 40,
            "image_scenes": ["FD_PRV_WEBP", "FD_WM_WEBP"],
        })

    def get_comments(
        self,
        note_id: str,
        cursor: str = "",
        xsec_token: str = "",
        top_comment_id: str = "",
    ) -> Any:
        """Get comments for a note.

        Args:
            note_id: Note ID
            cursor: Pagination cursor
            xsec_token: Security token (required — without it, API triggers captcha)
            top_comment_id: Pin a specific comment at the top (optional, pass empty string)
        """
        return self._main_api_get("/api/sns/web/v2/comment/page", {
            "note_id": note_id,
            "cursor": cursor,
            "top_comment_id": top_comment_id,
            "image_formats": "jpg,webp,avif",
            "xsec_token": xsec_token,
        })

    def get_all_comments(
        self,
        note_id: str,
        xsec_token: str = "",
        max_pages: int = 20,
    ) -> dict[str, Any]:
        """Get ALL comments for a note by auto-paginating.

        Returns a merged response with all comments concatenated.
        Stops when has_more is False or max_pages reached.
        """
        all_comments: list[dict[str, Any]] = []
        cursor = ""
        pages = 0

        while pages < max_pages:
            data = self.get_comments(note_id, cursor=cursor, xsec_token=xsec_token)
            if not isinstance(data, dict):
                break

            comments = data.get("comments", [])
            all_comments.extend(comments)
            pages += 1

            has_more = data.get("has_more", False)
            next_cursor = data.get("cursor", "")
            if not has_more or not next_cursor:
                break
            cursor = next_cursor
            logger.debug("Comments page %d fetched, %d so far", pages, len(all_comments))

        # Return merged result
        return {
            "comments": all_comments,
            "has_more": False,
            "cursor": "",
            "total_fetched": len(all_comments),
            "pages_fetched": pages,
        }

    def get_sub_comments(
        self,
        note_id: str,
        root_comment_id: str,
        num: int = 30,
        cursor: str = "",
    ) -> Any:
        """Get sub-comments (replies) for a comment."""
        return self._main_api_get("/api/sns/web/v2/comment/sub/page", {
            "note_id": note_id,
            "root_comment_id": root_comment_id,
            "num": num,
            "cursor": cursor,
        })

    # ─── Interaction Endpoints ──────────────────────────────────────────────

    def post_comment(self, note_id: str, content: str) -> dict[str, Any]:
        """Post a top-level comment on a note."""
        return self._main_api_post("/api/sns/web/v1/comment/post", {
            "note_id": note_id,
            "content": content,
            "at_users": [],
        })

    def reply_comment(
        self,
        note_id: str,
        target_comment_id: str,
        content: str,
    ) -> Any:
        """Reply to a specific comment."""
        return self._main_api_post("/api/sns/web/v1/comment/post", {
            "note_id": note_id,
            "content": content,
            "target_comment_id": target_comment_id,
            "at_users": [],
        })

    def like_note(self, note_id: str) -> dict[str, Any]:
        """Like a note."""
        return self._main_api_post("/api/sns/web/v1/note/like", {
            "note_oid": note_id,
        })

    def unlike_note(self, note_id: str) -> dict[str, Any]:
        """Unlike a note."""
        return self._main_api_post("/api/sns/web/v1/note/dislike", {
            "note_oid": note_id,
        })

    def favorite_note(self, note_id: str) -> dict[str, Any]:
        """Favorite (bookmark) a note."""
        return self._main_api_post("/api/sns/web/v1/note/collect", {
            "note_id": note_id,
        })

    def unfavorite_note(self, note_id: str) -> dict[str, Any]:
        """Unfavorite (unbookmark) a note."""
        return self._main_api_post("/api/sns/web/v1/note/uncollect", {
            "note_ids": note_id,
        })

    def delete_comment(self, note_id: str, comment_id: str) -> dict[str, Any]:
        """Delete a comment."""
        return self._main_api_post("/api/sns/web/v1/comment/delete", {
            "note_id": note_id,
            "comment_id": comment_id,
        })

    # ─── Creator/Posting Endpoints ────────────────────────────────────────

    def search_topics(self, keyword: str) -> dict[str, Any]:
        """Search for topics/hashtags."""
        return self._creator_post("/web_api/sns/v1/search/topic", {
            "keyword": keyword,
            "suggest_topic_request": {"title": "", "desc": ""},
            "page": {"page_size": 20, "page": 1},
        })

    def search_users(self, keyword: str) -> dict[str, Any]:
        """Search for users."""
        return self._creator_post("/web_api/sns/v1/search/user_info", {
            "keyword": keyword,
            "search_id": str(int(time.time() * 1000)),
            "page": {"page_size": 20, "page": 1},
        })

    def get_upload_permit(
        self,
        file_type: str = "image",
        count: int = 1,
    ) -> dict[str, str]:
        """Get upload permit for file upload."""
        data = self._creator_get("/api/media/v1/upload/web/permit", {
            "biz_name": "spectrum",
            "scene": file_type,
            "file_count": count,
            "version": 1,
            "source": "web",
        })

        permit = data["uploadTempPermits"][0]
        return {"fileId": permit["fileIds"][0], "token": permit["token"]}

    def upload_file(
        self,
        file_id: str,
        token: str,
        file_path: str,
        content_type: str = "image/jpeg",
    ) -> None:
        """Upload a file to XHS storage."""
        with open(file_path, "rb") as f:
            file_data = f.read()

        url = f"{UPLOAD_HOST}/{file_id}"
        resp = self._http.put(
            url,
            headers={
                "X-Cos-Security-Token": token,
                "Content-Type": content_type,
            },
            content=file_data,
        )

        if resp.status_code >= 400:
            raise XhsApiError(f"Upload failed: {resp.status_code} {resp.reason_phrase}")

    def create_image_note(
        self,
        title: str,
        desc: str,
        image_file_ids: list[str],
        topics: list[dict[str, str]] | None = None,
        is_private: bool = False,
    ) -> Any:
        """Create and publish an image note."""
        images = [{"file_id": fid, "metadata": {"source": -1}} for fid in image_file_ids]

        business_binds = {
            "version": 1,
            "noteId": 0,
            "noteOrderBind": {},
            "notePostTiming": {"postTime": None},
            "noteCollectionBind": {"id": ""},
        }

        data = {
            "common": {
                "type": "normal",
                "title": title,
                "note_id": "",
                "desc": desc,
                "source": '{"type":"web","ids":"","extraInfo":"{\\"subType\\":\\"official\\"}"}',
                "business_binds": json.dumps(business_binds),
                "ats": [],
                "hash_tag": topics or [],
                "post_loc": {},
                "privacy_info": {"op_type": 1, "type": 1 if is_private else 0},
            },
            "image_info": {"images": images},
            "video_info": None,
        }

        return self._main_api_post("/web_api/sns/v2/note", data, {
            "origin": CREATOR_HOST,
            "referer": f"{CREATOR_HOST}/",
        })

    def delete_note(self, note_id: str) -> dict[str, Any]:
        """Delete a note."""
        try:
            return self._creator_post("/api/galaxy/creator/note/delete", {
                "note_id": note_id,
            })
        except XhsApiError as exc:
            response = exc.response if isinstance(exc.response, dict) else {}
            if response.get("status") == 404 or "404" in str(exc):
                raise UnsupportedOperationError(
                    "Delete note is currently unavailable from the public web API. "
                    "The command remains experimental until the new endpoint is re-captured."
                ) from None
            raise

    def get_creator_note_list(self, tab: int = 0, page: int = 0) -> dict[str, Any]:
        """Get list of creator's own notes."""
        return self._creator_get("/api/galaxy/v2/creator/note/user/posted", {
            "tab": tab,
            "page": page,
        })

    # ─── P1: Social Graph Endpoints ───────────────────────────────────────

    def follow_user(self, user_id: str) -> dict[str, Any]:
        """Follow a user."""
        return self._main_api_post("/api/sns/web/v1/user/follow", {
            "target_user_id": user_id,
        })

    def unfollow_user(self, user_id: str) -> dict[str, Any]:
        """Unfollow a user."""
        return self._main_api_post("/api/sns/web/v1/user/unfollow", {
            "target_user_id": user_id,
        })

    # ─── P1: Discovery Endpoints ──────────────────────────────────────────

    def get_hot_feed(self, category: str = "homefeed.fashion_v3") -> dict[str, Any]:
        """Get hot/trending notes feed.

        Categories: homefeed.fashion_v3 (穿搭), homefeed.food_v3 (美食),
        homefeed.cosmetics_v3 (彩妆), homefeed.movie_and_tv_v3 (影视),
        homefeed.career_v3 (职场), homefeed.love_v3 (情感),
        homefeed.household_product_v3 (家居), homefeed.gaming_v3 (游戏),
        homefeed.travel_v3 (旅行), homefeed.fitness_v3 (健身)
        """
        return self.get_home_feed(category=category)

    # ─── P1: User Content Lists ───────────────────────────────────────────

    def get_user_favorites(self, user_id: str, cursor: str = "") -> dict[str, Any]:
        """Get a user's favorited (bookmarked) notes."""
        return self._main_api_get("/api/sns/web/v2/note/collect/page", {
            "user_id": user_id,
            "cursor": cursor,
            "num": 30,
        })

    # ─── P1: Notification Endpoints (reverse-engineered) ─────────────────

    def get_unread_count(self) -> dict[str, Any]:
        """Get unread notification counts.

        Returns: {unread_count: int, likes: int, connections: int, mentions: int}
        """
        return self._main_api_get("/api/sns/web/unread_count", {})

    def get_notification_mentions(self, cursor: str = "", num: int = 20) -> dict[str, Any]:
        """Get comment and @mention notifications."""
        return self._main_api_get("/api/sns/web/v1/you/mentions", {
            "num": num,
            "cursor": cursor,
        })

    def get_notification_likes(self, cursor: str = "", num: int = 20) -> dict[str, Any]:
        """Get like and collect notifications."""
        return self._main_api_get("/api/sns/web/v1/you/likes", {
            "num": num,
            "cursor": cursor,
        })

    def get_notification_connections(self, cursor: str = "", num: int = 20) -> dict[str, Any]:
        """Get new follower notifications."""
        return self._main_api_get("/api/sns/web/v1/you/connections", {
            "num": num,
            "cursor": cursor,
        })

    # ─── QR Login Endpoints ────────────────────────────────────────────────

    def login_activate(self) -> dict[str, Any]:
        """Activate session via login endpoint.

        Returns: {session, secure_session, user_id}
        The ``session`` field is the value for the ``web_session`` cookie.
        """
        return self._main_api_post("/api/sns/web/v1/login/activate", {})

    def create_qr_login(self) -> dict[str, Any]:
        """Create a QR code for login.

        Returns: {qr_id, code, url, multi_flag}
        The ``url`` field is the content to encode into the QR image.
        """
        return self._main_api_post("/api/sns/web/v1/login/qrcode/create", {
            "qr_type": 1,
        })

    def check_qr_status(self, qr_id: str, code: str) -> dict[str, Any]:
        """Poll QR code scan status.

        Returns: {codeStatus, userId, geoZone, result}
        codeStatus values:
            0 = waiting for scan
            1 = scanned, waiting for confirmation
            2 = confirmed / login success
        """
        uri = "/api/qrcode/userinfo"
        data = {"qrId": qr_id, "code": code}
        sign_headers = sign_main_api("POST", uri, self.cookies, payload=data)
        url = f"{EDITH_HOST}{uri}"

        headers = {
            **self._base_headers(),
            **sign_headers,
            "service-tag": "webcn",
        }

        logger.debug("QR poll POST %s body=%s", url, data)
        resp = self._http.post(
            url,
            headers=headers,
            content=json.dumps(data, separators=(",", ":")),
        )
        logger.debug("QR poll response: %s", resp.text[:500])

        raw = json.loads(resp.text)
        if raw.get("success"):
            return raw.get("data", {})
        raise XhsApiError(f"QR status check failed: {json.dumps(raw)[:300]}")

    # ─── HTML Fallback ────────────────────────────────────────────────────

    def get_note_from_html(self, note_id: str, xsec_token: str) -> dict[str, Any]:
        """Fallback: extract note data from HTML page's __INITIAL_STATE__."""
        import re

        url = f"{HOME_URL}/explore/{note_id}?xsec_token={xsec_token}&xsec_source=pc_feed"
        resp = self._http.get(
            url,
            headers={
                "user-agent": USER_AGENT,
                "referer": f"{HOME_URL}/",
                "cookie": cookies_to_string(self.cookies),
            },
        )

        html = resp.text
        match = re.search(r'window\.__INITIAL_STATE__=({.*})</script>', html)
        if not match:
            raise XhsApiError("Could not parse __INITIAL_STATE__ from HTML")

        # Replace bare `undefined` values with JSON null
        state_str = re.sub(r'\bundefined\b', 'null', match.group(1))
        state = json.loads(state_str)

        detail_map = state.get("note", {}).get("noteDetailMap", {})
        if detail_map:
            entry = detail_map.get(note_id) or next(iter(detail_map.values()), None)
            if entry and "note" in entry:
                return entry["note"]

        raise XhsApiError("Note not found in HTML state")
