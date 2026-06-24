from __future__ import annotations

import time
import html
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


RETRY_STATUS_CODES = {429, 500, 502, 503, 504}


@dataclass(frozen=True)
class HttpResult:
    url: str
    final_url: str
    status_code: int | None
    title: str = ""
    body_text: str = ""
    content_type: str = ""
    error: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    attempts: int = 1


class HttpClient:
    def __init__(
        self,
        *,
        timeout: float = 10.0,
        user_agent: str = "osint-toolkit/0.1",
        retries: int = 1,
        backoff_seconds: float = 1.0,
    ):
        self.timeout = timeout
        self.user_agent = user_agent
        self.retries = max(0, retries)
        self.backoff_seconds = max(0.0, backoff_seconds)
        self.context = ssl.create_default_context()

    def check(
        self,
        url: str,
        *,
        fetch_title: bool = False,
        headers: dict[str, str] | None = None,
        method: str = "GET",
        body: str = "",
    ) -> HttpResult:
        method = method.upper()
        result: HttpResult | None = None
        for attempt in range(self.retries + 1):
            result = self._check_once(url, fetch_title=fetch_title, headers=headers, method=method, body=body)
            result = replace(result, attempts=attempt + 1)
            if result.status_code not in RETRY_STATUS_CODES or attempt >= self.retries:
                return result
            delay = _retry_delay(result, self.backoff_seconds, attempt)
            if delay > 0:
                time.sleep(delay)
        return result

    def _check_once(
        self,
        url: str,
        *,
        fetch_title: bool,
        headers: dict[str, str] | None,
        method: str,
        body: str,
    ) -> HttpResult:
        if method == "POST":
            return self._request(url, method="POST", read_body=True, headers=headers, body=body)

        head = self._request(url, method="HEAD", read_body=False, headers=headers)
        if head.status_code and head.status_code not in {405, 403}:
            if fetch_title and head.status_code < 400:
                return self._request(url, method="GET", read_body=True, headers=headers)
            return head
        return self._request(url, method="GET", read_body=fetch_title, headers=headers)

    def _request(
        self,
        url: str,
        *,
        method: str,
        read_body: bool,
        headers: dict[str, str] | None = None,
        body: str = "",
    ) -> HttpResult:
        request_headers = {"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml"}
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(
            url,
            data=body.encode("utf-8") if method == "POST" else None,
            headers=request_headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                body = response.read(262_144) if read_body else b""
                content_type = response.headers.get("content-type", "")
                body_text = _decode_body(body, content_type)
                return HttpResult(
                    url=url,
                    final_url=response.geturl(),
                    status_code=response.getcode(),
                    title=_extract_title(body_text, content_type),
                    body_text=body_text,
                    content_type=content_type,
                    headers={key.lower(): value for key, value in response.headers.items()},
                )
        except urllib.error.HTTPError as exc:
            body = exc.read(262_144) if read_body else b""
            content_type = exc.headers.get("content-type", "") if exc.headers else ""
            body_text = _decode_body(body, content_type)
            return HttpResult(
                url=url,
                final_url=exc.geturl(),
                status_code=exc.code,
                title=_extract_title(body_text, content_type),
                body_text=body_text,
                content_type=content_type,
                error=str(exc),
                headers={key.lower(): value for key, value in exc.headers.items()} if exc.headers else {},
            )
        except urllib.error.URLError as exc:
            return HttpResult(url=url, final_url=url, status_code=None, error=str(exc.reason))
        except TimeoutError as exc:
            return HttpResult(url=url, final_url=url, status_code=None, error=str(exc))


def _retry_delay(result: HttpResult, backoff_seconds: float, attempt: int) -> float:
    retry_after = _parse_retry_after(result.headers.get("retry-after", ""))
    if retry_after is not None:
        return retry_after
    return backoff_seconds * (2**attempt)


def _parse_retry_after(value: str) -> float | None:
    value = value.strip()
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())


def _decode_body(body: bytes, content_type: str, *, limit: int = 65536) -> str:
    if not body or not _is_text_content(content_type):
        return ""
    return body.decode("utf-8", errors="ignore")[:limit]


def _is_text_content(content_type: str) -> bool:
    lowered = content_type.lower()
    return any(part in lowered for part in ("html", "text", "json", "xml"))


def _extract_title(body_text: str, content_type: str) -> str:
    if not body_text or "html" not in content_type.lower():
        return ""
    match = re.search(r"<title[^>]*>(.*?)</title>", body_text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return html.unescape(re.sub(r"\s+", " ", match.group(1))).strip()
