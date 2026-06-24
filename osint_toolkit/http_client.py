from __future__ import annotations

import html
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field


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


class HttpClient:
    def __init__(self, *, timeout: float = 10.0, user_agent: str = "osint-toolkit/0.1"):
        self.timeout = timeout
        self.user_agent = user_agent
        self.context = ssl.create_default_context()

    def check(self, url: str, *, fetch_title: bool = False) -> HttpResult:
        head = self._request(url, method="HEAD", read_body=False)
        if head.status_code and head.status_code not in {405, 403}:
            if fetch_title and head.status_code < 400:
                return self._request(url, method="GET", read_body=True)
            return head
        return self._request(url, method="GET", read_body=fetch_title)

    def _request(self, url: str, *, method: str, read_body: bool) -> HttpResult:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml"},
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
