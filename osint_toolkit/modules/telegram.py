from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient

HANDLE_RE = re.compile(r"^[A-Za-z0-9_]{5,32}$")


@dataclass(frozen=True)
class TelegramScanModule:
    name: str = "telegram-baseline"
    supported_targets: tuple[str, ...] = ("telegram",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        parsed = normalize_telegram_target(target.value)
        if not parsed:
            return (
                Finding(
                    module=self.name,
                    source="normalizer",
                    target=target.value,
                    status="invalid",
                    confidence="high",
                    evidence="Could not normalize input into a public Telegram handle or t.me URL.",
                ),
            )

        url, target_type = parsed
        if not config.live:
            return (
                Finding(
                    module=self.name,
                    source="telegram-url",
                    target=target.value,
                    status="planned",
                    url=url,
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to fetch public t.me metadata.",
                    metadata={"target_type": target_type},
                ),
            )

        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent)
        result = client.check(url, fetch_title=True)
        status = "candidate" if result.status_code and result.status_code < 400 else "unknown"
        return (
            Finding(
                module=self.name,
                source="telegram-url",
                target=target.value,
                status=status,
                url=result.final_url or url,
                title=result.title,
                http_status=result.status_code,
                confidence="medium" if result.status_code and result.status_code < 400 else "low",
                evidence=result.error or f"HTTP {result.status_code}",
                metadata={"target_type": target_type, "content_type": result.content_type},
            ),
        )


def normalize_telegram_target(value: str) -> tuple[str, str] | None:
    raw = value.strip()
    if not raw:
        return None
    if raw.startswith("@"):
        raw = raw[1:]
    if HANDLE_RE.match(raw):
        return f"https://t.me/{raw}", "handle"

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if parsed.netloc.lower() not in {"t.me", "telegram.me", "telegram.dog"}:
        return None
    path = parsed.path.strip("/")
    if not path:
        return None
    parts = path.split("/")
    handle = parts[0]
    if handle.startswith("+"):
        return f"https://t.me/{path}", "invite_or_private_link"
    if not HANDLE_RE.match(handle):
        return None
    if len(parts) >= 2 and parts[1].isdigit():
        return f"https://t.me/{handle}/{parts[1]}", "post"
    return f"https://t.me/{handle}", "handle"

