from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient, HttpResult

INSTAGRAM_HOSTS = {"instagram.com", "www.instagram.com"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9._]{1,30}$")
MEDIA_PATHS = {"p", "reel", "reels", "tv"}


@dataclass(frozen=True)
class InstagramTarget:
    url: str
    target_type: str
    username: str = ""
    shortcode: str = ""


@dataclass(frozen=True)
class InstagramPublicMetadata:
    username: str = ""
    display_name: str = ""
    account_id: str = ""
    description: str = ""
    canonical_url: str = ""
    profile_image_url: str = ""
    media_url: str = ""
    external_url: str = ""
    follower_count: str = ""
    following_count: str = ""
    post_count: str = ""
    is_private: str = ""
    is_verified: str = ""

    def to_metadata(self) -> dict[str, str]:
        metadata = {
            "platform": "instagram",
            "instagram_username": f"@{self.username}" if self.username else "",
            "display_name": self.display_name,
            "account_id": self.account_id,
            "description": self.description,
            "canonical_url": self.canonical_url,
            "profile_image_url": self.profile_image_url,
            "media_url": self.media_url,
            "external_url": self.external_url,
            "follower_count": self.follower_count,
            "following_count": self.following_count,
            "post_count": self.post_count,
            "is_private": self.is_private,
            "is_verified": self.is_verified,
        }
        return {key: value for key, value in metadata.items() if value}


@dataclass(frozen=True)
class InstagramPublicProfileModule:
    name: str = "instagram-public-profile"
    supported_targets: tuple[str, ...] = ("instagram",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        parsed = normalize_instagram_target(target.value)
        if not parsed:
            return (
                Finding(
                    module=self.name,
                    source="normalizer",
                    target=target.value,
                    status="invalid",
                    confidence="high",
                    evidence="Could not normalize input into an Instagram username, profile URL or public media URL.",
                    metadata={"platform": "instagram"},
                ),
            )

        metadata = _target_metadata(parsed)
        if not config.live:
            return (
                Finding(
                    module=self.name,
                    source=_source_for_target(parsed),
                    target=target.value,
                    status="planned",
                    url=parsed.url,
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to fetch public Instagram metadata.",
                    metadata=metadata,
                ),
            )

        client = HttpClient(
            timeout=config.timeout,
            user_agent=config.user_agent,
            retries=config.http_retries,
            backoff_seconds=config.http_backoff,
        )
        result = client.check(parsed.url, fetch_title=True, headers=_instagram_headers())
        public_metadata = extract_instagram_public_metadata(
            result.body_text,
            expected_username=parsed.username,
        )
        metadata.update(public_metadata.to_metadata())
        metadata["content_type"] = result.content_type
        metadata["http_attempts"] = str(result.attempts)
        if config.http_retries:
            metadata["http_retries"] = str(config.http_retries)
            metadata["http_backoff_seconds"] = str(config.http_backoff)

        status, confidence, evidence = classify_instagram_http_result(parsed, result, public_metadata)
        return (
            Finding(
                module=self.name,
                source=_source_for_target(parsed),
                target=target.value,
                status=status,
                url=result.final_url or parsed.url,
                title=result.title or public_metadata.display_name,
                http_status=result.status_code,
                confidence=confidence,
                evidence=evidence,
                metadata=metadata,
            ),
        )


def normalize_instagram_target(value: str) -> InstagramTarget | None:
    raw = value.strip()
    if not raw:
        return None
    if raw.startswith("@"):
        raw = raw[1:]
    if _is_valid_username(raw):
        return InstagramTarget(
            url=f"https://www.instagram.com/{raw}/",
            target_type="profile",
            username=raw,
        )

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = (parsed.hostname or "").lower()
    if host not in INSTAGRAM_HOSTS:
        return None
    parts = tuple(part for part in parsed.path.split("/") if part)
    if not parts:
        return None
    first = parts[0]
    if first in MEDIA_PATHS and len(parts) >= 2:
        shortcode = parts[1]
        if not re.fullmatch(r"[A-Za-z0-9_-]{3,64}", shortcode):
            return None
        return InstagramTarget(
            url=f"https://www.instagram.com/{first}/{shortcode}/",
            target_type="media",
            shortcode=shortcode,
        )
    if _is_valid_username(first):
        return InstagramTarget(
            url=f"https://www.instagram.com/{first}/",
            target_type="profile",
            username=first,
        )
    return None


def extract_instagram_public_metadata(
    body_text: str,
    *,
    expected_username: str = "",
) -> InstagramPublicMetadata:
    if not body_text:
        return InstagramPublicMetadata(username=expected_username)

    meta = _html_meta_values(body_text)
    canonical_url = _canonical_url(body_text) or meta.get("og:url", "")
    title = meta.get("og:title") or meta.get("twitter:title", "")
    description = meta.get("og:description") or meta.get("description", "")
    username = _username_from_title(title) or _username_from_url(canonical_url) or expected_username
    display_name = _display_name_from_title(title, username)
    counts = _counts_from_description(description)
    json_values = _json_profile_values(body_text)
    if not username:
        username = json_values.get("username", "")
    if not display_name:
        display_name = json_values.get("display_name", "") or json_values.get("full_name", "")

    return InstagramPublicMetadata(
        username=username,
        display_name=display_name,
        account_id=json_values.get("account_id", ""),
        description=_clean_text(description),
        canonical_url=canonical_url,
        profile_image_url=meta.get("og:image", "") or meta.get("twitter:image", ""),
        media_url=meta.get("og:video", "") or meta.get("og:image", ""),
        external_url=json_values.get("external_url", ""),
        follower_count=counts.get("followers", ""),
        following_count=counts.get("following", ""),
        post_count=counts.get("posts", ""),
        is_private=json_values.get("is_private", ""),
        is_verified=json_values.get("is_verified", ""),
    )


def classify_instagram_http_result(
    target: InstagramTarget,
    result: HttpResult,
    metadata: InstagramPublicMetadata,
) -> tuple[str, str, str]:
    if result.status_code is None:
        return "error", "low", result.error or "HTTP request failed."
    if result.status_code == 404:
        return "not_found", "high", "HTTP 404 from Instagram public page."
    if result.status_code and result.status_code >= 400:
        return "unknown", "low", result.error or f"HTTP {result.status_code}"
    if metadata.username or metadata.display_name or metadata.canonical_url:
        return (
            "candidate",
            "medium",
            f"HTTP {result.status_code}; public Instagram {target.target_type} metadata found.",
        )
    return (
        "candidate",
        "low",
        f"HTTP {result.status_code}; page fetched but profile metadata was limited.",
    )


def _target_metadata(target: InstagramTarget) -> dict[str, str]:
    metadata = {
        "platform": "instagram",
        "target_type": target.target_type,
    }
    if target.username:
        metadata["instagram_username"] = f"@{target.username}"
        metadata["username"] = target.username
    if target.shortcode:
        metadata["media_shortcode"] = target.shortcode
    return metadata


def _source_for_target(target: InstagramTarget) -> str:
    return "instagram-media-url" if target.target_type == "media" else "instagram-profile-url"


def _instagram_headers() -> dict[str, str]:
    return {
        "Accept-Language": "en-US,en;q=0.9",
    }


def _is_valid_username(username: str) -> bool:
    if not USERNAME_RE.fullmatch(username):
        return False
    return not username.startswith(".") and not username.endswith(".") and ".." not in username


def _html_meta_values(body_text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    pattern = re.compile(r"<meta\b[^>]*>", flags=re.IGNORECASE)
    for match in pattern.finditer(body_text):
        tag = match.group(0)
        key = _attribute(tag, "property") or _attribute(tag, "name")
        value = _attribute(tag, "content")
        if key and value:
            values.setdefault(key.lower(), _clean_text(value))
    return values


def _canonical_url(body_text: str) -> str:
    for match in re.finditer(r"<link\b[^>]*>", body_text, flags=re.IGNORECASE):
        tag = match.group(0)
        if _attribute(tag, "rel").lower() == "canonical":
            return _attribute(tag, "href")
    return ""


def _attribute(tag: str, name: str) -> str:
    pattern = re.compile(
        rf"""\b{name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""",
        flags=re.IGNORECASE,
    )
    match = pattern.search(tag)
    if not match:
        return ""
    value = next((group for group in match.groups() if group is not None), "")
    return html.unescape(value).strip()


def _username_from_title(title: str) -> str:
    match = re.search(r"\(@([A-Za-z0-9._]{1,30})\)", title)
    if match and _is_valid_username(match.group(1)):
        return match.group(1)
    return ""


def _username_from_url(url: str) -> str:
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() not in INSTAGRAM_HOSTS:
        return ""
    first = parsed.path.strip("/").split("/")[0]
    return first if _is_valid_username(first) else ""


def _display_name_from_title(title: str, username: str) -> str:
    if not title:
        return ""
    if username:
        title = re.sub(rf"\s*\(@{re.escape(username)}\).*", "", title).strip()
    title = re.sub(r"\s*•\s*Instagram.*", "", title).strip()
    return _clean_text(title)


def _counts_from_description(description: str) -> dict[str, str]:
    counts: dict[str, str] = {}
    patterns = {
        "followers": r"([\d,.]+[KMBkmb]?)\s+Followers",
        "following": r"([\d,.]+[KMBkmb]?)\s+Following",
        "posts": r"([\d,.]+[KMBkmb]?)\s+Posts",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, description, flags=re.IGNORECASE)
        if match:
            counts[key] = match.group(1).replace(",", "")
    return counts


def _json_profile_values(body_text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    simple_patterns = {
        "username": r'"username"\s*:\s*"([^"]{1,64})"',
        "display_name": r'"display_name"\s*:\s*"([^"]{1,256})"',
        "full_name": r'"full_name"\s*:\s*"([^"]{1,256})"',
        "account_id": r'"(?:id|profile_id)"\s*:\s*"(\d{2,32})"',
        "external_url": r'"external_url"\s*:\s*(".*?")',
        "is_private": r'"is_private"\s*:\s*(true|false)',
        "is_verified": r'"is_verified"\s*:\s*(true|false)',
    }
    for key, pattern in simple_patterns.items():
        match = re.search(pattern, body_text)
        if not match:
            continue
        raw_value = match.group(1)
        if key == "external_url":
            try:
                raw_value = json.loads(raw_value)
            except json.JSONDecodeError:
                raw_value = ""
        values[key] = _clean_text(str(raw_value))
    if values.get("username") and not _is_valid_username(values["username"]):
        values.pop("username", None)
    external_url = values.get("external_url", "")
    if external_url and not external_url.startswith(("http://", "https://")):
        values.pop("external_url", None)
    return values


def _clean_text(value: str, *, limit: int = 500) -> str:
    return re.sub(r"\s+", " ", html.unescape(value)).strip()[:limit]
