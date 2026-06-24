from __future__ import annotations

import html
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient, HttpResult

VK_HOSTS = {"vk.com", "www.vk.com", "m.vk.com", "vkontakte.ru", "www.vkontakte.ru"}
OK_HOSTS = {"ok.ru", "www.ok.ru", "m.ok.ru", "odnoklassniki.ru", "www.odnoklassniki.ru"}
MAILRU_HOSTS = {"my.mail.ru", "m.my.mail.ru"}
YANDEX_Q_HOSTS = {"yandex.ru", "www.yandex.ru"}
YANDEX_MARKET_HOSTS = {"market.yandex.ru"}
YANDEX_REVIEWS_HOSTS = {"reviews.yandex.ru"}
YANDEX_ZEN_HOSTS = {"zen.yandex.ru", "www.zen.yandex.ru"}
MAILRU_NAMESPACES = {"mail", "bk", "inbox", "list", "internet", "ya", "yandex", "gmail", "vk", "ok"}
RESERVED_VK_PATHS = {"album", "albums", "audios", "away", "feed", "friends", "groups", "im", "login", "search", "video", "videos"}
RESERVED_OK_PATHS = {"dk", "feed", "groups", "login", "messages", "search"}
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.-]{2,64}$")


@dataclass(frozen=True)
class SocialProfileTarget:
    platform: str
    platform_name: str
    platform_domain: str
    url: str
    identifier: str
    target_type: str
    account_id: str = ""

    def profile_key(self) -> str:
        return f"{self.platform}:{self.identifier}"


@dataclass(frozen=True)
class SocialPublicMetadata:
    display_name: str = ""
    description: str = ""
    canonical_url: str = ""
    profile_image_url: str = ""
    account_id: str = ""

    def to_metadata(self) -> dict[str, str]:
        metadata = {
            "display_name": self.display_name,
            "description": self.description,
            "canonical_url": self.canonical_url,
            "profile_image_url": self.profile_image_url,
            "account_id": self.account_id,
        }
        return {key: value for key, value in metadata.items() if value}


@dataclass(frozen=True)
class SocialPublicProfileModule:
    name: str = "social-public-profile"
    supported_targets: tuple[str, ...] = ("social",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        parsed = normalize_social_target(target.value)
        if not parsed:
            return (
                Finding(
                    module=self.name,
                    source="normalizer",
                    target=target.value,
                    status="invalid",
                    confidence="high",
                    evidence="Could not normalize input into a supported public VK/OK profile URL.",
                ),
            )

        metadata = _target_metadata(parsed)
        if not config.live:
            return (
                Finding(
                    module=self.name,
                    source=f"{parsed.platform}-profile-url",
                    target=target.value,
                    status="planned",
                    url=parsed.url,
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to fetch public social profile metadata.",
                    metadata=metadata,
                ),
            )

        client = HttpClient(
            timeout=config.timeout,
            user_agent=config.user_agent,
            retries=config.http_retries,
            backoff_seconds=config.http_backoff,
        )
        result = client.check(parsed.url, fetch_title=True, headers=_social_headers())
        public_metadata = extract_social_public_metadata(result.body_text, parsed)
        metadata.update(public_metadata.to_metadata())
        metadata["content_type"] = result.content_type
        metadata["http_attempts"] = str(result.attempts)
        if config.http_retries:
            metadata["http_retries"] = str(config.http_retries)
            metadata["http_backoff_seconds"] = str(config.http_backoff)

        status, confidence, evidence = classify_social_http_result(parsed, result, public_metadata)
        return (
            Finding(
                module=self.name,
                source=f"{parsed.platform}-profile-url",
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


def normalize_social_target(value: str) -> SocialProfileTarget | None:
    raw = value.strip()
    if not raw:
        return None
    prefixed = _target_from_prefix(raw)
    if prefixed:
        return prefixed

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = (parsed.hostname or "").lower()
    if host in VK_HOSTS:
        return _vk_target_from_path(parsed.path)
    if host in OK_HOSTS:
        return _ok_target_from_path(parsed.path)
    if host in MAILRU_HOSTS:
        return _mailru_target_from_path(parsed.path)
    if host in YANDEX_Q_HOSTS:
        return _yandex_target_from_path(parsed.path, service="q")
    if host in YANDEX_MARKET_HOSTS:
        return _yandex_target_from_path(parsed.path, service="market")
    if host in YANDEX_REVIEWS_HOSTS:
        return _yandex_target_from_path(parsed.path, service="reviews")
    if host in YANDEX_ZEN_HOSTS:
        return _yandex_target_from_path(parsed.path, service="zen")
    return None


def extract_social_public_metadata(body_text: str, target: SocialProfileTarget) -> SocialPublicMetadata:
    if not body_text:
        return SocialPublicMetadata(account_id=target.account_id)
    meta = _html_meta_values(body_text)
    canonical_url = _canonical_url(body_text) or meta.get("og:url", "")
    title = meta.get("og:title") or meta.get("twitter:title", "")
    description = meta.get("og:description") or meta.get("description", "")
    display_name = _display_name_from_title(title, target.platform_name)
    account_id = target.account_id or _account_id_from_url(canonical_url, target.platform)
    return SocialPublicMetadata(
        display_name=display_name,
        description=_clean_text(description),
        canonical_url=canonical_url,
        profile_image_url=meta.get("og:image", "") or meta.get("twitter:image", ""),
        account_id=account_id,
    )


def classify_social_http_result(
    target: SocialProfileTarget,
    result: HttpResult,
    metadata: SocialPublicMetadata,
) -> tuple[str, str, str]:
    if result.status_code is None:
        return "error", "low", result.error or "HTTP request failed."
    if result.status_code == 404:
        return "not_found", "high", f"HTTP 404 from public {target.platform_name} page."
    if result.status_code and result.status_code >= 400:
        return "unknown", "low", result.error or f"HTTP {result.status_code}"
    if metadata.display_name or metadata.canonical_url or metadata.profile_image_url:
        return "candidate", "medium", f"HTTP {result.status_code}; public {target.platform_name} metadata found."
    return "candidate", "low", f"HTTP {result.status_code}; page fetched but public profile metadata was limited."


def _target_from_prefix(raw: str) -> SocialProfileTarget | None:
    if ":" not in raw:
        return None
    platform, identifier = raw.split(":", 1)
    platform = platform.strip().lower()
    identifier = identifier.strip().strip("/")
    if platform in {"vk", "vkontakte"}:
        return _vk_target_from_identifier(identifier)
    if platform in {"ok", "odnoklassniki"}:
        return _ok_target_from_identifier(identifier)
    if platform in {"mailru", "mail.ru", "my.mail.ru"}:
        return _mailru_target_from_identifier(identifier)
    if platform in {"yandex", "ya"}:
        return _yandex_target_from_identifier(identifier)
    return None


def _vk_target_from_path(path: str) -> SocialProfileTarget | None:
    parts = _path_parts(path)
    if not parts or parts[0].lower() in RESERVED_VK_PATHS:
        return None
    return _vk_target_from_identifier(parts[0])


def _vk_target_from_identifier(identifier: str) -> SocialProfileTarget | None:
    normalized = identifier.strip().strip("/")
    if not _valid_identifier(normalized):
        return None
    target_type = "profile"
    account_id = ""
    lowered = normalized.lower()
    if re.fullmatch(r"id\d{1,20}", lowered):
        target_type = "profile_id"
        account_id = lowered[2:]
    elif re.fullmatch(r"(club|public)\d{1,20}", lowered):
        target_type = "community"
        account_id = re.sub(r"^\D+", "", lowered)
    return SocialProfileTarget(
        platform="vk",
        platform_name="VK",
        platform_domain="vk.com",
        url=f"https://vk.com/{normalized}",
        identifier=normalized,
        target_type=target_type,
        account_id=account_id,
    )


def _ok_target_from_path(path: str) -> SocialProfileTarget | None:
    parts = _path_parts(path)
    if not parts or parts[0].lower() in RESERVED_OK_PATHS:
        return None
    if parts[0].lower() in {"profile", "group"} and len(parts) >= 2:
        return _ok_target_from_identifier(f"{parts[0].lower()}/{parts[1]}")
    return _ok_target_from_identifier(parts[0])


def _ok_target_from_identifier(identifier: str) -> SocialProfileTarget | None:
    normalized = identifier.strip().strip("/")
    account_id = ""
    target_type = "profile"
    if "/" in normalized:
        kind, value = normalized.split("/", 1)
        kind = kind.lower()
        if kind not in {"profile", "group"} or not re.fullmatch(r"\d{2,32}", value):
            return None
        normalized = f"{kind}/{value}"
        target_type = "profile_id" if kind == "profile" else "group"
        account_id = value
    elif not _valid_identifier(normalized):
        return None
    return SocialProfileTarget(
        platform="ok",
        platform_name="Odnoklassniki",
        platform_domain="ok.ru",
        url=f"https://ok.ru/{normalized}",
        identifier=normalized,
        target_type=target_type,
        account_id=account_id,
    )


def _mailru_target_from_path(path: str) -> SocialProfileTarget | None:
    parts = _path_parts(path)
    if len(parts) < 2:
        return None
    return _mailru_target_from_identifier(f"{parts[0].lower()}/{parts[1]}")


def _mailru_target_from_identifier(identifier: str) -> SocialProfileTarget | None:
    normalized = identifier.strip().strip("/")
    if "/" in normalized:
        namespace, username = normalized.split("/", 1)
        namespace = namespace.lower()
    else:
        namespace, username = "mail", normalized
    username = username.strip().strip("/")
    if namespace not in MAILRU_NAMESPACES or not _valid_identifier(username):
        return None
    normalized = f"{namespace}/{username}"
    return SocialProfileTarget(
        platform="mailru",
        platform_name="Mail.ru",
        platform_domain="my.mail.ru",
        url=f"https://my.mail.ru/{normalized}/",
        identifier=normalized,
        target_type="mailru_profile",
    )


def _yandex_target_from_path(path: str, *, service: str) -> SocialProfileTarget | None:
    parts = _path_parts(path)
    if service == "q" and len(parts) >= 3 and parts[0].lower() == "q" and parts[1].lower() == "profile":
        return _yandex_target_from_identifier(f"q/{parts[2]}")
    if service in {"market", "reviews", "zen"} and len(parts) >= 2 and parts[0].lower() == "user":
        return _yandex_target_from_identifier(f"{service}/{parts[1]}")
    return None


def _yandex_target_from_identifier(identifier: str) -> SocialProfileTarget | None:
    normalized = identifier.strip().strip("/")
    if "/" in normalized:
        service, username = normalized.split("/", 1)
        service = service.lower()
    else:
        service, username = "q", normalized
    username = username.strip().strip("/")
    if service not in {"q", "market", "reviews", "zen"} or not _valid_identifier(username):
        return None

    if service == "q":
        url = f"https://yandex.ru/q/profile/{username}/"
        target_type = "yandex_q_profile"
        platform_domain = "yandex.ru"
    elif service == "market":
        url = f"https://market.yandex.ru/user/{username}"
        target_type = "yandex_market_user"
        platform_domain = "market.yandex.ru"
    elif service == "reviews":
        url = f"https://reviews.yandex.ru/user/{username}"
        target_type = "yandex_reviews_user"
        platform_domain = "reviews.yandex.ru"
    else:
        url = f"https://zen.yandex.ru/user/{username}"
        target_type = "yandex_zen_user"
        platform_domain = "zen.yandex.ru"

    return SocialProfileTarget(
        platform="yandex",
        platform_name="Yandex",
        platform_domain=platform_domain,
        url=url,
        identifier=f"{service}/{username}",
        target_type=target_type,
    )


def _target_metadata(target: SocialProfileTarget) -> dict[str, str]:
    metadata = {
        "platform": target.platform,
        "platform_name": target.platform_name,
        "platform_domain": target.platform_domain,
        "social_profile": target.profile_key(),
        "social_username": target.identifier,
        "target_type": target.target_type,
    }
    if target.account_id:
        metadata["account_id"] = target.account_id
    return metadata


def _social_headers() -> dict[str, str]:
    return {"Accept-Language": "ru,en-US;q=0.9,en;q=0.8"}


def _path_parts(path: str) -> tuple[str, ...]:
    return tuple(part for part in path.split("/") if part)


def _valid_identifier(value: str) -> bool:
    return bool(value) and IDENTIFIER_RE.fullmatch(value) is not None and not value.startswith(".")


def _html_meta_values(body_text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for match in re.finditer(r"<meta\b[^>]*>", body_text, flags=re.IGNORECASE):
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


def _display_name_from_title(title: str, platform_name: str) -> str:
    value = _clean_text(title)
    if not value:
        return ""
    separators = (f"| {platform_name}", "| VK", "| ВКонтакте", "| Одноклассники", "| OK")
    for separator in separators:
        if separator in value:
            value = value.split(separator, 1)[0].strip()
    return value


def _account_id_from_url(url: str, platform: str) -> str:
    parsed = urlparse(url)
    parts = _path_parts(parsed.path)
    if platform == "vk" and parts:
        match = re.fullmatch(r"(?:id|club|public)(\d{1,20})", parts[0].lower())
        return match.group(1) if match else ""
    if platform == "ok" and len(parts) >= 2 and parts[0].lower() in {"profile", "group"}:
        return parts[1] if re.fullmatch(r"\d{2,32}", parts[1]) else ""
    return ""


def _clean_text(value: str, *, limit: int = 500) -> str:
    return re.sub(r"\s+", " ", html.unescape(value)).strip()[:limit]
