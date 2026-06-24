from __future__ import annotations

import html
import re
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlparse

PUBLIC_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PUBLIC_PHONE_RE = re.compile(r"(?<!\w)(\+[1-9][\d\s().-]{7,24}\d)")
SOCIAL_HOST_SUFFIXES = (
    "facebook.com",
    "github.com",
    "instagram.com",
    "linkedin.com",
    "medium.com",
    "ok.ru",
    "pinterest.com",
    "reddit.com",
    "t.me",
    "telegram.me",
    "telegram.dog",
    "threads.net",
    "tiktok.com",
    "twitter.com",
    "vk.com",
    "x.com",
    "youtube.com",
)


def extract_public_emails(text: str, *, limit: int = 50) -> tuple[str, ...]:
    if not text:
        return ()
    normalized_text = html.unescape(text)
    emails: list[str] = []
    seen: set[str] = set()
    for match in PUBLIC_EMAIL_RE.finditer(normalized_text):
        email = match.group(0).strip(".,;:()[]{}<>\"'").lower()
        if not _looks_like_public_email(email):
            continue
        if email not in seen:
            seen.add(email)
            emails.append(email)
        if len(emails) >= limit:
            break
    return tuple(emails)


def split_emails_by_domain(emails: tuple[str, ...], domain: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    normalized_domain = domain.lower().strip(".")
    same_domain: list[str] = []
    external: list[str] = []
    for email in emails:
        email_domain = email.rsplit("@", 1)[-1].lower()
        if email_domain == normalized_domain or email_domain.endswith(f".{normalized_domain}"):
            same_domain.append(email)
        else:
            external.append(email)
    return tuple(same_domain), tuple(external)


def extract_public_phones(text: str, *, limit: int = 50) -> tuple[str, ...]:
    if not text:
        return ()
    normalized_text = html.unescape(text)
    phones: list[str] = []
    seen: set[str] = set()
    for match in PUBLIC_PHONE_RE.finditer(normalized_text):
        digits = re.sub(r"\D", "", match.group(1))
        if not 8 <= len(digits) <= 15:
            continue
        phone = f"+{digits}"
        if phone not in seen:
            seen.add(phone)
            phones.append(phone)
        if len(phones) >= limit:
            break
    return tuple(phones)


def extract_public_links(text: str, base_url: str, *, limit: int = 100) -> tuple[str, ...]:
    if not text or not base_url:
        return ()
    parser = _LinkParser()
    try:
        parser.feed(text)
    except Exception:
        return ()

    links: list[str] = []
    seen: set[str] = set()
    for raw_link in parser.links:
        link = _normalize_public_link(raw_link, base_url)
        if not link:
            continue
        key = link.lower()
        if key not in seen:
            seen.add(key)
            links.append(link)
        if len(links) >= limit:
            break
    return tuple(links)


def filter_social_links(links: tuple[str, ...], *, limit: int = 50) -> tuple[str, ...]:
    social: list[str] = []
    seen: set[str] = set()
    for link in links:
        host = (urlparse(link).hostname or "").lower().strip(".")
        if not _is_social_host(host):
            continue
        key = link.lower()
        if key not in seen:
            seen.add(key)
            social.append(link)
        if len(social) >= limit:
            break
    return tuple(social)


def _looks_like_public_email(value: str) -> bool:
    if not PUBLIC_EMAIL_RE.fullmatch(value):
        return False
    local, domain = value.rsplit("@", 1)
    if len(local) > 64 or len(domain) > 253:
        return False
    if ".." in local or ".." in domain:
        return False
    return True


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() not in {"a", "area", "link"}:
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                self.links.append(value.strip())


def _normalize_public_link(raw_link: str, base_url: str) -> str:
    link = html.unescape(raw_link).strip()
    if not link or link.startswith("#"):
        return ""
    parsed = urlparse(link)
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        return ""
    absolute, _fragment = urldefrag(urljoin(base_url, link))
    parsed_absolute = urlparse(absolute)
    if parsed_absolute.scheme not in {"http", "https"} or not parsed_absolute.netloc:
        return ""
    return absolute


def _is_social_host(host: str) -> bool:
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in SOCIAL_HOST_SUFFIXES)
