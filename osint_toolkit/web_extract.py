from __future__ import annotations

import html
import re

PUBLIC_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


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


def _looks_like_public_email(value: str) -> bool:
    if not PUBLIC_EMAIL_RE.fullmatch(value):
        return False
    local, domain = value.rsplit("@", 1)
    if len(local) > 64 or len(domain) > 253:
        return False
    if ".." in local or ".." in domain:
        return False
    return True
