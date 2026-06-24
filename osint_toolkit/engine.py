from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True)
class ScanTarget:
    kind: str
    value: str
    region: str = "all"


@dataclass(frozen=True)
class RunConfig:
    live: bool = False
    timeout: float = 10.0
    user_agent: str = "osint-toolkit/0.1"
    limit: int | None = None
    http_retries: int = 1
    http_backoff: float = 1.0
    request_delay: float = 0.0
    person_aliases: tuple[str, ...] = ()
    crawl_pages: int = 5
    crawl_depth: int = 1


@dataclass(frozen=True)
class Finding:
    module: str
    source: str
    target: str
    status: str
    url: str = ""
    title: str = ""
    http_status: int | None = None
    confidence: str = "unknown"
    evidence: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
    checked_at: str = field(default_factory=lambda: datetime.now().astimezone().isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, object]:
        return {
            "module": self.module,
            "source": self.source,
            "target": self.target,
            "status": self.status,
            "url": self.url,
            "title": self.title,
            "http_status": self.http_status,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "metadata": self.metadata,
            "checked_at": self.checked_at,
        }


class ScanModule(Protocol):
    name: str
    supported_targets: tuple[str, ...]

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        ...


class Engine:
    def __init__(self, modules: list[ScanModule]):
        self.modules = tuple(modules)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        for module in self.modules:
            if target.kind in module.supported_targets:
                findings.extend(module.scan(target, config))
        if config.limit is not None:
            findings = findings[: config.limit]
        return tuple(findings)
