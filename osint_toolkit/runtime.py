from __future__ import annotations

from .engine import Engine
from .modules import (
    DomainScanModule,
    EmailScanModule,
    PhoneScanModule,
    RuUaSourcePackModule,
    TelegramScanModule,
    UsernameScanModule,
    WebMetadataModule,
)


def build_default_engine() -> Engine:
    return Engine(
        [
            UsernameScanModule(),
            EmailScanModule(),
            PhoneScanModule(),
            DomainScanModule(),
            WebMetadataModule(),
            TelegramScanModule(),
            RuUaSourcePackModule(),
        ]
    )

