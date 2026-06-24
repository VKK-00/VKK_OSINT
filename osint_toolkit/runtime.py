from __future__ import annotations

from .engine import Engine
from .modules import (
    DomainScanModule,
    EmailScanModule,
    InstagramPublicProfileModule,
    PersonNameScanModule,
    PhoneScanModule,
    RuUaSourcePackModule,
    SocialPublicProfileModule,
    TelegramScanModule,
    UsernameScanModule,
    WebMetadataModule,
)


def build_default_engine() -> Engine:
    return Engine(
        [
            UsernameScanModule(),
            PersonNameScanModule(),
            EmailScanModule(),
            PhoneScanModule(),
            DomainScanModule(),
            WebMetadataModule(),
            TelegramScanModule(),
            InstagramPublicProfileModule(),
            SocialPublicProfileModule(),
            RuUaSourcePackModule(),
        ]
    )
