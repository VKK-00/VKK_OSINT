import unittest

from osint_toolkit.adapters import filter_adapters
from osint_toolkit.adapter_runner import run_adapter
from osint_toolkit.engine import Engine, RunConfig, ScanTarget
from osint_toolkit.modules import DomainScanModule, EmailScanModule, PhoneScanModule, UsernameScanModule, WebMetadataModule
from osint_toolkit.modules.domain import normalize_domain
from osint_toolkit.modules.phone import detect_country, is_e164_like, normalize_phone
from osint_toolkit.modules.ru_ua_sources import RuUaSourcePackModule
from osint_toolkit.modules.telegram import TelegramScanModule, normalize_telegram_target


class EngineTests(unittest.TestCase):
    def test_username_scan_dry_run_returns_planned_profile_urls(self):
        engine = Engine([UsernameScanModule()])
        findings = engine.scan(ScanTarget(kind="username", value="example_user"), RunConfig(limit=3))

        self.assertEqual(len(findings), 3)
        self.assertTrue(all(finding.status == "planned" for finding in findings))
        self.assertEqual(findings[0].source, "GitHub")
        self.assertEqual(findings[0].url, "https://github.com/example_user")

    def test_username_scan_region_ru_includes_ru_sources(self):
        engine = Engine([UsernameScanModule()])
        findings = engine.scan(ScanTarget(kind="username", value="durov", region="ru"), RunConfig())
        sources = {finding.source for finding in findings}

        self.assertIn("VK", sources)
        self.assertIn("OK.ru", sources)
        self.assertIn("GitHub", sources)

    def test_url_scan_dry_run_normalizes_scheme(self):
        engine = Engine([WebMetadataModule()])
        findings = engine.scan(ScanTarget(kind="url", value="example.com"), RunConfig())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "planned")
        self.assertEqual(findings[0].url, "https://example.com")

    def test_domain_scan_dry_run_plans_dns_and_http_metadata(self):
        engine = Engine([DomainScanModule()])
        findings = engine.scan(ScanTarget(kind="domain", value="https://example.com/path"), RunConfig())

        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0].source, "dns-resolution")
        self.assertEqual(findings[0].metadata["domain"], "example.com")
        self.assertEqual(findings[1].url, "https://example.com")
        self.assertEqual(findings[2].url, "http://example.com")

    def test_domain_normalizer_rejects_invalid_values(self):
        self.assertEqual(normalize_domain("https://Example.COM/a"), "example.com")
        self.assertEqual(normalize_domain("not a domain"), "")

    def test_telegram_scan_normalizes_handle_and_post_url(self):
        engine = Engine([TelegramScanModule()])
        handle = engine.scan(ScanTarget(kind="telegram", value="@durov"), RunConfig())
        post = engine.scan(ScanTarget(kind="telegram", value="https://t.me/telegram/123"), RunConfig())

        self.assertEqual(handle[0].url, "https://t.me/durov")
        self.assertEqual(handle[0].metadata["target_type"], "handle")
        self.assertEqual(post[0].url, "https://t.me/telegram/123")
        self.assertEqual(post[0].metadata["target_type"], "post")

    def test_telegram_normalizer_rejects_non_telegram_url(self):
        self.assertIsNone(normalize_telegram_target("https://example.com/durov"))

    def test_ru_ua_source_pack_filters_by_region(self):
        engine = Engine([RuUaSourcePackModule()])
        findings = engine.scan(ScanTarget(kind="ru-ua", value="all", region="ua"), RunConfig())
        sources = {finding.source for finding in findings}

        self.assertIn("DeepStateMap", sources)
        self.assertIn("paste.in.ua", sources)
        self.assertNotIn("VK", sources)

    def test_ru_ua_source_pack_platforms_selector(self):
        engine = Engine([RuUaSourcePackModule()])
        findings = engine.scan(ScanTarget(kind="ru-ua", value="platforms", region="ru"), RunConfig())
        sources = {finding.source for finding in findings}

        self.assertIn("VK", sources)
        self.assertIn("Odnoklassniki", sources)

    def test_email_scan_validates_syntax_and_plans_domain_resolution(self):
        engine = Engine([EmailScanModule()])
        findings = engine.scan(ScanTarget(kind="email", value="person@example.com"), RunConfig())

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].source, "syntax")
        self.assertEqual(findings[0].status, "valid")
        self.assertEqual(findings[1].source, "domain-resolution")
        self.assertEqual(findings[1].status, "planned")

    def test_email_scan_rejects_invalid_input(self):
        engine = Engine([EmailScanModule()])
        findings = engine.scan(ScanTarget(kind="email", value="not-an-email"), RunConfig())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "invalid")

    def test_phone_scan_normalizes_and_detects_ukraine_prefix(self):
        engine = Engine([PhoneScanModule()])
        findings = engine.scan(ScanTarget(kind="phone", value="+380 44 123 45 67"), RunConfig())

        self.assertEqual(findings[0].status, "valid")
        self.assertEqual(findings[0].metadata["normalized"], "+380441234567")
        self.assertEqual(findings[1].metadata["country"], "Ukraine")

    def test_phone_helpers(self):
        self.assertEqual(normalize_phone("00380 44 123 45 67"), "+380441234567")
        self.assertTrue(is_e164_like("+380441234567"))
        self.assertEqual(detect_country("+70000000000"), ("Russia/Kazakhstan", "ru"))

    def test_adapter_manifest_has_partial_native_and_restricted_items(self):
        partial = filter_adapters("partial_native")
        restricted = filter_adapters("restricted")

        self.assertTrue(any(adapter.repository == "sherlock-project/sherlock" for adapter in partial))
        self.assertTrue(any(adapter.repository == "alpkeskin/mosint" for adapter in partial))
        self.assertTrue(any(adapter.repository == "sundowndev/phoneinfoga" for adapter in partial))
        self.assertTrue(any(adapter.repository == "megadose/holehe" for adapter in restricted))

    def test_adapter_runner_dry_run_renders_command(self):
        finding = run_adapter(
            "sherlock-project/sherlock",
            ScanTarget(kind="username", value="example_user"),
        )

        self.assertEqual(finding.status, "planned")
        self.assertIn("sherlock example_user", finding.evidence)

    def test_adapter_runner_blocks_restricted_by_default(self):
        finding = run_adapter(
            "megadose/holehe",
            ScanTarget(kind="email", value="person@example.com"),
        )

        self.assertEqual(finding.status, "restricted")


if __name__ == "__main__":
    unittest.main()
