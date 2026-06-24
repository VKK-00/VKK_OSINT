import socket
import unittest
from unittest.mock import patch

from osint_toolkit.adapters import filter_adapters
from osint_toolkit.adapter_runner import run_adapter, run_adapter_findings
from osint_toolkit.dns_lookup import DnsLookupResult
from osint_toolkit.doctor import inspect_adapters
from osint_toolkit.engine import Engine, RunConfig, ScanTarget
from osint_toolkit.http_client import HttpResult
from osint_toolkit.investigation import render_investigation_json, render_investigation_markdown, run_investigation
from osint_toolkit.modules import DomainScanModule, EmailScanModule, PersonNameScanModule, PhoneScanModule, UsernameScanModule, WebMetadataModule
from osint_toolkit.modules.domain import normalize_domain
from osint_toolkit.modules.person import generate_username_candidates, normalize_person_name
from osint_toolkit.modules.phone import detect_country, is_e164_like, normalize_phone
from osint_toolkit.modules.ru_ua_sources import RuUaSourcePackModule
from osint_toolkit.modules.telegram import TelegramScanModule, normalize_telegram_target
from osint_toolkit.modules.username import classify_username_http_result, normalize_username
from osint_toolkit.sites import UsernameSite


class EngineTests(unittest.TestCase):
    def test_username_scan_dry_run_returns_planned_profile_urls(self):
        engine = Engine([UsernameScanModule()])
        findings = engine.scan(ScanTarget(kind="username", value="example-user"), RunConfig(limit=3))

        self.assertEqual(len(findings), 3)
        self.assertTrue(all(finding.status == "planned" for finding in findings))
        self.assertEqual(findings[0].source, "GitHub")
        self.assertEqual(findings[0].url, "https://github.com/example-user")

    def test_username_scan_applies_platform_rules(self):
        engine = Engine([UsernameScanModule()])
        findings = engine.scan(ScanTarget(kind="username", value="example_user"), RunConfig(limit=3))

        self.assertEqual(findings[0].source, "GitHub")
        self.assertEqual(findings[0].status, "skipped")
        self.assertEqual(findings[0].metadata["rule_status"], "skipped")
        self.assertIn("GitHub username rule", findings[0].evidence)
        self.assertEqual(findings[1].status, "planned")

    def test_username_scan_normalizes_at_prefix(self):
        engine = Engine([UsernameScanModule()])
        findings = engine.scan(ScanTarget(kind="username", value="@durov"), RunConfig(limit=1))

        self.assertEqual(normalize_username("@durov"), "durov")
        self.assertEqual(findings[0].url, "https://github.com/durov")
        self.assertEqual(findings[0].metadata["normalized_username"], "durov")

    def test_username_site_dataset_includes_extra_social_and_dev_sources(self):
        engine = Engine([UsernameScanModule()])
        findings = engine.scan(ScanTarget(kind="username", value="exampleuser"), RunConfig())
        sources = {finding.source for finding in findings}

        self.assertIn("NPM", sources)
        self.assertIn("Docker Hub", sources)
        self.assertIn("Linktree", sources)
        self.assertIn("Threads", sources)

    def test_username_live_classifier_uses_not_found_marker(self):
        site = UsernameSite(
            "Example",
            "https://example.com/{username}",
            not_found_markers=("No user named {username}",),
        )
        classification = classify_username_http_result(
            site,
            "missinguser",
            HttpResult(
                url="https://example.com/missinguser",
                final_url="https://example.com/missinguser",
                status_code=200,
                title="Profile",
                body_text="No user named missinguser was found.",
            ),
        )

        self.assertEqual(classification.status, "not_found")
        self.assertEqual(classification.confidence, "high")
        self.assertEqual(classification.content_rule, "not_found_marker")

    def test_username_live_classifier_uses_profile_marker(self):
        site = UsernameSite(
            "Example",
            "https://example.com/{username}",
            profile_markers=("profile-owner:{username}",),
        )
        classification = classify_username_http_result(
            site,
            "realuser",
            HttpResult(
                url="https://example.com/realuser",
                final_url="https://example.com/realuser",
                status_code=200,
                title="Real User",
                body_text="<main>profile-owner:realuser</main>",
            ),
        )

        self.assertEqual(classification.status, "candidate")
        self.assertEqual(classification.confidence, "high")
        self.assertEqual(classification.content_rule, "profile_marker")

    def test_username_live_classifier_keeps_status_without_content_marker(self):
        site = UsernameSite("Example", "https://example.com/{username}")
        classification = classify_username_http_result(
            site,
            "maybeuser",
            HttpResult(
                url="https://example.com/maybeuser",
                final_url="https://example.com/maybeuser",
                status_code=200,
                title="Maybe",
                body_text="<main>generic page</main>",
            ),
        )

        self.assertEqual(classification.status, "candidate")
        self.assertEqual(classification.confidence, "medium")
        self.assertEqual(classification.content_rule, "unmatched")

    def test_username_scan_region_ru_includes_ru_sources(self):
        engine = Engine([UsernameScanModule()])
        findings = engine.scan(ScanTarget(kind="username", value="durov", region="ru"), RunConfig())
        sources = {finding.source for finding in findings}

        self.assertIn("VK", sources)
        self.assertIn("OK.ru", sources)
        self.assertIn("GitHub", sources)

    def test_person_scan_generates_username_candidates_from_ru_ua_name(self):
        engine = Engine([PersonNameScanModule()])
        findings = engine.scan(ScanTarget(kind="person", value="Іван Петренко"), RunConfig(limit=4))
        usernames = [finding.metadata["username"] for finding in findings]

        self.assertEqual(findings[0].metadata["normalized_name"], "ivan petrenko")
        self.assertIn("ivanpetrenko", usernames)
        self.assertIn("ivan.petrenko", usernames)
        self.assertTrue(all(finding.status == "candidate" for finding in findings))

    def test_person_name_helpers_generate_stable_variants(self):
        self.assertEqual(normalize_person_name("Олена Іваненко"), "olena ivanenko")
        candidates = generate_username_candidates("olena ivanenko")
        usernames = [candidate.username for candidate in candidates]

        self.assertEqual(usernames[:4], ["olena", "olenaivanenko", "olena.ivanenko", "olena_ivanenko"])

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

        self.assertEqual(len(findings), 6)
        self.assertEqual(findings[0].source, "syntax")
        self.assertEqual(findings[0].status, "valid")
        self.assertEqual(findings[1].source, "domain-resolution")
        self.assertEqual(findings[1].status, "planned")
        self.assertEqual(findings[2].source, "mx-records")
        self.assertEqual(findings[2].status, "planned")
        self.assertEqual(findings[3].source, "txt-records")
        self.assertEqual(findings[3].status, "planned")
        self.assertEqual(findings[4].source, "spf-policy")
        self.assertEqual(findings[4].status, "planned")
        self.assertEqual(findings[5].source, "dmarc-policy")
        self.assertEqual(findings[5].status, "planned")

    def test_email_scan_live_adds_mx_and_txt_records(self):
        def fake_lookup(domain, record_type, *, timeout=10.0):
            if record_type == "MX":
                return DnsLookupResult(
                    domain=domain,
                    record_type=record_type,
                    status="candidate",
                    records=("10 mail.example.com",),
                )
            if domain.startswith("_dmarc."):
                return DnsLookupResult(
                    domain=domain,
                    record_type=record_type,
                    status="candidate",
                    records=("v=DMARC1; p=reject; rua=mailto:dmarc@example.com",),
                )
            return DnsLookupResult(
                domain=domain,
                record_type=record_type,
                status="candidate",
                records=("v=spf1 include:_spf.example.com -all",),
            )

        with patch("osint_toolkit.modules.email.socket.getaddrinfo", return_value=[(socket.AF_INET, None, None, "", ("93.184.216.34", 0))]), patch(
            "osint_toolkit.modules.email.lookup_dns_records",
            side_effect=fake_lookup,
        ):
            findings = Engine([EmailScanModule()]).scan(
                ScanTarget(kind="email", value="person@example.com"),
                RunConfig(live=True),
            )

        sources = {finding.source: finding for finding in findings}
        self.assertEqual(sources["domain-resolution"].status, "candidate")
        self.assertEqual(sources["mx-records"].metadata["records"], "10 mail.example.com")
        self.assertEqual(sources["txt-records"].metadata["records"], "v=spf1 include:_spf.example.com -all")
        self.assertEqual(sources["spf-policy"].metadata["policy"], "hardfail")
        self.assertEqual(sources["spf-policy"].metadata["include_count"], "1")
        self.assertEqual(sources["dmarc-policy"].metadata["policy"], "reject")

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

        findings = run_adapter_findings(
            "sherlock-project/sherlock",
            ScanTarget(kind="username", value="example_user"),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "planned")

    def test_adapter_runner_blocks_restricted_by_default(self):
        finding = run_adapter(
            "megadose/holehe",
            ScanTarget(kind="email", value="person@example.com"),
        )

        self.assertEqual(finding.status, "restricted")

    def test_doctor_reports_restricted_adapter(self):
        findings = inspect_adapters("restricted")
        statuses = {finding.source: finding.status for finding in findings}

        self.assertEqual(statuses["megadose/holehe"], "restricted")

    def test_investigation_runs_multiple_targets_and_adapter_dry_runs(self):
        result = run_investigation(
            (
                ScanTarget(kind="username", value="example_user"),
                ScanTarget(kind="domain", value="example.com"),
            ),
            title="test case",
            include_adapters=True,
            adapter_limit=3,
        )

        self.assertEqual(result.title, "test case")
        self.assertTrue(any(finding.module == "username-public-profiles" for finding in result.findings))
        self.assertTrue(any(finding.module == "domain-baseline" for finding in result.findings))
        self.assertTrue(any(finding.module == "external-adapter" for finding in result.adapter_findings))
        markdown = render_investigation_markdown(result)
        self.assertIn("# test case", markdown)
        self.assertIn("Adapter Dry Runs", markdown)

    def test_investigation_builds_entity_summary(self):
        result = run_investigation(
            (
                ScanTarget(kind="email", value="person@example.com"),
                ScanTarget(kind="phone", value="+380 44 123 45 67"),
                ScanTarget(kind="telegram", value="@durov"),
            )
        )

        entity_keys = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("email", "person@example.com"), entity_keys)
        self.assertIn(("domain", "example.com"), entity_keys)
        self.assertIn(("normalized-value", "+380441234567"), entity_keys)
        self.assertIn(("country", "ukraine"), entity_keys)
        self.assertIn(("telegram", "@durov"), entity_keys)
        self.assertIn(("url", "https://t.me/durov"), entity_keys)

        edge_keys = {
            (edge.source_kind, edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("email", "email_domain", "domain", "example.com"), edge_keys)
        self.assertIn(("phone", "normalized_as", "normalized-value", "+380441234567"), edge_keys)
        self.assertIn(("phone", "country_hint", "country", "ukraine"), edge_keys)
        self.assertIn(("telegram", "produced_url", "url", "https://t.me/durov"), edge_keys)
        self.assertIn(("url", "telegram_url_for", "telegram", "@durov"), edge_keys)

        markdown = render_investigation_markdown(result)
        self.assertIn("Entity Summary", markdown)
        self.assertIn("Graph Edges", markdown)
        self.assertIn("person@example.com", markdown)
        self.assertIn("@durov", markdown)

        json_output = render_investigation_json(result)
        self.assertIn('"entities"', json_output)
        self.assertIn('"edges"', json_output)
        self.assertIn('"value": "person@example.com"', json_output)


if __name__ == "__main__":
    unittest.main()
