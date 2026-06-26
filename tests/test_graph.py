import tempfile
import unittest
from pathlib import Path

from osint_toolkit.adapter_parsers import parse_adapter_output
from osint_toolkit.case_store import CaseStore
from osint_toolkit.entities import entities_from_findings, entities_from_targets, merge_entities
from osint_toolkit.engine import Finding, ScanTarget
from osint_toolkit.graph import (
    analyze_case_graph,
    analyze_cross_case_network,
    analyze_cross_case_path,
    graph_edges_from_case,
)
from osint_toolkit.investigation import run_investigation


class GraphAnalysisTests(unittest.TestCase):
    def test_analyze_case_graph_counts_and_neighbors(self):
        result = run_investigation(
            (
                ScanTarget(kind="email", value="person@example.com"),
                ScanTarget(kind="telegram", value="@durov"),
            ),
            title="graph case",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            store = CaseStore(Path(tmpdir) / "cases.sqlite")
            case_id = store.save(result, case_id="case-1")
            payload = store.load_case(case_id)

        analysis = analyze_case_graph(payload)

        self.assertEqual(analysis.case_id, "case-1")
        self.assertGreaterEqual(analysis.node_count, 4)
        self.assertGreaterEqual(analysis.edge_count, 2)
        self.assertIn(("email_domain", 1), analysis.relation_counts)
        self.assertIn(("email", 1), analysis.kind_counts)

        focused = analyze_case_graph(
            payload,
            focus_kind="email",
            focus_value="person@example.com",
        )
        neighbors = {(neighbor.kind, neighbor.value.lower(), neighbor.relation) for neighbor in focused.neighbors}
        self.assertIn(("domain", "example.com", "email_domain"), neighbors)

    def test_analyze_case_graph_rejects_incomplete_focus_and_bad_limit(self):
        payload = {
            "case": {"case_id": "case-1"},
            "entities": [],
            "edges": [],
        }

        with self.assertRaises(ValueError):
            analyze_case_graph(payload, focus_kind="email")
        with self.assertRaises(ValueError):
            analyze_case_graph(payload, limit=0)

    def test_analyze_cross_case_path_finds_weighted_path_across_cases(self):
        first = run_investigation(
            (ScanTarget(kind="email", value="person@example.com"),),
            title="first case",
        )
        second = run_investigation(
            (
                ScanTarget(kind="domain", value="example.com"),
                ScanTarget(kind="url", value="https://example.com/profile"),
            ),
            title="second case",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            store = CaseStore(Path(tmpdir) / "cases.sqlite")
            store.save(first, case_id="case-1")
            store.save(second, case_id="case-2")
            payloads = store.load_cases()

        analysis = analyze_cross_case_path(
            payloads,
            source_kind="email",
            source_value="person@example.com",
            target_kind="url",
            target_value="https://example.com/profile",
        )

        self.assertTrue(analysis.found)
        self.assertEqual(analysis.hop_count, 2)
        self.assertEqual([step.case_id for step in analysis.steps], ["case-1", "case-2"])
        self.assertEqual([step.direction for step in analysis.steps], ["out", "in"])
        self.assertEqual(analysis.steps[0].relation, "email_domain")
        self.assertEqual(analysis.steps[1].relation, "url_host")

    def test_analyze_cross_case_path_reports_missing_path_and_rejects_invalid_args(self):
        payload = {
            "case": {"case_id": "case-1"},
            "entities": [{"kind": "email", "value": "person@example.com"}],
            "edges": [],
        }
        analysis = analyze_cross_case_path(
            (payload,),
            source_kind="email",
            source_value="person@example.com",
            target_kind="domain",
            target_value="example.com",
        )

        self.assertFalse(analysis.found)
        self.assertEqual(analysis.hop_count, 0)
        self.assertEqual(analysis.steps, ())
        with self.assertRaises(ValueError):
            analyze_cross_case_path(
                (payload,),
                source_kind="email",
                source_value="person@example.com",
                target_kind="domain",
                target_value="example.com",
                max_depth=0,
            )

    def test_analyze_cross_case_network_aggregates_visible_graph(self):
        first = run_investigation(
            (ScanTarget(kind="email", value="person@example.com"),),
            title="first case",
        )
        second = run_investigation(
            (
                ScanTarget(kind="domain", value="example.com"),
                ScanTarget(kind="url", value="https://example.com/profile"),
            ),
            title="second case",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            store = CaseStore(Path(tmpdir) / "cases.sqlite")
            store.save(first, case_id="case-1")
            store.save(second, case_id="case-2")
            payloads = store.load_cases()

        network = analyze_cross_case_network(payloads, kind_filter="domain")

        self.assertEqual(network.case_count, 2)
        self.assertGreaterEqual(network.visible_node_count, 3)
        self.assertGreaterEqual(network.visible_edge_count, 2)
        nodes = {(node.kind, node.value.lower()): node for node in network.nodes}
        self.assertIn(("domain", "example.com"), nodes)
        self.assertEqual(nodes[("domain", "example.com")].case_count, 2)
        relations = {edge.relation for edge in network.edges}
        self.assertIn("email_domain", relations)
        self.assertIn("url_host", relations)

    def test_analyze_cross_case_network_rejects_bad_limits(self):
        payload = {"case": {"case_id": "case-1"}, "entities": [], "edges": []}

        with self.assertRaises(ValueError):
            analyze_cross_case_network((payload,), node_limit=0)
        with self.assertRaises(ValueError):
            analyze_cross_case_network((payload,), edge_limit=0)
        with self.assertRaises(ValueError):
            analyze_cross_case_network((payload,), min_degree=-1)

    def test_phoneinfoga_metadata_edges(self):
        target = ScanTarget(kind="phone", value="+380441234567")
        findings = parse_adapter_output(
            "sundowndev/phoneinfoga",
            target,
            """
            Results for ovh
            Found: true
            Number range: 0038044xxxxxxx
            City: Kyiv
            Zip code: 01001
            """,
        )
        entities = merge_entities(entities_from_targets((target,)), entities_from_findings(findings))
        edges = graph_edges_from_case((target,), findings, entities)

        edge_keys = {
            (edge.source_kind, edge.source_value, edge.relation, edge.target_kind, edge.target_value)
            for edge in edges
        }
        self.assertIn(("phone", "+380441234567", "phone_range_hint", "phone-range", "0038044xxxxxxx"), edge_keys)
        self.assertIn(("phone", "+380441234567", "location_hint", "location", "Kyiv"), edge_keys)
        self.assertIn(("phone", "+380441234567", "postal_code_hint", "postal-code", "01001"), edge_keys)

    def test_provider_metadata_edges(self):
        target = ScanTarget(kind="email", value="person@example.com")
        findings = (
            Finding(
                module="email-baseline",
                source="email-provider-signals",
                target="person@example.com",
                status="candidate",
                confidence="medium",
                evidence="Detected hosted email provider signals.",
                metadata={"domain": "example.com", "providers": "google_workspace, microsoft_365"},
            ),
        )

        entities = merge_entities(entities_from_targets((target,)), entities_from_findings(findings))
        entity_keys = {(entity.kind, entity.value.lower()) for entity in entities}
        self.assertIn(("provider", "google_workspace"), entity_keys)
        self.assertIn(("provider", "microsoft_365"), entity_keys)

        edges = graph_edges_from_case((target,), findings, entities)
        edge_keys = {
            (edge.source_kind, edge.source_value, edge.relation, edge.target_kind, edge.target_value)
            for edge in edges
        }
        self.assertIn(("email", "person@example.com", "uses_provider", "provider", "google_workspace"), edge_keys)
        self.assertIn(("email", "person@example.com", "uses_provider", "provider", "microsoft_365"), edge_keys)

    def test_certificate_transparency_subdomain_metadata_edges(self):
        target = ScanTarget(kind="domain", value="example.com")
        findings = (
            Finding(
                module="domain-baseline",
                source="certificate-transparency",
                target="example.com",
                status="candidate",
                confidence="medium",
                evidence="Found 2 unique subdomain(s).",
                metadata={"domain": "example.com", "subdomains": "api.example.com, www.example.com"},
            ),
        )

        entities = merge_entities(entities_from_targets((target,)), entities_from_findings(findings))
        entity_keys = {(entity.kind, entity.value.lower()) for entity in entities}
        self.assertIn(("subdomain", "api.example.com"), entity_keys)
        self.assertIn(("subdomain", "www.example.com"), entity_keys)

        edges = graph_edges_from_case((target,), findings, entities)
        edge_keys = {
            (edge.source_kind, edge.source_value, edge.relation, edge.target_kind, edge.target_value)
            for edge in edges
        }
        self.assertIn(("domain", "example.com", "discovered_subdomain", "subdomain", "api.example.com"), edge_keys)
        self.assertIn(("domain", "example.com", "discovered_subdomain", "subdomain", "www.example.com"), edge_keys)

    def test_email_domain_ct_subdomain_metadata_edges(self):
        target = ScanTarget(kind="email", value="person@example.com")
        findings = (
            Finding(
                module="email-baseline",
                source="email-domain-ct",
                target="person@example.com",
                status="candidate",
                confidence="medium",
                evidence="Found certificate transparency subdomains for the email domain.",
                metadata={"domain": "example.com", "subdomains": "api.example.com, www.example.com"},
            ),
        )

        entities = merge_entities(entities_from_targets((target,)), entities_from_findings(findings))
        entity_keys = {(entity.kind, entity.value.lower()) for entity in entities}
        self.assertIn(("subdomain", "api.example.com"), entity_keys)
        self.assertIn(("subdomain", "www.example.com"), entity_keys)

        edges = graph_edges_from_case((target,), findings, entities)
        edge_keys = {
            (edge.source_kind, edge.source_value, edge.relation, edge.target_kind, edge.target_value)
            for edge in edges
        }
        self.assertIn(("email", "person@example.com", "discovered_subdomain", "subdomain", "api.example.com"), edge_keys)
        self.assertIn(("email", "person@example.com", "discovered_subdomain", "subdomain", "www.example.com"), edge_keys)

    def test_rdap_metadata_edges(self):
        target = ScanTarget(kind="domain", value="example.com")
        findings = (
            Finding(
                module="domain-baseline",
                source="rdap-domain",
                target="example.com",
                status="candidate",
                confidence="medium",
                evidence="RDAP domain registration record found.",
                metadata={
                    "domain": "example.com",
                    "registrar": "Example Registrar, Inc.",
                    "nameservers": "a.iana-servers.net, b.iana-servers.net",
                },
            ),
        )

        entities = merge_entities(entities_from_targets((target,)), entities_from_findings(findings))
        entity_keys = {(entity.kind, entity.value.lower()) for entity in entities}
        self.assertIn(("registrar", "example registrar, inc."), entity_keys)
        self.assertIn(("nameserver", "a.iana-servers.net"), entity_keys)

        edges = graph_edges_from_case((target,), findings, entities)
        edge_keys = {
            (edge.source_kind, edge.source_value, edge.relation, edge.target_kind, edge.target_value)
            for edge in edges
        }
        self.assertIn(("domain", "example.com", "registered_via", "registrar", "Example Registrar, Inc."), edge_keys)
        self.assertIn(("domain", "example.com", "uses_nameserver", "nameserver", "a.iana-servers.net"), edge_keys)

    def test_whois_metadata_edges(self):
        target = ScanTarget(kind="domain", value="example.com")
        findings = (
            Finding(
                module="domain-baseline",
                source="whois-domain",
                target="example.com",
                status="candidate",
                confidence="medium",
                evidence="WHOIS domain registration record found.",
                metadata={
                    "domain": "example.com",
                    "whois_server": "whois.verisign-grs.com",
                    "whois_referral_server": "whois.example-registrar.test",
                    "registrar": "Example Registrar, Inc.",
                    "nameservers": "a.iana-servers.net, b.iana-servers.net",
                },
            ),
        )

        entities = merge_entities(entities_from_targets((target,)), entities_from_findings(findings))
        entity_keys = {(entity.kind, entity.value.lower()) for entity in entities}
        self.assertIn(("whois-server", "whois.verisign-grs.com"), entity_keys)
        self.assertIn(("whois-server", "whois.example-registrar.test"), entity_keys)
        self.assertIn(("registrar", "example registrar, inc."), entity_keys)

        edges = graph_edges_from_case((target,), findings, entities)
        edge_keys = {
            (edge.source_kind, edge.source_value, edge.relation, edge.target_kind, edge.target_value)
            for edge in edges
        }
        self.assertIn(("domain", "example.com", "queried_whois_server", "whois-server", "whois.verisign-grs.com"), edge_keys)
        self.assertIn(("domain", "example.com", "referred_whois_server", "whois-server", "whois.example-registrar.test"), edge_keys)
        self.assertIn(("domain", "example.com", "registered_via", "registrar", "Example Registrar, Inc."), edge_keys)

    def test_instagram_metadata_edges(self):
        target = ScanTarget(kind="instagram", value="https://www.instagram.com/exampleuser/")
        findings = (
            Finding(
                module="instagram-public-profile",
                source="instagram-profile-url",
                target="https://www.instagram.com/exampleuser/",
                status="candidate",
                url="https://www.instagram.com/exampleuser/",
                confidence="medium",
                evidence="Public Instagram profile metadata found.",
                metadata={
                    "platform": "instagram",
                    "instagram_username": "@exampleuser",
                    "display_name": "Example User",
                    "account_id": "123456789",
                    "canonical_url": "https://www.instagram.com/exampleuser/",
                    "profile_image_url": "https://cdninstagram.example/profile.jpg",
                    "external_url": "https://example.com",
                },
            ),
        )

        entities = merge_entities(entities_from_targets((target,)), entities_from_findings(findings))
        entity_keys = {(entity.kind, entity.value.lower()) for entity in entities}
        self.assertIn(("instagram", "@exampleuser"), entity_keys)
        self.assertIn(("platform", "instagram"), entity_keys)
        self.assertIn(("name", "example user"), entity_keys)
        self.assertIn(("account-id", "123456789"), entity_keys)
        self.assertIn(("url", "https://example.com"), entity_keys)

        edges = graph_edges_from_case((target,), findings, entities)
        edge_keys = {
            (edge.source_kind, edge.source_value, edge.relation, edge.target_kind, edge.target_value)
            for edge in edges
        }
        self.assertIn(("instagram", "https://www.instagram.com/exampleuser/", "normalized_instagram_account", "instagram", "@exampleuser"), edge_keys)
        self.assertIn(("instagram", "https://www.instagram.com/exampleuser/", "on_platform", "platform", "instagram"), edge_keys)
        self.assertIn(("instagram", "https://www.instagram.com/exampleuser/", "display_name_hint", "name", "Example User"), edge_keys)
        self.assertIn(("instagram", "https://www.instagram.com/exampleuser/", "account_id_hint", "account-id", "123456789"), edge_keys)
        self.assertIn(("instagram", "https://www.instagram.com/exampleuser/", "linked_external_url", "url", "https://example.com"), edge_keys)
        self.assertIn(("url", "https://www.instagram.com/exampleuser/", "instagram_url_for", "instagram", "@exampleuser"), edge_keys)

    def test_related_username_metadata_edges(self):
        target = ScanTarget(kind="username", value="bellingcat")
        findings = (
            Finding(
                module="external-adapter-parser",
                source="soxoj/maigret",
                target="bellingcat",
                status="candidate",
                url="https://github.com/bellingcat",
                confidence="high",
                evidence="Maigret GitHub: Claimed",
                metadata={
                    "parser": "maigret",
                    "related_usernames": "bellcat|bcat",
                },
            ),
        )

        entities = merge_entities(entities_from_targets((target,)), entities_from_findings(findings))
        entity_keys = {(entity.kind, entity.value.lower()) for entity in entities}
        self.assertIn(("username", "bellcat"), entity_keys)
        self.assertIn(("username", "bcat"), entity_keys)

        edges = graph_edges_from_case((target,), findings, entities)
        edge_keys = {
            (edge.source_kind, edge.source_value, edge.relation, edge.target_kind, edge.target_value)
            for edge in edges
        }
        self.assertIn(("username", "bellingcat", "related_username", "username", "bellcat"), edge_keys)
        self.assertIn(("username", "bellingcat", "related_username", "username", "bcat"), edge_keys)

    def test_social_profile_metadata_edges(self):
        target = ScanTarget(kind="social", value="vk:exampleuser")
        findings = (
            Finding(
                module="social-public-profile",
                source="vk-profile-url",
                target="vk:exampleuser",
                status="candidate",
                url="https://vk.com/exampleuser",
                confidence="medium",
                evidence="Public VK metadata found.",
                metadata={
                    "platform": "vk",
                    "platform_domain": "vk.com",
                    "social_profile": "vk:exampleuser",
                    "social_username": "exampleuser",
                    "display_name": "Example User",
                    "account_id": "12345",
                    "canonical_url": "https://vk.com/exampleuser",
                },
            ),
        )

        entities = merge_entities(entities_from_targets((target,)), entities_from_findings(findings))
        entity_keys = {(entity.kind, entity.value.lower()) for entity in entities}
        self.assertIn(("social-profile", "vk:exampleuser"), entity_keys)
        self.assertIn(("platform", "vk"), entity_keys)
        self.assertIn(("username", "exampleuser"), entity_keys)
        self.assertIn(("domain", "vk.com"), entity_keys)
        self.assertIn(("name", "example user"), entity_keys)

        edges = graph_edges_from_case((target,), findings, entities)
        edge_keys = {
            (edge.source_kind, edge.source_value, edge.relation, edge.target_kind, edge.target_value)
            for edge in edges
        }
        self.assertIn(("social", "vk:exampleuser", "normalized_social_profile", "social-profile", "vk:exampleuser"), edge_keys)
        self.assertIn(("social", "vk:exampleuser", "profile_username", "username", "exampleuser"), edge_keys)
        self.assertIn(("social", "vk:exampleuser", "platform_domain", "domain", "vk.com"), edge_keys)
        self.assertIn(("social", "vk:exampleuser", "display_name_hint", "name", "Example User"), edge_keys)
        self.assertIn(("url", "https://vk.com/exampleuser", "social_url_for", "social-profile", "vk:exampleuser"), edge_keys)

    def test_yandex_and_mailru_social_url_entities(self):
        findings = (
            Finding(
                module="social-public-profile",
                source="mailru-profile-url",
                target="mailru:exampleuser",
                status="planned",
                url="https://my.mail.ru/mail/exampleuser/",
                confidence="not_checked",
                metadata={"social_profile": "mailru:mail/exampleuser", "platform": "mailru"},
            ),
            Finding(
                module="social-public-profile",
                source="yandex-profile-url",
                target="yandex:q/exampleuser",
                status="planned",
                url="https://yandex.ru/q/profile/exampleuser/",
                confidence="not_checked",
                metadata={"social_profile": "yandex:q/exampleuser", "platform": "yandex"},
            ),
        )
        targets = (
            ScanTarget(kind="social", value="mailru:exampleuser"),
            ScanTarget(kind="social", value="yandex:q/exampleuser"),
        )

        entities = merge_entities(entities_from_targets(targets), entities_from_findings(findings))
        entity_keys = {(entity.kind, entity.value.lower()) for entity in entities}
        self.assertIn(("social-profile", "mailru:mail/exampleuser"), entity_keys)
        self.assertIn(("social-profile", "yandex:q/exampleuser"), entity_keys)

        edges = graph_edges_from_case(targets, findings, entities)
        edge_keys = {
            (edge.source_kind, edge.source_value, edge.relation, edge.target_kind, edge.target_value)
            for edge in edges
        }
        self.assertIn(("url", "https://my.mail.ru/mail/exampleuser/", "social_url_for", "social-profile", "mailru:mail/exampleuser"), edge_keys)
        self.assertIn(("url", "https://yandex.ru/q/profile/exampleuser/", "social_url_for", "social-profile", "yandex:q/exampleuser"), edge_keys)

    def test_page_email_metadata_edges(self):
        target = ScanTarget(kind="domain", value="example.com")
        findings = (
            Finding(
                module="domain-baseline",
                source="page-email-extraction",
                target="example.com",
                status="candidate",
                confidence="medium",
                evidence="Found 2 public email address(es).",
                metadata={"domain": "example.com", "emails": "info@example.com, support@example.com"},
            ),
        )

        entities = merge_entities(entities_from_targets((target,)), entities_from_findings(findings))
        entity_keys = {(entity.kind, entity.value.lower()) for entity in entities}
        self.assertIn(("email", "info@example.com"), entity_keys)
        self.assertIn(("email", "support@example.com"), entity_keys)

        edges = graph_edges_from_case((target,), findings, entities)
        edge_keys = {
            (edge.source_kind, edge.source_value, edge.relation, edge.target_kind, edge.target_value)
            for edge in edges
        }
        self.assertIn(("domain", "example.com", "page_contact_email", "email", "info@example.com"), edge_keys)
        self.assertIn(("domain", "example.com", "page_contact_email", "email", "support@example.com"), edge_keys)

    def test_web_crawl_metadata_edges(self):
        target = ScanTarget(kind="domain", value="example.com")
        findings = (
            Finding(
                module="domain-baseline",
                source="web-crawl",
                target="example.com",
                status="candidate",
                confidence="medium",
                evidence="Crawled 2 page(s).",
                metadata={
                    "domain": "example.com",
                    "discovered_urls": "https://example.com/contact",
                    "external_urls": "https://external.test/profile",
                    "social_urls": "https://vk.com/example",
                    "robots_sitemaps": "https://example.com/sitemap.xml",
                    "robots_disallow_paths": "/private",
                    "sitemap_sources": "https://example.com/sitemap.xml",
                    "sitemap_urls": "https://example.com/contact, https://example.com/about",
                    "emails": "info@example.com",
                    "phones": "+380441234567",
                },
            ),
        )

        entities = merge_entities(entities_from_targets((target,)), entities_from_findings(findings))
        entity_keys = {(entity.kind, entity.value.lower()) for entity in entities}
        self.assertIn(("url", "https://example.com/contact"), entity_keys)
        self.assertIn(("url", "https://external.test/profile"), entity_keys)
        self.assertIn(("url", "https://vk.com/example"), entity_keys)
        self.assertIn(("url", "https://example.com/about"), entity_keys)
        self.assertIn(("web-path", "/private"), entity_keys)
        self.assertIn(("phone", "+380441234567"), entity_keys)
        self.assertIn(("email", "info@example.com"), entity_keys)

        edges = graph_edges_from_case((target,), findings, entities)
        edge_keys = {
            (edge.source_kind, edge.source_value, edge.relation, edge.target_kind, edge.target_value)
            for edge in edges
        }
        self.assertIn(("domain", "example.com", "discovered_url", "url", "https://example.com/contact"), edge_keys)
        self.assertIn(("domain", "example.com", "linked_external_url", "url", "https://external.test/profile"), edge_keys)
        self.assertIn(("domain", "example.com", "linked_social_url", "url", "https://vk.com/example"), edge_keys)
        self.assertIn(("domain", "example.com", "robots_declared_sitemap", "url", "https://example.com/sitemap.xml"), edge_keys)
        self.assertIn(("domain", "example.com", "robots_disallow_path", "web-path", "/private"), edge_keys)
        self.assertIn(("domain", "example.com", "sitemap_url", "url", "https://example.com/about"), edge_keys)
        self.assertIn(("domain", "example.com", "page_contact_phone", "phone", "+380441234567"), edge_keys)


if __name__ == "__main__":
    unittest.main()
