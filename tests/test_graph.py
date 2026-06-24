import tempfile
import unittest
from pathlib import Path

from osint_toolkit.adapter_parsers import parse_adapter_output
from osint_toolkit.case_store import CaseStore
from osint_toolkit.entities import entities_from_findings, entities_from_targets, merge_entities
from osint_toolkit.engine import Finding, ScanTarget
from osint_toolkit.graph import analyze_case_graph, graph_edges_from_case
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
