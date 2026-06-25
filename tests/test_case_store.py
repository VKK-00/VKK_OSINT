import tempfile
import unittest
from pathlib import Path

from osint_toolkit.case_store import CaseStore, CaseStoreError
from osint_toolkit.engine import ScanTarget
from osint_toolkit.investigation import run_investigation


class CaseStoreTests(unittest.TestCase):
    def test_save_list_and_load_case(self):
        result = run_investigation(
            (
                ScanTarget(kind="email", value="person@example.com"),
                ScanTarget(kind="telegram", value="@durov"),
            ),
            title="stored case",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            store = CaseStore(Path(tmpdir) / "cases.sqlite")
            case_id = store.save(
                result,
                case_id="case-1",
                metadata={"workflow": "unit-test", "search_profile": {"name": "email-full"}},
            )
            records = store.list_cases()
            payload = store.load_case(case_id)
            payloads = store.load_cases()

        self.assertEqual(case_id, "case-1")
        self.assertEqual(records[0].case_id, "case-1")
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["case"]["case_id"], "case-1")
        self.assertEqual(records[0].title, "stored case")
        self.assertEqual(records[0].target_count, 2)
        self.assertGreater(records[0].entity_count, 0)
        self.assertGreater(records[0].edge_count, 0)
        self.assertEqual(payload["case"]["title"], "stored case")
        self.assertEqual(payload["metadata"]["workflow"], "unit-test")
        self.assertEqual(payload["metadata"]["search_profile"]["name"], "email-full")

        entities = {(entity["kind"], entity["value"].lower()) for entity in payload["entities"]}
        self.assertIn(("email", "person@example.com"), entities)
        self.assertIn(("domain", "example.com"), entities)
        self.assertIn(("telegram", "@durov"), entities)

        edges = {
            (edge["source_kind"], edge["relation"], edge["target_kind"], edge["target_value"].lower())
            for edge in payload["edges"]
        }
        self.assertIn(("email", "email_domain", "domain", "example.com"), edges)
        self.assertIn(("telegram", "produced_url", "url", "https://t.me/durov"), edges)

    def test_rejects_empty_case_id_and_invalid_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CaseStore(Path(tmpdir) / "cases.sqlite")
            result = run_investigation((ScanTarget(kind="email", value="person@example.com"),))

            with self.assertRaises(CaseStoreError):
                store.save(result, case_id=" ")
            with self.assertRaises(CaseStoreError):
                store.list_cases(limit=0)

    def test_entity_index_and_exact_entity_search(self):
        first = run_investigation(
            (
                ScanTarget(kind="email", value="person@example.com"),
                ScanTarget(kind="telegram", value="@durov"),
            ),
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

            records = store.list_entity_index(kind="domain", min_cases=2)
            hits = store.find_cases_by_entity(kind="domain", value="example.com")

        index = {(record.kind, record.value.lower()): record for record in records}
        self.assertIn(("domain", "example.com"), index)
        self.assertEqual(index[("domain", "example.com")].case_count, 2)
        self.assertEqual(set(index[("domain", "example.com")].cases), {"case-1", "case-2"})

        self.assertEqual({hit.case_id for hit in hits}, {"case-1", "case-2"})
        self.assertEqual({hit.title for hit in hits}, {"first case", "second case"})

    def test_entity_index_rejects_invalid_arguments(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CaseStore(Path(tmpdir) / "cases.sqlite")

            with self.assertRaises(CaseStoreError):
                store.list_entity_index(min_cases=0)
            with self.assertRaises(CaseStoreError):
                store.list_entity_index(limit=0)
            with self.assertRaises(CaseStoreError):
                store.find_cases_by_entity(kind="", value="example.com")
            with self.assertRaises(CaseStoreError):
                store.find_cases_by_entity(kind="domain", value="")


if __name__ == "__main__":
    unittest.main()
