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
            case_id = store.save(result, case_id="case-1")
            records = store.list_cases()
            payload = store.load_case(case_id)

        self.assertEqual(case_id, "case-1")
        self.assertEqual(records[0].case_id, "case-1")
        self.assertEqual(records[0].title, "stored case")
        self.assertEqual(records[0].target_count, 2)
        self.assertGreater(records[0].entity_count, 0)
        self.assertEqual(payload["case"]["title"], "stored case")

        entities = {(entity["kind"], entity["value"].lower()) for entity in payload["entities"]}
        self.assertIn(("email", "person@example.com"), entities)
        self.assertIn(("domain", "example.com"), entities)
        self.assertIn(("telegram", "@durov"), entities)

    def test_rejects_empty_case_id_and_invalid_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = CaseStore(Path(tmpdir) / "cases.sqlite")
            result = run_investigation((ScanTarget(kind="email", value="person@example.com"),))

            with self.assertRaises(CaseStoreError):
                store.save(result, case_id=" ")
            with self.assertRaises(CaseStoreError):
                store.list_cases(limit=0)


if __name__ == "__main__":
    unittest.main()
