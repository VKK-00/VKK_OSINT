import tempfile
import unittest
from pathlib import Path

from osint_toolkit.case_store import CaseStore
from osint_toolkit.engine import ScanTarget
from osint_toolkit.graph import analyze_case_graph
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


if __name__ == "__main__":
    unittest.main()
