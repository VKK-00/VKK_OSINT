import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_toolkit.image_runner import run_image_search
from osint_toolkit.search import build_search_plan


class ImageRunnerTests(unittest.TestCase):
    def test_image_execution_runs_local_tools_and_routes_derived_seeds(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "photo.jpg"
            image_path.write_bytes(b"not really an image")

            def fake_run(args, **kwargs):
                if "tesseract" in str(args).lower() or "stdout" in args:
                    stdout = "Contact admin@example.com https://example.com @example_user +380441234567"
                elif "--raw" in args:
                    stdout = "https://t.me/example_channel"
                else:
                    stdout = "metadata ok"
                return subprocess.CompletedProcess(args=args, returncode=0, stdout=stdout, stderr="")

            with patch("osint_toolkit.search.shutil.which", return_value="tool"), patch(
                "osint_toolkit.image_runner.shutil.which",
                return_value="tool",
            ), patch("osint_toolkit.image_runner.subprocess.run", side_effect=fake_run):
                plan = build_search_plan("image", str(image_path), profile_name="image-full")
                execution = run_image_search(plan, adapter_limit=0, derived_limit=10)

        target_keys = {(target.kind, target.value.lower()) for target in execution.derived_targets}
        self.assertIn(("email", "admin@example.com"), target_keys)
        self.assertIn(("url", "https://example.com"), target_keys)
        self.assertIn(("username", "example_user"), target_keys)
        self.assertIn(("phone", "+380441234567"), target_keys)
        self.assertIn(("telegram", "https://t.me/example_channel"), target_keys)
        self.assertIn("tesseract-ocr", execution.executed_local_tools)

        entities = {(entity.kind, entity.value.lower()) for entity in execution.investigation.entities}
        self.assertIn(("image", str(image_path).lower()), entities)
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("domain", "example.com"), entities)
        self.assertIn(("username", "example_user"), entities)

        edge_keys = {
            (edge.source_kind, edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in execution.investigation.edges
        }
        self.assertIn(("image", "related_email", "email", "admin@example.com"), edge_keys)
        self.assertIn(("image", "generated_username_candidate", "username", "example_user"), edge_keys)

    def test_image_execution_decodes_binary_tool_output_safely(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "photo.jpg"
            image_path.write_bytes(b"not really an image")

            def fake_run(args, **kwargs):
                return subprocess.CompletedProcess(
                    args=args,
                    returncode=0,
                    stdout=b"\xff\xfeContact binary@example.com",
                    stderr=b"",
                )

            with patch("osint_toolkit.search.shutil.which", return_value="tool"), patch(
                "osint_toolkit.image_runner.shutil.which",
                return_value="tool",
            ), patch("osint_toolkit.image_runner.subprocess.run", side_effect=fake_run):
                plan = build_search_plan("image", str(image_path), profile_name="image-full")
                execution = run_image_search(plan, adapter_limit=0, derived_limit=10)

        target_keys = {(target.kind, target.value.lower()) for target in execution.derived_targets}
        self.assertIn(("email", "binary@example.com"), target_keys)


if __name__ == "__main__":
    unittest.main()
