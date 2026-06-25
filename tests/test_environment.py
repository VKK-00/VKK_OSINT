import os
import unittest
from unittest.mock import patch

from osint_toolkit.environment import refresh_runtime_environment, _merge_path_values


class EnvironmentTests(unittest.TestCase):
    def test_merge_path_values_prefers_registry_order_and_dedupes(self):
        merged = _merge_path_values(
            r"C:\Windows;C:\Users\me\go\bin",
            r"C:\Users\me\.local\bin;C:\Windows",
            r"C:\Python\Scripts;C:\Users\me\go\bin",
        )

        self.assertEqual(
            merged.split(os.pathsep),
            [
                r"C:\Windows",
                r"C:\Users\me\go\bin",
                r"C:\Users\me\.local\bin",
                r"C:\Python\Scripts",
            ],
        )

    def test_refresh_runtime_environment_reads_windows_user_values(self):
        registry = {
            ("machine", "Path"): r"C:\Windows",
            ("user", "Path"): r"C:\Users\me\.local\bin",
            ("user", "BLACKBIRD_DIR"): r"C:\tools\blackbird",
        }

        def fake_registry(scope, name):
            return registry.get((scope, name), "")

        with patch("osint_toolkit.environment.os.name", "nt"), patch.dict(
            os.environ,
            {"PATH": r"C:\Python\Scripts"},
            clear=True,
        ), patch("osint_toolkit.environment._read_windows_registry_env", side_effect=fake_registry):
            applied = refresh_runtime_environment(keys=("BLACKBIRD_DIR",))

            self.assertEqual(applied, ("PATH", "BLACKBIRD_DIR"))
            self.assertEqual(os.environ["BLACKBIRD_DIR"], r"C:\tools\blackbird")
            self.assertEqual(
                os.environ["PATH"].split(os.pathsep),
                [r"C:\Windows", r"C:\Users\me\.local\bin", r"C:\Python\Scripts"],
            )

    def test_refresh_runtime_environment_does_not_overwrite_explicit_env(self):
        def fake_registry(scope, name):
            if name == "SOCIAL_ANALYZER_APP_JS":
                return r"C:\registry\app.js"
            return ""

        with patch("osint_toolkit.environment.os.name", "nt"), patch.dict(
            os.environ,
            {"PATH": "", "SOCIAL_ANALYZER_APP_JS": r"C:\explicit\app.js"},
            clear=True,
        ), patch("osint_toolkit.environment._read_windows_registry_env", side_effect=fake_registry):
            applied = refresh_runtime_environment(keys=("SOCIAL_ANALYZER_APP_JS",), refresh_path=False)

            self.assertEqual(applied, ())
            self.assertEqual(os.environ["SOCIAL_ANALYZER_APP_JS"], r"C:\explicit\app.js")


if __name__ == "__main__":
    unittest.main()
