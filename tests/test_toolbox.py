import re
import tempfile
import unittest
from pathlib import Path

from osint_toolkit.toolbox import TOOLBOX_INPUTS, render_toolbox_html, toolbox_sections, write_toolbox


class ToolboxTests(unittest.TestCase):
    def test_toolbox_sections_cover_current_osint_directions(self):
        titles = {section.title for section in toolbox_sections()}

        self.assertIn("Фото / изображение", titles)
        self.assertIn("Лицо / username / соцсети", titles)
        self.assertIn("Email / телефон", titles)
        self.assertIn("Домен / URL / web recon", titles)
        self.assertIn("РФ / Украина", titles)
        self.assertIn("Кейсы / граф / индекс", titles)

    def test_rendered_html_contains_profiles_and_photo_boundary(self):
        html = render_toolbox_html()

        self.assertIn("username-full", html)
        self.assertIn("email-safe", html)
        self.assertIn("domain-recon", html)
        self.assertIn("python -m osint_toolkit search phone", html)
        self.assertIn("python -m osint_toolkit search email", html)
        self.assertIn("python -m osint_toolkit search image", html)
        self.assertIn("python -m osint_toolkit search person", html)
        self.assertIn("--execute-adapters", html)
        self.assertIn("ready-only", html)
        self.assertIn("Image local execution", html)
        self.assertIn("python -m osint_toolkit tools doctor --profile all-safe", html)
        self.assertIn("python -m osint_toolkit tools install-plan --profile all-safe", html)
        self.assertIn("exiftool -a -u -g1 -ee", html)
        self.assertIn("tesseract", html)
        self.assertIn("zbarimg", html)
        self.assertIn("lens.google.com/upload", html)
        self.assertIn("tineye.com", html)
        self.assertIn("идентификацию личности по лицу", html)
        self.assertIn("[[--username {username}]]", html)
        self.assertIn("function commandWithFields", html)

    def test_command_templates_reference_known_inputs(self):
        known_inputs = {field.name for field in TOOLBOX_INPUTS}

        for section in toolbox_sections():
            for command in section.commands:
                placeholders = set(re.findall(r"{([a-z_]+)}", command.command_template))
                mandatory_template = re.sub(r"\[\[[^\]]+\]\]", "", command.command_template)
                mandatory_placeholders = set(re.findall(r"{([a-z_]+)}", mandatory_template))

                self.assertLessEqual(placeholders, known_inputs, command.title)
                self.assertLessEqual(set(command.required_inputs), known_inputs, command.title)
                self.assertLessEqual(
                    mandatory_placeholders,
                    set(command.required_inputs),
                    command.title,
                )

    def test_write_toolbox_creates_html_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "toolbox.html"
            path = write_toolbox(output)

            self.assertEqual(path, output)
            self.assertTrue(output.exists())
            self.assertIn("<!doctype html>", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
