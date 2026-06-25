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
        self.assertIn("bbot-passive-web", html)
        self.assertIn("python -m osint_toolkit search phone", html)
        self.assertIn("python -m osint_toolkit search email", html)
        self.assertIn("python -m osint_toolkit search image", html)
        self.assertIn("python -m osint_toolkit search person", html)
        self.assertIn("--execute-adapters", html)
        self.assertIn("ready-only", html)
        self.assertIn("Image local execution", html)
        self.assertIn("python -m osint_toolkit tools doctor --profile all-safe", html)
        self.assertIn("python -m osint_toolkit tools install-plan --profile all-safe", html)
        self.assertIn("python -m osint_toolkit tools install all-safe", html)
        self.assertIn("--install-missing", html)
        self.assertIn("exiftool -json -a -u -g1 -ee", html)
        self.assertIn("tesseract", html)
        self.assertIn("zbarimg", html)
        self.assertIn("lens.google.com/upload", html)
        self.assertIn("tineye.com", html)
        self.assertIn("идентификация личности по лицу", html)
        self.assertIn("[[--username {username}]]", html)
        self.assertIn("function commandWithFields", html)
        self.assertIn("Unified Search Runner", html)
        self.assertIn("Case Browser", html)
        self.assertIn("caseGraphSvg", html)
        self.assertIn("renderCaseGraph", html)
        self.assertIn("graphFilters", html)
        self.assertIn("edgeMatchesGraphFilters", html)
        self.assertIn("focusGraphNode", html)
        self.assertIn("clearGraphFilters", html)
        self.assertIn("data-graph-kind", html)
        self.assertIn("scope_note", html)
        self.assertIn("--scope-note", html)
        self.assertIn("/api/search", html)
        self.assertIn("/api/cases", html)
        self.assertIn("/api/cases/${encodeURIComponent(caseId)}/sources", html)
        self.assertIn("/api/case-index", html)
        self.assertIn("/api/case-path", html)
        self.assertIn("/api/case-network", html)
        self.assertIn("/api/cases/${encodeURIComponent(caseId)}/update", html)
        self.assertIn("/api/cases/${encodeURIComponent(caseId)}/delete", html)
        self.assertIn("workflow_filter", html)
        self.assertIn("profile_filter", html)
        self.assertIn("scope_query", html)
        self.assertIn("delete_confirm", html)
        self.assertIn("graph_filter", html)
        self.assertIn("case-update", html)
        self.assertIn("case-delete", html)
        self.assertIn("profile_file", html)
        self.assertIn("custom_profile", html)
        self.assertIn("profile_target_kinds", html)
        self.assertIn("profile_adapter_profiles", html)
        self.assertIn("profile_derived_targets", html)
        self.assertIn("derived_target_kinds", html)
        self.assertIn("/api/profiles", html)
        self.assertIn("/api/profiles/save", html)
        self.assertIn("/api/profiles/delete", html)
        self.assertIn("/api/tools", html)
        self.assertIn("/api/tools/install", html)
        self.assertIn("listProfiles", html)
        self.assertIn("toolsDoctor", html)
        self.assertIn("toolsInstall", html)
        self.assertIn("toolsInstallRun", html)
        self.assertIn("toolsEnv", html)
        self.assertIn("saveProfile", html)
        self.assertIn("deleteProfile", html)
        self.assertIn("loadBackendProfiles", html)
        self.assertIn("loadProfileTools", html)
        self.assertIn("runProfileToolsInstall", html)
        self.assertIn("postBackendJson", html)
        self.assertIn("profileEditorPayload", html)
        self.assertIn("profiles list --profile-file", html)
        self.assertIn("function updateCase", html)
        self.assertIn("function deleteCase", html)
        self.assertIn("showCaseSources", html)
        self.assertIn("case-path", html)
        self.assertIn("case-network", html)
        self.assertIn("showCasePath", html)
        self.assertIn("showCaseNetwork", html)
        self.assertIn("toolbox --serve --open", html)

    def test_rendered_html_can_embed_backend_connection(self):
        html = render_toolbox_html(backend_url="http://127.0.0.1:8765", backend_auth="test-auth")

        self.assertIn('"http://127.0.0.1:8765"', html)
        self.assertIn('"test-auth"', html)
        self.assertIn("X-OSINT-Token", html)

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
