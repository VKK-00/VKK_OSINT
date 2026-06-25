import unittest

from osint_toolkit.engine import ScanTarget
from osint_toolkit.search import (
    PlannedStep,
    SearchPlan,
    build_search_plan,
    classify_target,
    find_search_profile,
    ready_adapter_repositories,
)


class SearchPlanTests(unittest.TestCase):
    def test_classify_target_detects_common_seed_types(self):
        cases = {
            "+380441234567": "phone",
            "person@example.com": "email",
            "example.com": "domain",
            "https://example.com/profile": "url",
            "https://vk.com/example": "social",
            r"C:\evidence\photo.jpg": "image",
            "Ivan Petrenko": "person",
            "example_user": "username",
        }

        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(classify_target(value), expected)

    def test_phone_full_plan_includes_phone_services_and_excludes_restricted_default(self):
        plan = build_search_plan("phone", "+380441234567", profile_name="phone-full")
        sources = {step.source: step for step in plan.steps}

        self.assertIn("scan phone", sources)
        self.assertIn("sundowndev/phoneinfoga", sources)
        self.assertIn("smicallef/spiderfoot", sources)
        self.assertIn("jasonxtn/argus", sources)
        self.assertIn("Yvesssn/DetectDee", sources)
        self.assertEqual(sources["megadose/ignorant"].status, "excluded")

    def test_include_restricted_marks_phone_restricted_adapter(self):
        plan = build_search_plan(
            "phone",
            "+380441234567",
            profile_name="phone-full",
            include_restricted=True,
        )
        sources = {step.source: step for step in plan.steps}

        self.assertEqual(sources["megadose/ignorant"].status, "restricted")
        self.assertIn("Restricted adapters are included", " ".join(plan.warnings))

    def test_email_full_plan_includes_safe_email_services(self):
        plan = build_search_plan("email", "person@example.com", profile_name="email-full")
        sources = {step.source: step for step in plan.steps}

        self.assertIn("scan email", sources)
        self.assertIn("alpkeskin/mosint", sources)
        self.assertIn("khast3x/h8mail", sources)
        self.assertIn("thewhiteh4t/pwnedOrNot", sources)
        self.assertIn("kaifcodec/user-scanner", sources)
        self.assertIn("p1ngul1n0/blackbird", sources)
        self.assertEqual(sources["megadose/holehe"].status, "excluded")
        self.assertEqual(sources["martinvigo/email2phonenumber"].status, "excluded")

    def test_image_full_plan_includes_local_image_tools_and_face_id_warning(self):
        plan = build_search_plan("image", r"C:\evidence\photo.jpg", profile_name="image-full")
        sources = {step.source: step for step in plan.steps}

        self.assertIn("powershell-file-baseline", sources)
        self.assertIn("exiftool", sources)
        self.assertIn("imagemagick-identify", sources)
        self.assertIn("tesseract-ocr", sources)
        self.assertIn("zbarimg", sources)
        self.assertIn("face recognition", " ".join(plan.warnings))

    def test_profile_must_support_target_kind(self):
        with self.assertRaises(ValueError):
            build_search_plan("phone", "+380441234567", profile_name="email-full")

    def test_auto_profile_selects_target_default_profile(self):
        plan = build_search_plan("auto", "person@example.com", profile_name="auto")

        self.assertEqual(plan.target.kind, "email")
        self.assertEqual(plan.profile.name, "email-full")

    def test_person_full_plan_includes_derived_username_adapter_routes(self):
        plan = build_search_plan("person", "Ivan Petrenko", profile_name="person-full")
        sources = {step.source: step for step in plan.steps}

        self.assertIn("scan person", sources)
        self.assertIn("scan username", sources)
        self.assertIn("sherlock-project/sherlock", sources)
        self.assertEqual(sources["sherlock-project/sherlock"].target_kind, "username")
        self.assertEqual(sources["sherlock-project/sherlock"].target_value, "<derived usernames>")

    def test_ready_adapter_repositories_only_returns_ready_non_restricted_steps(self):
        plan = SearchPlan(
            target=ScanTarget(kind="username", value="example_user"),
            profile=find_search_profile("username-full"),
            steps=(
                PlannedStep(
                    stage="adapter",
                    source="ready/repo",
                    title="ready",
                    target_kind="username",
                    target_value="example_user",
                    status="ready",
                    readiness="ready",
                    metadata={"adapter_status": "planned"},
                ),
                PlannedStep(
                    stage="adapter",
                    source="restricted/repo",
                    title="restricted",
                    target_kind="username",
                    target_value="example_user",
                    status="ready",
                    readiness="ready",
                    metadata={"adapter_status": "restricted"},
                ),
                PlannedStep(
                    stage="adapter",
                    source="missing/repo",
                    title="missing",
                    target_kind="username",
                    target_value="example_user",
                    status="missing",
                    readiness="missing",
                    metadata={"adapter_status": "planned"},
                ),
                PlannedStep(
                    stage="adapter",
                    source="ready/repo",
                    title="duplicate",
                    target_kind="username",
                    target_value="example_user",
                    status="ready",
                    readiness="ready",
                    metadata={"adapter_status": "planned"},
                ),
                PlannedStep(
                    stage="native",
                    source="scan username",
                    title="native",
                    target_kind="username",
                    target_value="example_user",
                    status="planned",
                    readiness="built_in",
                ),
            ),
        )

        self.assertEqual(ready_adapter_repositories(plan), ("ready/repo",))


if __name__ == "__main__":
    unittest.main()
