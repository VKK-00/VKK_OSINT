import unittest

from osint_toolkit.catalog import Catalog
from osint_toolkit.workflows import recommend_projects, render_brief


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = Catalog.load()

    def test_loads_full_snapshot(self):
        stats = self.catalog.stats()
        self.assertEqual(stats["total"], 100)
        self.assertEqual(stats["people"], 55)
        self.assertEqual(stats["ru_ua"], 20)
        self.assertEqual(stats["intersection"], 15)

    def test_filters_direct_people_projects(self):
        projects = self.catalog.filter(kind="people", direct_only=True)
        self.assertEqual(len(projects), 32)
        self.assertEqual(projects[0].full_name, "sherlock-project/sherlock")
        self.assertTrue(all(project.people_level == "direct_tool" for project in projects))

    def test_filters_direct_ru_ua_projects(self):
        projects = self.catalog.filter(kind="ru-ua", level="direct_ru_ua")
        self.assertEqual(len(projects), 6)
        self.assertTrue(any(project.full_name == "snooppr/snoop" for project in projects))

    def test_query_search_uses_annotations(self):
        projects = self.catalog.filter(kind="people", query="instagram", limit=5)
        names = {project.full_name for project in projects}
        self.assertIn("Datalux/Osintgram", names)

    def test_recommend_username_prefers_direct_tools(self):
        _, projects = recommend_projects(self.catalog, "username", limit=5)
        names = [project.full_name for project in projects]
        self.assertIn("sherlock-project/sherlock", names)
        self.assertTrue(any(project.people_level == "direct_tool" for project in projects))

    def test_brief_contains_safety_boundaries(self):
        profile, projects = recommend_projects(self.catalog, "phone", limit=3)
        brief = render_brief(profile, projects, target_value="+000000000", region="all")
        self.assertIn("Do not place calls, send messages or trigger recovery flows", brief)
        self.assertIn("Evidence log template", brief)


if __name__ == "__main__":
    unittest.main()

