import unittest

from osint_toolkit.adapters import expand_adapter_repositories, find_adapter_profile, list_adapter_profiles


class AdapterProfileTests(unittest.TestCase):
    def test_list_and_find_adapter_profile(self):
        profiles = {profile.name: profile for profile in list_adapter_profiles()}

        self.assertIn("username-full", profiles)
        self.assertIn("email-safe", profiles)
        self.assertIn("domain-recon", profiles)
        self.assertIn("broad-recon", profiles)
        self.assertEqual(find_adapter_profile("USERNAME-FULL").name, "username-full")
        self.assertIn("sherlock-project/sherlock", profiles["username-full"].repositories)
        self.assertIn("qeeqbox/social-analyzer", profiles["username-full"].repositories)
        self.assertIn("iojw/socialscan", profiles["username-full"].repositories)
        self.assertIn("p1ngul1n0/blackbird", profiles["username-full"].repositories)
        self.assertIn("kaifcodec/user-scanner", profiles["username-full"].repositories)
        self.assertIn("qeeqbox/social-analyzer", profiles["username-ru-ua"].repositories)
        self.assertIn("khast3x/h8mail", profiles["email-safe"].repositories)
        self.assertIn("kaifcodec/user-scanner", profiles["email-safe"].repositories)
        self.assertIn("iojw/socialscan", profiles["email-safe"].repositories)
        self.assertIn("p1ngul1n0/blackbird", profiles["email-safe"].repositories)
        self.assertIn("projectdiscovery/subfinder", profiles["domain-recon"].repositories)
        self.assertIn("projectdiscovery/httpx", profiles["domain-recon"].repositories)
        self.assertIn("laramies/theHarvester", profiles["domain-recon"].repositories)
        self.assertIn("blacklanternsecurity/bbot", profiles["domain-recon"].repositories)
        self.assertIn("smicallef/spiderfoot", profiles["domain-recon"].repositories)
        self.assertIn("bbot-passive-web", profiles)
        self.assertIn("blacklanternsecurity/bbot-passive-web", profiles["bbot-passive-web"].repositories)
        self.assertIn("blacklanternsecurity/bbot", profiles["broad-recon"].repositories)
        self.assertIn("smicallef/spiderfoot", profiles["broad-recon"].repositories)
        self.assertIn("jasonxtn/argus", profiles["broad-recon"].repositories)

    def test_expand_adapter_repositories_dedupes_profiles_and_explicit_adapters(self):
        repositories = expand_adapter_repositories(
            ("username-ru-ua",),
            ("sherlock-project/sherlock", "soxoj/maigret"),
        )

        self.assertEqual(
            repositories,
            (
                "snooppr/snoop",
                "soxoj/maigret",
                "qeeqbox/social-analyzer",
                "sherlock-project/sherlock",
            ),
        )

    def test_expand_adapter_repositories_rejects_unknown_profile(self):
        with self.assertRaises(ValueError):
            expand_adapter_repositories(("unknown-profile",), ())


if __name__ == "__main__":
    unittest.main()
