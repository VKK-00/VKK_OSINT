import io
import socket
import unittest
import urllib.error
from unittest.mock import patch

from osint_toolkit.adapters import filter_adapters
from osint_toolkit.adapter_runner import run_adapter, run_adapter_findings
from osint_toolkit.dns_lookup import DnsLookupResult
from osint_toolkit.doctor import inspect_adapters
from osint_toolkit.engine import Engine, RunConfig, ScanTarget
from osint_toolkit.http_client import HttpClient, HttpResult
from osint_toolkit.investigation import render_investigation_json, render_investigation_markdown, run_investigation
from osint_toolkit.modules import DomainScanModule, EmailScanModule, PersonNameScanModule, PhoneScanModule, UsernameScanModule, WebMetadataModule
from osint_toolkit.modules.domain import normalize_domain, parse_crtsh_subdomains, parse_rdap_domain_record
from osint_toolkit.modules.person import generate_username_candidates, normalize_person_name
from osint_toolkit.modules.phone import detect_country, is_e164_like, normalize_phone
from osint_toolkit.modules.ru_ua_sources import RuUaSourcePackModule
from osint_toolkit.modules.telegram import TelegramScanModule, normalize_telegram_target
from osint_toolkit.modules.username import classify_username_http_result, normalize_username
from osint_toolkit.sites import (
    MAIGRET_IMPORTED_SITE_COUNT,
    SHERLOCK_IMPORTED_SITE_COUNT,
    USERNAME_SITES,
    WHATSMYNAME_IMPORTED_SITE_COUNT,
    UsernameSite,
)


class _FakeHttpResponse:
    def __init__(
        self,
        *,
        url: str = "https://example.com",
        status_code: int = 200,
        body: bytes = b"",
        content_type: str = "text/html",
    ):
        self._url = url
        self._status_code = status_code
        self._body = body
        self.headers = {"content-type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, limit: int) -> bytes:
        return self._body[:limit]

    def geturl(self) -> str:
        return self._url

    def getcode(self) -> int:
        return self._status_code


class _FakeDomainHttpClient:
    def __init__(self, results: tuple[HttpResult, ...]):
        self.results = list(results)
        self.requests: list[tuple[str, bool, dict[str, str] | None]] = []

    def check(self, url, *, fetch_title=False, headers=None, method="GET", body=""):
        self.requests.append((url, fetch_title, headers))
        return self.results.pop(0)


class EngineTests(unittest.TestCase):
    def test_username_scan_dry_run_returns_planned_profile_urls(self):
        engine = Engine([UsernameScanModule()])
        findings = engine.scan(ScanTarget(kind="username", value="example-user"), RunConfig(limit=3))

        self.assertEqual(len(findings), 3)
        self.assertTrue(all(finding.status == "planned" for finding in findings))
        self.assertEqual(findings[0].source, "GitHub")
        self.assertEqual(findings[0].url, "https://github.com/example-user")

    def test_username_scan_applies_platform_rules(self):
        engine = Engine([UsernameScanModule()])
        findings = engine.scan(ScanTarget(kind="username", value="example_user"), RunConfig(limit=3))

        self.assertEqual(findings[0].source, "GitHub")
        self.assertEqual(findings[0].status, "skipped")
        self.assertEqual(findings[0].metadata["rule_status"], "skipped")
        self.assertIn("GitHub username rule", findings[0].evidence)
        self.assertEqual(findings[1].status, "planned")

    def test_username_scan_normalizes_at_prefix(self):
        engine = Engine([UsernameScanModule()])
        findings = engine.scan(ScanTarget(kind="username", value="@durov"), RunConfig(limit=1))

        self.assertEqual(normalize_username("@durov"), "durov")
        self.assertEqual(findings[0].url, "https://github.com/durov")
        self.assertEqual(findings[0].metadata["normalized_username"], "durov")

    def test_username_site_dataset_includes_extra_social_and_dev_sources(self):
        engine = Engine([UsernameScanModule()])
        findings = engine.scan(ScanTarget(kind="username", value="exampleuser"), RunConfig())
        sources = {finding.source for finding in findings}

        self.assertIn("NPM", sources)
        self.assertIn("Docker Hub", sources)
        self.assertIn("Linktree", sources)
        self.assertIn("Threads", sources)

    def test_username_site_dataset_imports_sherlock_resource(self):
        sources = {site.name for site in USERNAME_SITES}
        imported_1337x = next(site for site in USERNAME_SITES if site.name == "1337x")
        anilist = next(site for site in USERNAME_SITES if site.name == "Anilist")
        avizo = next(site for site in USERNAME_SITES if site.name == "Avizo")
        wordpress = next(site for site in USERNAME_SITES if site.name == "WordPress")

        self.assertGreaterEqual(SHERLOCK_IMPORTED_SITE_COUNT, 450)
        self.assertGreaterEqual(len(USERNAME_SITES), 450)
        self.assertIn("Archive of Our Own", sources)
        self.assertEqual(imported_1337x.url_template, "https://www.1337x.to/user/{username}/")
        self.assertEqual(imported_1337x.source_projects, ("sherlock",))
        self.assertIn("<head><title>404 Not Found</title></head>", imported_1337x.not_found_markers)
        self.assertEqual(anilist.request_method, "POST")
        self.assertEqual(anilist.url_template, "https://graphql.anilist.co/")
        self.assertEqual(anilist.profile_url_template, "https://anilist.co/user/{username}/")
        self.assertIn('"variables":{"name":"{username}"}', anilist.request_body_template)
        self.assertEqual(avizo.not_found_url_template, "https://www.avizo.cz/")
        self.assertEqual(wordpress.not_found_url_template, "wordpress.com/typo/?subdomain=")

    def test_curated_username_sites_take_precedence_over_sherlock_duplicates(self):
        github = next(site for site in USERNAME_SITES if site.name == "GitHub")

        self.assertEqual(github.url_template, "https://github.com/{username}")
        self.assertEqual(github.source_projects, ("sherlock", "maigret", "whatsmyname"))

    def test_username_site_dataset_imports_whatsmyname_resource(self):
        names = {site.name for site in USERNAME_SITES}
        gitlab_api = next(site for site in USERNAME_SITES if site.name == "GitLab (WhatsMyName)")
        ctf = next(site for site in USERNAME_SITES if site.name == "247CTF")
        anilist = next(site for site in USERNAME_SITES if site.name == "AniList (WhatsMyName)")

        self.assertGreaterEqual(WHATSMYNAME_IMPORTED_SITE_COUNT, 700)
        self.assertGreaterEqual(len(USERNAME_SITES), 1000)
        self.assertIn("Reddit (WhatsMyName)", names)
        self.assertEqual(gitlab_api.url_template, "https://gitlab.com/api/v4/users?username={username}")
        self.assertEqual(gitlab_api.profile_url_template, "https://gitlab.com/{username}")
        self.assertEqual(gitlab_api.profile_markers, ('"id":',))
        self.assertEqual(gitlab_api.not_found_markers, ("[]",))
        self.assertEqual(gitlab_api.candidate_status_codes, (200,))
        self.assertEqual(gitlab_api.not_found_status_codes, (200,))
        self.assertEqual(ctf.source_projects, ("whatsmyname",))
        self.assertEqual(ctf.not_found_status_codes, (302,))
        self.assertEqual(anilist.request_method, "POST")
        self.assertEqual(anilist.url_template, "https://graphql.anilist.co")
        self.assertIn('{User(name:\\"{username}\\")', anilist.request_body_template)
        self.assertEqual(anilist.profile_url_template, "https://anilist.co/user/{username}")

    def test_username_site_dataset_imports_maigret_resource(self):
        instagram_api = next(site for site in USERNAME_SITES if site.name == "Instagram (Maigret)")
        aback = next(site for site in USERNAME_SITES if site.name == "Aback")

        self.assertGreaterEqual(MAIGRET_IMPORTED_SITE_COUNT, 1400)
        self.assertGreaterEqual(len(USERNAME_SITES), 1900)
        self.assertEqual(instagram_api.url_template, "https://www.instagram.com/api/v1/users/web_profile_info/?username={username}")
        self.assertEqual(instagram_api.profile_url_template, "https://www.instagram.com/{username}/")
        self.assertEqual(instagram_api.profile_markers, ('"biography"',))
        self.assertEqual(instagram_api.source_projects, ("maigret",))
        self.assertIn(("x-ig-app-id", "936619743392459"), instagram_api.request_headers)
        self.assertEqual(aback.region, "ua")

    def test_username_scan_region_ua_includes_maigret_ua_sources(self):
        engine = Engine([UsernameScanModule()])
        findings = engine.scan(ScanTarget(kind="username", value="exampleuser", region="ua"), RunConfig())
        sources = {finding.source for finding in findings}

        self.assertIn("Aback", sources)
        self.assertIn("GitHub", sources)

    def test_username_scan_exposes_probe_profile_url_metadata(self):
        site = next(site for site in USERNAME_SITES if site.name == "Instagram (Maigret)")
        findings = Engine([UsernameScanModule(sites=(site,))]).scan(
            ScanTarget(kind="username", value="exampleuser"),
            RunConfig(),
        )

        self.assertEqual(findings[0].url, "https://www.instagram.com/api/v1/users/web_profile_info/?username=exampleuser")
        self.assertEqual(findings[0].metadata["profile_url"], "https://www.instagram.com/exampleuser/")

    def test_username_live_classifier_uses_not_found_marker(self):
        site = UsernameSite(
            "Example",
            "https://example.com/{username}",
            not_found_markers=("No user named {username}",),
        )
        classification = classify_username_http_result(
            site,
            "missinguser",
            HttpResult(
                url="https://example.com/missinguser",
                final_url="https://example.com/missinguser",
                status_code=200,
                title="Profile",
                body_text="No user named missinguser was found.",
            ),
        )

        self.assertEqual(classification.status, "not_found")
        self.assertEqual(classification.confidence, "high")
        self.assertEqual(classification.content_rule, "not_found_marker")

    def test_username_live_scan_passes_site_specific_headers(self):
        site = UsernameSite(
            "Example",
            "https://example.com/{username}",
            request_headers=(("User-Agent", "WhatsMyName-Test"),),
        )
        with patch("osint_toolkit.modules.username.HttpClient.check") as check:
            check.return_value = HttpResult(
                url="https://example.com/realuser",
                final_url="https://example.com/realuser",
                status_code=200,
            )
            findings = Engine([UsernameScanModule(sites=(site,))]).scan(
                ScanTarget(kind="username", value="realuser"),
                RunConfig(live=True),
            )

        check.assert_called_once_with(
            "https://example.com/realuser",
            fetch_title=True,
            headers={"User-Agent": "WhatsMyName-Test"},
            method="GET",
            body="",
        )
        self.assertEqual(findings[0].metadata["custom_headers"], "yes")

    def test_username_live_scan_passes_post_body(self):
        site = UsernameSite(
            "Example",
            "https://example.com/graphql",
            profile_url_template="https://example.com/user/{username}",
            request_method="POST",
            request_body_template='{"username":"{username}","query":"query{literal}"}',
            request_headers=(("Content-Type", "application/json"),),
        )
        with patch("osint_toolkit.modules.username.HttpClient.check") as check:
            check.return_value = HttpResult(
                url="https://example.com/graphql",
                final_url="https://example.com/graphql",
                status_code=200,
            )
            findings = Engine([UsernameScanModule(sites=(site,))]).scan(
                ScanTarget(kind="username", value="realuser"),
                RunConfig(live=True),
            )

        check.assert_called_once_with(
            "https://example.com/graphql",
            fetch_title=True,
            headers={"Content-Type": "application/json"},
            method="POST",
            body='{"username":"realuser","query":"query{literal}"}',
        )
        self.assertEqual(findings[0].metadata["request_method"], "POST")
        self.assertEqual(findings[0].metadata["profile_url"], "https://example.com/user/realuser")

    def test_username_live_scan_sets_json_content_type_for_post_body(self):
        site = UsernameSite(
            "Example",
            "https://example.com/graphql",
            request_method="POST",
            request_body_template='{"username":"{username}"}',
        )
        with patch("osint_toolkit.modules.username.HttpClient.check") as check:
            check.return_value = HttpResult(
                url="https://example.com/graphql",
                final_url="https://example.com/graphql",
                status_code=200,
            )
            findings = Engine([UsernameScanModule(sites=(site,))]).scan(
                ScanTarget(kind="username", value="realuser"),
                RunConfig(live=True),
            )

        check.assert_called_once_with(
            "https://example.com/graphql",
            fetch_title=True,
            headers={"Content-Type": "application/json"},
            method="POST",
            body='{"username":"realuser"}',
        )
        self.assertEqual(findings[0].metadata["custom_headers"], "yes")

    def test_username_live_scan_delays_between_http_requests(self):
        sites = (
            UsernameSite("One", "https://one.example/{username}"),
            UsernameSite("Two", "https://two.example/{username}"),
        )
        with patch("osint_toolkit.modules.username.HttpClient.check") as check, patch(
            "osint_toolkit.modules.username.time.sleep"
        ) as sleep:
            check.return_value = HttpResult(
                url="https://example.com/realuser",
                final_url="https://example.com/realuser",
                status_code=200,
                attempts=2,
            )
            findings = Engine([UsernameScanModule(sites=sites)]).scan(
                ScanTarget(kind="username", value="realuser"),
                RunConfig(live=True, request_delay=0.25, http_retries=3, http_backoff=0.5),
            )

        sleep.assert_called_once_with(0.25)
        self.assertEqual(check.call_count, 2)
        self.assertEqual(findings[0].metadata["http_attempts"], "2")
        self.assertEqual(findings[0].metadata["http_retries"], "3")
        self.assertEqual(findings[0].metadata["http_backoff_seconds"], "0.5")
        self.assertEqual(findings[0].metadata["request_delay_seconds"], "0.25")

    def test_http_client_retries_rate_limited_post_with_retry_after(self):
        http_error = urllib.error.HTTPError(
            "https://example.com/api",
            429,
            "Too Many Requests",
            {"Retry-After": "2"},
            io.BytesIO(b"rate limited"),
        )
        response = _FakeHttpResponse(
            url="https://example.com/api",
            status_code=200,
            body=b'{"ok": true}',
            content_type="application/json",
        )

        with patch("osint_toolkit.http_client.urllib.request.urlopen", side_effect=[http_error, response]) as urlopen, patch(
            "osint_toolkit.http_client.time.sleep"
        ) as sleep:
            result = HttpClient(retries=1, backoff_seconds=0.1).check(
                "https://example.com/api",
                method="POST",
                body="{}",
            )

        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(2.0)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.attempts, 2)

    def test_username_live_classifier_handles_literal_braces_in_marker(self):
        site = UsernameSite(
            "Example",
            "https://example.com/{username}",
            not_found_markers=('{"users":[]}',),
        )
        classification = classify_username_http_result(
            site,
            "missinguser",
            HttpResult(
                url="https://example.com/missinguser",
                final_url="https://example.com/missinguser",
                status_code=200,
                title="Profile",
                body_text='{"users":[]}',
            ),
        )

        self.assertEqual(classification.status, "not_found")
        self.assertEqual(classification.confidence, "high")
        self.assertEqual(classification.content_rule, "not_found_marker")

    def test_username_live_classifier_uses_site_specific_not_found_status(self):
        site = UsernameSite(
            "Example",
            "https://example.com/{username}",
            not_found_status_codes=(302,),
        )
        classification = classify_username_http_result(
            site,
            "missinguser",
            HttpResult(
                url="https://example.com/missinguser",
                final_url="https://example.com/login",
                status_code=302,
            ),
        )

        self.assertEqual(classification.status, "not_found")
        self.assertEqual(classification.confidence, "high")
        self.assertEqual(classification.content_rule, "not_found_status")

    def test_username_live_classifier_uses_response_url_not_found_rule(self):
        site = UsernameSite(
            "Example",
            "https://example.com/{username}",
            not_found_url_template="https://example.com/not-found/{username}",
        )
        classification = classify_username_http_result(
            site,
            "missinguser",
            HttpResult(
                url="https://example.com/missinguser",
                final_url="https://example.com/not-found/missinguser/",
                status_code=200,
            ),
        )

        self.assertEqual(classification.status, "not_found")
        self.assertEqual(classification.confidence, "high")
        self.assertEqual(classification.content_rule, "response_url")

    def test_username_live_classifier_matches_scheme_less_response_url_prefix(self):
        site = UsernameSite(
            "Example",
            "https://{username}.example.com/",
            not_found_url_template="example.com/typo/?subdomain=",
        )
        classification = classify_username_http_result(
            site,
            "missinguser",
            HttpResult(
                url="https://missinguser.example.com/",
                final_url="https://example.com/typo/?subdomain=missinguser",
                status_code=200,
            ),
        )

        self.assertEqual(classification.status, "not_found")
        self.assertEqual(classification.confidence, "high")
        self.assertEqual(classification.content_rule, "response_url")

    def test_username_live_classifier_does_not_use_ambiguous_200_missing_status_without_marker(self):
        site = UsernameSite(
            "Example",
            "https://example.com/{username}",
            not_found_markers=("not found",),
            not_found_status_codes=(200,),
        )
        classification = classify_username_http_result(
            site,
            "maybeuser",
            HttpResult(
                url="https://example.com/maybeuser",
                final_url="https://example.com/maybeuser",
                status_code=200,
                title="Generic",
                body_text="Generic page",
            ),
        )

        self.assertEqual(classification.status, "candidate")
        self.assertEqual(classification.confidence, "medium")
        self.assertEqual(classification.content_rule, "unmatched")

    def test_username_live_classifier_uses_profile_marker(self):
        site = UsernameSite(
            "Example",
            "https://example.com/{username}",
            profile_markers=("profile-owner:{username}",),
        )
        classification = classify_username_http_result(
            site,
            "realuser",
            HttpResult(
                url="https://example.com/realuser",
                final_url="https://example.com/realuser",
                status_code=200,
                title="Real User",
                body_text="<main>profile-owner:realuser</main>",
            ),
        )

        self.assertEqual(classification.status, "candidate")
        self.assertEqual(classification.confidence, "high")
        self.assertEqual(classification.content_rule, "profile_marker")

    def test_username_live_classifier_keeps_status_without_content_marker(self):
        site = UsernameSite("Example", "https://example.com/{username}")
        classification = classify_username_http_result(
            site,
            "maybeuser",
            HttpResult(
                url="https://example.com/maybeuser",
                final_url="https://example.com/maybeuser",
                status_code=200,
                title="Maybe",
                body_text="<main>generic page</main>",
            ),
        )

        self.assertEqual(classification.status, "candidate")
        self.assertEqual(classification.confidence, "medium")
        self.assertEqual(classification.content_rule, "unmatched")

    def test_username_scan_region_ru_includes_ru_sources(self):
        engine = Engine([UsernameScanModule()])
        findings = engine.scan(ScanTarget(kind="username", value="durov", region="ru"), RunConfig())
        sources = {finding.source for finding in findings}

        self.assertIn("VK", sources)
        self.assertIn("OK.ru", sources)
        self.assertIn("GitHub", sources)

    def test_person_scan_generates_username_candidates_from_ru_ua_name(self):
        engine = Engine([PersonNameScanModule()])
        findings = engine.scan(ScanTarget(kind="person", value="Іван Петренко"), RunConfig(limit=16))
        usernames = [finding.metadata["username"] for finding in findings]
        strategies = {finding.metadata["strategy"] for finding in findings}

        self.assertEqual(findings[0].metadata["normalized_name"], "ivan petrenko")
        self.assertIn("ivanpetrenko", usernames)
        self.assertIn("ivan.petrenko", usernames)
        self.assertIn("vanyapetrenko", usernames)
        self.assertIn("alias_last_joined", strategies)
        self.assertTrue(all(finding.status == "candidate" for finding in findings))

    def test_person_name_helpers_generate_stable_variants(self):
        self.assertEqual(normalize_person_name("Олена Іваненко"), "olena ivanenko")
        candidates = generate_username_candidates("olena ivanenko")
        usernames = [candidate.username for candidate in candidates]
        strategies = {candidate.strategy for candidate in candidates}

        self.assertEqual(usernames[:4], ["olena", "olenaivanenko", "olena.ivanenko", "olena_ivanenko"])
        self.assertIn("elenaivanenko", usernames)
        self.assertIn("lena.ivanenko", usernames)
        self.assertIn("olenaivanenkoofficial", usernames)
        self.assertIn("handle_suffix", strategies)

    def test_person_name_helpers_include_operator_aliases(self):
        candidates = generate_username_candidates(
            "volodymyr zelenskyy",
            extra_aliases=("@ze-team", "служу народу"),
        )
        by_username = {candidate.username: candidate.strategy for candidate in candidates}

        self.assertEqual(by_username["ze-team"], "operator_alias")
        self.assertEqual(by_username["zeteamzelenskyy"], "operator_alias_last_joined")
        self.assertEqual(by_username["sluzhunarodu"], "operator_alias")
        self.assertEqual(by_username["sluzhunarodu.zelenskyy"], "operator_alias_dot_last")

    def test_person_scan_uses_operator_aliases_from_run_config(self):
        engine = Engine([PersonNameScanModule()])
        findings = engine.scan(
            ScanTarget(kind="person", value="Volodymyr Zelenskyy"),
            RunConfig(person_aliases=("ze-team",), limit=16),
        )
        by_username = {finding.metadata["username"]: finding.metadata["strategy"] for finding in findings}

        self.assertEqual(by_username["ze-team"], "operator_alias")
        self.assertEqual(by_username["zeteamzelenskyy"], "operator_alias_last_joined")

    def test_url_scan_dry_run_normalizes_scheme(self):
        engine = Engine([WebMetadataModule()])
        findings = engine.scan(ScanTarget(kind="url", value="example.com"), RunConfig())

        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0].status, "planned")
        self.assertEqual(findings[0].url, "https://example.com")
        self.assertEqual(findings[1].source, "page-email-extraction")
        self.assertEqual(findings[2].source, "web-crawl")

    def test_url_scan_live_extracts_public_emails(self):
        response = _FakeHttpResponse(
            url="https://example.com/contact",
            status_code=200,
            body=b"<html><title>Contact</title><a href='mailto:info@example.com'>Email</a></html>",
        )

        with patch("osint_toolkit.http_client.urllib.request.urlopen", return_value=response):
            findings = Engine([WebMetadataModule()]).scan(
                ScanTarget(kind="url", value="example.com/contact"),
                RunConfig(live=True),
            )

        sources = {finding.source: finding for finding in findings}
        self.assertEqual(sources["page-email-extraction"].status, "candidate")
        self.assertEqual(sources["page-email-extraction"].metadata["emails"], "info@example.com")
        self.assertEqual(sources["page-email-extraction"].metadata["email_count"], "1")
        self.assertEqual(sources["web-crawl"].metadata["email_count"], "1")

    def test_url_scan_live_crawls_same_site_links(self):
        fake_client = _FakeDomainHttpClient(
            (
                HttpResult(
                    url="https://example.com",
                    final_url="https://example.com",
                    status_code=200,
                    title="Home",
                    body_text=(
                        "<html><title>Home</title><a href='/about'>About</a>"
                        "<a href='https://github.com/example'>GitHub</a>"
                        "info@example.com +380 44 123 45 67</html>"
                    ),
                    content_type="text/html",
                ),
                HttpResult(
                    url="https://example.com/robots.txt",
                    final_url="https://example.com/robots.txt",
                    status_code=404,
                ),
                HttpResult(
                    url="https://example.com/sitemap.xml",
                    final_url="https://example.com/sitemap.xml",
                    status_code=404,
                ),
                HttpResult(
                    url="https://example.com/about",
                    final_url="https://example.com/about",
                    status_code=200,
                    title="About",
                    body_text="<html><title>About</title>team@example.com</html>",
                    content_type="text/html",
                ),
            )
        )

        with patch("osint_toolkit.modules.web.HttpClient", return_value=fake_client):
            findings = Engine([WebMetadataModule()]).scan(
                ScanTarget(kind="url", value="example.com"),
                RunConfig(live=True, crawl_pages=3, crawl_depth=1),
            )

        crawl = {finding.source: finding for finding in findings}["web-crawl"]
        self.assertEqual(crawl.status, "candidate")
        self.assertEqual(crawl.metadata["pages_fetched"], "2")
        self.assertEqual(crawl.metadata["emails"], "info@example.com, team@example.com")
        self.assertEqual(crawl.metadata["phones"], "+380441234567")
        self.assertEqual(crawl.metadata["discovered_urls"], "https://example.com/about")
        self.assertEqual(crawl.metadata["social_urls"], "https://github.com/example")

    def test_url_scan_live_uses_robots_and_sitemap_discovery(self):
        fake_client = _FakeDomainHttpClient(
            (
                HttpResult(
                    url="https://example.com",
                    final_url="https://example.com",
                    status_code=200,
                    title="Home",
                    body_text="<html><title>Home</title></html>",
                    content_type="text/html",
                ),
                HttpResult(
                    url="https://example.com/robots.txt",
                    final_url="https://example.com/robots.txt",
                    status_code=200,
                    body_text=(
                        "User-agent: *\n"
                        "Disallow: /private\n"
                        "Sitemap: https://example.com/main-sitemap.xml\n"
                    ),
                    content_type="text/plain",
                ),
                HttpResult(
                    url="https://example.com/main-sitemap.xml",
                    final_url="https://example.com/main-sitemap.xml",
                    status_code=200,
                    body_text=(
                        "<urlset>"
                        "<url><loc>https://example.com/contact</loc></url>"
                        "<url><loc>https://example.com/private</loc></url>"
                        "<url><loc>https://external.test/out</loc></url>"
                        "</urlset>"
                    ),
                    content_type="application/xml",
                ),
                HttpResult(
                    url="https://example.com/sitemap.xml",
                    final_url="https://example.com/sitemap.xml",
                    status_code=404,
                ),
                HttpResult(
                    url="https://example.com/contact",
                    final_url="https://example.com/contact",
                    status_code=200,
                    title="Contact",
                    body_text="info@example.com",
                    content_type="text/html",
                ),
            )
        )

        with patch("osint_toolkit.modules.web.HttpClient", return_value=fake_client):
            findings = Engine([WebMetadataModule()]).scan(
                ScanTarget(kind="url", value="example.com"),
                RunConfig(live=True, crawl_pages=2, crawl_depth=1),
            )

        crawl = {finding.source: finding for finding in findings}["web-crawl"]
        self.assertEqual(crawl.metadata["robots_url"], "https://example.com/robots.txt")
        self.assertEqual(crawl.metadata["robots_status"], "200")
        self.assertEqual(crawl.metadata["robots_sitemaps"], "https://example.com/main-sitemap.xml")
        self.assertEqual(crawl.metadata["robots_disallow_paths"], "/private")
        self.assertEqual(crawl.metadata["sitemap_sources"], "https://example.com/main-sitemap.xml")
        self.assertEqual(crawl.metadata["sitemap_url_count"], "2")
        self.assertEqual(crawl.metadata["sitemap_urls"], "https://example.com/contact, https://example.com/private")
        self.assertEqual(crawl.metadata["pages_fetched"], "2")
        self.assertEqual(crawl.metadata["emails"], "info@example.com")
        self.assertEqual(fake_client.requests[1][0], "https://example.com/robots.txt")
        self.assertEqual(fake_client.requests[2][0], "https://example.com/main-sitemap.xml")
        self.assertEqual(fake_client.requests[3][0], "https://example.com/sitemap.xml")

    def test_domain_scan_dry_run_plans_dns_and_http_metadata(self):
        engine = Engine([DomainScanModule()])
        findings = engine.scan(ScanTarget(kind="domain", value="https://example.com/path"), RunConfig())

        self.assertEqual(len(findings), 7)
        self.assertEqual(findings[0].source, "dns-resolution")
        self.assertEqual(findings[0].metadata["domain"], "example.com")
        self.assertEqual(findings[1].url, "https://example.com")
        self.assertEqual(findings[2].url, "http://example.com")
        self.assertEqual(findings[3].source, "page-email-extraction")
        self.assertEqual(findings[4].source, "web-crawl")
        self.assertEqual(findings[5].source, "certificate-transparency")
        self.assertIn("crt.sh", findings[5].url)
        self.assertEqual(findings[6].source, "rdap-domain")
        self.assertIn("rdap.org/domain/example.com", findings[6].url)

    def test_domain_normalizer_rejects_invalid_values(self):
        self.assertEqual(normalize_domain("https://Example.COM/a"), "example.com")
        self.assertEqual(normalize_domain("not a domain"), "")

    def test_parse_crtsh_subdomains_filters_wildcards_and_foreign_domains(self):
        body = """
        [
          {"name_value": "*.Example.com\\nwww.example.com\\nexample.com\\nforeign.test"},
          {"common_name": "api.example.com"}
        ]
        """

        self.assertEqual(parse_crtsh_subdomains(body, "example.com"), ("api.example.com", "www.example.com"))

    def test_parse_rdap_domain_record_extracts_registration_metadata(self):
        body = """
        {
          "ldhName": "EXAMPLE.COM",
          "handle": "2336799_DOMAIN_COM-VRSN",
          "status": ["client delete prohibited", "client transfer prohibited"],
          "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "b.iana-servers.net."}],
          "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"}
          ],
          "entities": [
            {
              "roles": ["registrar"],
              "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar, Inc."]]]
            }
          ]
        }
        """

        record = parse_rdap_domain_record(body, "example.com")

        self.assertEqual(record.domain, "example.com")
        self.assertEqual(record.registrar, "Example Registrar, Inc.")
        self.assertEqual(record.handle, "2336799_DOMAIN_COM-VRSN")
        self.assertEqual(record.nameservers, ("a.iana-servers.net", "b.iana-servers.net"))
        self.assertEqual(record.created_at, "1995-08-14T04:00:00Z")
        self.assertEqual(record.expires_at, "2026-08-13T04:00:00Z")

    def test_domain_scan_live_adds_ct_and_rdap_findings(self):
        ct_body = """
        [
          {"name_value": "*.example.com\\nwww.example.com\\napi.example.com"},
          {"common_name": "www.example.com"}
        ]
        """
        rdap_body = """
        {
          "ldhName": "example.com",
          "handle": "2336799_DOMAIN_COM-VRSN",
          "status": ["client transfer prohibited"],
          "nameservers": [{"ldhName": "a.iana-servers.net"}, {"ldhName": "b.iana-servers.net"}],
          "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"}
          ],
          "entities": [
            {
              "roles": ["registrar"],
              "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar, Inc."]]]
            }
          ]
        }
        """
        fake_client = _FakeDomainHttpClient(
            (
                HttpResult(
                    url="https://example.com",
                    final_url="https://example.com",
                    status_code=200,
                    title="Example",
                    body_text="<a href='mailto:info@example.com'>Contact</a> support@external.test <a href='/contact'>Contact page</a>",
                    content_type="text/html",
                    headers={"strict-transport-security": "max-age=31536000"},
                ),
                HttpResult(
                    url="http://example.com",
                    final_url="https://example.com",
                    status_code=301,
                    content_type="text/html",
                ),
                HttpResult(
                    url="https://example.com/robots.txt",
                    final_url="https://example.com/robots.txt",
                    status_code=200,
                    body_text="User-agent: *\nDisallow: /private\nSitemap: https://example.com/sitemap.xml\n",
                    content_type="text/plain",
                ),
                HttpResult(
                    url="https://example.com/sitemap.xml",
                    final_url="https://example.com/sitemap.xml",
                    status_code=200,
                    body_text="<urlset><url><loc>https://example.com/contact</loc></url></urlset>",
                    content_type="application/xml",
                ),
                HttpResult(
                    url="https://example.com/contact",
                    final_url="https://example.com/contact",
                    status_code=200,
                    title="Contact",
                    body_text="team@example.com +380 44 123 45 67 <a href='https://vk.com/example'>VK</a>",
                    content_type="text/html",
                ),
                HttpResult(
                    url="https://crt.sh/?q=%25.example.com&output=json",
                    final_url="https://crt.sh/?q=%25.example.com&output=json",
                    status_code=200,
                    body_text=ct_body,
                    content_type="application/json",
                ),
                HttpResult(
                    url="https://rdap.org/domain/example.com",
                    final_url="https://rdap.org/domain/example.com",
                    status_code=200,
                    body_text=rdap_body,
                    content_type="application/rdap+json",
                ),
            )
        )

        with patch(
            "osint_toolkit.modules.domain.socket.getaddrinfo",
            return_value=[(socket.AF_INET, None, None, "", ("93.184.216.34", 0))],
        ), patch("osint_toolkit.modules.domain.HttpClient", return_value=fake_client):
            findings = Engine([DomainScanModule()]).scan(
                ScanTarget(kind="domain", value="example.com"),
                RunConfig(live=True),
            )

        sources = {finding.source: finding for finding in findings}
        self.assertEqual(sources["page-email-extraction"].status, "candidate")
        self.assertEqual(sources["page-email-extraction"].metadata["emails"], "info@example.com, support@external.test")
        self.assertEqual(sources["page-email-extraction"].metadata["same_domain_email_count"], "1")
        self.assertEqual(sources["page-email-extraction"].metadata["external_email_count"], "1")
        self.assertEqual(sources["web-crawl"].metadata["pages_fetched"], "2")
        self.assertEqual(sources["web-crawl"].metadata["emails"], "info@example.com, support@external.test, team@example.com")
        self.assertEqual(sources["web-crawl"].metadata["phones"], "+380441234567")
        self.assertEqual(sources["web-crawl"].metadata["social_urls"], "https://vk.com/example")
        self.assertEqual(sources["web-crawl"].metadata["robots_disallow_paths"], "/private")
        self.assertEqual(sources["web-crawl"].metadata["sitemap_urls"], "https://example.com/contact")
        self.assertEqual(sources["certificate-transparency"].status, "candidate")
        self.assertEqual(sources["certificate-transparency"].metadata["subdomain_count"], "2")
        self.assertEqual(sources["certificate-transparency"].metadata["subdomains"], "api.example.com, www.example.com")
        self.assertEqual(fake_client.requests[5][2], {"Accept": "application/json"})
        self.assertEqual(sources["rdap-domain"].status, "candidate")
        self.assertEqual(sources["rdap-domain"].metadata["registrar"], "Example Registrar, Inc.")
        self.assertEqual(sources["rdap-domain"].metadata["nameservers"], "a.iana-servers.net, b.iana-servers.net")
        self.assertEqual(sources["rdap-domain"].metadata["expires_at"], "2026-08-13T04:00:00Z")
        self.assertEqual(fake_client.requests[6][2], {"Accept": "application/rdap+json, application/json"})

    def test_telegram_scan_normalizes_handle_and_post_url(self):
        engine = Engine([TelegramScanModule()])
        handle = engine.scan(ScanTarget(kind="telegram", value="@durov"), RunConfig())
        post = engine.scan(ScanTarget(kind="telegram", value="https://t.me/telegram/123"), RunConfig())

        self.assertEqual(handle[0].url, "https://t.me/durov")
        self.assertEqual(handle[0].metadata["target_type"], "handle")
        self.assertEqual(post[0].url, "https://t.me/telegram/123")
        self.assertEqual(post[0].metadata["target_type"], "post")

    def test_telegram_normalizer_rejects_non_telegram_url(self):
        self.assertIsNone(normalize_telegram_target("https://example.com/durov"))

    def test_ru_ua_source_pack_filters_by_region(self):
        engine = Engine([RuUaSourcePackModule()])
        findings = engine.scan(ScanTarget(kind="ru-ua", value="all", region="ua"), RunConfig())
        sources = {finding.source for finding in findings}

        self.assertIn("DeepStateMap", sources)
        self.assertIn("paste.in.ua", sources)
        self.assertNotIn("VK", sources)

    def test_ru_ua_source_pack_platforms_selector(self):
        engine = Engine([RuUaSourcePackModule()])
        findings = engine.scan(ScanTarget(kind="ru-ua", value="platforms", region="ru"), RunConfig())
        sources = {finding.source for finding in findings}

        self.assertIn("VK", sources)
        self.assertIn("Odnoklassniki", sources)

    def test_email_scan_validates_syntax_and_plans_domain_resolution(self):
        engine = Engine([EmailScanModule()])
        findings = engine.scan(ScanTarget(kind="email", value="person@example.com"), RunConfig())

        self.assertEqual(len(findings), 11)
        self.assertEqual(findings[0].source, "syntax")
        self.assertEqual(findings[0].status, "valid")
        self.assertEqual(findings[1].source, "domain-resolution")
        self.assertEqual(findings[1].status, "planned")
        self.assertEqual(findings[2].source, "mx-records")
        self.assertEqual(findings[2].status, "planned")
        self.assertEqual(findings[3].source, "ns-records")
        self.assertEqual(findings[3].status, "planned")
        self.assertEqual(findings[4].source, "txt-records")
        self.assertEqual(findings[4].status, "planned")
        self.assertEqual(findings[5].source, "txt-service-signals")
        self.assertEqual(findings[5].status, "planned")
        self.assertEqual(findings[6].source, "spf-policy")
        self.assertEqual(findings[6].status, "planned")
        self.assertEqual(findings[7].source, "dmarc-policy")
        self.assertEqual(findings[7].status, "planned")
        self.assertEqual(findings[8].source, "mta-sts-policy")
        self.assertEqual(findings[8].status, "planned")
        self.assertEqual(findings[9].source, "tls-rpt-policy")
        self.assertEqual(findings[9].status, "planned")
        self.assertEqual(findings[10].source, "bimi-policy")
        self.assertEqual(findings[10].status, "planned")

    def test_email_scan_live_adds_mx_and_txt_records(self):
        def fake_lookup(domain, record_type, *, timeout=10.0):
            if record_type == "MX":
                return DnsLookupResult(
                    domain=domain,
                    record_type=record_type,
                    status="candidate",
                    records=("10 mail.example.com",),
                )
            if record_type == "NS":
                return DnsLookupResult(
                    domain=domain,
                    record_type=record_type,
                    status="candidate",
                    records=("ns1.example.com",),
                )
            if domain.startswith("_dmarc."):
                return DnsLookupResult(
                    domain=domain,
                    record_type=record_type,
                    status="candidate",
                    records=("v=DMARC1; p=reject; rua=mailto:dmarc@example.com",),
                )
            if domain.startswith("_mta-sts."):
                return DnsLookupResult(
                    domain=domain,
                    record_type=record_type,
                    status="candidate",
                    records=("v=STSv1; id=20260624",),
                )
            if domain.startswith("_smtp._tls."):
                return DnsLookupResult(
                    domain=domain,
                    record_type=record_type,
                    status="candidate",
                    records=("v=TLSRPTv1; rua=mailto:tls@example.com",),
                )
            if domain.startswith("default._bimi."):
                return DnsLookupResult(
                    domain=domain,
                    record_type=record_type,
                    status="candidate",
                    records=("v=BIMI1; l=https://example.com/bimi.svg; a=https://example.com/vmc.pem",),
                )
            return DnsLookupResult(
                domain=domain,
                record_type=record_type,
                status="candidate",
                records=("v=spf1 include:_spf.example.com -all", "google-site-verification=abc"),
            )

        with patch("osint_toolkit.modules.email.socket.getaddrinfo", return_value=[(socket.AF_INET, None, None, "", ("93.184.216.34", 0))]), patch(
            "osint_toolkit.modules.email.lookup_dns_records",
            side_effect=fake_lookup,
        ):
            findings = Engine([EmailScanModule()]).scan(
                ScanTarget(kind="email", value="person@example.com"),
                RunConfig(live=True),
            )

        sources = {finding.source: finding for finding in findings}
        self.assertEqual(sources["domain-resolution"].status, "candidate")
        self.assertEqual(sources["mx-records"].metadata["records"], "10 mail.example.com")
        self.assertEqual(sources["ns-records"].metadata["records"], "ns1.example.com")
        self.assertEqual(
            sources["txt-records"].metadata["records"],
            "v=spf1 include:_spf.example.com -all | google-site-verification=abc",
        )
        self.assertEqual(sources["txt-service-signals"].metadata["signal_types"], "google_site_verification")
        self.assertEqual(sources["spf-policy"].metadata["policy"], "hardfail")
        self.assertEqual(sources["spf-policy"].metadata["include_count"], "1")
        self.assertEqual(sources["dmarc-policy"].metadata["policy"], "reject")
        self.assertEqual(sources["mta-sts-policy"].metadata["id"], "20260624")
        self.assertEqual(sources["tls-rpt-policy"].metadata["rua"], "mailto:tls@example.com")
        self.assertEqual(sources["bimi-policy"].metadata["l"], "https://example.com/bimi.svg")

    def test_email_scan_rejects_invalid_input(self):
        engine = Engine([EmailScanModule()])
        findings = engine.scan(ScanTarget(kind="email", value="not-an-email"), RunConfig())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "invalid")

    def test_phone_scan_normalizes_and_detects_ukraine_prefix(self):
        engine = Engine([PhoneScanModule()])
        findings = engine.scan(ScanTarget(kind="phone", value="+380 44 123 45 67"), RunConfig())

        self.assertEqual(findings[0].status, "valid")
        self.assertEqual(findings[0].metadata["normalized"], "+380441234567")
        self.assertEqual(findings[1].metadata["country"], "Ukraine")

    def test_phone_helpers(self):
        self.assertEqual(normalize_phone("00380 44 123 45 67"), "+380441234567")
        self.assertTrue(is_e164_like("+380441234567"))
        self.assertEqual(detect_country("+70000000000"), ("Russia/Kazakhstan", "ru"))

    def test_adapter_manifest_has_partial_native_and_restricted_items(self):
        partial = filter_adapters("partial_native")
        restricted = filter_adapters("restricted")

        self.assertTrue(any(adapter.repository == "sherlock-project/sherlock" for adapter in partial))
        self.assertTrue(any(adapter.repository == "WebBreacher/WhatsMyName" for adapter in partial))
        self.assertTrue(any(adapter.repository == "alpkeskin/mosint" for adapter in partial))
        self.assertTrue(any(adapter.repository == "sundowndev/phoneinfoga" for adapter in partial))
        self.assertTrue(any(adapter.repository == "megadose/holehe" for adapter in restricted))

    def test_adapter_runner_dry_run_renders_command(self):
        finding = run_adapter(
            "sherlock-project/sherlock",
            ScanTarget(kind="username", value="example_user"),
        )

        self.assertEqual(finding.status, "planned")
        self.assertIn("sherlock example_user", finding.evidence)

        findings = run_adapter_findings(
            "sherlock-project/sherlock",
            ScanTarget(kind="username", value="example_user"),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "planned")

    def test_adapter_runner_renders_target_specific_user_scanner_commands(self):
        email = run_adapter(
            "kaifcodec/user-scanner",
            ScanTarget(kind="email", value="person@example.com"),
        )
        username = run_adapter(
            "kaifcodec/user-scanner",
            ScanTarget(kind="username", value="example_user"),
        )

        self.assertEqual(email.status, "planned")
        self.assertIn("user-scanner -e person@example.com -f json", email.evidence)
        self.assertEqual(username.status, "planned")
        self.assertIn("user-scanner -u example_user -f json", username.evidence)

    def test_adapter_runner_renders_region_specific_maigret_command(self):
        all_regions = run_adapter(
            "soxoj/maigret",
            ScanTarget(kind="username", value="example_user"),
        )
        ua = run_adapter(
            "soxoj/maigret",
            ScanTarget(kind="username", value="example_user", region="ua"),
        )

        self.assertEqual(all_regions.status, "planned")
        self.assertIn("maigret example_user --json ndjson", all_regions.evidence)
        self.assertNotIn("--tags", all_regions.evidence)
        self.assertEqual(ua.status, "planned")
        self.assertIn("maigret example_user --json ndjson --tags ua", ua.evidence)

    def test_adapter_runner_renders_region_specific_snoop_command(self):
        all_regions = run_adapter(
            "snooppr/snoop",
            ScanTarget(kind="username", value="example_user"),
        )
        ua = run_adapter(
            "snooppr/snoop",
            ScanTarget(kind="username", value="example_user", region="ua"),
        )

        self.assertEqual(all_regions.status, "planned")
        self.assertIn("snoop --no-func --found-print example_user", all_regions.evidence)
        self.assertNotIn("--include", all_regions.evidence)
        self.assertEqual(ua.status, "planned")
        self.assertIn("snoop --no-func --found-print --include UA example_user", ua.evidence)

    def test_adapter_runner_blocks_restricted_by_default(self):
        finding = run_adapter(
            "megadose/holehe",
            ScanTarget(kind="email", value="person@example.com"),
        )

        self.assertEqual(finding.status, "restricted")

    def test_doctor_reports_restricted_adapter(self):
        findings = inspect_adapters("restricted")
        statuses = {finding.source: finding.status for finding in findings}

        self.assertEqual(statuses["megadose/holehe"], "restricted")

    def test_investigation_runs_multiple_targets_and_adapter_dry_runs(self):
        result = run_investigation(
            (
                ScanTarget(kind="username", value="example_user"),
                ScanTarget(kind="domain", value="example.com"),
            ),
            title="test case",
            include_adapters=True,
            adapter_limit=3,
        )

        self.assertEqual(result.title, "test case")
        self.assertTrue(any(finding.module == "username-public-profiles" for finding in result.findings))
        self.assertTrue(any(finding.module == "domain-baseline" for finding in result.findings))
        self.assertTrue(any(finding.module == "external-adapter" for finding in result.adapter_findings))
        markdown = render_investigation_markdown(result)
        self.assertIn("# test case", markdown)
        self.assertIn("Adapter Dry Runs", markdown)

    def test_investigation_builds_entity_summary(self):
        result = run_investigation(
            (
                ScanTarget(kind="email", value="person@example.com"),
                ScanTarget(kind="phone", value="+380 44 123 45 67"),
                ScanTarget(kind="telegram", value="@durov"),
            )
        )

        entity_keys = {(entity.kind, entity.value.lower()) for entity in result.entities}
        self.assertIn(("email", "person@example.com"), entity_keys)
        self.assertIn(("domain", "example.com"), entity_keys)
        self.assertIn(("normalized-value", "+380441234567"), entity_keys)
        self.assertIn(("country", "ukraine"), entity_keys)
        self.assertIn(("telegram", "@durov"), entity_keys)
        self.assertIn(("url", "https://t.me/durov"), entity_keys)

        edge_keys = {
            (edge.source_kind, edge.relation, edge.target_kind, edge.target_value.lower())
            for edge in result.edges
        }
        self.assertIn(("email", "email_domain", "domain", "example.com"), edge_keys)
        self.assertIn(("phone", "normalized_as", "normalized-value", "+380441234567"), edge_keys)
        self.assertIn(("phone", "country_hint", "country", "ukraine"), edge_keys)
        self.assertIn(("telegram", "produced_url", "url", "https://t.me/durov"), edge_keys)
        self.assertIn(("url", "telegram_url_for", "telegram", "@durov"), edge_keys)

        markdown = render_investigation_markdown(result)
        self.assertIn("Entity Summary", markdown)
        self.assertIn("Graph Edges", markdown)
        self.assertIn("person@example.com", markdown)
        self.assertIn("@durov", markdown)

        json_output = render_investigation_json(result)
        self.assertIn('"entities"', json_output)
        self.assertIn('"edges"', json_output)
        self.assertIn('"value": "person@example.com"', json_output)


if __name__ == "__main__":
    unittest.main()
