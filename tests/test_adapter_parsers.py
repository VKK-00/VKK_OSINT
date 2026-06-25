import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osint_toolkit.adapter_parsers import parse_adapter_output
from osint_toolkit.adapter_runner import run_adapter_findings
from osint_toolkit.entities import entities_from_findings
from osint_toolkit.engine import ScanTarget


class AdapterParserTests(unittest.TestCase):
    def test_parse_username_adapter_urls(self):
        findings = parse_adapter_output(
            "sherlock-project/sherlock",
            ScanTarget(kind="username", value="example_user"),
            """
            [+] GitHub: https://github.com/example_user
            [+] Reddit: https://www.reddit.com/user/example_user
            [-] Instagram: Not Found
            """,
        )

        urls = {finding.url for finding in findings}
        self.assertIn("https://github.com/example_user", urls)
        self.assertIn("https://www.reddit.com/user/example_user", urls)
        self.assertTrue(all(finding.module == "external-adapter-parser" for finding in findings))
        self.assertTrue(any(finding.metadata["site_name"] == "GitHub" for finding in findings))
        instagram = next(finding for finding in findings if finding.metadata["site_name"] == "Instagram")
        self.assertEqual(instagram.status, "not_found")
        self.assertEqual(instagram.metadata["raw_status"], "Available")

    def test_parse_sherlock_csv_report(self):
        findings = parse_adapter_output(
            "sherlock-project/sherlock",
            ScanTarget(kind="username", value="example_user"),
            """
            username,name,url_main,url_user,exists,http_status,response_time_s
            example_user,GitHub,https://github.com,https://github.com/example_user,Claimed,200,0.12
            example_user,Instagram,https://www.instagram.com,https://www.instagram.com/example_user,Available,404,0.08
            example_user,TikTok,https://www.tiktok.com,https://www.tiktok.com/@example_user,WAF,403,0.30
            example_user,Chess,https://chess.example,https://chess.example/example_user,Illegal,,0.01
            """,
        )

        statuses = {finding.metadata["site_name"]: finding.status for finding in findings}
        self.assertEqual(statuses["GitHub"], "candidate")
        self.assertEqual(statuses["Instagram"], "not_found")
        self.assertEqual(statuses["TikTok"], "error")
        self.assertEqual(statuses["Chess"], "skipped")

        github = next(finding for finding in findings if finding.metadata["site_name"] == "GitHub")
        instagram = next(finding for finding in findings if finding.metadata["site_name"] == "Instagram")
        self.assertEqual(github.url, "https://github.com/example_user")
        self.assertEqual(github.metadata["domain"], "github.com")
        self.assertEqual(github.metadata["http_status"], "200")
        self.assertEqual(github.metadata["response_time_s"], "0.12")
        self.assertEqual(instagram.url, "")
        self.assertEqual(instagram.metadata["checked_url"], "https://www.instagram.com/example_user")

    def test_parse_nexfil_saved_txt_report(self):
        findings = parse_adapter_output(
            "thewhiteh4t/nexfil",
            ScanTarget(kind="username", value="example_user"),
            """
            nexfil v1.0.6
            ----------------------------------------
            Username : example_user
            Start Time : Wed Jun 24 21:00:00 2026
            End Time : Wed Jun 24 21:00:05 2026
            Total Hits : 2
            Total Timeouts : 1
            Total Errors : 3

            URLs :

            https://github.com/example_user
            https://www.reddit.com/user/example_user

            ----------------------------------------
            """,
        )

        summary = next(finding for finding in findings if finding.status == "observed")
        self.assertEqual(summary.metadata["parser"], "nexfil")
        self.assertEqual(summary.metadata["total_hits"], "2")
        self.assertEqual(summary.metadata["total_timeouts"], "1")
        self.assertEqual(summary.metadata["total_errors"], "3")

        urls = {finding.url for finding in findings if finding.url}
        self.assertEqual(urls, {"https://github.com/example_user", "https://www.reddit.com/user/example_user"})
        github = next(finding for finding in findings if finding.url == "https://github.com/example_user")
        self.assertEqual(github.status, "candidate")
        self.assertEqual(github.confidence, "high")
        self.assertEqual(github.metadata["domain"], "github.com")

    def test_parse_detectdee_result_lines(self):
        findings = parse_adapter_output(
            "Yvesssn/DetectDee",
            ScanTarget(kind="username", value="example_user"),
            """
            example_user, github, https://github.com/example_user
            INFO[2026-06-25] [+] example_user     v2ex           : https://www.v2ex.com/member/example_user
            example_user, github, https://github.com/example_user
            """,
        )

        self.assertEqual(len(findings), 2)
        urls = {finding.url for finding in findings}
        self.assertIn("https://github.com/example_user", urls)
        self.assertIn("https://www.v2ex.com/member/example_user", urls)
        github = next(finding for finding in findings if finding.metadata["site_name"] == "github")
        self.assertEqual(github.metadata["parser"], "detectdee")
        self.assertEqual(github.metadata["username"], "example_user")
        self.assertEqual(github.status, "candidate")

    def test_parse_yark_archive_json(self):
        archive = {
            "version": 3,
            "url": "https://www.youtube.com/channel/ExampleChannel",
            "videos": [
                {
                    "id": "abc123DEF",
                    "uploaded": "2026-06-20T10:00:00",
                    "width": 1920,
                    "height": 1080,
                    "title": {
                        "2026-06-20T10:00:00": "Original title",
                        "2026-06-21T10:00:00": "Updated title",
                    },
                    "description": {"2026-06-20T10:00:00": "Contact admin@example.com"},
                    "views": {"2026-06-20T10:00:00": 1200},
                    "likes": {"2026-06-20T10:00:00": 55},
                    "thumbnail": {"2026-06-20T10:00:00": "thumbhash"},
                    "deleted": {"2026-06-20T10:00:00": False},
                    "notes": [{"id": "note-1", "timestamp": 10, "title": "clip", "body": "note"}],
                }
            ],
            "livestreams": [],
            "shorts": [
                {
                    "id": "short001",
                    "uploaded": "2026-06-22T10:00:00",
                    "width": 1080,
                    "height": 1920,
                    "title": {"2026-06-22T10:00:00": "Short title"},
                    "description": {"2026-06-22T10:00:00": ""},
                    "views": {"2026-06-22T10:00:00": 300},
                    "likes": {"2026-06-22T10:00:00": None},
                    "thumbnail": {"2026-06-22T10:00:00": "shortthumb"},
                    "deleted": {"2026-06-22T10:00:00": True},
                    "notes": [],
                }
            ],
        }

        findings = parse_adapter_output(
            "Owez/yark",
            ScanTarget(kind="url", value="https://www.youtube.com/channel/ExampleChannel"),
            json.dumps(archive),
        )

        summary = next(finding for finding in findings if finding.status == "observed" and not finding.url)
        self.assertEqual(summary.metadata["parser"], "yark")
        self.assertEqual(summary.metadata["archive_url"], "https://www.youtube.com/channel/ExampleChannel")
        self.assertEqual(summary.metadata["videos_count"], "1")
        self.assertEqual(summary.metadata["shorts_count"], "1")
        self.assertEqual(summary.metadata["target_kind"], "url")

        video = next(finding for finding in findings if finding.metadata.get("video_id") == "abc123DEF")
        self.assertEqual(video.status, "candidate")
        self.assertEqual(video.url, "https://www.youtube.com/watch?v=abc123DEF")
        self.assertEqual(video.metadata["title"], "Updated title")
        self.assertEqual(video.metadata["views"], "1200")
        self.assertEqual(video.metadata["notes_count"], "1")
        self.assertEqual(video.metadata["description_excerpt"], "Contact admin@example.com")
        short = next(finding for finding in findings if finding.metadata.get("video_id") == "short001")
        self.assertEqual(short.status, "observed")
        self.assertEqual(short.metadata["category"], "short")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("url", "https://www.youtube.com/watch?v=abc123def"), entities)
        self.assertIn(("domain", "www.youtube.com"), entities)
        self.assertIn(("email", "admin@example.com"), entities)

    def test_parse_pwnedornot_breach_stdout(self):
        findings = parse_adapter_output(
            "thewhiteh4t/pwnedOrNot",
            ScanTarget(kind="email", value="person@example.com"),
            """
            [+] Checking Breach status for person@example.com [ pwned ]

            [*] Total Breaches : 2

            Breach       : Adobe
            Domain       : adobe.com
            Date         : 2013-10-04
            BreachedInfo : Emails, Passwords, Usernames
            Fabricated   : False
            Verified     : True
            Retired      : False
            Spam         : False

            Breach       : Example
            Domain       : example.com
            Date         : 2020-01-01
            BreachedInfo : Emails
            Fabricated   : False
            Verified     : False
            Retired      : False
            Spam         : False
            """,
        )

        summary = next(finding for finding in findings if finding.metadata["category"] == "breach-summary")
        self.assertEqual(summary.status, "candidate")
        self.assertEqual(summary.metadata["parser"], "pwnedornot")
        self.assertEqual(summary.metadata["breach_count"], "2")
        self.assertFalse(any(finding.metadata["category"] == "credential-exposure" for finding in findings))

        adobe = next(finding for finding in findings if finding.metadata.get("breach_name") == "Adobe")
        self.assertEqual(adobe.status, "candidate")
        self.assertEqual(adobe.confidence, "high")
        self.assertEqual(adobe.metadata["domain"], "adobe.com")
        self.assertEqual(adobe.metadata["breach_date"], "2013-10-04")
        self.assertEqual(adobe.metadata["data_classes"], "Emails, Passwords, Usernames")

    def test_parse_pwnedornot_not_pwned_and_redacts_dump_values(self):
        findings = parse_adapter_output(
            "thewhiteh4t/pwnedOrNot",
            ScanTarget(kind="email", value="person@example.com"),
            """
            [+] Checking Breach status for person@example.com [ not pwned ]
            [+] Looking for Dumps... [ Dumps Found ]

            [+] Passwords :

            hunter2
            person@example.com:supersecret
            """,
        )

        summary = next(finding for finding in findings if finding.metadata["category"] == "breach-summary")
        credential = next(finding for finding in findings if finding.metadata["category"] == "credential-exposure")
        self.assertEqual(summary.status, "not_found")
        self.assertEqual(credential.status, "candidate")
        self.assertEqual(credential.metadata["sensitive_value_redacted"], "true")

        joined = "\n".join(
            [finding.evidence for finding in findings]
            + [str(sorted(finding.metadata.items())) for finding in findings]
        )
        self.assertNotIn("hunter2", joined)
        self.assertNotIn("supersecret", joined)

    def test_parse_mosint_style_key_values(self):
        findings = parse_adapter_output(
            "alpkeskin/mosint",
            ScanTarget(kind="email", value="person@example.com"),
            """
            Email: person@example.com
            Domain: example.com
            Name: Example Person
            """,
        )

        metadata = [finding.metadata for finding in findings]
        self.assertTrue(any(item.get("domain") == "example.com" for item in metadata))
        self.assertTrue(any(item.get("name") == "Example Person" for item in metadata))
        self.assertTrue(any(item.get("parser") == "email" for item in metadata))

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("email", "person@example.com"), entities)
        self.assertIn(("domain", "example.com"), entities)
        self.assertIn(("name", "example person"), entities)

    def test_parse_mosint_json_report(self):
        findings = parse_adapter_output(
            "alpkeskin/mosint",
            ScanTarget(kind="email", value="target@example.com"),
            """
            {
              "email": "target@example.com",
              "verified": true,
              "emailrep": {
                "email": "target@example.com",
                "reputation": "medium",
                "suspicious": true,
                "references": 2,
                "details": {
                  "credentials_leaked": true,
                  "data_breach": true,
                  "profiles": ["twitter"],
                  "first_seen": "2020-01-01",
                  "deliverable": true,
                  "valid_mx": true,
                  "primary_mx": "mx.example.com"
                }
              },
              "breachdirectory": {
                "success": true,
                "found": 1,
                "result": [
                  {
                    "has_password": true,
                    "sources": ["combo-db"],
                    "password": "secret-value",
                    "sha1": "sha1-value",
                    "hash": "hash-value"
                  }
                ]
              },
              "haveibeenpwned": [
                {
                  "Name": "Adobe",
                  "Title": "Adobe",
                  "Domain": "adobe.com",
                  "BreachDate": "2013-10-04",
                  "PwnCount": 100,
                  "DataClasses": ["Email addresses", "Passwords"],
                  "IsVerified": true
                }
              ],
              "hunter": {
                "data": {
                  "domain": "example.com",
                  "organization": "Example Inc",
                  "country": "US",
                  "emails": [
                    {
                      "value": "admin@example.com",
                      "first_name": "Admin",
                      "last_name": "User",
                      "position": "Security",
                      "verification": {"status": "valid"},
                      "sources": [{"uri": "https://example.com/team", "domain": "example.com"}]
                    }
                  ],
                  "linked_domains": ["example.org"]
                },
                "meta": {"results": 1}
              },
              "psbdmp": ["https://psbdmp.ws/dump/abc"],
              "google_search": ["https://example.com/contact"],
              "dns_records": [{"Type": "MX", "Value": "10 mx.example.com"}],
              "instagram_exists": true,
              "twitter_exists": true
            }
            """,
        )

        self.assertTrue(any(finding.metadata.get("parser") == "mosint" for finding in findings))
        self.assertTrue(any(finding.metadata.get("category") == "email-reputation" for finding in findings))
        self.assertTrue(any(finding.metadata.get("breach_name") == "Adobe" for finding in findings))
        self.assertTrue(any(finding.metadata.get("source_label") == "combo-db" for finding in findings))
        self.assertTrue(any(finding.metadata.get("category") == "credential-exposure" for finding in findings))
        self.assertTrue(any(finding.metadata.get("email") == "admin@example.com" for finding in findings))
        self.assertTrue(any(finding.url == "https://example.com/team" for finding in findings))
        self.assertTrue(any(finding.url == "https://psbdmp.ws/dump/abc" for finding in findings))

        for finding in findings:
            self.assertNotIn("secret-value", finding.evidence)
            self.assertFalse(any(value == "secret-value" for value in finding.metadata.values()))
            self.assertFalse(any(value == "sha1-value" for value in finding.metadata.values()))
            self.assertFalse(any(value == "hash-value" for value in finding.metadata.values()))

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("domain", "adobe.com"), entities)
        self.assertIn(("domain", "example.org"), entities)
        self.assertIn(("name", "admin user"), entities)
        self.assertIn(("country", "us"), entities)

    def test_parse_phoneinfoga_style_key_values(self):
        findings = parse_adapter_output(
            "sundowndev/phoneinfoga",
            ScanTarget(kind="phone", value="+380441234567"),
            """
            Running scan for phone number +380441234567...

            Results for local
            Raw local: 0441234567
            E164: +380441234567
            International: 380441234567
            International format: +380441234567
            Country: UA
            Country code: UA
            Carrier: Example Mobile
            Line type: mobile

            Results for googlesearch
            Social media:
                    URL: https://www.google.com/search?q=site%3Avk.com+intext%3A%22380441234567%22

            Results for ovh
            Found: true
            Number range: 0038044xxxxxxx
            City: Kyiv
            Zip code: 01001

            The following scanners returned errors:
            googlecse: search engine ID and/or API key is not defined

            3 scanner(s) succeeded
            """,
        )

        metadata = [finding.metadata for finding in findings]
        self.assertTrue(any(item.get("normalized") == "+380441234567" for item in metadata))
        self.assertTrue(any(item.get("country") == "UA" for item in metadata))
        self.assertTrue(any(item.get("carrier") == "Example Mobile" for item in metadata))
        self.assertTrue(any(item.get("line_type") == "mobile" for item in metadata))
        self.assertTrue(any(item.get("number_range") == "0038044xxxxxxx" for item in metadata))
        self.assertTrue(any(item.get("zip_code") == "01001" for item in metadata))
        self.assertTrue(any(item.get("scanner") == "googlecse" and item.get("error") for item in metadata))

        urls = {finding.url for finding in findings}
        self.assertIn("https://www.google.com/search?q=site%3Avk.com+intext%3A%22380441234567%22", urls)

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("normalized-value", "+380441234567"), entities)
        self.assertIn(("country", "ua"), entities)
        self.assertIn(("carrier", "example mobile"), entities)
        self.assertIn(("line-type", "mobile"), entities)
        self.assertIn(("phone-range", "0038044xxxxxxx"), entities)
        self.assertIn(("postal-code", "01001"), entities)

    def test_parse_phoneinfoga_rest_json_results(self):
        findings = parse_adapter_output(
            "sundowndev/phoneinfoga",
            ScanTarget(kind="phone", value="+79516566591"),
            """
            {
              "numverify": {
                "valid": true,
                "number": "79516566591",
                "local_format": "9516566591",
                "international_format": "+79516566591",
                "country_prefix": "+7",
                "country_code": "RU",
                "country_name": "Russian Federation",
                "location": "Saint Petersburg and Leningrad Oblast",
                "carrier": "OJSC St. Petersburg Telecom",
                "line_type": "mobile"
              },
              "googlesearch": {
                "social_media": [
                  {
                    "number": "+79516566591",
                    "dork": "site:vk.com intext:\\"79516566591\\"",
                    "url": "https://www.google.com/search?q=site%3Avk.com+intext%3A%2279516566591%22"
                  }
                ]
              },
              "googlecse": {
                "homepage": "https://cse.google.com/cse?cx=example",
                "result_count": 1,
                "total_result_count": 1,
                "total_request_count": 1,
                "items": [
                  {
                    "title": "Example profile",
                    "url": "https://example.com/profile"
                  }
                ]
              }
            }
            """,
        )

        metadata = [finding.metadata for finding in findings]
        self.assertTrue(any(item.get("scanner") == "numverify" and item.get("country") == "Russian Federation" for item in metadata))
        self.assertTrue(any(item.get("scanner") == "numverify" and item.get("country_code") == "RU" for item in metadata))
        self.assertTrue(any(item.get("scanner") == "numverify" and item.get("location") == "Saint Petersburg and Leningrad Oblast" for item in metadata))
        self.assertTrue(any(item.get("dork") == 'site:vk.com intext:"79516566591"' for item in metadata))
        self.assertTrue(any(item.get("title") == "Example profile" for item in metadata))

        urls = {finding.url for finding in findings}
        self.assertIn("https://www.google.com/search?q=site%3Avk.com+intext%3A%2279516566591%22", urls)
        self.assertIn("https://cse.google.com/cse?cx=example", urls)
        self.assertIn("https://example.com/profile", urls)

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("normalized-value", "+79516566591"), entities)
        self.assertIn(("country", "russian federation"), entities)
        self.assertIn(("country-code", "ru"), entities)
        self.assertIn(("location", "saint petersburg and leningrad oblast"), entities)

    def test_parse_maigret_ndjson_report(self):
        findings = parse_adapter_output(
            "soxoj/maigret",
            ScanTarget(kind="username", value="bellingcat", region="ua"),
            """
            {"sitename":"GitHub","url_user":"https://github.com/bellingcat","http_status":200,"status":{"username":"bellingcat","site_name":"GitHub","url":"https://github.com/bellingcat","status":"Claimed","ids":{"fullname":"Bellingcat","location":"Netherlands"},"tags":["coding","global"]}}
            {"sitename":"Example","url_user":"https://example.com/bellingcat","http_status":404,"status":{"username":"bellingcat","site_name":"Example","url":"https://example.com/bellingcat","status":"Available","ids":{},"tags":["ua"]}}
            """,
        )

        self.assertEqual(len(findings), 2)
        github = next(finding for finding in findings if finding.metadata["site_name"] == "GitHub")
        self.assertEqual(github.status, "candidate")
        self.assertEqual(github.confidence, "high")
        self.assertEqual(github.url, "https://github.com/bellingcat")
        self.assertEqual(github.metadata["parser"], "maigret")
        self.assertEqual(github.metadata["name"], "Bellingcat")
        self.assertEqual(github.metadata["location"], "Netherlands")

        missing = next(finding for finding in findings if finding.metadata["site_name"] == "Example")
        self.assertEqual(missing.status, "not_found")
        self.assertEqual(missing.url, "")
        self.assertEqual(missing.metadata["checked_url"], "https://example.com/bellingcat")
        self.assertEqual(missing.metadata["region"], "UA")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("domain", "github.com"), entities)
        self.assertIn(("name", "bellingcat"), entities)
        self.assertIn(("location", "netherlands"), entities)
        self.assertIn(("region", "ua"), entities)
        self.assertNotIn(("domain", "example.com"), entities)

    def test_parse_maigret_simple_json_report(self):
        findings = parse_adapter_output(
            "soxoj/maigret",
            ScanTarget(kind="username", value="bellingcat"),
            """
            {
              "Telegram": {
                "url_user": "https://t.me/bellingcat",
                "http_status": 200,
                "status": {
                  "username": "bellingcat",
                  "site_name": "Telegram",
                  "url": "https://t.me/bellingcat",
                  "status": "Claimed",
                  "ids": {"country": "Ukraine"},
                  "tags": ["ua", "messaging"]
                }
              }
            }
            """,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].metadata["site_name"], "Telegram")
        self.assertEqual(findings[0].metadata["country"], "Ukraine")
        self.assertEqual(findings[0].metadata["region"], "UA")

    def test_parse_maigret_richer_dossier_fields(self):
        findings = parse_adapter_output(
            "soxoj/maigret",
            ScanTarget(kind="username", value="bellingcat"),
            """
            {"sitename":"GitHub","url_main":"https://github.com","url_user":"https://github.com/bellingcat","url_probe":"https://api.github.com/users/bellingcat","http_status":200,"rank":123,"is_similar":false,"parsing_enabled":true,"site":{"engine":"github","checkType":"message","type":"username","disabled":false,"alexaRank":42,"url":"https://github.com/{username}","urlProbe":"https://api.github.com/users/{username}","tags":["coding","us"]},"status":{"username":"bellingcat","site_name":"GitHub","url":"https://github.com/bellingcat","status":"Claimed","ids":{"fullname":"Bellingcat","city":"Amsterdam","country_code":"NL","locale":"en-NL","bio":"Open source investigations and verification.","gender":"unknown","created_at":"2014-07-15T12:00:00Z","latest_activity_at":"2026-06-20T08:00:00Z","followers_total":12345,"following_total":12,"public_repos":3,"company":"Bellingcat","occupation":"Investigative newsroom","website":"https://www.bellingcat.com","image":"https://avatars.githubusercontent.com/u/123","username":["bellingcat","bellcat"],"emails":["tips@bellingcat.com"],"phones":["+31201234567"]},"tags":["coding","global"]}}
            """,
        )

        self.assertEqual(len(findings), 1)
        github = findings[0]
        self.assertEqual(github.metadata["url_probe"], "https://api.github.com/users/bellingcat")
        self.assertEqual(github.metadata["rank"], "123")
        self.assertEqual(github.metadata["is_similar"], "False")
        self.assertEqual(github.metadata["parsing_enabled"], "True")
        self.assertEqual(github.metadata["site_engine"], "github")
        self.assertEqual(github.metadata["site_check_type"], "message")
        self.assertEqual(github.metadata["site_id_type"], "username")
        self.assertEqual(github.metadata["site_disabled"], "False")
        self.assertEqual(github.metadata["site_alexa_rank"], "42")
        self.assertEqual(github.metadata["site_url_probe_template"], "https://api.github.com/users/{username}")
        self.assertEqual(github.metadata["site_tags"], "coding, us")
        self.assertEqual(github.metadata["name"], "Bellingcat")
        self.assertEqual(github.metadata["location"], "Amsterdam")
        self.assertEqual(github.metadata["country_code"], "NL")
        self.assertEqual(github.metadata["locale"], "en-NL")
        self.assertEqual(github.metadata["bio"], "Open source investigations and verification.")
        self.assertEqual(github.metadata["gender"], "unknown")
        self.assertEqual(github.metadata["created_at"], "2014-07-15T12:00:00Z")
        self.assertEqual(github.metadata["last_seen"], "2026-06-20T08:00:00Z")
        self.assertEqual(github.metadata["followers"], "12345")
        self.assertEqual(github.metadata["following"], "12")
        self.assertEqual(github.metadata["public_repos"], "3")
        self.assertEqual(github.metadata["organization"], "Bellingcat")
        self.assertEqual(github.metadata["occupation"], "Investigative newsroom")
        self.assertEqual(github.metadata["external_urls"], "https://www.bellingcat.com")
        self.assertEqual(github.metadata["profile_image_url"], "https://avatars.githubusercontent.com/u/123")
        self.assertEqual(github.metadata["emails"], "tips@bellingcat.com")
        self.assertEqual(github.metadata["phones"], "+31201234567")
        self.assertEqual(github.metadata["related_usernames"], "bellcat")
        self.assertEqual(github.metadata["maigret_ids_count"], "18")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("email", "tips@bellingcat.com"), entities)
        self.assertIn(("phone", "+31201234567"), entities)
        self.assertIn(("url", "https://www.bellingcat.com"), entities)
        self.assertIn(("url", "https://avatars.githubusercontent.com/u/123"), entities)
        self.assertIn(("username", "bellcat"), entities)
        self.assertIn(("country-code", "nl"), entities)

    def test_parse_maigret_csv_report(self):
        findings = parse_adapter_output(
            "soxoj/maigret",
            ScanTarget(kind="username", value="bellingcat"),
            """
            username,name,url_main,url_user,exists,http_status
            bellingcat,GitHub,https://github.com,https://github.com/bellingcat,Claimed,200
            bellingcat,Example,https://example.com,https://example.com/bellingcat,Available,404
            bellingcat,Broken,https://broken.example,https://broken.example/bellingcat,Unknown,0
            """,
        )

        statuses = {finding.metadata["site_name"]: finding.status for finding in findings}
        self.assertEqual(statuses["GitHub"], "candidate")
        self.assertEqual(statuses["Example"], "not_found")
        self.assertEqual(statuses["Broken"], "error")
        github = next(finding for finding in findings if finding.metadata["site_name"] == "GitHub")
        self.assertEqual(github.url, "https://github.com/bellingcat")
        example = next(finding for finding in findings if finding.metadata["site_name"] == "Example")
        self.assertEqual(example.url, "")
        self.assertEqual(example.metadata["checked_url"], "https://example.com/bellingcat")

    def test_parse_user_scanner_json_results(self):
        findings = parse_adapter_output(
            "kaifcodec/user-scanner",
            ScanTarget(kind="username", value="kaifcodec"),
            """
            [
              {
                "status": "Found",
                "reason": "",
                "username": "kaifcodec",
                "site_name": "Github",
                "category": "Dev",
                "url": "https://github.com/kaifcodec",
                "extra": {"name": "Kaif", "followers": "243"}
              },
              {
                "status": "Not Found",
                "reason": "",
                "username": "kaifcodec",
                "site_name": "Example",
                "category": "Social",
                "url": "https://example.com/kaifcodec",
                "extra": {}
              }
            ]
            """,
        )

        self.assertEqual(len(findings), 2)
        github = next(finding for finding in findings if finding.metadata["site_name"] == "Github")
        self.assertEqual(github.status, "candidate")
        self.assertEqual(github.confidence, "high")
        self.assertEqual(github.url, "https://github.com/kaifcodec")
        self.assertEqual(github.metadata["parser"], "user-scanner")
        self.assertEqual(github.metadata["username"], "kaifcodec")
        self.assertEqual(github.metadata["extra_name"], "Kaif")
        missing = next(finding for finding in findings if finding.metadata["site_name"] == "Example")
        self.assertEqual(missing.status, "not_found")
        self.assertEqual(missing.url, "")
        self.assertEqual(missing.metadata["checked_url"], "https://example.com/kaifcodec")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("username", "kaifcodec"), entities)
        self.assertIn(("domain", "github.com"), entities)
        self.assertNotIn(("domain", "example.com"), entities)

    def test_parse_user_scanner_email_json_result(self):
        findings = parse_adapter_output(
            "kaifcodec/user-scanner",
            ScanTarget(kind="email", value="target@gmail.com"),
            """
            {
              "email": "target@gmail.com",
              "category": "Social",
              "site_name": "Instagram",
              "status": "Registered",
              "url": "https://instagram.com",
              "extra": "",
              "reason": ""
            }
            """,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "candidate")
        self.assertEqual(findings[0].metadata["email"], "target@gmail.com")
        self.assertEqual(findings[0].metadata["category"], "Social")

    def test_parse_user_scanner_verbose_lines(self):
        findings = parse_adapter_output(
            "kaifcodec/user-scanner",
            ScanTarget(kind="email", value="johndoe@gmail.com"),
            """
            [ok] Huggingface [https://huggingface.co] (johndoe@gmail.com): Registered
            [x] Envato [https://account.envato.com] (johndoe@gmail.com): Available
            """,
        )

        statuses = {finding.metadata["site_name"]: finding.status for finding in findings}
        self.assertEqual(statuses["Huggingface"], "candidate")
        self.assertEqual(statuses["Envato"], "not_found")
        envato = next(finding for finding in findings if finding.metadata["site_name"] == "Envato")
        self.assertEqual(envato.url, "")
        self.assertEqual(envato.metadata["checked_url"], "https://account.envato.com")

    def test_parse_h8mail_json_report_redacts_sensitive_values(self):
        findings = parse_adapter_output(
            "khast3x/h8mail",
            ScanTarget(kind="email", value="target@example.com"),
            """
            {
              "targets": [
                {
                  "target": "target@example.com",
                  "pwn_num": 3,
                  "data": [
                    ["HIBP3:Adobe", "HIBP3:LinkedIn"],
                    ["HUNTER_RELATED:admin@example.com"],
                    ["SNUS_USERNAME:targetuser", "SNUS_PASSWORD:secret-value", "SNUS_SOURCE:combo-db"],
                    ["HIBP3_PASTE:https://pastebin.com/abc123"]
                  ]
                }
              ]
            }
            """,
        )

        self.assertTrue(any(finding.metadata.get("parser") == "h8mail" for finding in findings))
        summary = next(finding for finding in findings if finding.metadata.get("category") == "breach-summary")
        self.assertEqual(summary.status, "candidate")
        self.assertEqual(summary.metadata["breach_count"], "3")

        related = next(finding for finding in findings if finding.metadata.get("category") == "related-email")
        self.assertEqual(related.metadata["email"], "admin@example.com")
        self.assertEqual(related.metadata["domain"], "example.com")

        username = next(finding for finding in findings if finding.metadata.get("username") == "targetuser")
        self.assertEqual(username.metadata["category"], "username")

        secret = next(finding for finding in findings if finding.metadata.get("category") == "credential-exposure")
        self.assertEqual(secret.metadata["sensitive_value_redacted"], "true")
        self.assertNotIn("secret-value", secret.evidence)
        self.assertFalse(any(value == "secret-value" for value in secret.metadata.values()))

        paste = next(finding for finding in findings if finding.url == "https://pastebin.com/abc123")
        self.assertEqual(paste.metadata["domain"], "pastebin.com")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("username", "targetuser"), entities)
        self.assertIn(("domain", "pastebin.com"), entities)

    def test_parse_snoop_csv_report(self):
        findings = parse_adapter_output(
            "snooppr/snoop",
            ScanTarget(kind="username", value="example_user", region="ua"),
            """
            Resource,Geo,Url,Url_username,Status,Http_code,Deceleration/s,Response/s,Time/s,Session/kB
            GitHub,US,https://github.com,https://github.com/example_user,найден!,200,0.1,0.2,0.3,12
            Example UA,UA,https://example.ua,https://example.ua/example_user,Увы!,404,0.1,0.2,0.4,4
            Broken RU,RU,https://broken.ru,https://broken.ru/example_user,блок,сбой,0.1,0.2,0.5,Bad
            «-----------------------------------,----,-----------------------------------,--------------------------------------------------------,-------------,-----------------,-------------------------------------,-----------------,----------------------------,--------------»
            Nick=example_user
            """,
        )

        self.assertEqual(len(findings), 3)
        github = next(finding for finding in findings if finding.metadata["site_name"] == "GitHub")
        self.assertEqual(github.status, "candidate")
        self.assertEqual(github.confidence, "high")
        self.assertEqual(github.url, "https://github.com/example_user")
        self.assertEqual(github.metadata["parser"], "snoop")
        self.assertEqual(github.metadata["region"], "US")
        self.assertEqual(github.metadata["domain"], "github.com")

        missing = next(finding for finding in findings if finding.metadata["site_name"] == "Example UA")
        self.assertEqual(missing.status, "not_found")
        self.assertEqual(missing.url, "")
        self.assertEqual(missing.metadata["checked_url"], "https://example.ua/example_user")

        blocked = next(finding for finding in findings if finding.metadata["site_name"] == "Broken RU")
        self.assertEqual(blocked.status, "error")
        self.assertEqual(blocked.confidence, "low")
        self.assertEqual(blocked.url, "")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("domain", "github.com"), entities)
        self.assertIn(("region", "ua"), entities)
        self.assertIn(("region", "ru"), entities)
        self.assertNotIn(("domain", "example.ua"), entities)
        self.assertNotIn(("domain", "broken.ru"), entities)

    def test_parse_snoop_stdout_lines(self):
        findings = parse_adapter_output(
            "snooppr/snoop",
            ScanTarget(kind="username", value="example_user"),
            """
            [+] GitHub: https://github.com/example_user
            [-] VK: Увы!
            """,
        )

        statuses = {finding.metadata["site_name"]: finding.status for finding in findings}
        self.assertEqual(statuses["GitHub"], "candidate")
        self.assertEqual(statuses["VK"], "not_found")
        github = next(finding for finding in findings if finding.metadata["site_name"] == "GitHub")
        self.assertEqual(github.url, "https://github.com/example_user")

    def test_parse_subfinder_jsonl_and_plain_subdomains(self):
        findings = parse_adapter_output(
            "projectdiscovery/subfinder",
            ScanTarget(kind="domain", value="example.com"),
            """
            {"host":"api.example.com","input":"example.com","source":"crtsh"}
            www.example.com
            example.com
            unrelated.test
            """,
        )

        subdomains = {finding.metadata.get("subdomain") for finding in findings}
        self.assertEqual(subdomains, {"api.example.com", "www.example.com"})
        api = next(finding for finding in findings if finding.metadata["subdomain"] == "api.example.com")
        self.assertEqual(api.status, "candidate")
        self.assertEqual(api.confidence, "high")
        self.assertEqual(api.metadata["domain"], "example.com")
        self.assertEqual(api.metadata["source_label"], "crtsh")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("subdomain", "api.example.com"), entities)
        self.assertIn(("subdomain", "www.example.com"), entities)

    def test_parse_httpx_jsonl_results(self):
        findings = parse_adapter_output(
            "projectdiscovery/httpx",
            ScanTarget(kind="domain", value="example.com"),
            """
            {"url":"https://www.example.com","input":"www.example.com","host":"www.example.com","status_code":200,"title":"Example","webserver":"nginx","tech":["Bootstrap","jQuery"],"content_type":"text/html","response_time":"120ms","ip":"93.184.216.34"}
            {"url":"https://broken.example.com","failed":true,"error":"timeout"}
            """,
        )

        alive = next(finding for finding in findings if finding.url == "https://www.example.com")
        self.assertEqual(alive.status, "candidate")
        self.assertEqual(alive.http_status, 200)
        self.assertEqual(alive.title, "Example")
        self.assertEqual(alive.metadata["domain"], "www.example.com")
        self.assertEqual(alive.metadata["tech"], "Bootstrap, jQuery")
        self.assertEqual(alive.metadata["webserver"], "nginx")

        failed = next(finding for finding in findings if finding.metadata.get("checked_url") == "https://broken.example.com")
        self.assertEqual(failed.status, "error")
        self.assertEqual(failed.url, "")
        self.assertEqual(failed.metadata["error"], "timeout")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("url", "https://www.example.com"), entities)
        self.assertIn(("domain", "www.example.com"), entities)
        self.assertNotIn(("url", "https://broken.example.com"), entities)

    def test_parse_amass_passive_output(self):
        findings = parse_adapter_output(
            "owasp-amass/amass",
            ScanTarget(kind="domain", value="example.com"),
            """
            example.com (FQDN) --> node --> www.example.com (FQDN)
            api.example.com
            other.test
            """,
        )

        subdomains = {finding.metadata.get("subdomain") for finding in findings}
        self.assertEqual(subdomains, {"api.example.com", "www.example.com"})
        self.assertTrue(all(finding.metadata["parser"] == "amass" for finding in findings))

    def test_parse_theharvester_json_report(self):
        findings = parse_adapter_output(
            "laramies/theHarvester",
            ScanTarget(kind="domain", value="example.com"),
            """
            {
              "emails": ["Admin@Example.com", "person@external.test"],
              "hosts": ["api.example.com:93.184.216.34", "www.example.com", "example.com", "unrelated.test"],
              "ips": ["93.184.216.34"],
              "interesting_urls": ["https://www.example.com/login"],
              "asns": ["AS15133"],
              "people": [{"first_name": "Example", "last_name": "Person"}],
              "linkedin_people": ["Example Employee"]
            }
            """,
        )

        metadata = [finding.metadata for finding in findings]
        self.assertTrue(any(item.get("email") == "admin@example.com" for item in metadata))
        self.assertTrue(any(item.get("email") == "person@external.test" for item in metadata))
        self.assertTrue(any(item.get("subdomain") == "api.example.com" and item.get("ip") == "93.184.216.34" for item in metadata))
        self.assertTrue(any(item.get("subdomain") == "www.example.com" for item in metadata))
        self.assertFalse(any(item.get("subdomain") == "example.com" for item in metadata))
        self.assertFalse(any(item.get("subdomain") == "unrelated.test" for item in metadata))
        self.assertTrue(any(item.get("category") == "asn" and item.get("asn") == "AS15133" for item in metadata))
        self.assertTrue(any(item.get("category") == "person" and item.get("name") == "Example Person" for item in metadata))

        urls = {finding.url for finding in findings}
        self.assertIn("https://www.example.com/login", urls)

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("subdomain", "api.example.com"), entities)
        self.assertIn(("url", "https://www.example.com/login"), entities)
        self.assertIn(("name", "example person"), entities)

    def test_parse_theharvester_json_report_preserves_source_attribution(self):
        findings = parse_adapter_output(
            "laramies/theHarvester",
            ScanTarget(kind="domain", value="example.com"),
            """
            {
              "emails_by_source": {
                "hunter": [{"email": "sales@example.com"}],
                "crtsh": ["admin@example.com"]
              },
              "hosts_by_source": {
                "crtsh": ["api.example.com:93.184.216.34"]
              },
              "source_results": {
                "otx": {
                  "interesting_urls": ["https://www.example.com/login"],
                  "ips": ["93.184.216.34"]
                }
              },
              "people": [{"name": "Example Person", "source": "linkedin"}]
            }
            """,
        )

        metadata = [finding.metadata for finding in findings]
        self.assertTrue(any(item.get("email") == "sales@example.com" and item.get("source_label") == "hunter" for item in metadata))
        self.assertTrue(any(item.get("email") == "admin@example.com" and item.get("source_label") == "crtsh" for item in metadata))
        self.assertTrue(
            any(
                item.get("subdomain") == "api.example.com"
                and item.get("ip") == "93.184.216.34"
                and item.get("source_label") == "crtsh"
                for item in metadata
            )
        )
        self.assertTrue(any(finding.url == "https://www.example.com/login" and finding.metadata.get("source_label") == "otx" for finding in findings))
        self.assertTrue(any(item.get("ip") == "93.184.216.34" and item.get("source_label") == "otx" for item in metadata))
        self.assertTrue(any(item.get("name") == "Example Person" and item.get("source_label") == "linkedin" for item in metadata))
        self.assertTrue(any("(source: hunter)" in finding.evidence for finding in findings))

    def test_parse_theharvester_stash_records_preserves_sources(self):
        findings = parse_adapter_output(
            "laramies/theHarvester",
            ScanTarget(kind="domain", value="example.com"),
            """
            {
              "results": [
                {"resource": "api.example.com", "type": "host", "source": "crtsh"},
                {"resource": "admin@example.com", "type": "email", "source": "hunter"},
                {"resource": "93.184.216.34", "type": "ip", "source": "dnsdumpster"},
                {"resource": "https://www.example.com/api", "type": "api_endpoint", "source": "api_scan"}
              ]
            }
            """,
        )

        metadata = [finding.metadata for finding in findings]
        self.assertTrue(any(item.get("subdomain") == "api.example.com" and item.get("source_label") == "crtsh" for item in metadata))
        self.assertTrue(any(item.get("email") == "admin@example.com" and item.get("source_label") == "hunter" for item in metadata))
        self.assertTrue(any(item.get("ip") == "93.184.216.34" and item.get("source_label") == "dnsdumpster" for item in metadata))
        self.assertTrue(any(finding.url == "https://www.example.com/api" and finding.metadata.get("source_label") == "api_scan" for finding in findings))

    def test_parse_theharvester_console_output(self):
        findings = parse_adapter_output(
            "laramies/theHarvester",
            ScanTarget(kind="domain", value="example.com"),
            """
            [*] Emails found: 1
            ----------------------
            contact@example.com

            [*] Hosts found: 1
            ---------------------
            api.example.com

            [*] Interesting Urls found: 1
            --------------------
            https://www.example.com/admin
            """,
        )

        self.assertTrue(any(finding.metadata.get("email") == "contact@example.com" for finding in findings))
        self.assertTrue(any(finding.metadata.get("subdomain") == "api.example.com" for finding in findings))
        self.assertTrue(any(finding.url == "https://www.example.com/admin" for finding in findings))

    def test_parse_bbot_json_events(self):
        findings = parse_adapter_output(
            "blacklanternsecurity/bbot",
            ScanTarget(kind="domain", value="example.com"),
            "\n".join(
                (
                    '{"type":"DNS_NAME","data":"api.example.com","module":"certspotter","scope_description":"in-scope","tags":["subdomain","in-scope"],"resolved_hosts":["93.184.216.34"]}',
                    '{"type":"EMAIL_ADDRESS","data":"admin@example.com","module":"emailformat","scope_description":"in-scope"}',
                    '{"type":"URL","data":"https://www.example.com/login","module":"httpx","scope_description":"in-scope"}',
                    '{"type":"IP_ADDRESS","data":"93.184.216.34","module":"dnsresolve"}',
                    '{"type":"OPEN_TCP_PORT","data":"api.example.com:443","host":"api.example.com","port":443,"module":"portscan"}',
                    '{"type":"TECHNOLOGY","data":"nginx","module":"wappalyzer"}',
                )
            ),
        )

        metadata = [finding.metadata for finding in findings]
        self.assertTrue(any(item.get("parser") == "bbot" for item in metadata))
        self.assertTrue(any(item.get("subdomain") == "api.example.com" and item.get("ip") == "93.184.216.34" for item in metadata))
        self.assertTrue(any(item.get("email") == "admin@example.com" for item in metadata))
        self.assertTrue(any(item.get("ip") == "93.184.216.34" for item in metadata))
        self.assertTrue(any(item.get("port") == "443" for item in metadata))
        self.assertTrue(any(item.get("technology") == "nginx" for item in metadata))
        self.assertIn("https://www.example.com/login", {finding.url for finding in findings})

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("subdomain", "api.example.com"), entities)
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("url", "https://www.example.com/login"), entities)
        self.assertIn(("ip", "93.184.216.34"), entities)
        self.assertIn(("port", "443"), entities)
        self.assertIn(("technology", "nginx"), entities)

    def test_parse_bbot_stdout_events(self):
        findings = parse_adapter_output(
            "blacklanternsecurity/bbot",
            ScanTarget(kind="domain", value="example.com"),
            """
            [DNS_NAME] api.example.com certspotter (distance-0, in-scope, subdomain)
            [EMAIL_ADDRESS] admin@example.com emailformat (distance-0, in-scope)
            [URL] https://www.example.com/login httpx (distance-0, in-scope)
            """,
        )

        self.assertTrue(any(finding.metadata.get("subdomain") == "api.example.com" for finding in findings))
        self.assertTrue(any(finding.metadata.get("email") == "admin@example.com" for finding in findings))
        self.assertTrue(any(finding.url == "https://www.example.com/login" for finding in findings))

    def test_parse_bbot_passive_web_alias_uses_bbot_parser(self):
        findings = parse_adapter_output(
            "blacklanternsecurity/bbot-passive-web",
            ScanTarget(kind="domain", value="example.com"),
            '{"type":"URL","data":"https://www.example.com/login","module":"httpx","scope_description":"in-scope"}',
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].url, "https://www.example.com/login")
        self.assertEqual(findings[0].metadata["parser"], "bbot")
        self.assertEqual(findings[0].metadata["repository"], "blacklanternsecurity/bbot-passive-web")

    def test_parse_spiderfoot_json_events(self):
        findings = parse_adapter_output(
            "smicallef/spiderfoot",
            ScanTarget(kind="domain", value="example.com"),
            """
            [
              {"type":"INTERNET_NAME","data":"api.example.com","module":"sfp_dnsresolve","confidence":100},
              {"type":"EMAILADDR","data":"Admin@Example.com","module":"sfp_email","confidence":80},
              {"type":"WEBLINK","data":"https://www.example.com/login","module":"sfp_spider","confidence":80},
              {"type":"IP_ADDRESS","data":"93.184.216.34","module":"sfp_dnsresolve","confidence":80},
              {"type":"TCP_PORT_OPEN","data":"api.example.com:443","module":"sfp_portscan","confidence":80},
              {"type":"PHONE_NUMBER","data":"+380441234567","module":"sfp_phone","confidence":80},
              {"type":"HUMAN_NAME","data":"Example Person","module":"sfp_names","confidence":80}
            ]
            """,
        )

        metadata = [finding.metadata for finding in findings]
        self.assertTrue(any(item.get("parser") == "spiderfoot" for item in metadata))
        self.assertTrue(any(item.get("target_kind") == "domain" and item.get("target_value") == "example.com" for item in metadata))
        self.assertTrue(any(item.get("subdomain") == "api.example.com" for item in metadata))
        self.assertTrue(any(item.get("email") == "admin@example.com" for item in metadata))
        self.assertTrue(any(item.get("ip") == "93.184.216.34" for item in metadata))
        self.assertTrue(any(item.get("port") == "443" for item in metadata))
        self.assertTrue(any(item.get("phone") == "+380441234567" for item in metadata))
        self.assertTrue(any(item.get("name") == "Example Person" for item in metadata))
        self.assertIn("https://www.example.com/login", {finding.url for finding in findings})

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("subdomain", "api.example.com"), entities)
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("url", "https://www.example.com/login"), entities)
        self.assertIn(("ip", "93.184.216.34"), entities)
        self.assertIn(("port", "443"), entities)
        self.assertIn(("phone", "+380441234567"), entities)
        self.assertIn(("name", "example person"), entities)

    def test_parse_spiderfoot_stdout_events(self):
        findings = parse_adapter_output(
            "smicallef/spiderfoot",
            ScanTarget(kind="domain", value="example.com"),
            """
            [INTERNET_NAME] api.example.com
            [EMAILADDR] admin@example.com
            [WEBLINK] https://www.example.com/login
            """,
        )

        self.assertTrue(any(finding.metadata.get("subdomain") == "api.example.com" for finding in findings))
        self.assertTrue(any(finding.metadata.get("email") == "admin@example.com" for finding in findings))
        self.assertTrue(any(finding.url == "https://www.example.com/login" for finding in findings))

    def test_parse_spiderfoot_non_domain_target_examples(self):
        cases = (
            (
                ScanTarget(kind="email", value="person@example.com"),
                """
                [
                  {"type":"EMAILADDR","data":"person@example.com","module":"sfp_email","confidence":90},
                  {"type":"PHONE_NUMBER","data":"+380441234567","module":"sfp_phone","confidence":80},
                  {"type":"ACCOUNT_EXTERNAL_OWNED","data":"@example_user","module":"sfp_accounts","confidence":70},
                  {"type":"WEBLINK","data":"https://example.com/profile","module":"sfp_spider","confidence":80}
                ]
                """,
                {("email", "person@example.com"), ("phone", "+380441234567"), ("username", "example_user"), ("url", "https://example.com/profile")},
            ),
            (
                ScanTarget(kind="phone", value="+380441234567"),
                """
                [
                  {"type":"PHONE_NUMBER","data":"+380441234567","module":"sfp_phone","confidence":90},
                  {"type":"EMAILADDR","data":"owner@example.com","module":"sfp_email","confidence":60},
                  {"type":"USERNAME","data":"example_user","module":"sfp_accounts","confidence":70}
                ]
                """,
                {("phone", "+380441234567"), ("email", "owner@example.com"), ("username", "example_user")},
            ),
            (
                ScanTarget(kind="username", value="example_user"),
                """
                [
                  {"type":"USERNAME","data":"example_user","module":"sfp_accounts","confidence":90},
                  {"type":"HUMAN_NAME","data":"Example Person","module":"sfp_names","confidence":70},
                  {"type":"WEBLINK","data":"https://social.example/example_user","module":"sfp_spider","confidence":70}
                ]
                """,
                {("username", "example_user"), ("name", "Example Person"), ("url", "https://social.example/example_user")},
            ),
        )

        for target, output, expected_entities in cases:
            with self.subTest(target=target):
                findings = parse_adapter_output("smicallef/spiderfoot", target, output)
                metadata = [finding.metadata for finding in findings]
                self.assertTrue(
                    any(
                        item.get("parser") == "spiderfoot"
                        and item.get("target_kind") == target.kind
                        and item.get("target_value") == target.value
                        for item in metadata
                    )
                )
                entities = {(entity.kind, entity.value) for entity in entities_from_findings(findings)}
                self.assertTrue(expected_entities.issubset(entities))

    def test_parse_argus_stdout_events(self):
        findings = parse_adapter_output(
            "jasonxtn/argus",
            ScanTarget(kind="domain", value="example.com"),
            """
            Associated Hosts: api.example.com
            Email Harvesting: admin@example.com
            Archive History: https://www.example.com/login
            IP Info: 93.184.216.34
            Open Ports Scan: 443/tcp open
            Technology Stack: nginx
            Contact: +380441234567
            """,
        )

        metadata = [finding.metadata for finding in findings]
        self.assertTrue(any(item.get("parser") == "argus" for item in metadata))
        self.assertTrue(any(item.get("subdomain") == "api.example.com" for item in metadata))
        self.assertTrue(any(item.get("email") == "admin@example.com" for item in metadata))
        self.assertTrue(any(item.get("ip") == "93.184.216.34" for item in metadata))
        self.assertTrue(any(item.get("port") == "443" for item in metadata))
        self.assertTrue(any(item.get("technology") == "nginx" for item in metadata))
        self.assertTrue(any(item.get("phone") == "+380441234567" for item in metadata))
        self.assertIn("https://www.example.com/login", {finding.url for finding in findings})

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("subdomain", "api.example.com"), entities)
        self.assertIn(("email", "admin@example.com"), entities)
        self.assertIn(("url", "https://www.example.com/login"), entities)
        self.assertIn(("ip", "93.184.216.34"), entities)
        self.assertIn(("port", "443"), entities)
        self.assertIn(("technology", "nginx"), entities)
        self.assertIn(("phone", "+380441234567"), entities)

    def test_parse_argus_per_target_examples(self):
        cases = (
            (
                ScanTarget(kind="email", value="person@example.com"),
                """
                {"module":"Email Intel","email":"person@example.com","host":"mail.example.com","ip":"93.184.216.34"}
                Linked Profile: https://social.example/person
                Open Ports Scan: 443/tcp open
                Technology Stack: nginx
                """,
                {("email", "person@example.com"), ("subdomain", "mail.example.com"), ("ip", "93.184.216.34"), ("url", "https://social.example/person"), ("port", "443"), ("technology", "nginx")},
            ),
            (
                ScanTarget(kind="phone", value="+380441234567"),
                """
                Contact: +380441234567
                Owner Email: owner@example.com
                Portal: https://phone.example/profile
                IP Info: 93.184.216.35
                """,
                {("phone", "+380441234567"), ("email", "owner@example.com"), ("url", "https://phone.example/profile"), ("ip", "93.184.216.35")},
            ),
            (
                ScanTarget(kind="username", value="example_user"),
                """
                Associated Hosts: profile.example.com
                Profile URL: https://profiles.example/example_user
                Email Harvesting: example_user@example.com
                Server Info: Apache
                """,
                {("subdomain", "profile.example.com"), ("url", "https://profiles.example/example_user"), ("email", "example_user@example.com"), ("technology", "Apache")},
            ),
            (
                ScanTarget(kind="domain", value="example.com"),
                """
                [{"module":"Infra","url":"https://api.example.com/login","subdomain":"api.example.com","port":8443,"technology":["nginx","waf"]}]
                """,
                {("url", "https://api.example.com/login"), ("subdomain", "api.example.com"), ("port", "8443"), ("technology", "nginx, waf")},
            ),
        )

        for target, output, expected_entities in cases:
            with self.subTest(target=target):
                findings = parse_adapter_output("jasonxtn/argus", target, output)
                metadata = [finding.metadata for finding in findings]
                self.assertTrue(
                    any(
                        item.get("parser") == "argus"
                        and item.get("target_kind") == target.kind
                        and item.get("target_value") == target.value
                        for item in metadata
                    )
                )
                entities = {(entity.kind, entity.value) for entity in entities_from_findings(findings)}
                self.assertTrue(expected_entities.issubset(entities))

    def test_parse_social_analyzer_json_profiles(self):
        findings = parse_adapter_output(
            "qeeqbox/social-analyzer",
            ScanTarget(kind="username", value="example_user"),
            """
            {
              "detected": [
                {
                  "link": "https://github.com/example_user",
                  "status": "good",
                  "rate": "%100.00",
                  "title": "Example User",
                  "language": "en",
                  "type": "coding",
                  "country": "us",
                  "metadata": [{"key": "bio"}]
                },
                {
                  "link": "https://twitter.com/example_user",
                  "status": "maybe",
                  "rate": "%66.67"
                }
              ],
              "unknown": [
                {
                  "site": "Missing Example",
                  "link": "https://missing.example/example_user"
                }
              ],
              "failed": [
                {
                  "site": "Broken Example",
                  "link": "https://broken.example/example_user"
                }
              ]
            }
            """,
        )

        statuses = {finding.metadata.get("site_name"): finding.status for finding in findings}
        self.assertEqual(statuses["github.com"], "candidate")
        self.assertEqual(statuses["twitter.com"], "candidate")
        self.assertEqual(statuses["Missing Example"], "not_found")
        self.assertEqual(statuses["Broken Example"], "error")

        github = next(finding for finding in findings if finding.url == "https://github.com/example_user")
        self.assertEqual(github.confidence, "high")
        self.assertEqual(github.metadata["parser"], "social-analyzer")
        self.assertEqual(github.metadata["result_status"], "good")
        self.assertEqual(github.metadata["rate"], "%100.00")
        self.assertEqual(github.metadata["platform_domain"], "github.com")
        self.assertEqual(github.metadata["social_username"], "example_user")
        self.assertEqual(github.metadata["metadata_count"], "1")

        missing = next(finding for finding in findings if finding.metadata.get("site_name") == "Missing Example")
        self.assertEqual(missing.url, "")
        self.assertEqual(missing.metadata["checked_url"], "https://missing.example/example_user")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("url", "https://github.com/example_user"), entities)
        self.assertIn(("domain", "github.com"), entities)
        self.assertIn(("domain", "twitter.com"), entities)
        self.assertIn(("username", "example_user"), entities)
        self.assertIn(("country", "us"), entities)

    def test_parse_socialscan_json_results(self):
        findings = parse_adapter_output(
            "iojw/socialscan",
            ScanTarget(kind="username", value="example_user"),
            json.dumps(
                {
                    "example_user": [
                        {
                            "platform": "GitHub",
                            "query": "example_user",
                            "available": "False",
                            "valid": "True",
                            "success": "True",
                            "message": "Username is already taken",
                            "link": "https://github.com/example_user",
                        },
                        {
                            "platform": "GitLab",
                            "query": "example_user",
                            "available": "True",
                            "valid": "True",
                            "success": "True",
                            "message": "Available",
                        },
                        {
                            "platform": "Reddit",
                            "query": "bad username",
                            "available": "False",
                            "valid": "False",
                            "success": "True",
                            "message": "Invalid username",
                        },
                        {
                            "platform": "Twitter",
                            "query": "example_user",
                            "available": "False",
                            "valid": "False",
                            "success": "False",
                            "message": "ClientError - rate limited",
                        },
                    ]
                }
            ),
        )

        statuses = {finding.metadata.get("platform"): finding.status for finding in findings}
        self.assertEqual(statuses["GitHub"], "candidate")
        self.assertEqual(statuses["GitLab"], "not_found")
        self.assertEqual(statuses["Reddit"], "skipped")
        self.assertEqual(statuses["Twitter"], "error")

        github = next(finding for finding in findings if finding.metadata.get("platform") == "GitHub")
        self.assertEqual(github.url, "https://github.com/example_user")
        self.assertEqual(github.confidence, "high")
        self.assertEqual(github.metadata["parser"], "socialscan")
        self.assertEqual(github.metadata["availability_status"], "taken_or_reserved")
        self.assertEqual(github.metadata["username"], "example_user")
        self.assertEqual(github.metadata["domain"], "github.com")
        self.assertEqual(github.metadata["available"], "False")

        gitlab = next(finding for finding in findings if finding.metadata.get("platform") == "GitLab")
        self.assertEqual(gitlab.url, "")
        self.assertEqual(gitlab.metadata["availability_status"], "available")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("url", "https://github.com/example_user"), entities)
        self.assertIn(("domain", "github.com"), entities)
        self.assertIn(("username", "example_user"), entities)

    def test_parse_socialscan_email_json_results(self):
        findings = parse_adapter_output(
            "iojw/socialscan",
            ScanTarget(kind="email", value="person@example.com"),
            json.dumps(
                {
                    "GitHub": [
                        {
                            "platform": "GitHub",
                            "query": "person@example.com",
                            "available": "False",
                            "valid": "True",
                            "success": "True",
                            "message": "Email is already taken",
                        }
                    ]
                }
            ),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "candidate")
        self.assertEqual(findings[0].metadata["parser"], "socialscan")
        self.assertEqual(findings[0].metadata["email"], "person@example.com")
        self.assertEqual(findings[0].metadata["platform"], "GitHub")
        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("email", "person@example.com"), entities)

    def test_parse_blackbird_json_export_profiles(self):
        findings = parse_adapter_output(
            "p1ngul1n0/blackbird",
            ScanTarget(kind="username", value="example_user"),
            """
            [
              {
                "name": "GitHub",
                "url": "https://github.com/example_user",
                "category": "coding",
                "status": "FOUND",
                "metadata": [
                  {"name": "Name", "value": "Example User"},
                  {"name": "Location", "value": "Kyiv"},
                  {"name": "Profile Image", "value": "https://avatars.githubusercontent.com/u/123"}
                ]
              },
              {
                "name": "Missing Example",
                "url": "https://missing.example/example_user",
                "category": "social",
                "status": "NOT-FOUND"
              }
            ]
            """,
        )

        statuses = {finding.metadata.get("site_name"): finding.status for finding in findings}
        self.assertEqual(statuses["GitHub"], "candidate")
        self.assertEqual(statuses["Missing Example"], "not_found")

        github = next(finding for finding in findings if finding.metadata.get("site_name") == "GitHub")
        self.assertEqual(github.url, "https://github.com/example_user")
        self.assertEqual(github.metadata["parser"], "blackbird")
        self.assertEqual(github.metadata["category"], "coding")
        self.assertEqual(github.metadata["platform_domain"], "github.com")
        self.assertEqual(github.metadata["social_username"], "example_user")
        self.assertEqual(github.metadata["name"], "Example User")
        self.assertEqual(github.metadata["location"], "Kyiv")
        self.assertEqual(github.metadata["profile_image_url"], "https://avatars.githubusercontent.com/u/123")

        missing = next(finding for finding in findings if finding.metadata.get("site_name") == "Missing Example")
        self.assertEqual(missing.url, "")
        self.assertEqual(missing.metadata["checked_url"], "https://missing.example/example_user")

        entities = {(entity.kind, entity.value.lower()) for entity in entities_from_findings(findings)}
        self.assertIn(("url", "https://github.com/example_user"), entities)
        self.assertIn(("domain", "github.com"), entities)
        self.assertIn(("username", "example_user"), entities)
        self.assertIn(("name", "example user"), entities)
        self.assertIn(("location", "kyiv"), entities)

    def test_parse_blackbird_stdout_found_profile(self):
        findings = parse_adapter_output(
            "p1ngul1n0/blackbird",
            ScanTarget(kind="email", value="person@example.com"),
            "✔️ [GitHub] https://github.com/example_user\n",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "candidate")
        self.assertEqual(findings[0].url, "https://github.com/example_user")
        self.assertEqual(findings[0].metadata["parser"], "blackbird")
        self.assertEqual(findings[0].metadata["email"], "person@example.com")

    def test_run_adapter_findings_adds_parsed_results_after_execution(self):
        completed = subprocess.CompletedProcess(
            args=["sherlock", "example_user"],
            returncode=0,
            stdout="[+] GitHub: https://github.com/example_user\n",
            stderr="",
        )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="sherlock"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            return_value=completed,
        ):
            findings = run_adapter_findings(
                "sherlock-project/sherlock",
                ScanTarget(kind="username", value="example_user"),
                execute=True,
            )

        self.assertEqual(findings[0].module, "external-adapter")
        self.assertEqual(findings[0].status, "completed")
        self.assertTrue(any(finding.url == "https://github.com/example_user" for finding in findings[1:]))

    def test_run_sherlock_adapter_reads_generated_csv_report_after_execution(self):
        def fake_run(args, **kwargs):
            self.assertIn("--csv", args)
            self.assertIn("--txt", args)
            self.assertIn("--print-all", args)
            output_dir = Path(args[args.index("--folderoutput") + 1])
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "example_user.csv").write_text(
                "username,name,url_main,url_user,exists,http_status,response_time_s\n"
                "example_user,GitHub,https://github.com,https://github.com/example_user,Claimed,200,0.1\n"
                "example_user,Instagram,https://www.instagram.com,https://www.instagram.com/example_user,Available,404,0.1\n",
                encoding="utf-8",
            )
            (output_dir / "example_user.txt").write_text(
                "https://github.com/example_user\nTotal Websites Username Detected On : 1\n",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="Search completed\n", stderr="")

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="sherlock"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            findings = run_adapter_findings(
                "sherlock-project/sherlock",
                ScanTarget(kind="username", value="example_user"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["generated_output_files"], "2")
        self.assertIn("--folderoutput", findings[0].metadata["command"])
        statuses = {finding.metadata.get("site_name"): finding.status for finding in findings[1:]}
        self.assertEqual(statuses["GitHub"], "candidate")
        self.assertEqual(statuses["Instagram"], "not_found")
        self.assertEqual(
            sum(1 for finding in findings[1:] if finding.url == "https://github.com/example_user"),
            1,
        )

    def test_run_nexfil_adapter_reads_autosaved_txt_report_after_execution(self):
        def fake_run(args, **kwargs):
            self.assertEqual(args[:3], ["nexfil", "-u", "example_user"])
            output_dir = Path(kwargs["cwd"])
            self.assertEqual(kwargs["env"]["HOME"], str(output_dir))
            dump_dir = output_dir / ".local" / "share" / "nexfil" / "dumps"
            dump_dir.mkdir(parents=True, exist_ok=True)
            (dump_dir / "example_user_123.txt").write_text(
                "nexfil v1.0.6\n"
                "----------------------------------------\n"
                "Username : example_user\n"
                "Total Hits : 1\n"
                "Total Timeouts : 0\n"
                "Total Errors : 0\n\n"
                "URLs : \n\n"
                "https://github.com/example_user\n"
                "----------------------------------------\n",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=(
                    "|---> Twitter : https://twitter.com/thewhiteh4t\n"
                    "https://github.com/example_user\n"
                    "[+] Saved : report\n"
                ),
                stderr="",
            )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="nexfil"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            findings = run_adapter_findings(
                "thewhiteh4t/nexfil",
                ScanTarget(kind="username", value="example_user"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["generated_output_files"], "1")
        self.assertEqual(
            sum(1 for finding in findings[1:] if finding.url == "https://github.com/example_user"),
            1,
        )
        self.assertFalse(any(finding.url == "https://twitter.com/thewhiteh4t" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("parser") == "nexfil" for finding in findings[1:]))

    def test_run_maigret_adapter_reads_generated_json_report_after_execution(self):
        def fake_run(args, **kwargs):
            output_dir = Path(args[args.index("--folderoutput") + 1])
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "report_bellingcat_ndjson.json").write_text(
                '{"sitename":"GitHub","url_user":"https://github.com/bellingcat","http_status":200,'
                '"status":{"username":"bellingcat","site_name":"GitHub","url":"https://github.com/bellingcat",'
                '"status":"Claimed","ids":{"fullname":"Bellingcat"},"tags":["global"]}}\n',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="JSON report saved\n", stderr="")

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="maigret"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            findings = run_adapter_findings(
                "soxoj/maigret",
                ScanTarget(kind="username", value="bellingcat"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["generated_output_files"], "1")
        self.assertIn("--folderoutput", findings[0].metadata["command"])
        self.assertTrue(any(finding.metadata.get("parser") == "maigret" for finding in findings[1:]))
        self.assertTrue(any(finding.url == "https://github.com/bellingcat" for finding in findings[1:]))

    def test_run_mosint_adapter_reads_generated_json_report_after_execution(self):
        def fake_run(args, **kwargs):
            self.assertIn("--silent", args)
            output_file = Path(args[args.index("--output") + 1])
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(
                '{"email":"target@example.com","verified":true,'
                '"hunter":{"data":{"domain":"example.com","emails":[{"value":"admin@example.com"}]},"meta":{"results":1}},'
                '"breachdirectory":{"success":true,"found":1,"result":[{"has_password":true,"password":"secret-value","sources":["combo-db"]}]}}',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="JSON report saved\n", stderr="")

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="mosint"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            findings = run_adapter_findings(
                "alpkeskin/mosint",
                ScanTarget(kind="email", value="target@example.com"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["generated_output_files"], "1")
        self.assertIn("--output", findings[0].metadata["command"])
        self.assertTrue(any(finding.metadata.get("parser") == "mosint" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("email") == "admin@example.com" for finding in findings[1:]))
        self.assertFalse(any("secret-value" in finding.evidence for finding in findings))

    def test_run_h8mail_adapter_reads_generated_json_report_after_execution(self):
        def fake_run(args, **kwargs):
            self.assertIn("--hide", args)
            output_file = Path(args[args.index("-j") + 1])
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(
                '{"targets":[{"target":"target@example.com","pwn_num":1,'
                '"data":[["HUNTER_RELATED:admin@example.com"],["SNUS_PASSWORD:secret-value","SNUS_SOURCE:combo-db"]]}]}',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="JSON report saved\n", stderr="")

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="h8mail"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            findings = run_adapter_findings(
                "khast3x/h8mail",
                ScanTarget(kind="email", value="target@example.com"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["generated_output_files"], "1")
        self.assertIn("-j", findings[0].metadata["command"])
        self.assertTrue(any(finding.metadata.get("parser") == "h8mail" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("email") == "admin@example.com" for finding in findings[1:]))
        self.assertFalse(any("secret-value" in finding.evidence for finding in findings))

    def test_run_theharvester_adapter_reads_generated_json_report_after_execution(self):
        def fake_run(args, **kwargs):
            if tuple(args) == ("theHarvester", "-h"):
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="theHarvester\n  -d\n  -b\n", stderr="")
            self.assertEqual(args[:5], ["theHarvester", "-d", "example.com", "-b", "all"])
            output_file = Path(args[args.index("-f") + 1])
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(
                '{"emails":["admin@example.com"],"hosts":["api.example.com"],"interesting_urls":["https://www.example.com/login"]}',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="JSON File saved\n", stderr="")

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="theHarvester"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            findings = run_adapter_findings(
                "laramies/theHarvester",
                ScanTarget(kind="domain", value="example.com"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["generated_output_files"], "1")
        self.assertIn("-f", findings[0].metadata["command"])
        self.assertTrue(any(finding.metadata.get("parser") == "theharvester" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("email") == "admin@example.com" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("subdomain") == "api.example.com" for finding in findings[1:]))
        self.assertTrue(any(finding.url == "https://www.example.com/login" for finding in findings[1:]))

    def test_run_spiderfoot_adapter_requires_script_path_before_execution(self):
        with patch.dict(os.environ, {}, clear=True), patch("osint_toolkit.adapter_runner.subprocess.run") as run:
            findings = run_adapter_findings(
                "smicallef/spiderfoot",
                ScanTarget(kind="domain", value="example.com"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "config_missing")
        self.assertEqual(findings[0].metadata["missing_env"], "SPIDERFOOT_SF_PATH")
        run.assert_not_called()

    def test_run_spiderfoot_adapter_parses_json_stdout_after_execution(self):
        completed = subprocess.CompletedProcess(
            args=["python", "sf.py", "-s", "person@example.com", "-u", "passive", "-o", "json", "-q"],
            returncode=0,
            stdout=(
                '[{"type":"EMAILADDR","data":"person@example.com","module":"sfp_email","confidence":90},'
                '{"type":"PHONE_NUMBER","data":"+380441234567","module":"sfp_phone","confidence":80},'
                '{"type":"USERNAME","data":"example_user","module":"sfp_accounts","confidence":70}]'
            ),
            stderr="",
        )

        with patch.dict(os.environ, {"SPIDERFOOT_SF_PATH": "C:\\tools\\spiderfoot\\sf.py"}), patch(
            "osint_toolkit.adapter_runner.shutil.which",
            return_value="C:\\Python\\python.exe",
        ), patch("osint_toolkit.adapter_runner.subprocess.run", return_value=completed) as run:
            findings = run_adapter_findings(
                "smicallef/spiderfoot",
                ScanTarget(kind="email", value="person@example.com"),
                execute=True,
            )

        args = run.call_args.args[0]
        self.assertEqual(args[:3], ["C:\\Python\\python.exe", "C:\\tools\\spiderfoot\\sf.py", "-s"])
        self.assertEqual(args[3], "person@example.com")
        self.assertIn("-u", args)
        self.assertIn("passive", args)
        self.assertEqual(findings[0].status, "completed")
        self.assertTrue(any(finding.metadata.get("parser") == "spiderfoot" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("email") == "person@example.com" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("phone") == "+380441234567" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("username") == "example_user" for finding in findings[1:]))

    def test_run_argus_adapter_feeds_interactive_script_after_execution(self):
        def fake_run(args, **kwargs):
            self.assertEqual(args, ["C:\\tools\\argus.exe"])
            self.assertEqual(kwargs["input"], "set target example.com\nrunall infra\nviewout\nexit\n")
            self.assertTrue(kwargs["text"])
            self.assertTrue(kwargs["capture_output"])
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=(
                    "Associated Hosts: api.example.com\n"
                    "Email Harvesting: admin@example.com\n"
                    "Archive History: https://www.example.com/login\n"
                ),
                stderr="",
            )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="C:\\tools\\argus.exe"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            findings = run_adapter_findings(
                "jasonxtn/argus",
                ScanTarget(kind="domain", value="example.com"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["stdin_lines"], "4")
        self.assertTrue(any(finding.metadata.get("parser") == "argus" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("email") == "admin@example.com" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("subdomain") == "api.example.com" for finding in findings[1:]))
        self.assertTrue(any(finding.url == "https://www.example.com/login" for finding in findings[1:]))

    def test_run_yark_adapter_reads_generated_archive_json_after_execution(self):
        target = ScanTarget(kind="url", value="https://www.youtube.com/channel/ExampleChannel")

        def fake_run(args, **kwargs):
            self.assertEqual(args[:2], ["C:\\tools\\yark.exe", "new"])
            self.assertEqual(args[2], "youtube.com-channel-examplechannel")
            self.assertEqual(args[3], target.value)
            archive_dir = Path(kwargs["cwd"]) / args[2]
            archive_dir.mkdir(parents=True)
            (archive_dir / "yark.json").write_text(
                json.dumps(
                    {
                        "version": 3,
                        "url": target.value,
                        "videos": [
                            {
                                "id": "abc123DEF",
                                "uploaded": "2026-06-20T10:00:00",
                                "width": 1920,
                                "height": 1080,
                                "title": {"2026-06-20T10:00:00": "Archived title"},
                                "description": {"2026-06-20T10:00:00": "Archived description"},
                                "views": {"2026-06-20T10:00:00": 1200},
                                "likes": {"2026-06-20T10:00:00": 55},
                                "thumbnail": {"2026-06-20T10:00:00": "thumbhash"},
                                "deleted": {"2026-06-20T10:00:00": False},
                                "notes": [],
                            }
                        ],
                        "livestreams": [],
                        "shorts": [],
                    }
                ),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="Creating new channel..\n", stderr="")

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="C:\\tools\\yark.exe"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            findings = run_adapter_findings("Owez/yark", target, execute=True)

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["generated_output_files"], "1")
        parsed = [finding for finding in findings[1:] if finding.metadata.get("parser") == "yark"]
        self.assertTrue(parsed)
        self.assertTrue(any(finding.url == "https://www.youtube.com/watch?v=abc123DEF" for finding in parsed))

    def test_run_social_analyzer_adapter_parses_json_stdout_after_execution(self):
        def fake_run(args, **kwargs):
            self.assertEqual(args[:4], ["C:\\node\\node.exe", "C:\\tools\\social-analyzer\\app.js", "--username", "example_user"])
            self.assertIn("--output", args)
            self.assertIn("json", args)
            self.assertIn("--countries", args)
            self.assertIn("ru", args)
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout='{"detected":[{"link":"https://github.com/example_user","status":"good","rate":"%100.00"}]}',
                stderr="",
            )

        with patch.dict(os.environ, {"SOCIAL_ANALYZER_APP_JS": "C:\\tools\\social-analyzer\\app.js"}), patch(
            "osint_toolkit.adapter_runner.shutil.which",
            return_value="C:\\node\\node.exe",
        ), patch("osint_toolkit.adapter_runner.subprocess.run", side_effect=fake_run):
            findings = run_adapter_findings(
                "qeeqbox/social-analyzer",
                ScanTarget(kind="username", value="example_user", region="ru"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertTrue(any(finding.metadata.get("parser") == "social-analyzer" for finding in findings[1:]))
        self.assertTrue(any(finding.url == "https://github.com/example_user" for finding in findings[1:]))

    def test_run_socialscan_adapter_reads_generated_json_after_execution(self):
        def fake_run(args, **kwargs):
            self.assertEqual(args[:2], ["C:\\tools\\socialscan.exe", "example_user"])
            self.assertIn("--json", args)
            output_path = Path(args[args.index("--json") + 1])
            output_path.write_text(
                json.dumps(
                    {
                        "example_user": [
                            {
                                "platform": "GitHub",
                                "query": "example_user",
                                "available": "False",
                                "valid": "True",
                                "success": "True",
                                "message": "Username is already taken",
                                "link": "https://github.com/example_user",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="Completed 1 queries\n", stderr="")

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="C:\\tools\\socialscan.exe"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            findings = run_adapter_findings(
                "iojw/socialscan",
                ScanTarget(kind="username", value="example_user"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["generated_output_files"], "1")
        parsed = [finding for finding in findings[1:] if finding.metadata.get("parser") == "socialscan"]
        self.assertTrue(parsed)
        self.assertTrue(any(finding.url == "https://github.com/example_user" for finding in parsed))

    def test_run_blackbird_adapter_reads_fresh_generated_json_after_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            blackbird_dir = Path(directory)
            results_dir = blackbird_dir / "results"
            stale_dir = results_dir / "old_01_01_2026_blackbird"
            stale_dir.mkdir(parents=True)
            (stale_dir / "old_01_01_2026_blackbird.json").write_text(
                '[{"name":"Old","url":"https://old.example/example_user","status":"FOUND"}]',
                encoding="utf-8",
            )

            def fake_run(args, **kwargs):
                self.assertEqual(args[:4], ["C:\\Python\\python.exe", "blackbird.py", "--username", "example_user"])
                self.assertIn("--json", args)
                self.assertIn("--no-update", args)
                self.assertEqual(Path(kwargs["cwd"]), blackbird_dir)
                fresh_dir = results_dir / "example_user_06_25_2026_blackbird"
                fresh_dir.mkdir(parents=True)
                (fresh_dir / "example_user_06_25_2026_blackbird.json").write_text(
                    '[{"name":"GitHub","url":"https://github.com/example_user","category":"coding","status":"FOUND"}]',
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="Saved results\n", stderr="")

            with patch.dict(os.environ, {"BLACKBIRD_DIR": str(blackbird_dir)}), patch(
                "osint_toolkit.adapter_runner.shutil.which",
                return_value="C:\\Python\\python.exe",
            ), patch("osint_toolkit.adapter_runner.subprocess.run", side_effect=fake_run):
                findings = run_adapter_findings(
                    "p1ngul1n0/blackbird",
                    ScanTarget(kind="username", value="example_user"),
                    execute=True,
                )

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["generated_output_files"], "1")
        self.assertTrue(any(finding.metadata.get("parser") == "blackbird" for finding in findings[1:]))
        urls = {finding.url for finding in findings[1:]}
        self.assertIn("https://github.com/example_user", urls)
        self.assertNotIn("https://old.example/example_user", urls)

    def test_run_bbot_adapter_reads_generated_json_events_after_execution(self):
        def fake_run(args, **kwargs):
            if tuple(args) == ("bbot", "-h"):
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="bbot usage\n  -t TARGET\n  -p PRESET\n", stderr="")
            if tuple(args) == ("bbot", "-t", "example.com", "-p", "subdomain-enum", "-rf", "passive", "--dry-run", "-y"):
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="dry run ok\n", stderr="")
            self.assertEqual(args[:7], ["bbot", "-t", "example.com", "-p", "subdomain-enum", "-rf", "passive"])
            output_dir = Path(args[args.index("-o") + 1])
            scan_dir = output_dir / "osint-toolkit"
            scan_dir.mkdir(parents=True, exist_ok=True)
            (scan_dir / "output.json").write_text(
                '{"type":"DNS_NAME","data":"api.example.com","module":"certspotter","scope_description":"in-scope"}\n'
                '{"type":"EMAIL_ADDRESS","data":"admin@example.com","module":"emailformat","scope_description":"in-scope"}\n'
                '{"type":"URL","data":"https://www.example.com/login","module":"httpx","scope_description":"in-scope"}\n',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="Scan complete\n", stderr="")

        with patch.dict(os.environ, {"BBOT_RUNNER": "native"}), patch(
            "osint_toolkit.adapter_runner.shutil.which",
            return_value="bbot",
        ), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            findings = run_adapter_findings(
                "blacklanternsecurity/bbot",
                ScanTarget(kind="domain", value="example.com"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["generated_output_files"], "1")
        self.assertIn("-o", findings[0].metadata["command"])
        self.assertIn("-n osint-toolkit", findings[0].metadata["command"])
        self.assertTrue(any(finding.metadata.get("parser") == "bbot" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("email") == "admin@example.com" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("subdomain") == "api.example.com" for finding in findings[1:]))
        self.assertTrue(any(finding.url == "https://www.example.com/login" for finding in findings[1:]))

    def test_run_bbot_passive_web_adapter_uses_broader_passive_command(self):
        def fake_run(args, **kwargs):
            if tuple(args) == ("bbot", "-h"):
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="bbot usage\n  -t TARGET\n  -p PRESET\n  -rf FLAG\n  -ef FLAG\n", stderr="")
            if tuple(args) == (
                "bbot",
                "-t",
                "example.com",
                "-p",
                "subdomain-enum",
                "web-basic",
                "-rf",
                "passive",
                "-ef",
                "active",
                "aggressive",
                "deadly",
                "portscan",
                "web-screenshots",
                "--dry-run",
                "-y",
            ):
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="dry run ok\n", stderr="")
            self.assertEqual(
                args[:15],
                [
                    "bbot",
                    "-t",
                    "example.com",
                    "-p",
                    "subdomain-enum",
                    "web-basic",
                    "-rf",
                    "passive",
                    "-ef",
                    "active",
                    "aggressive",
                    "deadly",
                    "portscan",
                    "web-screenshots",
                    "-o",
                ],
            )
            output_dir = Path(args[args.index("-o") + 1])
            scan_dir = output_dir / "osint-toolkit"
            scan_dir.mkdir(parents=True, exist_ok=True)
            (scan_dir / "output.json").write_text(
                '{"type":"URL","data":"https://www.example.com/login","module":"httpx","scope_description":"in-scope"}\n',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="Scan complete\n", stderr="")

        with patch.dict(os.environ, {"BBOT_RUNNER": "native"}), patch(
            "osint_toolkit.adapter_runner.shutil.which",
            return_value="bbot",
        ), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            side_effect=fake_run,
        ):
            findings = run_adapter_findings(
                "blacklanternsecurity/bbot-passive-web",
                ScanTarget(kind="domain", value="example.com"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertIn("web-basic", findings[0].metadata["command"])
        self.assertIn("-ef active aggressive deadly portscan web-screenshots", findings[0].metadata["command"])
        self.assertTrue(any(finding.metadata.get("parser") == "bbot" for finding in findings[1:]))
        self.assertTrue(any(finding.url == "https://www.example.com/login" for finding in findings[1:]))

    def test_run_user_scanner_adapter_adds_parsed_json_results_after_execution(self):
        completed = subprocess.CompletedProcess(
            args=["user-scanner", "-u", "kaifcodec", "-f", "json"],
            returncode=0,
            stdout='[{"status":"Found","username":"kaifcodec","site_name":"Github","category":"Dev","url":"https://github.com/kaifcodec","extra":{},"reason":""}]',
            stderr="",
        )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="user-scanner"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            return_value=completed,
        ):
            findings = run_adapter_findings(
                "kaifcodec/user-scanner",
                ScanTarget(kind="username", value="kaifcodec"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertTrue(any(finding.metadata.get("site_name") == "Github" for finding in findings[1:]))

    def test_run_pwnedornot_adapter_adds_parsed_breach_results_after_execution(self):
        completed = subprocess.CompletedProcess(
            args=["pwnedornot", "-e", "person@example.com", "-n"],
            returncode=0,
            stdout="""
            [+] Checking Breach status for person@example.com [ pwned ]

            [*] Total Breaches : 1

            Breach       : Adobe
            Domain       : adobe.com
            Date         : 2013-10-04
            BreachedInfo : Emails, Passwords
            Fabricated   : False
            Verified     : True
            Retired      : False
            Spam         : False
            """,
            stderr="",
        )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="pwnedornot"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            return_value=completed,
        ):
            findings = run_adapter_findings(
                "thewhiteh4t/pwnedOrNot",
                ScanTarget(kind="email", value="person@example.com"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertIn("-n", findings[0].metadata["command"])
        self.assertTrue(any(finding.metadata.get("parser") == "pwnedornot" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("breach_name") == "Adobe" for finding in findings[1:]))

    def test_run_detectdee_adapter_reads_generated_result_file_after_execution(self):
        def fake_run(args, **kwargs):
            if list(args[1:]) == ["detect", "-h"]:
                return subprocess.CompletedProcess(
                    args=args,
                    returncode=0,
                    stdout="DetectDee detect [flags]\n  -n, --name\n  -e, --email\n  -p, --phone\n  -o, --output\n",
                    stderr="",
                )
            self.assertEqual(args[1:4], ["detect", "-n", "example_user"])
            self.assertIn("-f", args)
            self.assertIn("C:\\tools\\DetectDee\\data.json", args)
            output_file = Path(args[args.index("-o") + 1])
            output_file.write_text(
                "example_user, github, https://github.com/example_user\n",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="Detect completed\n", stderr="")

        with patch.dict(os.environ, {"DETECTDEE_DATA": "C:\\tools\\DetectDee\\data.json"}), patch(
            "osint_toolkit.adapter_runner.shutil.which",
            return_value="C:\\tools\\DetectDee.exe",
        ), patch("osint_toolkit.adapter_runner.subprocess.run", side_effect=fake_run):
            findings = run_adapter_findings(
                "Yvesssn/DetectDee",
                ScanTarget(kind="username", value="example_user"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertEqual(findings[0].metadata["generated_output_files"], "1")
        self.assertIn("-o", findings[0].metadata["command"])
        self.assertTrue(any(finding.metadata.get("parser") == "detectdee" for finding in findings[1:]))
        self.assertTrue(any(finding.url == "https://github.com/example_user" for finding in findings[1:]))

    def test_run_snoop_adapter_adds_parsed_results_after_execution(self):
        completed = subprocess.CompletedProcess(
            args=["snoop", "--no-func", "--found-print", "--include", "UA", "example_user"],
            returncode=0,
            stdout="[+] Example UA: https://example.ua/example_user\n",
            stderr="",
        )

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="snoop"), patch(
            "osint_toolkit.adapter_runner.subprocess.run",
            return_value=completed,
        ):
            findings = run_adapter_findings(
                "snooppr/snoop",
                ScanTarget(kind="username", value="example_user", region="ua"),
                execute=True,
            )

        self.assertEqual(findings[0].status, "completed")
        self.assertTrue(any(finding.metadata.get("parser") == "snoop" for finding in findings[1:]))
        self.assertTrue(any(finding.url == "https://example.ua/example_user" for finding in findings[1:]))


if __name__ == "__main__":
    unittest.main()
