import os
import subprocess
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
            args=["python", "sf.py", "-s", "example.com", "-u", "passive", "-o", "json", "-q"],
            returncode=0,
            stdout=(
                '[{"type":"INTERNET_NAME","data":"api.example.com","module":"sfp_dnsresolve","confidence":100},'
                '{"type":"EMAILADDR","data":"admin@example.com","module":"sfp_email","confidence":80},'
                '{"type":"WEBLINK","data":"https://www.example.com/login","module":"sfp_spider","confidence":80}]'
            ),
            stderr="",
        )

        with patch.dict(os.environ, {"SPIDERFOOT_SF_PATH": "C:\\tools\\spiderfoot\\sf.py"}), patch(
            "osint_toolkit.adapter_runner.shutil.which",
            return_value="C:\\Python\\python.exe",
        ), patch("osint_toolkit.adapter_runner.subprocess.run", return_value=completed) as run:
            findings = run_adapter_findings(
                "smicallef/spiderfoot",
                ScanTarget(kind="domain", value="example.com"),
                execute=True,
            )

        args = run.call_args.args[0]
        self.assertEqual(args[:3], ["C:\\Python\\python.exe", "C:\\tools\\spiderfoot\\sf.py", "-s"])
        self.assertIn("-u", args)
        self.assertIn("passive", args)
        self.assertEqual(findings[0].status, "completed")
        self.assertTrue(any(finding.metadata.get("parser") == "spiderfoot" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("email") == "admin@example.com" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("subdomain") == "api.example.com" for finding in findings[1:]))
        self.assertTrue(any(finding.url == "https://www.example.com/login" for finding in findings[1:]))

    def test_run_bbot_adapter_reads_generated_json_events_after_execution(self):
        def fake_run(args, **kwargs):
            self.assertEqual(args[:7], ["bbot", "-t", "example.com", "-p", "subdomain-enum", "-rf", "passive"])
            output_dir = Path(args[args.index("--output") + 1])
            scan_dir = output_dir / "osint-toolkit"
            scan_dir.mkdir(parents=True, exist_ok=True)
            (scan_dir / "output.json").write_text(
                '{"type":"DNS_NAME","data":"api.example.com","module":"certspotter","scope_description":"in-scope"}\n'
                '{"type":"EMAIL_ADDRESS","data":"admin@example.com","module":"emailformat","scope_description":"in-scope"}\n'
                '{"type":"URL","data":"https://www.example.com/login","module":"httpx","scope_description":"in-scope"}\n',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="Scan complete\n", stderr="")

        with patch("osint_toolkit.adapter_runner.shutil.which", return_value="bbot"), patch(
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
        self.assertIn("--output", findings[0].metadata["command"])
        self.assertTrue(any(finding.metadata.get("parser") == "bbot" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("email") == "admin@example.com" for finding in findings[1:]))
        self.assertTrue(any(finding.metadata.get("subdomain") == "api.example.com" for finding in findings[1:]))
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
