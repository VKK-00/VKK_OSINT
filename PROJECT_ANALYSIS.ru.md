# Анализ проекта

## Цель проекта

Создать собственную единую OSINT-систему на основе уже собранного каталога GitHub OSINT-проектов.

Целевая модель — 1:1 функциональная совместимость с upstream-проектами в одном интерфейсе: часть возможностей переносится в native-модули, часть подключается через внешние CLI/API adapters, а высокорисковые механики выносятся в restricted-слой.

Под 1:1 здесь понимается не безусловное копирование исходников, а воспроизведение поведения: такой же класс входов, сопоставимый результат, единая нормализация в `Finding`, понятные confidence/status и явно описанный gap, если upstream-поведение ещё не покрыто. Внешний adapter считается рабочим способом 1:1 parity, когда он запускает реальный upstream CLI/API и нормализует его вывод. Буквальный перенос кода возможен только после проверки лицензии и совместимости.

Операционная цель следующего слоя описана в `DEEP_INTEGRATION_PLAN.ru.md`: один seed должен автоматически разворачиваться в полный fan-out по совместимым native-модулям и upstream tools, без ручного запуска каждого сервиса отдельно.

## Что делает проект

Проект хранит датированные CSV/Markdown/JSON-срезы GitHub OSINT-проектов и предоставляет Python CLI/engine поверх этих данных.

CLI работает в пяти режимах:

- catalog/recommend/brief — работа с curated-каталогом;
- scan/adapters — единое ядро выполнения и карта функциональной совместимости upstream-проектов;
- search — high-level fan-out планировщик и executor: один seed -> native checks, compatible adapters, readiness/install hints, local image tools; при `--execute-adapters` запускаются ready non-restricted adapters или ready local image tools с derived-seed fan-out в единый report/case;
- investigate — объединение нескольких seed values, native findings, adapter dry-runs и нормализованных сущностей в один отчёт;
- toolbox — локальное HTML-окно для ручного выбора OSINT-направления, сборки copy-ready CLI-команд и, в `--serve` режиме, запуска unified `search` jobs через локальный backend.

Первый native-слой уже выполняет:

- person-name expansion: нормализация имени, RU/UA transliteration и username-кандидаты;
- username public profile checks по 2014 активным URL/check-шаблонам: 38 curated правил, импорт Sherlock `data.json` GET/POST entries, импорт WhatsMyName `wmn-data.json` GET/POST entries и sanitized Maigret site rules, совместимые по классу задачи с Sherlock/Maigret/WhatsMyName/Nexfil;
- platform-specific username rules: несовместимые site checks возвращаются как `skipped`, без построения заведомо неверного URL;
- content marker rules для live username checks: profile markers повышают confidence, soft-404 markers дают `not_found`;
- email baseline checks: синтаксис, live domain resolution, MX/NS/TXT lookup, SPF, DMARC, MTA-STS, TLS-RPT, BIMI и TXT service signal classification;
- phone baseline checks: нормализация, E.164-like validation и country-prefix signal;
- domain baseline recon: DNS resolution, HTTP/HTTPS metadata, bounded same-site crawler, robots/sitemap discovery, public email/phone/social link extraction, presence security headers, certificate transparency subdomain discovery, RDAP registration lookup и raw WHOIS fallback;
- Telegram baseline: handle/post URL normalization и optional live public metadata;
- Instagram/social baseline: username/profile/media URL normalization и optional live public profile/media metadata без login/session flows;
- RU social baseline: VK/OK/Yandex/Mail.ru public profile URL normalization и optional live public page metadata без API/login/session flows;
- RU/UA source pack: curated карты, Telegram/RU platforms, geospatial и pastebin источники;
- базовый web metadata scan, public email extraction, robots/sitemap discovery и bounded same-site crawl по URL, совместимый с начальным web-check/Photon слоем;
- external adapter dry-run/execute runner для настроенных upstream CLI;
- adapter stdout parser: извлечение URL, email, phone и key/value сигналов из выполненных upstream CLI;
- scripted stdin для интерактивных upstream CLI adapters;
- generated report ingestion: внешние adapters могут писать JSON/CSV во временную output-папку, upstream checkout `results/` или конкретный временный output-файл, после чего runner читает эти файлы и передаёт их в parser;
- Sherlock adapter: `sherlock <username> --no-color --print-all --csv --txt --folderoutput <tempdir>` в execute-режиме и parser stdout/CSV/TXT для username profile discovery;
- Nexfil adapter: `nexfil -u <username>` запускается в isolated temporary workdir/HOME, parser читает stdout и autosaved TXT reports;
- Mosint adapter: `mosint --silent <email> --output <temp.json>` и parser upstream JSON для email reputation, breaches, related emails/domains, paste/search URLs, social flags и DNS records;
- h8mail adapter: `h8mail -t <email> --hide -j <temp.json>` и parser фактического upstream JSON без переноса password/hash/token-like значений в evidence;
- PhoneInfoga adapter: `phoneinfoga scan -n <number>` и parser upstream CLI/API output для local/numverify/googlesearch/googlecse/ovh phone intelligence;
- Maigret adapter: `--json ndjson`, RU/UA `--tags`, parser JSON/CSV dossier findings;
- Snoop adapter: RU/UA-aware command rendering через `--include RU|UA` и parser stdout/CSV-отчётов;
- Social Analyzer adapter: `node <SOCIAL_ANALYZER_APP_JS> --username <username> --output json --mode fast --method all --filter good,maybe --profiles detected [--countries ru|ua]` и parser JSON `detected`/`unknown`/`failed` profile findings;
- Blackbird adapter: `python blackbird.py --username|--email <value> --json --no-update --timeout 30` из `BLACKBIRD_DIR`, fresh JSON export ingestion и parser stdout found-lines для username/email account discovery;
- Subfinder adapter: `subfinder -d <domain> -oJ -silent` и parser JSONL/plain output в `subdomain` findings;
- httpx adapter: `httpx -u <domain-or-url> -json -silent -status-code -title -tech-detect ...` и parser JSONL/plain HTTP probe findings;
- passive Amass adapter: `amass enum -passive -nocolor -d <domain>` и parser stdout/JSON-like FQDN/subdomain output;
- theHarvester adapter: `theHarvester -d <domain> -b all -f <temp.json>` и parser generated JSON/stdout для emails, hosts, URLs, IPs, ASNs и people fields;
- BBOT adapter: `bbot -t <target> -p subdomain-enum -rf passive --output <tempdir> --name osint-toolkit` и parser generated JSON/NDJSON/stdout events для DNS names, emails, URLs, IPs, ports, technologies и findings;
- SpiderFoot adapter: `python <SPIDERFOOT_SF_PATH> -s <target> -u passive -o json -q` и parser JSON/stdout events для domains, subdomains, emails, phones, URLs, IPs, ports, names, technologies и findings;
- Argus adapter: интерактивный `argus` со stdin-сценарием `set target`, `runall infra`, `viewout`, `exit` и parser stdout/cache-like output для URLs, emails, phones, subdomains, IPs, ports и technologies;
- adapter setup/readiness layer: install hints, docs URLs, PATH/env readiness;
- adapter profiles: готовые группы upstream adapters для типовых расследований;
- adapter doctor: проверка фактической доступности upstream CLI в `PATH`;
- profile tools workflow: `tools doctor/install-plan/env --profile ...` показывает readiness, install/config actions и env variable names без значений;
- custom search profiles: `--profile-file` загружает JSON profiles с валидацией target kinds, adapter profiles, repositories и local tools;
- unified search planner/executor: `search` классифицирует один seed, выбирает default/full или custom profile, строит план native/adapters/local-tools, показывает readiness/missing/config/restricted/excluded статусы, запускает ready non-restricted adapters и выполняет local image tools при `--execute-adapters`;
- investigation runner: один кейс, несколько seed-типов, entity summary, graph edges, единый Markdown/JSON отчёт;
- executed adapter ingestion inside investigation: явный `--execute-adapters` добавляет parsed upstream CLI findings в entities, graph edges и case store;
- SQLite case store: сохранение и повторный просмотр кейсов, targets, entities, edges, findings и workflow/profile/scope policy metadata;
- saved case graph analysis: счётчики связей/типов сущностей, top connected nodes и focus-запрос соседей сущности;
- cross-case entity index: поиск повторяющихся email/domain/telegram/instagram/url и других сущностей между сохранёнными кейсами;
- cross-case path analysis: weighted shortest path между двумя сущностями по объединённым graph edges saved cases;
- cross-case network analysis: bounded общий graph по нескольким saved cases с aggregation, degree/case_count и фильтрами kind/relation;
- local toolbox: один HTML-пульт с seed-полями и направлениями для фото-зацепок, OCR, EXIF/metadata, QR/barcodes, reverse image portals, person/username/social, email/phone, domain/url, RU/UA, cases/clickable SVG graph/index и adapter profiles;
- toolbox backend: `toolbox --serve` поднимает локальный token-protected HTTP server, принимает только структурированные `/api/search` payloads включая `scope_note` и guarded `profile_file`, ведёт job queue, logs/status/report access, `/api/profiles`/save/delete и allowlisted case endpoints для saved SQLite cases/graph/index/update/delete;
- dry-run режим без сетевых запросов по умолчанию;
- live режим только при явном `--live`.

## Структура репозитория

- `top_100_osint_github_2026-06-24.csv` — исходный top-100 GitHub OSINT snapshot.
- `osint_people_projects_2026-06-24.csv` — curated-срез OSINT по лицам.
- `osint_ru_ua_projects_2026-06-24.csv` — curated-срез РФ/Украина/ru-platform.
- `osint_people_ru_ua_2026-06-24.csv` — объединённая разметка people + ru/ua.
- `osint_toolkit/` — Python-пакет CLI.
- `osint_toolkit/modules/` — native scan-модули.
- `osint_toolkit/search.py` — unified search profiles, target classifier и fan-out planner.
- `osint_toolkit/toolbox.py` — генератор локального HTML-пульта с направлениями, шаблонами команд, optional backend runner UI, Case Browser, safe case management controls и bounded clickable SVG-визуализацией сохранённого графа.
- `osint_toolkit/toolbox_server.py` — локальный backend для `toolbox --serve`: token auth, allowlisted unified search jobs со `scope_note`, status/logs/report endpoints и allowlisted case endpoints.
- `osint_toolkit/resources/sherlock_data.json` — встроенный snapshot Sherlock `sherlock_project/resources/data.json`, commit `206068d`, MIT license.
- `osint_toolkit/resources/whatsmyname_wmn_data.json` — встроенный snapshot WhatsMyName `wmn-data.json`, commit `7c44595`, CC BY-SA 4.0 license.
- `osint_toolkit/resources/maigret_sites.json` — sanitized projection Maigret `maigret/resources/data.json`, commit `2484509`, MIT license.
- `osint_toolkit/resources/THIRD_PARTY_NOTICES.txt` — notice по скопированному upstream dataset.
- `tests/` — unittest-тесты.
- `README.md` — пользовательская инструкция.
- `DEEP_INTEGRATION_PLAN.ru.md` — дорожная карта глубокой интеграции: unified `search`, profiles, install/readiness layer, fan-out execution и acceptance criteria.
- `pyproject.toml` — упаковка и console script.

## Ключевые файлы, модули, классы и функции

- `osint_toolkit/models.py`
  - `OsintProject` — нормализованная запись репозитория.
- `osint_toolkit/catalog.py`
  - `Catalog.load()` — загрузка CSV и объединение разметки.
  - `Catalog.filter()` — основная фильтрация.
  - `Catalog.stats()` — агрегированная статистика.
- `osint_toolkit/engine.py`
  - `ScanTarget` — нормализованная цель сканирования.
  - `RunConfig` — dry-run/live, timeout, limit, HTTP backoff, crawler limits и person alias inputs.
  - `Finding` — единый формат результата.
  - `Engine` — запуск подходящих модулей.
- `osint_toolkit/modules/username.py`
  - `UsernameScanModule` — Sherlock/Maigret/WhatsMyName-подобные проверки публичных профилей.
  - `normalize_username()` — нормализация leading `@` для username inputs.
  - `classify_username_http_result()` — status/content classifier для live username checks.
- `osint_toolkit/sites.py`
  - `UsernameSite` — check URL template, optional profile URL template, регион, upstream source projects и platform-specific username rule.
  - `UsernameSite.candidate_status_codes`, `not_found_status_codes`, `request_headers` — перенос WhatsMyName `e_code`, `m_code` и per-site headers в native live checks.
  - `match_content()` — сопоставление title/body с profile/not-found markers.
  - `CURATED_USERNAME_SITES` — локально уточнённые 38 public profile templates.
  - `SHERLOCK_USERNAME_SITES` — импортированные из Sherlock `data.json` templates.
  - `WHATSMYNAME_USERNAME_SITES` — импортированные GET/POST-compatible entries из WhatsMyName `wmn-data.json`.
  - `MAIGRET_USERNAME_SITES` — импортированные sanitized site rules из Maigret.
  - `USERNAME_SITES` — merged native dataset; curated правила идут первыми, одинаковые URL дедуплицируются, одноимённые альтернативные checks получают суффикс источника.
- `osint_toolkit/http_client.py`
  - `HttpResult.body_text` — ограниченный текст ответа для content marker checks.
- `osint_toolkit/modules/person.py`
  - `PersonNameScanModule` — safe person-name expansion в bounded username-кандидаты, по умолчанию до 24 вариантов.
  - `generate_username_candidates()` — стабильные варианты `firstlast`, `first.last`, `first_initial_last`, reverse-order handles, common given-name aliases, operator-provided aliases, handle suffixes и RU/UA transliteration.
- `osint_toolkit/modules/email.py`
  - `EmailScanModule` — базовая проверка email: синтаксис, доменное разрешение, MX/NS/TXT lookup, SPF/DMARC/MTA-STS/TLS-RPT/BIMI и TXT service signal findings.
- `osint_toolkit/email_auth.py`
  - `classify_spf_policy()` — классификация SPF из доменного TXT: отсутствие, multiple SPF warning, `all` policy, include/redirect counts.
  - `classify_dmarc_policy()` — классификация DMARC из `_dmarc.<domain>` TXT: отсутствие, multiple DMARC warning, `p=`, `sp=`, alignment, percent и report URI tags.
  - `classify_mta_sts_policy()`, `classify_tls_rpt_policy()`, `classify_bimi_policy()` — классификация additional email-security TXT records.
  - `classify_txt_service_signals()` — распознавание публичных ownership/service markers в root-domain TXT без вывода token values в signal finding.
- `osint_toolkit/dns_lookup.py`
  - `lookup_dns_records()` — запуск системного `nslookup` для MX/NS/TXT без дополнительных Python-зависимостей.
  - `parse_nslookup_records()` — parser Windows/Unix-style `nslookup` output для MX/NS/TXT; TXT chunks соединяются в одну запись, чтобы SPF/DMARC/additional TXT records не теряли длинные значения.
- `osint_toolkit/modules/phone.py`
  - `PhoneScanModule` — нормализация и country-prefix сигнал для телефонных номеров.
- `osint_toolkit/modules/domain.py`
  - `DomainScanModule` — DNS, HTTP/HTTPS baseline, bounded same-site crawler, certificate transparency lookup, RDAP lookup и WHOIS lookup для доменов.
  - `parse_crtsh_subdomains()` — parser `crt.sh` JSON, который нормализует wildcard/common-name значения в bounded `subdomain` signals.
  - `parse_rdap_domain_record()` — parser RDAP JSON, который извлекает registrar, domain handle, statuses, nameservers и registration/expiration dates.
- `osint_toolkit/whois_lookup.py`
  - `lookup_whois_domain()` — raw WHOIS query через TCP port 43 с TLD server mapping и optional registrar WHOIS referral.
  - `parse_whois_domain_record()` — parser WHOIS text, который извлекает registrar, WHOIS server, nameservers, statuses и dates без переноса контактоподобного сырого текста в evidence.
- `osint_toolkit/web_extract.py`
  - `extract_public_emails()` — bounded extraction публичных email-адресов из уже загруженного HTML/text.
  - `extract_public_phones()` — bounded extraction E.164-like phone values из HTML/text.
  - `extract_public_links()` — нормализация HTTP(S)-ссылок из HTML относительно base URL.
  - `filter_social_links()` — выделение ссылок на распространённые social/profile платформы.
  - `split_emails_by_domain()` — разделение same-domain и external email findings для domain recon metadata.
- `osint_toolkit/web_crawler.py`
  - `crawl_public_site()` — bounded same-site crawler поверх `HttpClient`, который переиспользует initial HTTP results, читает `robots.txt`/sitemap и обходит только HTTP(S)-ссылки в рамках лимитов.
  - `CrawlResult`/`CrawledPage` — агрегированные страницы, robots/sitemap discovery, ссылки, public emails, phones и social URLs.
  - `crawl_metadata()` — перевод результата обхода в metadata для `Finding`.
- `osint_toolkit/modules/telegram.py`
  - `TelegramScanModule` — нормализация Telegram handles/post URLs и live t.me metadata.
- `osint_toolkit/modules/instagram.py`
  - `InstagramPublicProfileModule` — нормализация Instagram usernames/profile/media URLs и live public metadata.
  - `normalize_instagram_target()` — поддерживает `@username`, `instagram.com/<username>/` и public media URLs `/p/`, `/reel/`, `/reels/`, `/tv/`.
  - `extract_instagram_public_metadata()` — извлекает meta/JSON поля: display name, account id, canonical/profile/media/external URLs, public counters и privacy/verification flags без сохранения сырого HTML.
- `osint_toolkit/modules/social.py`
  - `SocialPublicProfileModule` — safe public profile wrapper для VK/OK/Yandex/Mail.ru.
  - `normalize_social_target()` — поддерживает `vk:<identifier>`, `ok:<identifier>`, `mailru:<identifier>`, `mailru:<namespace>/<identifier>`, `yandex:q/<identifier>`, `yandex:market/<identifier>`, `yandex:reviews/<identifier>`, `yandex:zen/<identifier>`, прямые `vk.com`, `ok.ru`, `my.mail.ru` и публичные Yandex profile URLs.
  - `extract_social_public_metadata()` — извлекает public title/meta/canonical/image fields и account id, если он виден из публичного URL.
- `osint_toolkit/modules/ru_ua_sources.py`
  - `RuUaSourcePackModule` — curated RU/UA source pack.
- `osint_toolkit/modules/web.py`
  - `WebMetadataModule` — HTTP status/final URL/title, public page email extraction и bounded same-site crawl.
- `osint_toolkit/adapters.py`
  - `AdapterSpec` — карта upstream-проектов, лицензий, режима интеграции, target-specific command templates и текущего статуса.
  - `AdapterProfile` — reusable группы adapters для `investigate --adapter-profile`.
  - `expand_adapter_repositories()` — разворачивает профили и ручные repositories в дедуплицированный allowlist.
- `osint_toolkit/adapter_parsers.py`
  - `parse_adapter_output()` — нормализация stdout/stderr внешних CLI в дополнительные `Finding`.
  - Поддерживает базовые URL/email/phone/key-value patterns для generic adapter output.
  - Поддерживает `sherlock-project/sherlock` stdout и generated CSV/TXT reports: `Claimed`, `Available`, `Unknown`, `Illegal`, `WAF` нормализуются в `Finding`.
  - Поддерживает `thewhiteh4t/nexfil` stdout и autosaved TXT reports: найденные profile URLs и summary metrics нормализуются в `Finding`.
  - Поддерживает `sundowndev/phoneinfoga` CLI sections и REST/API-like JSON: scanner outputs `local`, `numverify`, `googlesearch`, `googlecse`, `ovh` нормализуются в `Finding`.
  - Поддерживает `soxoj/maigret` NDJSON/simple JSON/CSV reports: site/status/url/tags/ids нормализуются в `Finding`.
  - Поддерживает `alpkeskin/mosint` JSON reports: verification/emailrep/breachdirectory/HIBP/Hunter/search/DNS/social/ipapi сигналы нормализуются в `Finding`; credential values редактируются.
  - Поддерживает `khast3x/h8mail` JSON reports: target/pwn_num/data нормализуются в breach summary, related emails, usernames, source labels и paste URLs; credential values редактируются.
  - Поддерживает `user-scanner` JSON/verbose output: site/category/status/url/extra нормализуются в `Finding`.
  - Поддерживает `snooppr/snoop` stdout и CSV rows: `найден!`, `Увы!`, `блок` нормализуются в статусы без ложных URL/domain для отрицательных строк.
  - Поддерживает `qeeqbox/social-analyzer` JSON output: `detected`/`unknown`/`failed` профили нормализуются в site/profile URL/status/rate metadata.
  - Поддерживает `p1ngul1n0/blackbird` JSON exports и stdout found-lines: site/category/status/profile URL и extracted metadata нормализуются в `Finding`.
  - Поддерживает `projectdiscovery/subfinder` JSONL/plain output: subdomains нормализуются в `Finding.metadata["subdomain"]`.
  - Поддерживает `projectdiscovery/httpx` JSONL/plain output: URL, HTTP status, title, webserver, tech, content-type, response-time, IP/CNAME и error state нормализуются в `Finding`.
  - Поддерживает `owasp-amass/amass` passive stdout/JSON-like output: FQDN/subdomain values нормализуются в `subdomain` findings.
  - Поддерживает `laramies/theHarvester` generated JSON/stdout output: emails, hosts/vhosts, URLs, IPs, ASNs и people fields нормализуются в `Finding`.
  - Поддерживает `blacklanternsecurity/bbot` generated JSON/NDJSON/stdout events: `DNS_NAME`, `EMAIL_ADDRESS`, `URL`, `IP_ADDRESS`, `OPEN_TCP_PORT`, `TECHNOLOGY`, `FINDING` и `VULNERABILITY` нормализуются в `Finding`.
  - Поддерживает `smicallef/spiderfoot` JSON/stdout events: `INTERNET_NAME`, `DOMAIN_NAME`, `EMAILADDR`, `WEBLINK`, `IP_ADDRESS`, `TCP_PORT_OPEN`, `PHONE_NUMBER`, `HUMAN_NAME`, `TECHNOLOGY`, ASN и vulnerability/finding events нормализуются в `Finding`.
- `osint_toolkit/adapter_setup.py`
  - `AdapterSetup` — readiness/install/config view для adapter.
  - `build_adapter_setup()` — проверка executable в `PATH`, install command, docs URL и env readiness.
- `osint_toolkit/adapter_runner.py`
  - `run_adapter()` — обратно совместимый single-summary wrapper.
  - `run_adapter_findings()` — dry-run или явный запуск внешнего CLI adapter без shell, с parser findings после успешного запуска.
- `osint_toolkit/doctor.py`
  - `inspect_adapters()` — диагностика доступности upstream adapters.
- `osint_toolkit/entities.py`
  - `Entity` — нормализованная сущность кейса: email, phone, domain, URL, Telegram handle, Instagram handle, social profile, IP, port, technology, country/region и т.д.
  - `entities_from_targets()` — извлечение сущностей из seed values.
  - `entities_from_findings()` — извлечение сущностей из native и adapter findings.
  - `merge_entities()` — дедупликация сущностей с учётом confidence.
- `osint_toolkit/graph.py`
  - `GraphEdge` — отношение между двумя сущностями.
  - `graph_edges_from_case()` — построение связей `email -> domain`, `email -> related_email`, `domain|url -> page_contact_email/page_contact_phone/discovered_url/social_url/sitemap_url/robots_disallow_path`, `domain -> subdomain`, `domain -> registrar/nameserver/whois-server`, `url -> domain`, `url -> instagram`, `url -> social-profile`, `instagram -> platform/display name/account id/public URLs`, `social -> social-profile/platform/display name/account id/public URLs`, `target -> finding URL`, `phone -> country/normalized/carrier/location/line-type/phone-range/postal-code`.
  - `analyze_case_graph()` — аналитика сохранённого кейса: node/edge counts, relation counts, kind counts, top connected nodes и соседи выбранной сущности.
- `osint_toolkit/case_store.py`
  - `CaseStore` — SQLite-хранилище расследований.
  - `save()` — сохраняет `InvestigationResult` и optional case metadata в таблицы `cases`, `targets`, `entities`, `edges`, `findings`, `case_metadata`.
  - `list_cases()` — список сохранённых кейсов.
  - `load_case()` — выгрузка одного кейса для CLI output.
  - `list_entity_index()` — cross-case индекс сущностей с количеством кейсов.
  - `find_cases_by_entity()` — поиск сохранённых кейсов по точной сущности.
- `osint_toolkit/investigation.py`
  - `run_investigation()` — multi-target native scan + optional adapter dry-runs + entity summary.
  - `render_investigation_markdown()` — единый отчёт по кейсу.
- `osint_toolkit/workflows.py`
  - `recommend_projects()` — подбор ресурсов под тип задачи.
  - `render_brief()` — генерация Markdown-brief.
- `osint_toolkit/output.py`
  - форматирование таблиц, Markdown, CSV и JSON.
  - `format_search_profiles()` и `format_search_profile_detail()` — вывод built-in/custom search profiles для `profiles list/show`.
- `osint_toolkit/search.py`
  - `SearchProfile`, `LocalToolSpec`, `PlannedStep`, `SearchPlan` — модели unified plan.
  - `load_search_profiles()` — загрузка custom search profiles из JSON-файла с валидацией имён, target kinds, adapter profiles, repositories и local tools.
  - `classify_target()` — auto-kind для phone/email/domain/url/social/image/person/username.
  - `build_search_plan()` — строит deterministic fan-out plan по target/profile/region.
- `osint_toolkit/toolbox.py`
  - `toolbox_sections()` — машинно-читаемое описание направлений, cards и шаблонов команд.
  - `render_toolbox_html()` — HTML/CSS/JS для локального пульта; без backend остаётся static copy-ready режимом, с backend URL/token показывает unified search runner и Case Browser.
  - `write_toolbox()` — запись HTML-файла на диск.
- `osint_toolkit/toolbox_server.py`
  - `ToolboxJobRunner` — создаёт allowlisted `python -m osint_toolkit search ...` jobs, ограничивает output paths и profile-file inputs рабочей папкой backend, валидирует/пишет custom search profiles и сохраняет stdout/stderr/status.
  - `ToolboxRequestHandler` — HTTP endpoints `/api/search`, `/api/profiles`, `/api/profiles/save`, `/api/profiles/delete`, `/api/jobs`, `/api/jobs/<id>`, `/api/jobs/<id>/report`, `/api/cases`, `/api/cases/<id>`, `/api/cases/<id>/graph`, `/api/cases/<id>/update`, `/api/cases/<id>/delete`, `/api/case-index`, `/api/case-path`, `/api/case-network`, `/api/health`.
  - `run_toolbox_server()` — CLI entrypoint для `toolbox --serve`.
- `osint_toolkit/case_store.py`
  - `CaseStore.save()` — сохраняет investigation result, graph и metadata в SQLite.
  - `CaseStore.list_cases()` — выводит summary cases и поддерживает фильтры metadata `workflow`, `profile`, `scope_query`.
  - `CaseStore.update_case()` — меняет allowlisted management fields: title и metadata keys вроде `scope_note`.
  - `CaseStore.delete_case()` — удаляет один кейс через SQLite cascade.
  - `CaseStore.load_case()`/`load_cases()` — возвращают case payloads для CLI/API/graph analytics.
- `osint_toolkit/cli.py`
  - argparse CLI: `stats`, `catalog`, `show`, `scan`, `search`, `profiles`, `adapters`, `adapter-profiles`, `adapter-setup`, `doctor`, `run-adapter`, `toolbox`, `investigate`, `cases`, `case-show`, `case-update`, `case-delete`, `case-graph`, `case-index`, `case-path`, `case-network`, `recommend`, `brief`.

## Как система работает end-to-end

Каталоговый поток:

1. Пользователь запускает `python -m osint_toolkit catalog|show|stats|recommend|brief`.
2. CLI определяет папку данных: `--data-dir` или корень репозитория.
3. `Catalog.load()` читает top-100 CSV и overlay-разметку people/ru-ua.
4. Команда применяет фильтры или профиль workflow.
5. Результат выводится в консоль или записывается как Markdown-brief.

Toolbox-поток:

1. Static mode: пользователь запускает `python -m osint_toolkit toolbox --out osint_toolbox.html`; CLI вызывает `write_toolbox()`, который берёт текущее описание направлений и adapter profiles.
2. `render_toolbox_html()` создаёт самодостаточный HTML/CSS/JS без внешних assets; пользователь заполняет seed-поля один раз, а cards подставляют значения в шаблоны команд.
3. Served mode: пользователь запускает `python -m osint_toolkit toolbox --serve --open`; CLI создаёт session token, пишет HTML с backend URL/token и поднимает локальный HTTP server.
4. Browser отправляет только структурированный `/api/search` payload: target kind/value, profile/custom profile, optional profile file, region, execute/plan mode, limits, report path, case DB и optional scope note.
5. Backend валидирует profile file только внутри рабочей папки backend, собирает allowlisted `python -m osint_toolkit search ...`, запускает job в фоне, показывает queue/status/stdout/stderr и отдаёт report content по job id.
6. Browser может запросить `/api/profiles`, чтобы увидеть built-in и custom profiles из указанного JSON-файла до запуска search, или сохранить/удалить custom profile через `/api/profiles/save` и `/api/profiles/delete`.
7. Case Browser читает `/api/cases` с optional workflow/profile/scope filters, `/api/cases/<id>` и `/api/cases/<id>/graph`, рисует bounded SVG-граф из сохранённых `entities`/`edges` и показывает summary/focus analysis рядом с JSON; клик или Enter/Space на узле заполняет focus entity и перезапрашивает соседей.
8. Case Browser меняет только allowlisted поля title/scope_note через `/api/cases/<id>/update`; delete идёт через `/api/cases/<id>/delete` только если typed confirmation точно совпадает с `case_id`.
9. HTML не загружает фото сам; для фото served mode запускает только тот же `search image ... --execute-adapters`, а reverse image portals остаются ручной загрузкой.

Search-поток:

1. Пользователь запускает `python -m osint_toolkit search <kind|auto> <value> --profile <profile>` с `--plan-only` или `--execute-adapters`.
2. `classify_target()` определяет target kind для `auto`.
3. `build_search_plan()` выбирает profile: например phone -> `phone-full`, email -> `email-full`, image -> `image-full`.
4. Planner добавляет built-in native steps, разворачивает adapter profiles через `expand_adapter_repositories()` и проверяет readiness через `build_adapter_setup()`.
5. Для image target planner добавляет local-tool routes: PowerShell baseline/hash, ExifTool, ImageMagick, Tesseract и zbarimg.
6. В plan-only режиме результат выводится как table/Markdown/CSV/JSON через `format_search_plan()`. Missing/config/restricted tools остаются строками плана, а не ошибками.
7. В adapter execution режиме `ready_adapter_repositories()` выбирает только `stage=adapter,status=ready,readiness=ready` и отсекает restricted entries даже при `--include-restricted`.
8. `run_investigation()` получает исходный target, `profile.native_kinds` и allowlist ready repositories, запускает только native target kinds из профиля и внешние adapters через существующий `run_adapter_findings()`, затем сохраняет Markdown/JSON report и SQLite case при `--out`/`--case-db`; `--scope-note` попадает в case metadata как текстовый контекст/рамки проверки.
9. Для `image` target `run_image_search()` запускает ready local tools, добавляет missing/error/timeout findings по остальным local tools, извлекает URL/email/phone/username/domain clues и маршрутизирует derived targets через обычный `search`/`run_investigation()` flow.

Scan-поток:

1. Пользователь запускает `python -m osint_toolkit scan <kind> <value>`.
2. CLI создаёт `ScanTarget` и `RunConfig`.
3. `Engine` выбирает native-модули по `target.kind`.
4. В dry-run модуль возвращает planned findings без сетевых запросов или `skipped`, если username не проходит правило конкретной платформы.
5. В live-режиме модуль выполняет публичные HTTP checks, применяет site-specific headers, читает title/body excerpt и возвращает `Finding`; для URL/domain дополнительно может запускаться bounded same-site crawler с metadata по robots.txt, sitemap, найденным URL/email/phone/social links.

Adapter-поток:

1. Пользователь запускает `python -m osint_toolkit run-adapter <repo> <kind> <value>`.
2. `find_adapter()` находит `AdapterSpec`.
3. По умолчанию возвращается planned finding с командой.
4. При `--execute` команда запускается через `subprocess.run()` без shell, только если executable найден в `PATH`.
5. Если adapter объявляет `command_input_template`, runner подаёт отрендеренный сценарий в stdin процесса.
6. Если adapter объявляет generated report files, runner создаёт временную output-папку, добавляет upstream-аргумент output folder или output file и читает сгенерированные файлы.
7. `parse_adapter_output()` извлекает дополнительные findings из stdout/stderr и generated report text для поддерживаемых adapter families, включая username/email/phone adapters и domain-recon/broad-recon adapters Subfinder/httpx/passive Amass/theHarvester/BBOT/SpiderFoot/Argus.
8. Restricted adapters требуют отдельный `--allow-restricted`.

Adapter setup-поток:

1. Пользователь запускает `python -m osint_toolkit adapter-setup [repo]`.
2. `build_adapter_setup()` читает install/config metadata из `AdapterSpec`.
3. Проверяется наличие executable в `PATH` и обязательных переменных окружения.
4. Результат выводится как table/Markdown/CSV/JSON, без автоматической установки внешнего инструмента.

Investigation-поток:

1. Пользователь запускает `python -m osint_toolkit investigate` с одним или несколькими seed values.
2. CLI превращает каждый seed в `ScanTarget`.
3. `run_investigation()` запускает native scan-модули; в обычном `investigate` режиме доступны все native target kinds, а в `search --execute-adapters` набор ограничивается `profile.native_kinds`.
4. Derived username targets прогоняются через native username scan и, при `--include-adapters`, через совместимые adapters.
5. При `--execute-adapters` совместимые adapters запускаются через `run_adapter_findings()`; stdout/stderr parser добавляет дополнительные adapter findings. Для domain seeds профиль `domain-recon` может добавить Subfinder/httpx/passive Amass/theHarvester/BBOT/SpiderFoot, а профиль `broad-recon` может добавить BBOT/SpiderFoot/Argus; их parsed findings входят в тот же graph.
6. `entities.py` извлекает и объединяет сущности из входных целей, `Finding.url`, `Finding.evidence` и `Finding.metadata`.
7. `graph.py` строит связи между сущностями, включая `person -> username -> url`, `domain|url -> page_contact_email`, `domain|url -> page_contact_phone`, `domain|url -> sitemap_url`, `domain|url -> robots_disallow_path`, `domain|url -> discovered/social URL`, `domain -> ip|port|technology`, `instagram -> public profile metadata` и `social -> VK/OK public profile metadata`.
8. Если указан `--case-db`, `CaseStore` сохраняет кейс в SQLite до вывода отчёта; `--scope-note` сохраняется в metadata без изменения таблиц findings/entities/edges.
9. Отчёт выводится как Markdown или JSON; Markdown содержит `Entity Summary`, `Graph Edges`, native findings, adapter dry-runs или executed adapter findings и review checklist.

Case-store поток:

1. Пользователь запускает `python -m osint_toolkit cases --case-db <path>`.
2. `CaseStore.list_cases()` читает summary сохранённых кейсов и применяет optional filters `workflow`, `profile`, `scope_query`.
3. Пользователь запускает `python -m osint_toolkit case-show --case-db <path> <case_id>`.
4. `CaseStore.load_case()` возвращает targets, entities, edges и findings в table/Markdown/JSON формате.
5. Пользователь запускает `python -m osint_toolkit case-update --case-db <path> <case_id> --title ... --scope-note ...`.
6. `CaseStore.update_case()` меняет только title и metadata, не пересчитывая findings/entities/edges.
7. Пользователь запускает `python -m osint_toolkit case-delete --case-db <path> <case_id> --yes`.
8. `CaseStore.delete_case()` удаляет кейс и дочерние rows через SQLite cascade.
9. Пользователь запускает `python -m osint_toolkit case-graph --case-db <path> <case_id>`.
10. `analyze_case_graph()` строит summary сохранённого графа и, при указанном фокусе, возвращает соседей конкретной сущности.
11. Пользователь запускает `python -m osint_toolkit case-index --case-db <path>`.
12. `CaseStore.list_entity_index()` строит индекс сущностей по всем сохранённым кейсам; `find_cases_by_entity()` показывает кейсы для точной сущности.
13. Пользователь запускает `python -m osint_toolkit case-path --case-db <path> --from-kind ... --to-kind ...`.
14. `CaseStore.load_cases()` загружает bounded набор saved cases, а `analyze_cross_case_path()` строит объединённый graph и возвращает weighted shortest path с provenance по каждому hop.
15. Пользователь запускает `python -m osint_toolkit case-network --case-db <path>`.
16. `analyze_cross_case_network()` агрегирует одинаковые graph edges между saved cases, считает degree/case_count и отдаёт bounded visible subgraph для CLI/API/toolbox.

## Поток данных

Источник истины — локальные CSV-файлы. Код не изменяет эти CSV при обычной работе.

Поток:

Каталог:

`CSV snapshot -> Catalog.load() -> OsintProject[] -> filter/recommend/brief -> console/Markdown output`

Toolbox:

`ToolboxSection[] + AdapterProfile[] -> render_toolbox_html() -> local HTML -> operator fills image path/seeds/profile fields -> copy-ready command OR /api/profiles|/api/profiles/save|/api/profiles/delete|/api/search -> ToolboxJobRunner -> python -m osint_toolkit search -> report/case -> Case Browser /api/cases|graph|update|delete|case-index|case-path|case-network`

Search:

`seed -> classify_target() -> SearchProfile -> native steps + AdapterSpec readiness + LocalToolSpec readiness -> SearchPlan -> plan output OR profile-scoped native execution + ready adapter allowlist/local image runner -> run_investigation() -> report/case`

Сканирование:

`CLI target -> ScanTarget -> Engine -> ScanModule[] -> Finding[] planned/skipped/live -> table/Markdown/CSV/JSON`

Email DNS/auth enrichment:

`email -> domain -> socket.getaddrinfo + nslookup MX/TXT -> SPF classifier + nslookup _dmarc TXT -> DMARC classifier -> Finding[]`

Person expansion:

`person seed -> PersonNameScanModule -> username candidates -> derived username ScanTarget[] -> UsernameScanModule/adapters -> Entity[]/GraphEdge[]`

Instagram:

`instagram seed -> InstagramPublicProfileModule -> public profile/media URL -> public metadata -> Entity[]/GraphEdge[]`

RU social:

`social seed -> SocialPublicProfileModule -> VK/OK/Yandex/Mail.ru public profile URL -> public metadata -> Entity[]/GraphEdge[]`

Адаптеры:

`CLI adapter request -> AdapterSpec -> command_template/target-specific command_templates/command_input_template -> dry-run/external process -> summary Finding -> parsed Finding[]`

Domain-recon adapters:

`domain/url seed -> domain-recon/broad-recon profile -> subfinder/httpx/passive amass/theHarvester/BBOT/SpiderFoot/Argus -> JSONL/plain stdout/generated JSON/events/stdin-driven output -> subdomain/email/phone/url/domain/ip/port/technology metadata -> Entity[]/GraphEdge[]`

Setup adapters:

`AdapterSpec -> AdapterSetup -> PATH/env readiness -> table/Markdown/CSV/JSON`

Investigation:

`multiple CLI seeds -> ScanTarget[] -> Engine -> Finding[] -> optional adapter profile/allowlist -> adapter dry-runs/executions -> Entity[] -> GraphEdge[] -> Markdown/JSON report`

Сохранённые кейсы:

`InvestigationResult + workflow/profile/scope policy metadata -> CaseStore(SQLite) -> cases/case-show/case-graph/case-index/case-path/case-network -> table/Markdown/CSV/JSON`

## Внешние интеграции

В рантайме сетевые интеграции есть только в явном live-режиме scan-команд.

Существующие CSV были собраны из GitHub ранее. Каталоговые команды не ходят в GitHub API.

Native live-модули используют публичные HTTP(S) URL checks через стандартную библиотеку Python. Для username live checks сохраняется только ограниченный текст ответа в памяти процесса, чтобы применить content marker rules; на диск body не пишется.

Instagram live-модуль использует публичную HTML/meta/JSON информацию страницы профиля или media URL. Сырой HTML не сохраняется, login/session/cookies не используются.

Social live-модуль для VK/OK/Yandex/Mail.ru использует только публичную HTML/meta информацию страницы профиля, группы или публичного profile-like URL. API tokens, login/session/cookies и приватные endpoints не используются.

Email live-модуль использует `socket.getaddrinfo()` и системный `nslookup` для MX/TXT. TXT результата домена достаточно для SPF classifier, а DMARC classifier делает отдельный TXT lookup по `_dmarc.<domain>`. Если `nslookup` недоступен, результат DNS-записи возвращается как `missing`, а не как падение команды.

SQLite используется локально через стандартную библиотеку `sqlite3`; внешнего сервера БД нет.

External adapters должны подключать upstream CLI/API без копирования кода, если лицензия, масштаб или язык проекта делают прямой перенос неразумным. Для `sherlock-project/sherlock` зафиксирован executable adapter target `sherlock <username>` с generated args `--no-color --print-all --csv --txt --folderoutput <tempdir>`. Для `thewhiteh4t/nexfil` зафиксирован executable adapter target `nexfil -u <username>` с временным cwd/HOME, потому что upstream autosave пишет TXT reports относительно рабочей директории/HOME. Для `alpkeskin/mosint` зафиксирован executable adapter target `mosint --silent <email> --output <temp.json>` с временным JSON output file. Для `h8mail` зафиксирован executable adapter target `h8mail -t <email> --hide -j <temp.json>` с временным JSON output file. Для `soxoj/maigret` включён JSON-report template `maigret <username> --json ndjson [--tags ru|ua]` с временным `--folderoutput`. Для `qeeqbox/social-analyzer` включён Node adapter `node <SOCIAL_ANALYZER_APP_JS> --username <username> --output json --mode fast --method all --filter good,maybe --profiles detected [--countries ru|ua]`; проект распространяется под AGPL-3.0, поэтому parity делается через запуск upstream app.js и JSON output ingestion, а не через перенос upstream Node-кода. Для `p1ngul1n0/blackbird` включён checkout adapter `python blackbird.py --username|--email <value> --json --no-update --timeout 30` с `BLACKBIRD_DIR` как рабочей папкой и fresh JSON ingestion из `BLACKBIRD_DIR/results`; в snapshot нет явной license metadata, поэтому код не переносится внутрь. Для `user-scanner` включены target-specific JSON templates: `user-scanner -e <email> -f json` и `user-scanner -u <username> -f json`. Для `snooppr/snoop` включён username template `snoop --no-func --found-print [--include RU|UA] <username>`. Для `sundowndev/phoneinfoga` включён executable adapter target `phoneinfoga scan -n <number>`; проект PhoneInfoga распространяется под GPL-3.0, поэтому текущий 1:1 паритет делается через CLI/API output ingestion, а не через перенос upstream Go-кода в Python-пакет. Для domain/web recon включены executable adapters: `projectdiscovery/subfinder` через `subfinder -d <domain> -oJ -silent`, `projectdiscovery/httpx` через `httpx -u <domain-or-url> -json -silent -status-code -title -tech-detect ...`, `owasp-amass/amass` через пассивный `amass enum -passive -nocolor -d <domain>`, `laramies/theHarvester` через `theHarvester -d <domain> -b all -f <temp.json>`, `blacklanternsecurity/bbot` через `bbot -t <target> -p subdomain-enum -rf passive --output <tempdir> --name osint-toolkit`, `smicallef/spiderfoot` через `python <SPIDERFOOT_SF_PATH> -s <target> -u passive -o json -q` и `jasonxtn/argus` через интерактивный `argus` со stdin-сценарием `set target <target>`, `runall infra`, `viewout`, `exit`. theHarvester распространяется под GPL-2.0-only, BBOT под GPL-3.0, SpiderFoot и Argus под MIT; поэтому паритет реализуется через generated JSON/stdout/event/stdin-driven ingestion, а не через перенос upstream Python-кода.

## Конфигурация, переменные окружения и секреты

Секреты в коде проекта не используются и не сохраняются. Внешние upstream adapters могут требовать собственные config/provider files с API keys; эти файлы остаются вне репозитория и управляются оператором.

Конфигурация:

- `--data-dir` — путь к папке с CSV.
- `--format` — формат вывода для команд `catalog` и `show`.
- `--out` — путь Markdown-файла для `brief`.
- `search --scope-note` — текстовый контекст/рамки проверки, который сохраняется в case metadata при `--case-db`.
- `toolbox --out` — путь HTML-файла локального пульта.
- `toolbox --open` — открыть созданный HTML в браузере через стандартный `webbrowser`.
- `toolbox --serve` — поднять локальный backend для запуска unified `search` jobs из toolbox.
- `toolbox --host` и `toolbox --port` — адрес локального backend в served mode.
- `search --profile` — profile для fan-out планирования: `auto`, built-in `phone-full`, `email-full`, `username-full`, `person-full`, `passive-recon`, `web-full`, `image-full`, `social-full`, `ru-ua-full`, `all-safe`, `safe` или имя custom profile из `--profile-file`.
- `search --profile-file` — JSON-файл custom search profiles; файл принимает top-level list или объект `{"profiles": [...]}` и валидируется перед планированием.
- `search --plan-only` — вывести план без запуска tools.
- `search --execute-adapters` — запустить только ready non-restricted adapters из SearchPlan и записать unified report/case.
- `search image ... --execute-adapters` — запустить ready local image tools, извлечь derived seeds и записать unified report/case.
- `search --include-restricted` — показать restricted tools в плане с явной маркировкой.
- `search --format table|markdown|csv|json` — формат плана.
- `profiles list [--profile-file]` — список built-in и optional custom search profiles.
- `profiles show <profile> [--profile-file]` — подробный вывод одного search profile.
- `profiles export <profile> --out <path> [--profile-file]` — экспорт одного profile в reusable JSON-wrapper `{"profiles": [...]}`.
- `tools doctor --profile [--profile-file]` — readiness по adapters и local tools search-профиля.
- `tools install-plan --profile [--profile-file]` — install/config actions по missing/config tools без автоматической установки; excluded/restricted adapters не выдаются как обычные install actions.
- `tools env --profile [--profile-file]` — только имена required/optional env variables, без значений.
- `scan --live` — явное разрешение сетевых проверок.
- `scan --timeout` — HTTP timeout.
- `scan email --live` — дополнительно делает domain resolution, MX/TXT lookup, SPF classification и DMARC lookup/classification.
- `scan --region` — фильтр URL-шаблонов или workflow по региону.
- `investigate --person` — повторяемое имя человека для username expansion.
- `investigate --include-adapters` — добавить dry-run команды совместимых upstream adapters.
- `investigate --adapter-profile` — повторяемая готовая группа adapters.
- `investigate --adapter` — повторяемый allowlist конкретных upstream repositories для `--include-adapters`.
- `investigate --execute-adapters` — явно запустить совместимые upstream CLI adapters после `--include-adapters`.
- `investigate --allow-restricted-adapters` — разрешить restricted adapters только вместе с `--execute-adapters` после scope review.
- `investigate --adapter-timeout` — timeout для внешних adapter CLI.
- `investigate --format markdown|json` — формат отчёта по кейсу.
- `investigate --case-db` — SQLite-файл для сохранения кейса.
- `investigate --case-id` — стабильный ID кейса, если нужен повторяемый ключ.
- `investigate --scope-note` — текстовый контекст/рамки проверки, который сохраняется в case metadata при `--case-db`.
- `cases --workflow` — фильтр saved cases по metadata workflow.
- `cases --profile` — фильтр saved cases по requested/search profile или adapter profile metadata.
- `cases --scope-query` — case-insensitive substring filter по metadata `scope_note`.
- `case-update --title` — меняет title saved case без изменения findings/entities/edges.
- `case-update --scope-note` — upsert metadata `scope_note` saved case.
- `case-delete --yes` — обязательное CLI-подтверждение удаления одного saved case.
- `toolbox /api/profiles?profile_file=...` — token-protected listing built-in/custom profiles; `profile_file` должен находиться внутри рабочей папки backend.
- `toolbox /api/profiles/save` — token-protected upsert custom search profile в JSON-файл внутри рабочей папки backend после полной валидации.
- `toolbox /api/profiles/delete` — token-protected удаление custom search profile из guarded profile JSON.
- `toolbox /api/search` `profile_file` — optional profile JSON path внутри рабочей папки backend; backend валидирует custom profile перед добавлением `--profile-file`.
- `case-graph --entity-kind` и `case-graph --entity-value` — focus-сущность для поиска соседей в сохранённом графе.
- `case-graph --limit` — ограничение top nodes и списка соседей.
- `case-index --kind` — фильтр типа сущности в cross-case индексе.
- `case-index --value` — точное значение сущности для поиска кейсов; требует `--kind`.
- `case-index --min-cases` — минимальное число кейсов для строки индекса.
- `case-index --limit` — максимальное число строк индекса.
- `case-path --from-kind`, `--from-value`, `--to-kind`, `--to-value` — source/target entities для cross-case path поиска.
- `case-path --case-limit` — максимальное число свежих saved cases, загружаемых для объединённого графа.
- `case-path --max-depth` — максимальное число hops для weighted shortest path.
- `case-network --kind` — optional entity-kind neighborhood filter для общего saved-case graph.
- `case-network --relation` — optional relation filter для общего saved-case graph.
- `case-network --case-limit`, `--node-limit`, `--edge-limit`, `--min-degree` — границы общего graph view.
- `run-adapter --execute` — явный запуск внешнего CLI; для поддерживаемых stdout/generated-report formats добавляет parsed findings.
- `adapter-setup` — показать install/config/readiness plan для adapters.

Переменные окружения, которые только отражаются в adapter readiness metadata:

- `SUBFINDER_CONFIG`, `SUBFINDER_PROVIDER_CONFIG` — upstream Subfinder config/provider config paths.
- `AMASS_CONFIG` — upstream Amass config path.
- `THEHARVESTER_API_KEY` — upstream API key for optional protected REST routes; CLI provider API keys остаются во внешней конфигурации theHarvester.
- `SPIDERFOOT_SF_PATH` — обязательный путь к локальному upstream `sf.py` для SpiderFoot CLI adapter.
- `SOCIAL_ANALYZER_APP_JS` — обязательный путь к локальному upstream `app.js` для Social Analyzer adapter после clone/npm install.
- `BLACKBIRD_DIR` — обязательный путь к локальному upstream checkout Blackbird с `blackbird.py`, установленными requirements и папкой `results/`.
- `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`, `CENSYS_API_ID`, `CENSYS_API_SECRET`, `GOOGLE_API_KEY`, `HIBP_API_KEY` — optional provider keys для upstream Argus modules; toolkit их не сохраняет и не печатает.

## Команды запуска, тестирования, проверки и отладки

Запуск:

```powershell
python -m osint_toolkit stats
python -m osint_toolkit toolbox --out osint_toolbox.html
python -m osint_toolkit toolbox --out osint_toolbox.html --open
python -m osint_toolkit toolbox --serve --open
python -m osint_toolkit toolbox --serve --port 8766 --out osint_toolbox.html
python -m osint_toolkit search phone +380441234567 --profile phone-full --plan-only
python -m osint_toolkit search phone +380441234567 --profile phone-full --execute-adapters --adapter-limit 3 --out reports/phone.md --case-db cases.sqlite --case-id phone-001 --scope-note "internal validation scope"
python -m osint_toolkit search email person@example.com --profile email-full --plan-only --format markdown
python -m osint_toolkit search auto https://vk.com/example --profile auto --plan-only --format json
python -m osint_toolkit search image C:\evidence\photo.jpg --profile image-full --plan-only
python -m osint_toolkit search image C:\evidence\photo.jpg --profile image-full --execute-adapters --out reports/photo.md --case-db cases.sqlite --case-id photo-001 --scope-note "image source context review"
python -m osint_toolkit search email person@example.com --profile case-email-safe --profile-file profiles\case_profiles.json --plan-only
python -m osint_toolkit profiles list --format markdown
python -m osint_toolkit profiles export email-full --out profiles\email-full.json
python -m osint_toolkit tools doctor --profile all-safe --format markdown
python -m osint_toolkit tools doctor --profile case-email-safe --profile-file profiles\case_profiles.json --format markdown
python -m osint_toolkit tools install-plan --profile image-full --format markdown
python -m osint_toolkit tools env --profile email-full --format json
python -m osint_toolkit catalog --kind people --direct-only --limit 10
python -m osint_toolkit scan person "Ivan Petrenko" --limit 10
python -m osint_toolkit scan username exampleuser --limit 10
python -m osint_toolkit scan username exampleuser --region ru --live --limit 5 --http-retries 2 --request-delay 0.2
python -m osint_toolkit scan email person@example.com --live
python -m osint_toolkit scan phone +380441234567
python -m osint_toolkit scan domain example.com --live --crawl-pages 5 --crawl-depth 1
python -m osint_toolkit scan telegram "@durov"
python -m osint_toolkit scan instagram "@exampleuser" --live
python -m osint_toolkit scan social vk:exampleuser --live
python -m osint_toolkit scan social yandex:q/exampleuser
python -m osint_toolkit scan ru-ua all --region ua
python -m osint_toolkit scan url https://example.com --live --crawl-pages 5 --crawl-depth 1
python -m osint_toolkit adapters
python -m osint_toolkit adapter-profiles
python -m osint_toolkit adapter-setup sherlock-project/sherlock
python -m osint_toolkit doctor
python -m osint_toolkit run-adapter sherlock-project/sherlock username example_user
python -m osint_toolkit run-adapter thewhiteh4t/nexfil username example_user
python -m osint_toolkit run-adapter qeeqbox/social-analyzer username example_user --region ua
python -m osint_toolkit run-adapter p1ngul1n0/blackbird username example_user
python -m osint_toolkit run-adapter p1ngul1n0/blackbird email person@example.com
python -m osint_toolkit run-adapter alpkeskin/mosint email person@example.com
python -m osint_toolkit run-adapter khast3x/h8mail email person@example.com
python -m osint_toolkit run-adapter instaloader/instaloader instagram https://www.instagram.com/exampleuser/
python -m osint_toolkit run-adapter sundowndev/phoneinfoga phone +380441234567
python -m osint_toolkit run-adapter projectdiscovery/subfinder domain example.com
python -m osint_toolkit run-adapter projectdiscovery/httpx domain example.com
python -m osint_toolkit run-adapter owasp-amass/amass domain example.com
python -m osint_toolkit run-adapter laramies/theHarvester domain example.com
python -m osint_toolkit run-adapter smicallef/spiderfoot domain example.com
python -m osint_toolkit run-adapter blacklanternsecurity/bbot domain example.com
python -m osint_toolkit run-adapter jasonxtn/argus domain example.com
python -m osint_toolkit investigate --person "Ivan Petrenko" --include-adapters --adapter-profile username-full --adapter-limit 2
python -m osint_toolkit investigate --domain example.com --include-adapters --adapter-profile domain-recon --adapter-limit 6
python -m osint_toolkit investigate --domain example.com --include-adapters --adapter-profile broad-recon --adapter-limit 3
python -m osint_toolkit investigate --username example_user --domain example.com --telegram "@durov" --instagram "@exampleuser" --social vk:exampleuser --include-adapters
python -m osint_toolkit investigate --username example_user --include-adapters --adapter-profile username-full --adapter-limit 2
python -m osint_toolkit investigate --username example_user --include-adapters --adapter soxoj/maigret
python -m osint_toolkit investigate --username example_user --include-adapters --execute-adapters --adapter-limit 1
python -m osint_toolkit investigate --email person@example.com --case-db cases.sqlite --case-id case-001 --scope-note "internal validation scope"
python -m osint_toolkit cases --case-db cases.sqlite
python -m osint_toolkit cases --case-db cases.sqlite --workflow search --profile email-full --scope-query internal
python -m osint_toolkit case-update --case-db cases.sqlite case-001 --title "reviewed case" --scope-note "reviewed scope"
python -m osint_toolkit case-show --case-db cases.sqlite case-001 --format json
python -m osint_toolkit case-graph --case-db cases.sqlite case-001
python -m osint_toolkit case-graph --case-db cases.sqlite case-001 --entity-kind email --entity-value person@example.com --format json
python -m osint_toolkit case-delete --case-db cases.sqlite case-001 --yes
python -m osint_toolkit case-index --case-db cases.sqlite --kind domain --min-cases 2
python -m osint_toolkit case-index --case-db cases.sqlite --kind email --value person@example.com --format json
python -m osint_toolkit case-path --case-db cases.sqlite --from-kind email --from-value person@example.com --to-kind url --to-value https://example.com/profile --format json
python -m osint_toolkit case-network --case-db cases.sqlite --kind domain --format markdown
python -m osint_toolkit recommend username --region ru
python -m osint_toolkit brief --task username --target-value example --out reports/example.md
```

Тесты:

```powershell
python -m unittest discover -s tests
```

Editable install:

```powershell
python -m pip install -e .
osint-toolkit stats
```

## Важные архитектурные решения

- Используется только стандартная библиотека Python. Это снижает риск установки и упрощает запуск на Windows.
- CLI читает уже проверенные CSV, а не тянет актуальные данные из GitHub. Это делает результаты воспроизводимыми.
- Система строится вокруг единого `Finding`, чтобы результаты native-модулей и external adapters можно было объединять.
- Person-name expansion выдаёт только низкоуверенные username-кандидаты; подтверждение делается отдельными username checks/adapters.
- Username module проверяет platform-specific syntax до URL check, чтобы не превращать несовместимый username в ложный planned URL.
- Username live classifier сначала учитывает title/body markers, затем site-specific status rules из WhatsMyName/Maigret: soft-404 marker сильнее HTTP status, profile marker повышает confidence, а `m_code`/`e_code` и status-code rules помогают классифицировать сайты без body marker.
- HTTP live checks повторяют 429 и temporary 5xx с `Retry-After` или exponential backoff; username scan поддерживает операторский `--request-delay` между live URL checks.
- Web/domain crawler bounded по страницам и глубине: по умолчанию 5 страниц и глубина 1, читает `robots.txt`, sitemap XML/text и HTTP(S) same-site links, без JavaScript rendering, форм и авторизации.
- WHOIS lookup выполняется через port 43 и сохраняет только доменные поля. Полный raw WHOIS text не попадает в evidence, потому что он часто содержит контактные данные.
- Adapter parser не считается источником истины: он нормализует stdout уже запущенного upstream CLI, а не заменяет native logic upstream-проекта.
- Generated report files читаются из временной директории или временного файла и удаляются после parsing; постоянное хранение остаётся задачей case store/report output.
- Для adapters, которые пишут outputs внутри собственного checkout, runner делает snapshot generated files до запуска и читает только новые или изменённые файлы после запуска; это нужно для Blackbird `BLACKBIRD_DIR/results`, чтобы не подтянуть старые отчёты.
- Investigation adapter execution является opt-in: `--include-adapters` остаётся dry-run, а запуск внешнего кода требует отдельного `--execute-adapters`.
- Investigation adapter allowlist выбирается оператором через повторяемый `--adapter`; без allowlist система использует совместимые adapters из `AdapterSpec`.
- Adapter profiles являются статическим удобным слоем поверх `AdapterSpec`, а не отдельным источником истины.
- Adapter setup layer не устанавливает внешние инструменты автоматически: он показывает install plan/readiness, чтобы не запускать непроверенный код без решения оператора.
- Region-aware adapter placeholders используются только при наличии `ScanTarget.region=ru|ua`; для `all` пустые части команды отбрасываются.
- `Entity` отделён от `Finding`: finding описывает источник и сигнал, entity описывает нормализованный объект, а `GraphEdge` описывает связь между объектами.
- `ip`, `port`, `technology` добавлены как общие graph-сущности, потому что BBOT, theHarvester, httpx и будущие recon adapters регулярно дают именно такие события.
- SQLite case store отделён от engine: сканирование можно использовать без записи на диск, а сохранение включается явно через `--case-db`.
- Graph analysis отделён от case store: SQLite хранит факты кейса, а `analyze_case_graph()` вычисляет summary и neighbors без изменения схемы БД.
- Cross-case entity index использует уже сохранённую таблицу `entities`; новая таблица не добавлена, потому что индекс пока вычисляется read-only запросами и не требует миграции.
- Toolbox сохраняет static mode без сервера и новых зависимостей; served mode открывает локальный порт только по явному `--serve`, требует per-session token и принимает только structured unified `search` jobs, а не произвольные shell-команды.
- В photo-направлении toolbox добавляет только небиометрические маршруты: file hash/baseline, EXIF/metadata, OCR, QR/barcodes и reverse image source/context search. Идентификация личности по лицу не реализуется.
- Unified `search` использует planner как источник правды для execution: запуск идёт только по ready non-restricted adapter steps, поэтому missing/config/restricted tools не превращаются в неявные процессы.
- Dry-run используется по умолчанию для scan-команд. Live-сетевые проверки требуют явного `--live`.
- Лицензионно сложные или большие проекты подключаются adapters вместо прямого копирования кода.
- Password recovery flows, email-to-account и phone-to-account механики не переносятся в native-код без restricted-режима.
- Разметка people/ru-ua считается curated-слоем поверх top-100, а не абсолютной классификацией качества.

## Рассмотренные варианты реализации

- Полноценный web UI заменён более узким local execution backend: `toolbox --serve` запускает только allowlisted unified `search`, а не любые commands из cards. Это закрывает one-window execution для главного fan-out сценария без превращения браузера в shell.
- Буквальное копирование кода из всех проектов: допускается только после license review. Обязательный путь для цели — 1:1 functional parity поведения через native-compatible modules, external adapters и documented restricted/excluded decisions.
- Новая база данных SQLite: пока не нужна, CSV достаточно для каталога; для истории scan-запусков может понадобиться позже.

## Текущие ограничения, риски и открытые вопросы

- Каталог основан на snapshot от 2026-06-24; GitHub stars и актуальность проектов меняются.
- Качество и безопасность внешних репозиториев не аудированы.
- Native person-name expansion использует шаблоны имени/фамилии, reverse-order variants, initials, curated common given-name aliases, operator-provided alias dictionaries, handle suffixes и RU/UA transliteration; пока нет bundled historical alias datasets и platform-specific alias scoring.
- Первый native username module уже импортирует Sherlock GET/POST site dataset, WhatsMyName GET/POST dataset и sanitized Maigret site rules, покрывает URL-template/status-code слой, Sherlock response-url `errorUrl`, часть platform syntax rules, custom headers, POST bodies, базовый HTTP retry/backoff и часть content marker rules, но не всю логику Sherlock/Maigret/WhatsMyName: Maigret engine templates/activation/recursive/reporting logic ещё не встроены, нет полного набора WAF/error-handling rules, site-specific rate-limit tuning и enrichment.
- Social Analyzer adapter по умолчанию использует fast JSON mode, `--filter good,maybe`, `--profiles detected` и optional `--countries ru|ua`; web/API UI, screenshots/OCR, slow/special modes, full metadata/screenshot pipeline и Node version enforcement остаются upstream/операторской ответственностью.
- Blackbird adapter по умолчанию использует `--json --no-update --timeout 30` для username/email и читает только свежие JSON exports; upstream AI profiling, PDF/CSV/DUMP exports, proxy/permutation options, update workflow и enhanced Instagram session metadata пока остаются операторскими/upstream режимами.
- Native email module делает MX/NS/TXT lookup, SPF/DMARC/MTA-STS/TLS-RPT/BIMI classifiers и root TXT service signal classifier, но пока не делает native breach lookup, local cache или own API enrichment; Mosint/h8mail покрывают часть enrichment через external adapters.
- Native phone module пока не делает carrier lookup, reputation lookup или external API enrichment.
- Native web/domain crawler уже собирает robots/sitemap URLs, robots disallow paths, same-site URLs, external URLs, social URLs, public emails и E.164-like phones, но остаётся bounded и mostly HTML/XML/text-only: нет headless browser, JavaScript rendering, form submission, full robots policy enforcement и широкого SpiderFoot/Photon-style обхода.
- BBOT adapter по умолчанию запускает только passive `subdomain-enum`; broader presets, deadly modules, web screenshots, dir busting и aggressive web scan не включаются без явного отдельного решения.
- SpiderFoot adapter по умолчанию запускает только passive use-case через CLI JSON stdout; web/API server mode, full module policy mapping и активные use cases не включаются без отдельного решения.
- Argus adapter по умолчанию подаёт только scripted `runall infra`; остальные 135 upstream modules, API-backed checks и более активные категории требуют отдельного mode mapping и scope review.
- Native WHOIS parser покрывает common WHOIS field names и несколько TLD server mappings, но не все registry-specific formats и не экспортирует полный raw WHOIS text.
- Telegram module пока не использует Telegram API и не получает private/group data.
- Instagram module пока является safe public metadata wrapper: нет login/session handling, private data access, follower/following scraping, comments/messages export, media archive ingestion или обхода platform rate limits.
- Social module для VK/OK/Yandex/Mail.ru пока является safe public metadata wrapper: нет VK/OK/Yandex/Mail.ru API adapters, login/session handling, private profile access, follower scraping, comments/messages export или обхода platform rate limits.
- Toolbox static mode не выполняет команды из браузера; served mode выполняет structured unified `search` jobs через локальный backend. Собственного OCR/EXIF engine нет: image execution использует локально установленные ExifTool, ImageMagick, Tesseract, zbarimg и PowerShell hash baseline. Reverse image search остаётся ручной загрузкой на внешние сайты. Face recognition и поиск человека по лицу не добавлены.
- Served toolbox принимает custom `profile_file` только из рабочей папки backend; profile editor пишет только canonical validated JSON в этой границе. Это осознанное ограничение против чтения/записи произвольных локальных файлов из браузера.
- Case management intentionally narrow: `case-update` и `/api/cases/<id>/update` меняют только title/scope_note, а `case-delete` и `/api/cases/<id>/delete` требуют явного подтверждения; нет bulk delete, raw SQL editor или редактирования saved findings/entities/edges из UI.
- `search --execute-adapters` запускает только ready non-restricted external adapters. Для image targets он запускает ready local tools и маршрутизирует derived seeds; face recognition и identity-by-face matching не реализуются.
- RU/UA source pack пока curated вручную из текущего snapshot, без автообновления.
- Adapter runner запускает только те CLI, которые уже установлены в `PATH`; установкой upstream-проектов он пока не занимается.
- Adapter setup metadata покрывает ключевые upstream adapters, но install commands могут меняться; перед установкой нужно сверяться с upstream docs URL.
- Adapter manifest теперь включает generated CSV/TXT folder template для `sherlock-project/sherlock`, isolated workdir TXT ingestion для `thewhiteh4t/nexfil`, generated JSON-file templates для `alpkeskin/mosint`, `h8mail` и `laramies/theHarvester`, generated JSON-report folder template для `soxoj/maigret`, generated JSON/NDJSON output folder template для `blacklanternsecurity/bbot`, required-env Python script template для `smicallef/spiderfoot`, interactive stdin template для `jasonxtn/argus`, target-specific executable templates для `user-scanner`, region-aware template для `snooppr/snoop`, required-env Node template для `qeeqbox/social-analyzer`, checkout/results template для `p1ngul1n0/blackbird` и executable template для `sundowndev/phoneinfoga`; более сложные adapters могут потребовать richer per-mode config.
- Adapter parser покрывает общие URL/email/phone/key-value patterns, Sherlock stdout/CSV/TXT reports, Nexfil stdout/TXT reports, Mosint JSON reports, h8mail JSON reports, Maigret JSON/CSV reports, `user-scanner` JSON/verbose output, Snoop stdout/CSV output, Social Analyzer JSON output, Blackbird JSON/stdout output, PhoneInfoga CLI/API output, domain-recon adapters Subfinder/httpx/passive Amass/theHarvester, BBOT events, SpiderFoot events и Argus stdout/cache-like output; сложные JSON/CSV/HTML exports остальных upstream ещё не разобраны.
- Adapter profiles в `adapters.py` пока статические. Search-layer profiles можно расширять через `--profile-file`, управлять через `profiles list/show/export` и создавать/удалять в served toolbox через guarded profile editor; saved cases хранят workflow/profile/adapter/scope policy metadata, но enforcement per-case policy и richer approval workflow ещё нет.
- Graph edges покрывают базовые отношения, включая `email -> domain`, `domain -> email`, `domain -> phone`, `domain -> discovered/social/sitemap URL`, `domain -> robots disallow path`, `domain -> subdomain`, `domain -> registrar`, `domain -> nameserver`, `domain -> whois-server`, `domain -> ip|port|technology`, `url -> instagram`, `url -> social-profile`, `instagram -> platform/display name/account id/public URLs`, `social -> social-profile/platform/display name/account id/public URLs` и adapter-derived `email -> related_email`; есть summary/focus-neighbor analytics, cross-case entity index, weighted shortest path, bounded cross-case network, command toolbox, served Case Browser и clickable bounded SVG graph, но нет advanced graph layout/filter UI.
- SQLite schema сейчас версии 3; при изменении таблиц нужна явная миграция.
- Рекомендации и scan-результаты являются техническими сигналами, не юридической или операционной инструкцией.
- Для будущего расширения может понадобиться отдельный ingestion pipeline и повторяемый классификатор.

## Что нужно обновлять при изменениях проекта

- При изменении CSV-схемы обновлять `Catalog.load()` и тесты.
- При добавлении native-модуля обновлять `engine.py`, `cli.py`, README и тесты.
- При изменении username site dataset/rules обновлять `sites.py`, username tests, README и parity-карту.
- При изменении HTTP body/title parsing обновлять `http_client.py`, username classifier tests и safety notes в README/analysis.
- При изменении web crawler или metadata extraction обновлять `web_extract.py`, `web_crawler.py`, web/domain tests, graph/entity mapping, README и parity-карту.
- При изменении WHOIS lookup/parser обновлять `whois_lookup.py`, `modules/domain.py`, graph/entity mapping, README и parity-карту.
- При изменении Instagram/social public metadata layer обновлять `modules/instagram.py`, graph/entity mapping, CLI/investigation tests, README и parity-карту.
- При изменении VK/OK RU social public metadata layer обновлять `modules/social.py`, graph/entity mapping, CLI/investigation tests, README и parity-карту.
- При изменении DNS lookup или email auth classification обновлять `dns_lookup.py`, `email_auth.py`, email tests, README и parity-карту.
- При изменении person-name expansion обновлять `modules/person.py`, graph/entity mapping, investigation tests и parity-карту.
- При подключении upstream-проекта обновлять `adapters.py`, указать лицензию, режим интеграции и parity gap.
- При изменении adapter profiles обновлять `adapters.py`, CLI-тесты, README и parity-карту.
- При изменении install/config требований или target-specific command templates adapters обновлять `AdapterSpec`, `adapter_setup.py`, `doctor.py`, tests и README.
- При добавлении parser для upstream stdout обновлять `adapter_parsers.py`, tests и `UPSTREAM_PARITY.ru.md`.
- При изменении схемы сущностей обновлять `entities.py`, `investigation.py`, README и тесты JSON/Markdown.
- При изменении graph relations обновлять `graph.py`, `case_store.py`, README и тесты.
- При изменении SQLite-схемы обновлять `case_store.py`, schema version, тесты сохранения и документацию.
- При изменении cross-case индекса или path analysis обновлять `case_store.py`, `graph.py`, `output.py`, CLI/toolbox tests и README.
- При изменении toolbox-направлений или шаблонов команд обновлять `toolbox.py`, CLI-тесты, README и этот анализ.
- При изменении целевой модели unified search/fan-out обновлять `DEEP_INTEGRATION_PLAN.ru.md`, README и этот анализ.
- При изменении search profiles или planner обновлять `search.py`, `output.py`, CLI-тесты, README, `DEEP_INTEGRATION_PLAN.ru.md` и этот анализ.
- При добавлении команд обновлять `README.md` и этот анализ.
- При изменении safety-границ обновлять `README.md`, `workflows.py` и тесты brief/recommend.
- При новом snapshot обновлять дату в `catalog.py` или добавить явный выбор snapshot.

## Журнал существенных изменений анализа

- 2026-06-24: добавлен Python CLI `osint_toolkit` поверх существующих OSINT snapshot CSV.
- 2026-06-24: цель уточнена до единой OSINT-системы с 1:1 functional parity; добавлены engine, native scan modules и adapter manifest.
- 2026-06-24: добавлен report-level entity summary для объединения seed values, native findings и adapter dry-runs в расследовании.
- 2026-06-24: добавлено SQLite-хранилище кейсов и CLI-команды `cases`/`case-show`.
- 2026-06-24: добавлен базовый adapter stdout parser и `run_adapter_findings()` для executed upstream CLI outputs.
- 2026-06-24: добавлен adapter setup/readiness layer и CLI-команда `adapter-setup`.
- 2026-06-24: добавлены `GraphEdge`, report-level graph edges и сохранение edges в SQLite case store.
- 2026-06-24: добавлены `analyze_case_graph()` и CLI-команда `case-graph` для summary сохранённого графа и запроса соседей сущности.
- 2026-06-24: добавлены `case-index`, `list_entity_index()` и `find_cases_by_entity()` для cross-case поиска повторяющихся сущностей.
- 2026-06-24: добавлен explicit `investigate --execute-adapters`, который запускает configured upstream CLI adapters и включает parsed findings в общий кейс.
- 2026-06-24: добавлен повторяемый `investigate --adapter` allowlist для выбора конкретных upstream adapters в кейсе.
- 2026-06-24: добавлены `AdapterProfile`, команда `adapter-profiles` и `investigate --adapter-profile` для готовых групп adapters.
- 2026-06-24: добавлены `PersonNameScanModule`, `scan person` и `investigate --person` с derived username scan/adapters и graph-связью `person -> username`.
- 2026-06-24: расширен person-name expansion: common RU/UA/name aliases, reverse-order handles, initials и handle suffixes теперь попадают в username candidates.
- 2026-06-24: добавлены operator-provided aliases для person expansion: `--person-alias`, `--person-alias-file`, `RunConfig.person_aliases` и graph propagation в `person -> username`.
- 2026-06-24: расширен native username dataset до 38 URL-шаблонов и добавлены platform-specific username rules со статусом `skipped`.
- 2026-06-24: импортирован Sherlock `data.json` как native package resource; активный username dataset расширен до 479 URL-шаблонов после дедупликации curated и upstream-записей.
- 2026-06-24: импортирован WhatsMyName `wmn-data.json` как native package resource; активный username dataset расширен до 1071 check-шаблона с WMN `e_string`/`m_string`, `e_code`/`m_code` и custom headers.
- 2026-06-24: импортирована sanitized projection Maigret `data.json` как native package resource; активный username dataset расширен до 1993 check-шаблонов с Maigret regex, markers, tags, safe headers и probe/profile URL metadata.
- 2026-06-24: добавлен native POST-check support для Sherlock `request_payload` и 22 WhatsMyName POST entries; активный username dataset содержит 2014 check-шаблонов, включая 23 active POST checks после дедупликации.
- 2026-06-24: добавлен native Sherlock `errorType=response_url` support; импортируются 27 `errorUrl` rules, из них 26 active checks остаются после дедупликации.
- 2026-06-24: добавлен HTTP retry/backoff для 429/temporary 5xx, `Retry-After`, CLI-параметры `--http-retries`, `--http-backoff` и username `--request-delay`.
- 2026-06-24: добавлены `HttpResult.body_text`, username content marker rules и `classify_username_http_result()` для soft-404/profile confidence в live checks.
- 2026-06-24: добавлен `dns_lookup.py`; `EmailScanModule` теперь планирует и выполняет MX/TXT lookup через `nslookup` в live-режиме.
- 2026-06-24: добавлен `email_auth.py`; `EmailScanModule` теперь классифицирует SPF и DMARC, а adapter manifest расширен executable target для `h8mail`.
- 2026-06-24: расширен native Email OSINT DNS layer: NS lookup, root TXT service signals, MTA-STS, TLS-RPT и BIMI classifiers.
- 2026-06-24: `AdapterSpec` получил target-specific `command_templates`; `user-scanner` теперь запускается как adapter для email и username.
- 2026-06-24: добавлен parser для `user-scanner` JSON/verbose results; executed output теперь превращается в `Finding`/entities/graph signals.
- 2026-06-24: добавлен RU/UA-aware command rendering и parser stdout/CSV для `snooppr/snoop`; Snoop findings теперь попадают в `Finding`/entities/graph signals.
- 2026-06-24: добавлен generated report ingestion для adapters и Maigret parser для NDJSON/simple JSON/CSV reports.
- 2026-06-24: h8mail переведён на generated JSON output file `-j <temp.json>`; добавлен parser upstream JSON и graph-связь `email -> related_email` с редактированием credential values.
- 2026-06-24: Mosint переведён на generated JSON output file `--output <temp.json>`; добавлен parser upstream JSON для reputation/breach/Hunter/search/DNS/social сигналов с редактированием credential values.
- 2026-06-24: добавлен PhoneInfoga parser для CLI sections и REST/API-like JSON; phone findings теперь создают graph-связи к country/country-code/carrier/location/line-type/phone-range/postal-code и URL из Google dorks/CSE.
- 2026-06-24: Sherlock execute mode теперь добавляет generated CSV/TXT output folder; parser stdout/CSV/TXT нормализует `Claimed`, `Available`, `Unknown`, `Illegal`, `WAF` в единые findings.
- 2026-06-24: Nexfil execute mode теперь запускается в isolated temporary workdir/HOME; parser stdout/TXT нормализует autosaved profile URLs и summary metrics.
- 2026-06-24: расширен native Web/domain recon: `DomainScanModule` теперь планирует и выполняет `crt.sh` certificate transparency lookup, а CT names попадают в `subdomain` entities и graph edges `domain -> subdomain`.
- 2026-06-24: добавлен native RDAP lookup для domain recon: registrar/nameservers/status/events попадают в `rdap-domain` finding, `registrar`/`nameserver` entities и graph edges `domain -> registrar|nameserver`.
- 2026-06-24: добавлен native public page email extraction для domain/url recon: emails из fetched landing pages попадают в `page-email-extraction` findings, `email` entities и graph edges `domain|url -> email`.
- 2026-06-24: добавлен bounded same-site crawler для domain/url recon: `--crawl-pages` и `--crawl-depth` ограничивают HTML-only обход, а найденные URLs/emails/phones/social links попадают в `web-crawl` findings, entities и graph edges.
- 2026-06-24: crawler расширен robots/sitemap discovery: `robots.txt` `Sitemap:`/`Disallow` и sitemap XML/text URLs нормализуются в `web-crawl` metadata, entities и graph edges.
- 2026-06-24: добавлен raw WHOIS fallback для domain recon: WHOIS port 43 parser извлекает registrar/nameservers/statuses/dates и WHOIS server metadata без копирования полного сырого WHOIS текста в evidence.
- 2026-06-24: добавлен native Instagram/social public metadata layer: `scan instagram` и `investigate --instagram` нормализуют username/profile/media URLs, извлекают public metadata и создают `instagram` entities/graph edges; `instaloader` adapter теперь принимает `instagram` target.
- 2026-06-24: добавлен native RU social public metadata layer: `scan social` и `investigate --social` нормализуют VK/OK public profile URLs, извлекают public page metadata и создают `social-profile` entities/graph edges.
- 2026-06-24: RU social layer расширен на Yandex/Mail.ru public profile-like URLs: `mailru:*` и `yandex:*` targets нормализуются в `social-profile` entities и graph edges без API/login/session flows.
- 2026-06-24: добавлен `domain-recon` adapter profile: Subfinder/httpx/passive Amass command templates и parsers превращают upstream subdomain/HTTP probe output в `Finding`/entities/graph signals.
- 2026-06-24: `laramies/theHarvester` переведён из non-executable manifest item в executable external adapter: `theHarvester -d <domain> -b all -f <temp.json>`; parser читает generated JSON/stdout и нормализует emails, hosts/vhosts, URLs, IPs, ASNs и people fields без переноса GPL-кода.
- 2026-06-25: добавлен `blacklanternsecurity/bbot` external adapter в passive `subdomain-enum` режиме: runner задаёт временный `--output`/`--name`, parser читает generated JSON/NDJSON/stdout events и нормализует DNS names, emails, URLs, IPs, ports, technologies, findings и vulnerabilities; graph/entity mapping расширен сущностями `ip`, `port` и `technology`.
- 2026-06-25: добавлен `smicallef/spiderfoot` external adapter в passive CLI режиме: runner требует `SPIDERFOOT_SF_PATH`, запускает upstream `sf.py` через Python, блокирует `--execute` при missing required env и parser нормализует SpiderFoot JSON/stdout events в entities/graph signals.
- 2026-06-25: добавлен `jasonxtn/argus` interactive external adapter: runner поддерживает scripted stdin, профиль `broad-recon` объединяет BBOT/SpiderFoot/Argus, parser нормализует Argus stdout/cache-like output в URLs, emails, phones, subdomains, IPs, ports и technologies.
- 2026-06-25: добавлен `qeeqbox/social-analyzer` external adapter: runner требует `SOCIAL_ANALYZER_APP_JS`, запускает upstream Node `app.js` в fast JSON mode с optional RU/UA country filter, а parser нормализует `detected`/`unknown`/`failed` profiles в `Finding`/entities/graph signals.
- 2026-06-25: добавлен `p1ngul1n0/blackbird` external adapter: runner поддерживает upstream checkout working directory через `BLACKBIRD_DIR`, читает только свежие/изменённые JSON exports из `results/`, а parser нормализует Blackbird username/email account hits в entities/graph signals.
- 2026-06-25: добавлен `toolbox` HTML-пульт: одно локальное окно для seed-полей, направлений OSINT, фото-зацепок без face-ID, cases/graph/index и adapter profiles с copy-ready CLI-командами.
- 2026-06-25: photo-раздел `toolbox` расширен локальными image routes: PowerShell baseline/hash, ExifTool metadata, ImageMagick identify, Tesseract OCR, zbarimg QR/barcodes и reverse image search portals для source/context search.
- 2026-06-25: добавлен `DEEP_INTEGRATION_PLAN.ru.md` — план перехода от отдельных `scan`/`run-adapter` маршрутов к unified `search`, где один phone/email/username/person/domain/url/image/social seed запускает все совместимые native-модули и adapters в единый отчёт.
- 2026-06-25: реализован Stage 1 unified search planner: команда `search --plan-only`, profiles `phone-full`/`email-full`/`username-full`/`person-full`/`passive-recon`/`web-full`/`image-full`/`social-full`/`ru-ua-full`, readiness статусы adapters/local tools и форматирование плана.
- 2026-06-25: реализован ready-only execution для `search --execute-adapters`: из SearchPlan выбираются только ready non-restricted adapters, результаты проходят через existing investigation/report/case-store слой, restricted и image local tools не запускаются.
- 2026-06-25: добавлен local image execution: ready ExifTool/ImageMagick/Tesseract/zbarimg/PowerShell tools выполняются локально, extracted seeds превращаются в обычные search targets, отчёт и case-store получают provenance, entities и graph.
- 2026-06-25: добавлен `tools doctor/install-plan/env --profile`: profile-level readiness, install/config actions и безопасный вывод env variable names без значений.
- 2026-06-25: добавлен `toolbox --serve`: локальный token-protected backend для запуска queued unified `search` jobs из HTML-пульта, с logs/status/report endpoints и ограничением output paths рабочей папкой backend.
- 2026-06-25: добавлен `--profile-file` для `search` и `tools doctor/install-plan/env`: custom search profiles загружаются из JSON, валидируются и участвуют в fan-out planning/readiness без изменения built-in profiles.
- 2026-06-25: добавлена команда `profiles list/show/export`: built-in и custom search profiles можно просматривать и экспортировать в reusable JSON без чтения кода.
- 2026-06-25: SQLite case store расширен таблицей `case_metadata`: `search --case-db` и `investigate --case-db` сохраняют workflow/profile/adapter policy metadata, а `case-show` выводит её в JSON/Markdown/table.
- 2026-06-25: `toolbox --serve` расширен Case Browser: HTML-пульт читает `/api/cases`, `/api/cases/<id>`, `/api/cases/<id>/graph` и `/api/case-index` через token-protected backend без произвольного shell.
- 2026-06-25: `search --scope-note` и `investigate --scope-note` сохраняют текстовый scope/context в `case_metadata`, чтобы saved cases фиксировали рамки проверки рядом с profile/execution policy.
- 2026-06-25: Case Browser в `toolbox --serve` получил bounded SVG-визуализацию saved case graph из `entities`/`edges`; `/api/search` payload теперь передаёт `scope_note` в allowlisted CLI command.
- 2026-06-25: SVG-граф в Case Browser стал кликабельным: выбор узла заполняет focus entity и запускает focus-neighbor analysis через существующий graph endpoint.
- 2026-06-25: добавлен cross-case weighted path analysis: `case-path`, `/api/case-path`, toolbox Path-кнопка и Markdown/table/JSON форматирование path hops с `case_id`/relation/direction/confidence/source/weight.
- 2026-06-25: добавлен bounded cross-case network analysis: `case-network`, `/api/case-network`, toolbox Network-кнопка, aggregation одинаковых edges, degree/case_count и фильтры kind/relation.
- 2026-06-25: добавлен safe case management слой: `cases --workflow/--profile/--scope-query`, `case-update`, `case-delete --yes`, `/api/cases/<id>/update`, `/api/cases/<id>/delete` и toolbox controls для filtered list, title/scope update и typed-confirm delete.
- 2026-06-25: `toolbox --serve` получил guarded custom profile integration: `/api/profiles`, поля `Profile file`/`Custom profile`, path guard внутри backend cwd и передачу `--profile-file` в allowlisted `/api/search` jobs после JSON validation.
- 2026-06-25: served toolbox расширен минимальным profile editor: `/api/profiles/save`, `/api/profiles/delete`, поля profile target/native/adapter/local/excluded lists, canonical JSON write и повторная валидация всего custom profile file перед сохранением.
- 2026-06-25: `search --execute-adapters` теперь передаёт `profile.native_kinds` в `run_investigation()`, поэтому custom adapter-only profiles не запускают скрытые native-модули вне выбранного профиля.
