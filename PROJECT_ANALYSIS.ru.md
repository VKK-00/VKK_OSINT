# Анализ проекта

## Цель проекта

Создать собственную единую OSINT-систему на основе уже собранного каталога GitHub OSINT-проектов.

Целевая модель — 1:1 функциональная совместимость с upstream-проектами в одном интерфейсе: часть возможностей переносится в native-модули, часть подключается через внешние CLI/API adapters, а высокорисковые механики выносятся в restricted-слой.

Под 1:1 здесь понимается не безусловное копирование исходников, а воспроизведение поведения: такой же класс входов, сопоставимый результат, единая нормализация в `Finding`, понятные confidence/status и явно описанный gap, если upstream-поведение ещё не покрыто. Буквальный перенос кода возможен только после проверки лицензии и совместимости.

## Что делает проект

Проект хранит датированные CSV/Markdown/JSON-срезы GitHub OSINT-проектов и предоставляет Python CLI/engine поверх этих данных.

CLI работает в трёх режимах:

- catalog/recommend/brief — работа с curated-каталогом;
- scan/adapters — единое ядро выполнения и карта функциональной совместимости upstream-проектов;
- investigate — объединение нескольких seed values, native findings, adapter dry-runs и нормализованных сущностей в один отчёт.

Первый native-слой уже выполняет:

- person-name expansion: нормализация имени, RU/UA transliteration и username-кандидаты;
- username public profile checks по 2014 активным URL/check-шаблонам: 38 curated правил, импорт Sherlock `data.json` GET/POST entries, импорт WhatsMyName `wmn-data.json` GET/POST entries и sanitized Maigret site rules, совместимые по классу задачи с Sherlock/Maigret/WhatsMyName/Nexfil;
- platform-specific username rules: несовместимые site checks возвращаются как `skipped`, без построения заведомо неверного URL;
- content marker rules для live username checks: profile markers повышают confidence, soft-404 markers дают `not_found`;
- email baseline checks: синтаксис, live domain resolution, MX/NS/TXT lookup, SPF, DMARC, MTA-STS, TLS-RPT, BIMI и TXT service signal classification;
- phone baseline checks: нормализация, E.164-like validation и country-prefix signal;
- domain baseline recon: DNS resolution, HTTP/HTTPS metadata, bounded same-site crawler, robots/sitemap discovery, public email/phone/social link extraction, presence security headers, certificate transparency subdomain discovery и RDAP registration lookup;
- Telegram baseline: handle/post URL normalization и optional live public metadata;
- RU/UA source pack: curated карты, Telegram/RU platforms, geospatial и pastebin источники;
- базовый web metadata scan, public email extraction, robots/sitemap discovery и bounded same-site crawl по URL, совместимый с начальным web-check/Photon слоем;
- external adapter dry-run/execute runner для настроенных upstream CLI;
- adapter stdout parser: извлечение URL, email, phone и key/value сигналов из выполненных upstream CLI;
- generated report ingestion: внешние adapters могут писать JSON/CSV во временную output-папку или конкретный временный output-файл, после чего runner читает эти файлы и передаёт их в parser;
- Sherlock adapter: `sherlock <username> --no-color --print-all --csv --txt --folderoutput <tempdir>` в execute-режиме и parser stdout/CSV/TXT для username profile discovery;
- Nexfil adapter: `nexfil -u <username>` запускается в isolated temporary workdir/HOME, parser читает stdout и autosaved TXT reports;
- Mosint adapter: `mosint --silent <email> --output <temp.json>` и parser upstream JSON для email reputation, breaches, related emails/domains, paste/search URLs, social flags и DNS records;
- h8mail adapter: `h8mail -t <email> --hide -j <temp.json>` и parser фактического upstream JSON без переноса password/hash/token-like значений в evidence;
- PhoneInfoga adapter: `phoneinfoga scan -n <number>` и parser upstream CLI/API output для local/numverify/googlesearch/googlecse/ovh phone intelligence;
- Maigret adapter: `--json ndjson`, RU/UA `--tags`, parser JSON/CSV dossier findings;
- Snoop adapter: RU/UA-aware command rendering через `--include RU|UA` и parser stdout/CSV-отчётов;
- adapter setup/readiness layer: install hints, docs URLs, PATH/env readiness;
- adapter profiles: готовые группы upstream adapters для типовых расследований;
- adapter doctor: проверка фактической доступности upstream CLI в `PATH`;
- investigation runner: один кейс, несколько seed-типов, entity summary, graph edges, единый Markdown/JSON отчёт;
- executed adapter ingestion inside investigation: явный `--execute-adapters` добавляет parsed upstream CLI findings в entities, graph edges и case store;
- SQLite case store: сохранение и повторный просмотр кейсов, targets, entities, edges и findings;
- saved case graph analysis: счётчики связей/типов сущностей, top connected nodes и focus-запрос соседей сущности;
- cross-case entity index: поиск повторяющихся email/domain/telegram/url и других сущностей между сохранёнными кейсами;
- dry-run режим без сетевых запросов по умолчанию;
- live режим только при явном `--live`.

## Структура репозитория

- `top_100_osint_github_2026-06-24.csv` — исходный top-100 GitHub OSINT snapshot.
- `osint_people_projects_2026-06-24.csv` — curated-срез OSINT по лицам.
- `osint_ru_ua_projects_2026-06-24.csv` — curated-срез РФ/Украина/ru-platform.
- `osint_people_ru_ua_2026-06-24.csv` — объединённая разметка people + ru/ua.
- `osint_toolkit/` — Python-пакет CLI.
- `osint_toolkit/modules/` — native scan-модули.
- `osint_toolkit/resources/sherlock_data.json` — встроенный snapshot Sherlock `sherlock_project/resources/data.json`, commit `206068d`, MIT license.
- `osint_toolkit/resources/whatsmyname_wmn_data.json` — встроенный snapshot WhatsMyName `wmn-data.json`, commit `7c44595`, CC BY-SA 4.0 license.
- `osint_toolkit/resources/maigret_sites.json` — sanitized projection Maigret `maigret/resources/data.json`, commit `2484509`, MIT license.
- `osint_toolkit/resources/THIRD_PARTY_NOTICES.txt` — notice по скопированному upstream dataset.
- `tests/` — unittest-тесты.
- `README.md` — пользовательская инструкция.
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
  - `DomainScanModule` — DNS, HTTP/HTTPS baseline, bounded same-site crawler, certificate transparency lookup и RDAP lookup для доменов.
  - `parse_crtsh_subdomains()` — parser `crt.sh` JSON, который нормализует wildcard/common-name значения в bounded `subdomain` signals.
  - `parse_rdap_domain_record()` — parser RDAP JSON, который извлекает registrar, domain handle, statuses, nameservers и registration/expiration dates.
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
- `osint_toolkit/adapter_setup.py`
  - `AdapterSetup` — readiness/install/config view для adapter.
  - `build_adapter_setup()` — проверка executable в `PATH`, install command, docs URL и env readiness.
- `osint_toolkit/adapter_runner.py`
  - `run_adapter()` — обратно совместимый single-summary wrapper.
  - `run_adapter_findings()` — dry-run или явный запуск внешнего CLI adapter без shell, с parser findings после успешного запуска.
- `osint_toolkit/doctor.py`
  - `inspect_adapters()` — диагностика доступности upstream adapters.
- `osint_toolkit/entities.py`
  - `Entity` — нормализованная сущность кейса: email, phone, domain, URL, Telegram handle, country/region и т.д.
  - `entities_from_targets()` — извлечение сущностей из seed values.
  - `entities_from_findings()` — извлечение сущностей из native и adapter findings.
  - `merge_entities()` — дедупликация сущностей с учётом confidence.
- `osint_toolkit/graph.py`
  - `GraphEdge` — отношение между двумя сущностями.
  - `graph_edges_from_case()` — построение связей `email -> domain`, `email -> related_email`, `domain|url -> page_contact_email/page_contact_phone/discovered_url/social_url/sitemap_url/robots_disallow_path`, `url -> domain`, `target -> finding URL`, `phone -> country/normalized/carrier/location/line-type/phone-range/postal-code`.
  - `analyze_case_graph()` — аналитика сохранённого кейса: node/edge counts, relation counts, kind counts, top connected nodes и соседи выбранной сущности.
- `osint_toolkit/case_store.py`
  - `CaseStore` — SQLite-хранилище расследований.
  - `save()` — сохраняет `InvestigationResult` в таблицы `cases`, `targets`, `entities`, `edges`, `findings`.
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
- `osint_toolkit/cli.py`
  - argparse CLI: `stats`, `catalog`, `show`, `scan`, `adapters`, `adapter-profiles`, `adapter-setup`, `doctor`, `run-adapter`, `investigate`, `cases`, `case-show`, `case-graph`, `case-index`, `recommend`, `brief`.

## Как система работает end-to-end

Каталоговый поток:

1. Пользователь запускает `python -m osint_toolkit catalog|show|stats|recommend|brief`.
2. CLI определяет папку данных: `--data-dir` или корень репозитория.
3. `Catalog.load()` читает top-100 CSV и overlay-разметку people/ru-ua.
4. Команда применяет фильтры или профиль workflow.
5. Результат выводится в консоль или записывается как Markdown-brief.

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
5. Если adapter объявляет generated report files, runner создаёт временную output-папку, добавляет upstream-аргумент output folder или output file и читает сгенерированные файлы.
6. `parse_adapter_output()` извлекает дополнительные findings из stdout/stderr и generated report text для поддерживаемых adapter families.
7. Restricted adapters требуют отдельный `--allow-restricted`.

Adapter setup-поток:

1. Пользователь запускает `python -m osint_toolkit adapter-setup [repo]`.
2. `build_adapter_setup()` читает install/config metadata из `AdapterSpec`.
3. Проверяется наличие executable в `PATH` и обязательных переменных окружения.
4. Результат выводится как table/Markdown/CSV/JSON, без автоматической установки внешнего инструмента.

Investigation-поток:

1. Пользователь запускает `python -m osint_toolkit investigate` с одним или несколькими seed values.
2. CLI превращает каждый seed в `ScanTarget`.
3. `run_investigation()` запускает native scan-модули; person seeds разворачиваются в derived username targets.
4. Derived username targets прогоняются через native username scan и, при `--include-adapters`, через совместимые adapters.
5. При `--execute-adapters` совместимые adapters запускаются через `run_adapter_findings()`; stdout/stderr parser добавляет дополнительные adapter findings.
6. `entities.py` извлекает и объединяет сущности из входных целей, `Finding.url`, `Finding.evidence` и `Finding.metadata`.
7. `graph.py` строит связи между сущностями, включая `person -> username -> url`, `domain|url -> page_contact_email`, `domain|url -> page_contact_phone`, `domain|url -> sitemap_url`, `domain|url -> robots_disallow_path` и `domain|url -> discovered/social URL`.
8. Если указан `--case-db`, `CaseStore` сохраняет кейс в SQLite до вывода отчёта.
9. Отчёт выводится как Markdown или JSON; Markdown содержит `Entity Summary`, `Graph Edges`, native findings, adapter dry-runs или executed adapter findings и review checklist.

Case-store поток:

1. Пользователь запускает `python -m osint_toolkit cases --case-db <path>`.
2. `CaseStore.list_cases()` читает summary сохранённых кейсов.
3. Пользователь запускает `python -m osint_toolkit case-show --case-db <path> <case_id>`.
4. `CaseStore.load_case()` возвращает targets, entities, edges и findings в table/Markdown/JSON формате.
5. Пользователь запускает `python -m osint_toolkit case-graph --case-db <path> <case_id>`.
6. `analyze_case_graph()` строит summary сохранённого графа и, при указанном фокусе, возвращает соседей конкретной сущности.
7. Пользователь запускает `python -m osint_toolkit case-index --case-db <path>`.
8. `CaseStore.list_entity_index()` строит индекс сущностей по всем сохранённым кейсам; `find_cases_by_entity()` показывает кейсы для точной сущности.

## Поток данных

Источник истины — локальные CSV-файлы. Код не изменяет эти CSV при обычной работе.

Поток:

Каталог:

`CSV snapshot -> Catalog.load() -> OsintProject[] -> filter/recommend/brief -> console/Markdown output`

Сканирование:

`CLI target -> ScanTarget -> Engine -> ScanModule[] -> Finding[] planned/skipped/live -> table/Markdown/CSV/JSON`

Email DNS/auth enrichment:

`email -> domain -> socket.getaddrinfo + nslookup MX/TXT -> SPF classifier + nslookup _dmarc TXT -> DMARC classifier -> Finding[]`

Person expansion:

`person seed -> PersonNameScanModule -> username candidates -> derived username ScanTarget[] -> UsernameScanModule/adapters -> Entity[]/GraphEdge[]`

Адаптеры:

`CLI adapter request -> AdapterSpec -> command_template/target-specific command_templates -> dry-run/external process -> summary Finding -> parsed Finding[]`

Setup adapters:

`AdapterSpec -> AdapterSetup -> PATH/env readiness -> table/Markdown/CSV/JSON`

Investigation:

`multiple CLI seeds -> ScanTarget[] -> Engine -> Finding[] -> optional adapter profile/allowlist -> adapter dry-runs/executions -> Entity[] -> GraphEdge[] -> Markdown/JSON report`

Сохранённые кейсы:

`InvestigationResult -> CaseStore(SQLite) -> cases/case-show/case-graph/case-index -> table/Markdown/CSV/JSON`

## Внешние интеграции

В рантайме сетевые интеграции есть только в явном live-режиме scan-команд.

Существующие CSV были собраны из GitHub ранее. Каталоговые команды не ходят в GitHub API.

Native live-модули используют публичные HTTP(S) URL checks через стандартную библиотеку Python. Для username live checks сохраняется только ограниченный текст ответа в памяти процесса, чтобы применить content marker rules; на диск body не пишется.

Email live-модуль использует `socket.getaddrinfo()` и системный `nslookup` для MX/TXT. TXT результата домена достаточно для SPF classifier, а DMARC classifier делает отдельный TXT lookup по `_dmarc.<domain>`. Если `nslookup` недоступен, результат DNS-записи возвращается как `missing`, а не как падение команды.

SQLite используется локально через стандартную библиотеку `sqlite3`; внешнего сервера БД нет.

External adapters должны подключать upstream CLI/API без копирования кода, если лицензия, масштаб или язык проекта делают прямой перенос неразумным. Для `sherlock-project/sherlock` зафиксирован executable adapter target `sherlock <username>` с generated args `--no-color --print-all --csv --txt --folderoutput <tempdir>`. Для `thewhiteh4t/nexfil` зафиксирован executable adapter target `nexfil -u <username>` с временным cwd/HOME, потому что upstream autosave пишет TXT reports относительно рабочей директории/HOME. Для `alpkeskin/mosint` зафиксирован executable adapter target `mosint --silent <email> --output <temp.json>` с временным JSON output file. Для `h8mail` зафиксирован executable adapter target `h8mail -t <email> --hide -j <temp.json>` с временным JSON output file. Для `soxoj/maigret` включён JSON-report template `maigret <username> --json ndjson [--tags ru|ua]` с временным `--folderoutput`. Для `user-scanner` включены target-specific JSON templates: `user-scanner -e <email> -f json` и `user-scanner -u <username> -f json`. Для `snooppr/snoop` включён username template `snoop --no-func --found-print [--include RU|UA] <username>`. Для `sundowndev/phoneinfoga` включён executable adapter target `phoneinfoga scan -n <number>`; проект PhoneInfoga распространяется под GPL-3.0, поэтому текущий 1:1 паритет делается через CLI/API output ingestion, а не через перенос upstream Go-кода в Python-пакет.

## Конфигурация, переменные окружения и секреты

Секреты не используются.

Конфигурация:

- `--data-dir` — путь к папке с CSV.
- `--format` — формат вывода для команд `catalog` и `show`.
- `--out` — путь Markdown-файла для `brief`.
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
- `case-graph --entity-kind` и `case-graph --entity-value` — focus-сущность для поиска соседей в сохранённом графе.
- `case-graph --limit` — ограничение top nodes и списка соседей.
- `case-index --kind` — фильтр типа сущности в cross-case индексе.
- `case-index --value` — точное значение сущности для поиска кейсов; требует `--kind`.
- `case-index --min-cases` — минимальное число кейсов для строки индекса.
- `case-index --limit` — максимальное число строк индекса.
- `run-adapter --execute` — явный запуск внешнего CLI; для поддерживаемых stdout/generated-report formats добавляет parsed findings.
- `adapter-setup` — показать install/config/readiness plan для adapters.

## Команды запуска, тестирования, проверки и отладки

Запуск:

```powershell
python -m osint_toolkit stats
python -m osint_toolkit catalog --kind people --direct-only --limit 10
python -m osint_toolkit scan person "Ivan Petrenko" --limit 10
python -m osint_toolkit scan username exampleuser --limit 10
python -m osint_toolkit scan username exampleuser --region ru --live --limit 5 --http-retries 2 --request-delay 0.2
python -m osint_toolkit scan email person@example.com --live
python -m osint_toolkit scan phone +380441234567
python -m osint_toolkit scan domain example.com --live --crawl-pages 5 --crawl-depth 1
python -m osint_toolkit scan telegram "@durov"
python -m osint_toolkit scan ru-ua all --region ua
python -m osint_toolkit scan url https://example.com --live --crawl-pages 5 --crawl-depth 1
python -m osint_toolkit adapters
python -m osint_toolkit adapter-profiles
python -m osint_toolkit adapter-setup sherlock-project/sherlock
python -m osint_toolkit doctor
python -m osint_toolkit run-adapter sherlock-project/sherlock username example_user
python -m osint_toolkit run-adapter thewhiteh4t/nexfil username example_user
python -m osint_toolkit run-adapter alpkeskin/mosint email person@example.com
python -m osint_toolkit run-adapter khast3x/h8mail email person@example.com
python -m osint_toolkit run-adapter sundowndev/phoneinfoga phone +380441234567
python -m osint_toolkit investigate --person "Ivan Petrenko" --include-adapters --adapter-profile username-full --adapter-limit 2
python -m osint_toolkit investigate --username example_user --domain example.com --telegram "@durov" --include-adapters
python -m osint_toolkit investigate --username example_user --include-adapters --adapter-profile username-full --adapter-limit 2
python -m osint_toolkit investigate --username example_user --include-adapters --adapter soxoj/maigret
python -m osint_toolkit investigate --username example_user --include-adapters --execute-adapters --adapter-limit 1
python -m osint_toolkit investigate --email person@example.com --case-db cases.sqlite --case-id case-001
python -m osint_toolkit cases --case-db cases.sqlite
python -m osint_toolkit case-show --case-db cases.sqlite case-001 --format json
python -m osint_toolkit case-graph --case-db cases.sqlite case-001
python -m osint_toolkit case-graph --case-db cases.sqlite case-001 --entity-kind email --entity-value person@example.com --format json
python -m osint_toolkit case-index --case-db cases.sqlite --kind domain --min-cases 2
python -m osint_toolkit case-index --case-db cases.sqlite --kind email --value person@example.com --format json
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
- Adapter parser не считается источником истины: он нормализует stdout уже запущенного upstream CLI, а не заменяет native logic upstream-проекта.
- Generated report files читаются из временной директории или временного файла и удаляются после parsing; постоянное хранение остаётся задачей case store/report output.
- Investigation adapter execution является opt-in: `--include-adapters` остаётся dry-run, а запуск внешнего кода требует отдельного `--execute-adapters`.
- Investigation adapter allowlist выбирается оператором через повторяемый `--adapter`; без allowlist система использует совместимые adapters из `AdapterSpec`.
- Adapter profiles являются статическим удобным слоем поверх `AdapterSpec`, а не отдельным источником истины.
- Adapter setup layer не устанавливает внешние инструменты автоматически: он показывает install plan/readiness, чтобы не запускать непроверенный код без решения оператора.
- Region-aware adapter placeholders используются только при наличии `ScanTarget.region=ru|ua`; для `all` пустые части команды отбрасываются.
- `Entity` отделён от `Finding`: finding описывает источник и сигнал, entity описывает нормализованный объект, а `GraphEdge` описывает связь между объектами.
- SQLite case store отделён от engine: сканирование можно использовать без записи на диск, а сохранение включается явно через `--case-db`.
- Graph analysis отделён от case store: SQLite хранит факты кейса, а `analyze_case_graph()` вычисляет summary и neighbors без изменения схемы БД.
- Cross-case entity index использует уже сохранённую таблицу `entities`; новая таблица не добавлена, потому что индекс пока вычисляется read-only запросами и не требует миграции.
- Dry-run используется по умолчанию для scan-команд. Live-сетевые проверки требуют явного `--live`.
- Лицензионно сложные или большие проекты подключаются adapters вместо прямого копирования кода.
- Password recovery flows, email-to-account и phone-to-account механики не переносятся в native-код без restricted-режима.
- Разметка people/ru-ua считается curated-слоем поверх top-100, а не абсолютной классификацией качества.

## Рассмотренные варианты реализации

- Полноценный web UI: отложен, потому что сначала нужно стабилизировать engine/adapters.
- Буквальное копирование кода из всех проектов: допускается только после license review. Обязательный путь для цели — 1:1 functional parity поведения через native-compatible modules, external adapters и documented restricted/excluded decisions.
- Новая база данных SQLite: пока не нужна, CSV достаточно для каталога; для истории scan-запусков может понадобиться позже.

## Текущие ограничения, риски и открытые вопросы

- Каталог основан на snapshot от 2026-06-24; GitHub stars и актуальность проектов меняются.
- Качество и безопасность внешних репозиториев не аудированы.
- Native person-name expansion использует шаблоны имени/фамилии, reverse-order variants, initials, curated common given-name aliases, operator-provided alias dictionaries, handle suffixes и RU/UA transliteration; пока нет bundled historical alias datasets и platform-specific alias scoring.
- Первый native username module уже импортирует Sherlock GET/POST site dataset, WhatsMyName GET/POST dataset и sanitized Maigret site rules, покрывает URL-template/status-code слой, Sherlock response-url `errorUrl`, часть platform syntax rules, custom headers, POST bodies, базовый HTTP retry/backoff и часть content marker rules, но не всю логику Sherlock/Maigret/WhatsMyName: Maigret engine templates/activation/recursive/reporting logic ещё не встроены, нет полного набора WAF/error-handling rules, site-specific rate-limit tuning и enrichment.
- Native email module делает MX/NS/TXT lookup, SPF/DMARC/MTA-STS/TLS-RPT/BIMI classifiers и root TXT service signal classifier, но пока не делает native breach lookup, local cache или own API enrichment; Mosint/h8mail покрывают часть enrichment через external adapters.
- Native phone module пока не делает carrier lookup, reputation lookup или external API enrichment.
- Native web/domain crawler уже собирает robots/sitemap URLs, robots disallow paths, same-site URLs, external URLs, social URLs, public emails и E.164-like phones, но остаётся bounded и mostly HTML/XML/text-only: нет headless browser, JavaScript rendering, form submission, full robots policy enforcement и широкого SpiderFoot/Photon-style обхода.
- Telegram module пока не использует Telegram API и не получает private/group data.
- RU/UA source pack пока curated вручную из текущего snapshot, без автообновления.
- Adapter runner запускает только те CLI, которые уже установлены в `PATH`; установкой upstream-проектов он пока не занимается.
- Adapter setup metadata покрывает ключевые upstream adapters, но install commands могут меняться; перед установкой нужно сверяться с upstream docs URL.
- Adapter manifest теперь включает generated CSV/TXT folder template для `sherlock-project/sherlock`, isolated workdir TXT ingestion для `thewhiteh4t/nexfil`, generated JSON-file templates для `alpkeskin/mosint` и `h8mail`, generated JSON-report folder template для `soxoj/maigret`, target-specific executable templates для `user-scanner`, region-aware template для `snooppr/snoop` и executable template для `sundowndev/phoneinfoga`; более сложные adapters могут потребовать richer per-mode config.
- Adapter parser покрывает общие URL/email/phone/key-value patterns, Sherlock stdout/CSV/TXT reports, Nexfil stdout/TXT reports, Mosint JSON reports, h8mail JSON reports, Maigret JSON/CSV reports, `user-scanner` JSON/verbose output, Snoop stdout/CSV output и PhoneInfoga CLI/API output; сложные JSON/CSV/HTML exports остальных upstream ещё не разобраны.
- Adapter profiles пока статические; нет пользовательских профилей и per-case persistent adapter policy.
- Graph edges покрывают базовые отношения, включая `email -> domain`, `domain -> email`, `domain -> phone`, `domain -> discovered/social/sitemap URL`, `domain -> robots disallow path`, `domain -> subdomain`, `domain -> registrar`, `domain -> nameserver` и adapter-derived `email -> related_email`; есть summary/focus-neighbor analytics и cross-case entity index, но нет weighted path finding, cross-case edge graph и визуального UI.
- SQLite schema сейчас версии 2; при изменении таблиц нужна явная миграция.
- Рекомендации и scan-результаты являются техническими сигналами, не юридической или операционной инструкцией.
- Для будущего расширения может понадобиться отдельный ingestion pipeline и повторяемый классификатор.

## Что нужно обновлять при изменениях проекта

- При изменении CSV-схемы обновлять `Catalog.load()` и тесты.
- При добавлении native-модуля обновлять `engine.py`, `cli.py`, README и тесты.
- При изменении username site dataset/rules обновлять `sites.py`, username tests, README и parity-карту.
- При изменении HTTP body/title parsing обновлять `http_client.py`, username classifier tests и safety notes в README/analysis.
- При изменении web crawler или metadata extraction обновлять `web_extract.py`, `web_crawler.py`, web/domain tests, graph/entity mapping, README и parity-карту.
- При изменении DNS lookup или email auth classification обновлять `dns_lookup.py`, `email_auth.py`, email tests, README и parity-карту.
- При изменении person-name expansion обновлять `modules/person.py`, graph/entity mapping, investigation tests и parity-карту.
- При подключении upstream-проекта обновлять `adapters.py`, указать лицензию, режим интеграции и parity gap.
- При изменении adapter profiles обновлять `adapters.py`, CLI-тесты, README и parity-карту.
- При изменении install/config требований или target-specific command templates adapters обновлять `AdapterSpec`, `adapter_setup.py`, `doctor.py`, tests и README.
- При добавлении parser для upstream stdout обновлять `adapter_parsers.py`, tests и `UPSTREAM_PARITY.ru.md`.
- При изменении схемы сущностей обновлять `entities.py`, `investigation.py`, README и тесты JSON/Markdown.
- При изменении graph relations обновлять `graph.py`, `case_store.py`, README и тесты.
- При изменении SQLite-схемы обновлять `case_store.py`, schema version, тесты сохранения и документацию.
- При изменении cross-case индекса обновлять `case_store.py`, `output.py`, CLI-тесты и README.
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
