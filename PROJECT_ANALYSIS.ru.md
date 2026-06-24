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
- username public profile checks по 38 URL-шаблонам, совместимые по классу задачи с Sherlock/Maigret/WhatsMyName/Nexfil;
- platform-specific username rules: несовместимые site checks возвращаются как `skipped`, без построения заведомо неверного URL;
- content marker rules для live username checks: profile markers повышают confidence, soft-404 markers дают `not_found`;
- email baseline checks: синтаксис, live domain resolution, MX/TXT lookup, SPF и DMARC policy classification;
- phone baseline checks: нормализация, E.164-like validation и country-prefix signal;
- domain baseline recon: DNS resolution, HTTP/HTTPS metadata и presence security headers;
- Telegram baseline: handle/post URL normalization и optional live public metadata;
- RU/UA source pack: curated карты, Telegram/RU platforms, geospatial и pastebin источники;
- базовый web metadata scan по URL, совместимый с начальным web-check слоем;
- external adapter dry-run/execute runner для настроенных upstream CLI;
- adapter stdout parser: извлечение URL, email, phone и key/value сигналов из выполненных upstream CLI;
- generated report ingestion: внешние adapters могут писать JSON/CSV во временную output-папку или конкретный временный output-файл, после чего runner читает эти файлы и передаёт их в parser;
- h8mail adapter: `h8mail -t <email> --hide -j <temp.json>` и parser фактического upstream JSON без переноса password/hash/token-like значений в evidence;
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
  - `RunConfig` — dry-run/live, timeout и limit.
  - `Finding` — единый формат результата.
  - `Engine` — запуск подходящих модулей.
- `osint_toolkit/modules/username.py`
  - `UsernameScanModule` — Sherlock/Maigret/WhatsMyName-подобные проверки публичных профилей.
  - `normalize_username()` — нормализация leading `@` для username inputs.
  - `classify_username_http_result()` — status/content classifier для live username checks.
- `osint_toolkit/sites.py`
  - `UsernameSite` — URL template, регион, upstream source projects и platform-specific username rule.
  - `match_content()` — сопоставление title/body с profile/not-found markers.
  - `USERNAME_SITES` — текущий native dataset из 38 public profile templates.
- `osint_toolkit/http_client.py`
  - `HttpResult.body_text` — ограниченный текст ответа для content marker checks.
- `osint_toolkit/modules/person.py`
  - `PersonNameScanModule` — safe person-name expansion в username-кандидаты.
  - `generate_username_candidates()` — стабильные варианты `firstlast`, `first.last`, `first_initial_last` и RU/UA transliteration.
- `osint_toolkit/modules/email.py`
  - `EmailScanModule` — базовая проверка email: синтаксис, доменное разрешение, MX/TXT lookup, SPF/DMARC findings.
- `osint_toolkit/email_auth.py`
  - `classify_spf_policy()` — классификация SPF из доменного TXT: отсутствие, multiple SPF warning, `all` policy, include/redirect counts.
  - `classify_dmarc_policy()` — классификация DMARC из `_dmarc.<domain>` TXT: отсутствие, multiple DMARC warning, `p=`, `sp=`, alignment, percent и report URI tags.
- `osint_toolkit/dns_lookup.py`
  - `lookup_dns_records()` — запуск системного `nslookup` для MX/TXT без дополнительных Python-зависимостей.
  - `parse_nslookup_records()` — parser Windows/Unix-style `nslookup` output для MX/TXT; TXT chunks соединяются в одну запись, чтобы SPF/DMARC не теряли длинные значения.
- `osint_toolkit/modules/phone.py`
  - `PhoneScanModule` — нормализация и country-prefix сигнал для телефонных номеров.
- `osint_toolkit/modules/domain.py`
  - `DomainScanModule` — DNS и HTTP/HTTPS baseline для доменов.
- `osint_toolkit/modules/telegram.py`
  - `TelegramScanModule` — нормализация Telegram handles/post URLs и live t.me metadata.
- `osint_toolkit/modules/ru_ua_sources.py`
  - `RuUaSourcePackModule` — curated RU/UA source pack.
- `osint_toolkit/modules/web.py`
  - `WebMetadataModule` — HTTP status/final URL/title.
- `osint_toolkit/adapters.py`
  - `AdapterSpec` — карта upstream-проектов, лицензий, режима интеграции, target-specific command templates и текущего статуса.
  - `AdapterProfile` — reusable группы adapters для `investigate --adapter-profile`.
  - `expand_adapter_repositories()` — разворачивает профили и ручные repositories в дедуплицированный allowlist.
- `osint_toolkit/adapter_parsers.py`
  - `parse_adapter_output()` — нормализация stdout/stderr внешних CLI в дополнительные `Finding`.
  - Поддерживает базовые URL/email/phone/key-value patterns для Sherlock/Maigret/Nexfil/Mosint/PhoneInfoga-подобного вывода.
  - Поддерживает `soxoj/maigret` NDJSON/simple JSON/CSV reports: site/status/url/tags/ids нормализуются в `Finding`.
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
  - `graph_edges_from_case()` — построение связей `email -> domain`, `email -> related_email`, `url -> domain`, `target -> finding URL`, `phone -> country/normalized`.
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
5. В live-режиме модуль выполняет публичные HTTP checks, читает title/body excerpt и возвращает `Finding` с `content_rule` metadata.

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
7. `graph.py` строит связи между сущностями, включая `person -> username -> url`.
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

External adapters должны подключать upstream CLI/API без копирования кода, если лицензия, масштаб или язык проекта делают прямой перенос неразумным. Для `h8mail` зафиксирован executable adapter target `h8mail -t <email> --hide -j <temp.json>` с временным JSON output file. Для `soxoj/maigret` включён JSON-report template `maigret <username> --json ndjson [--tags ru|ua]` с временным `--folderoutput`. Для `user-scanner` включены target-specific JSON templates: `user-scanner -e <email> -f json` и `user-scanner -u <username> -f json`. Для `snooppr/snoop` включён username template `snoop --no-func --found-print [--include RU|UA] <username>`.

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
python -m osint_toolkit scan username exampleuser --region ru --live --limit 5
python -m osint_toolkit scan email person@example.com --live
python -m osint_toolkit scan phone +380441234567
python -m osint_toolkit scan domain example.com --live
python -m osint_toolkit scan telegram "@durov"
python -m osint_toolkit scan ru-ua all --region ua
python -m osint_toolkit scan url https://example.com --live
python -m osint_toolkit adapters
python -m osint_toolkit adapter-profiles
python -m osint_toolkit adapter-setup sherlock-project/sherlock
python -m osint_toolkit doctor
python -m osint_toolkit run-adapter sherlock-project/sherlock username example_user
python -m osint_toolkit run-adapter khast3x/h8mail email person@example.com
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
- Username live classifier сначала учитывает HTTP status, затем title/body markers: soft-404 marker сильнее HTTP 200, profile marker повышает confidence.
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
- Native person-name expansion пока использует базовые шаблоны имени/фамилии и RU/UA transliteration; нет словарей никнеймов, исторических alias и platform-specific username rules.
- Первый native username module покрывает URL-template/status-code слой, часть platform syntax rules и часть content marker rules, но не всю логику Sherlock/Maigret: нет полного upstream site dataset, полного набора custom content error rules, rate-limit logic и enrichment.
- Native email module делает MX/TXT lookup и SPF/DMARC classifier, но пока не делает breach lookup, NS/additional TXT classifiers или external API enrichment.
- Native phone module пока не делает carrier lookup, reputation lookup или external API enrichment.
- Telegram module пока не использует Telegram API и не получает private/group data.
- RU/UA source pack пока curated вручную из текущего snapshot, без автообновления.
- Adapter runner запускает только те CLI, которые уже установлены в `PATH`; установкой upstream-проектов он пока не занимается.
- Adapter setup metadata покрывает ключевые upstream adapters, но install commands могут меняться; перед установкой нужно сверяться с upstream docs URL.
- Adapter manifest теперь включает generated JSON-file template для `h8mail`, generated JSON-report folder template для `soxoj/maigret`, target-specific executable templates для `user-scanner` и region-aware template для `snooppr/snoop`; более сложные adapters могут потребовать richer per-mode config.
- Adapter parser покрывает общие URL/email/phone/key-value patterns, h8mail JSON reports, Maigret JSON/CSV reports, `user-scanner` JSON/verbose output и Snoop stdout/CSV output; сложные JSON/CSV/HTML exports остальных upstream ещё не разобраны.
- Adapter profiles пока статические; нет пользовательских профилей и per-case persistent adapter policy.
- Graph edges покрывают базовые отношения, включая `email -> domain` и adapter-derived `email -> related_email`; есть summary/focus-neighbor analytics и cross-case entity index, но нет weighted path finding, cross-case edge graph и визуального UI.
- SQLite schema сейчас версии 2; при изменении таблиц нужна явная миграция.
- Рекомендации и scan-результаты являются техническими сигналами, не юридической или операционной инструкцией.
- Для будущего расширения может понадобиться отдельный ingestion pipeline и повторяемый классификатор.

## Что нужно обновлять при изменениях проекта

- При изменении CSV-схемы обновлять `Catalog.load()` и тесты.
- При добавлении native-модуля обновлять `engine.py`, `cli.py`, README и тесты.
- При изменении username site dataset/rules обновлять `sites.py`, username tests, README и parity-карту.
- При изменении HTTP body/title parsing обновлять `http_client.py`, username classifier tests и safety notes в README/analysis.
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
- 2026-06-24: расширен native username dataset до 38 URL-шаблонов и добавлены platform-specific username rules со статусом `skipped`.
- 2026-06-24: добавлены `HttpResult.body_text`, username content marker rules и `classify_username_http_result()` для soft-404/profile confidence в live checks.
- 2026-06-24: добавлен `dns_lookup.py`; `EmailScanModule` теперь планирует и выполняет MX/TXT lookup через `nslookup` в live-режиме.
- 2026-06-24: добавлен `email_auth.py`; `EmailScanModule` теперь классифицирует SPF и DMARC, а adapter manifest расширен executable target для `h8mail`.
- 2026-06-24: `AdapterSpec` получил target-specific `command_templates`; `user-scanner` теперь запускается как adapter для email и username.
- 2026-06-24: добавлен parser для `user-scanner` JSON/verbose results; executed output теперь превращается в `Finding`/entities/graph signals.
- 2026-06-24: добавлен RU/UA-aware command rendering и parser stdout/CSV для `snooppr/snoop`; Snoop findings теперь попадают в `Finding`/entities/graph signals.
- 2026-06-24: добавлен generated report ingestion для adapters и Maigret parser для NDJSON/simple JSON/CSV reports.
- 2026-06-24: h8mail переведён на generated JSON output file `-j <temp.json>`; добавлен parser upstream JSON и graph-связь `email -> related_email` с редактированием credential values.
