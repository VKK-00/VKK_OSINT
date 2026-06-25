# План глубокой интеграции OSINT-сервисов

## Цель

Сделать из текущего набора native-модулей, adapters и toolbox не набор отдельных команд, а единый OSINT-агрегатор:

`один ввод -> все подходящие native checks и upstream tools -> единые findings -> entities -> graph -> case report`

Пример целевого поведения:

```powershell
python -m osint_toolkit search phone +380441234567 --profile phone-full --plan-only
python -m osint_toolkit search email person@example.com --profile email-full --plan-only
python -m osint_toolkit search username example_user --profile username-full --plan-only
python -m osint_toolkit search domain example.com --profile passive-recon --plan-only
```

Здесь оператор вводит один seed, а система сама:

- определяет тип цели;
- выбирает все совместимые native-модули и adapters;
- проверяет readiness внешних tools;
- запускает доступные tools в согласованном режиме;
- нормализует stdout/JSON/CSV/report files;
- объединяет дубли;
- строит entity graph;
- сохраняет кейс и отчёт.

## Что значит “снять ограничения”

Нужно снять операционное ограничение текущей архитектуры: оператор не должен вручную запускать каждый upstream-tool отдельно.

Не нужно снимать контроль законного scope, redaction, rate limits, audit trail и явное включение рискованных режимов. Эти вещи должны остаться частью системы, иначе aggregator станет плохо проверяемым и опасным для самого оператора.

Практическая модель:

- `plan` — показать, какие tools будут использованы и почему.
- `execute-safe` — запускать public/passive/low-risk tools, которые уже настроены.
- `execute-scoped` — запускать более широкие tools только после явного выбора профиля и записи scope в case metadata.
- `restricted` — password-recovery/account-enumeration/private-data flows не входят в default/full profiles; если они когда-либо добавляются, только отдельным режимом, отдельной маркировкой и отдельными тестами redaction.

## Текущая база

Уже есть:

- native engine: `scan person|username|email|phone|domain|url|telegram|instagram|social|ru-ua`;
- `investigate` для multi-target cases;
- adapter manifest `AdapterSpec`;
- adapter profiles: `username-full`, `username-ru-ua`, `email-safe`, `phone-safe`, `url-archive`, `domain-recon`, `broad-recon`;
- adapter runner с dry-run/execute;
- parsers для многих upstream outputs;
- generated report ingestion;
- SQLite case store;
- graph edges and cross-case entity index;
- static `toolbox` window and optional local execution backend.

Главный core gap закрыт: `search --plan-only` строит единый high-level fan-out plan, `search --execute-adapters` запускает ready non-restricted external adapters, image execution запускает ready local tools и маршрутизирует derived seeds, а `tools doctor/install-plan/env --profile` закрывает readiness/install/config visibility. UI gap также закрыт для unified search: `toolbox --serve` поднимает локальный token-protected backend, запускает queued `/api/search` jobs, показывает logs/status/report links и отдаёт `/api/tools` readiness/install/env views по выбранному профилю. Static `toolbox --out` остаётся безопасным copy-ready режимом.

## Целевая архитектура

```mermaid
flowchart LR
  A["Input seed"] --> B["Target classifier"]
  B --> C["Capability router"]
  C --> D["Native plan"]
  C --> E["Adapter plan"]
  C --> F["Image/tool plan"]
  D --> G["Execution queue"]
  E --> G
  F --> G
  G --> H["Native runner"]
  G --> I["Adapter runner"]
  G --> J["Local tool runner"]
  H --> K["Finding normalizer"]
  I --> K
  J --> K
  K --> L["Entity extraction"]
  L --> M["Graph builder"]
  M --> N["Case store"]
  M --> O["Markdown/JSON report"]
  N --> P["Cross-case index"]
```

Ключевые компоненты:

- `SearchRequest` — один или несколько seed values, profile, region, execution mode, scope metadata, limits.
- `Capability` — машинно-читаемое описание того, что tool умеет: target kinds, risk level, install/readiness, parser, output type, rate-limit hints.
- `SearchPlan` — конкретный список native/adapters/local tools для запуска.
- `ExecutionQueue` — запуск tools с timeout, retries, concurrency limits и per-tool logs.
- `ResultNormalizer` — приведение всего к `Finding`, `Entity`, `GraphEdge`.
- `ResultMerger` — дедупликация URL/email/phone/domain/profile hits, объединение confidence и source provenance.
- `CaseReport` — Markdown/JSON report + SQLite case store.

## Команды, которые нужно добавить

### `search`

Основная команда “один seed -> все сервисы”.

```powershell
python -m osint_toolkit search phone +380441234567 --profile phone-full --plan-only
python -m osint_toolkit search email person@example.com --profile email-full --region ua --plan-only
python -m osint_toolkit search username example_user --profile username-full --execute-adapters
python -m osint_toolkit search domain example.com --profile passive-recon --case-db cases.sqlite
```

Параметры:

- `target_kind` и `target_value`, либо `--auto` для определения типа.
- `--profile safe|full|ru-ua-full|passive-recon|broad-recon|custom`.
- `--plan-only` — только показать план.
- `--execute-adapters` — запускать внешние CLI.
- `--install-missing` — позже, после installer layer.
- `--case-db`, `--case-id`, `--out`, `--format markdown|json`.
- `--max-tools`, `--timeout`, `--concurrency`, `--request-delay`.
- `--scope-note` — текстовое основание/контекст проверки, сохраняется в case metadata.

### `tools install`

Единая установка внешних tools из manifest.

```powershell
python -m osint_toolkit tools install phone-safe
python -m osint_toolkit tools install username-full
python -m osint_toolkit tools install domain-recon
python -m osint_toolkit tools doctor --profile all-safe
```

Первый вариант должен быть осторожным:

- показывать команды установки;
- проверять PATH/env;
- не скачивать непроверенный код без явного подтверждения;
- поддерживать Windows notes.

### `profiles`

Пользовательские profiles поверх manifest.

```powershell
python -m osint_toolkit profiles list
python -m osint_toolkit profiles show phone-full
python -m osint_toolkit profiles export phone-full --out profiles/phone-full.json
```

Формат profile:

```json
{
  "name": "phone-full",
  "target_kinds": ["phone"],
  "native": ["phone"],
  "adapters": [
    "sundowndev/phoneinfoga",
    "smicallef/spiderfoot",
    "jasonxtn/argus",
    "Yvesssn/DetectDee"
  ],
  "excluded_by_default": [
    "megadose/ignorant"
  ]
}
```

## Направления интеграции

### Phone

Цель: пользователь вводит телефон, система запускает всё применимое.

Target:

```powershell
python -m osint_toolkit search phone +380441234567 --profile phone-full --execute-adapters
```

Состав:

- native `scan phone`: нормализация, E.164-like validation, country prefix.
- `sundowndev/phoneinfoga`: phone intelligence.
- `smicallef/spiderfoot`: passive phone target mode, если `SPIDERFOOT_SF_PATH` настроен.
- `jasonxtn/argus`: broad infra/OSINT route, если установлен.
- `Yvesssn/DetectDee`: executable detect adapter для phone/email/username checks через `DetectDee detect -p|-e|-n ... -f <DETECTDEE_DATA>`.
- `megadose/ignorant`: только restricted profile, не default/full.

Что нужно реализовать:

- profile `phone-full`;
- router: `phone -> native phone + phone-safe + broad-recon phone-compatible`;
- parser gap review для SpiderFoot/Argus phone-specific output;
- confidence model: normalized phone, country/carrier/location/search URLs, account-like hits отдельно;
- report section `Phone Sources`.

Acceptance:

- `search phone ... --plan-only` показывает все совместимые tools и почему missing tools пропущены.
- `search phone ... --execute-adapters` запускает все ready tools без ручного перечисления.
- отчёт показывает source-by-source results, dedupe и graph.

### Email

Target:

```powershell
python -m osint_toolkit search email person@example.com --profile email-full --execute-adapters
```

Состав:

- native email: syntax, domain, MX/NS/TXT, SPF, DMARC, MTA-STS, TLS-RPT, BIMI, service markers.
- `alpkeskin/mosint`: email reputation, breaches, related emails/domains, search URLs, DNS.
- `khast3x/h8mail`: breaches and related emails.
- `thewhiteh4t/pwnedOrNot`: compromised email lookup.
- `kaifcodec/user-scanner`: email account checks.
- `p1ngul1n0/blackbird`: email account discovery.
- `smicallef/spiderfoot`: email target.
- `jasonxtn/argus`: email target.
- `megadose/holehe`, `martinvigo/email2phonenumber`: restricted, separate profile only.

Что нужно реализовать:

- profile `email-full`;
- parser coverage for pwnedOrNot is implemented for safe stdout breach status and breach rows.
- API key readiness metadata grouped by provider;
- redaction tests for breach/password/hash/token-like values;
- output grouping: auth/security, breach/reputation, related identities, domains, URLs.

Acceptance:

- один email запускает all ready email-compatible adapters;
- secrets and credential-like values never appear in reports;
- related emails/domains enter graph with provenance.

### Username / Person / Social

Target:

```powershell
python -m osint_toolkit search username example_user --profile username-full --execute-adapters
python -m osint_toolkit search person "Ivan Petrenko" --profile person-full --region ua
```

Состав:

- native person expansion.
- native username checks with Sherlock/WhatsMyName/Maigret datasets.
- Sherlock external reports.
- Maigret external reports.
- Social Analyzer.
- Blackbird.
- Nexfil.
- Snoop RU/UA.
- user-scanner.
- Instaloader for Instagram.
- DetectDee executable detect route and socialscan candidate after mapping.

Что нужно реализовать:

- `person-full` profile: person expansion -> derived username fan-out.
- profile-specific derived target limits.
- platform scoring and conflict handling.
- Snoop/Maigret/Social Analyzer RU/UA routing.
- optional screenshots/OCR remains separate because it changes data volume and dependencies.

Acceptance:

- `search person` creates derived usernames and runs compatible tools automatically.
- all profile URLs dedupe by normalized URL/platform/username.
- report separates `candidate`, `not_found`, `error`, `skipped`.

### Domain / URL / Web

Target:

```powershell
python -m osint_toolkit search domain example.com --profile passive-recon --execute-adapters
python -m osint_toolkit search url https://example.com --profile web-full --execute-adapters
```

Состав:

- native domain/url: DNS, HTTP, crawler, robots/sitemap, CT, RDAP, WHOIS.
- Subfinder.
- httpx.
- passive Amass.
- theHarvester.
- BBOT passive.
- SpiderFoot passive.
- Argus infra route.
- Yark for URL/media archive workflows.

Что нужно реализовать:

- profiles `passive-recon`, `web-full`;
- host normalization and root-domain extraction;
- duplicate entity merge across CT/Subfinder/Amass/BBOT/SpiderFoot;
- result severity/risk tags for exposed tech, open ports and findings.

Acceptance:

- one domain produces combined subdomain, URL, email, phone, IP, port, tech graph.
- report shows per-tool coverage and missing config.
- active/bruteforce modules are not accidentally enabled in passive profile.

### Image / Photo

Target:

```powershell
python -m osint_toolkit search image C:\evidence\photo.jpg --profile image-full
```

Состав:

- local baseline/hash.
- ExifTool metadata.
- ImageMagick identify.
- Tesseract OCR.
- zbarimg QR/barcodes.
- reverse image portals in toolbox.
- extracted URL/email/phone/username/domain clues routed into `search` as derived targets.

Что нужно реализовать:

- `image` target kind.
- local tool runner for `exiftool`, `magick`, `tesseract`, `zbarimg`.
- parser for EXIF JSON output and OCR text extraction.
- derived target extraction from OCR/QR/metadata.
- no face recognition, no identity-by-face matching.

Acceptance:

- one image yields metadata findings, OCR findings, QR findings and derived OSINT seeds.
- derived seeds can run through normal `search` fan-out.
- report clearly marks local metadata vs external search routes.

### Telegram / Instagram / RU Social / RU-UA

Состав:

- native Telegram public metadata.
- native Instagram public metadata.
- native VK/OK/Yandex/Mail.ru public metadata.
- Snoop/Maigret/Social Analyzer RU/UA filters.
- RU/UA source pack.

Что нужно реализовать:

- `social-full` profile;
- platform-specific target classifiers: `@handle`, `t.me`, `instagram.com`, `vk.com`, `ok.ru`, Yandex/Mail.ru profile-like URLs;
- common output schema for display name, account id, public URLs, platform, domain, public counters;
- optional archive adapter routing where lawful and supported.

Acceptance:

- social URL/handle automatically routes to the right native module and compatible adapters.
- RU/UA region setting affects Snoop/Maigret/Social Analyzer.

## Installation and readiness layer

Проблема пользователя: “не хочу подключать каждый сервис отдельно”.

Решение:

1. `tools doctor --profile <profile>` показывает missing/ready/config-required/excluded.
2. `tools install-plan --profile <profile>` генерирует команды установки под Windows для missing/config tools; excluded/restricted не выдаются как обычная установка.
3. `tools install <profile>` можно добавить позже как explicit mode with prompts.
4. `tools env` показывает только names of required variables, never values.

Минимальный install matrix:

- Python/pipx: Sherlock, Maigret, h8mail, Nexfil, Instaloader, user-scanner, Yark, BBOT, Argus.
- Go: Mosint, Subfinder, httpx, Amass.
- Manual/binary/venv: PhoneInfoga, Snoop, SpiderFoot, Blackbird, Social Analyzer, theHarvester, pwnedOrNot.
- Local image tools: ExifTool, ImageMagick, Tesseract, zbarimg.

## Profiles to add

Первый набор:

- `phone-full`
- `email-full`
- `person-full`
- `social-full`
- `passive-recon`
- `web-full`
- `image-full`
- `ru-ua-full`
- `all-safe`

Profile fields:

- `name`
- `target_kinds`
- `native_modules`
- `adapter_profiles`
- `adapter_repositories`
- `local_tools`
- `default_execution_mode`
- `max_concurrency`
- `default_timeout`
- `excluded_repositories`
- `scope_requirements`

## Parser and normalization backlog

Приоритет 1:

- Закрыт для текущего parser scope Stage 1.

Приоритет 2:

- Socialscan integration review.
- Maigret richer dossier fields.
- BBOT broader passive presets with explicit profile.
- theHarvester API-source attribution.

## Unified output model

Каждый result должен иметь:

- source tool;
- source command or native module name;
- target kind/value;
- status: `candidate`, `confirmed`, `not_found`, `skipped`, `error`, `metadata`;
- confidence;
- evidence summary;
- redacted raw excerpt if safe;
- entities;
- graph edges;
- execution metadata: start/end/duration, exit code, timeout, parser version.

## Safety and audit controls

Для security use-case важны не “запреты ради запретов”, а воспроизводимость и контролируемость:

- каждое внешнее выполнение записывает tool, version if available, command args without secrets, exit code and duration;
- secret/API key values never printed;
- password/hash/token-like values redacted;
- report distinguishes public metadata, inferred signals and account-like hits;
- restricted flows excluded from normal full profiles;
- per-tool timeout and rate limit;
- `--scope-note` saved into case metadata;
- all risky expansions must be visible in `--plan-only`.

## Этапы реализации

### Этап 1 — Unified Search Router

Deliverables:

- `osint_toolkit/search.py`;
- CLI `search`;
- `SearchProfile`, `LocalToolSpec`, `PlannedStep`, `SearchPlan`;
- auto target classifier;
- mapping target kind -> native modules + adapter profiles + local image tools;
- `--plan-only`;
- ready-only `--execute-adapters` path for external adapters;
- local image tool execution with derived seed routing.

Status: planner, ready-only external adapter execution and image local-tool execution are implemented in the current codebase.

Tests:

- plan for phone/email/username/domain/image includes expected tools;
- missing adapters appear as missing, not as failures;
- profile filtering works.

### Этап 2 — Fan-out Execution

Deliverables:

- execute ready adapters automatically from `SearchPlan`;
- per-tool timeout/concurrency;
- combined markdown/json report;
- case-store save.

Tests:

- mocked external adapters run in order/queue;
- failed adapter does not fail the whole search;
- duplicate entities merge.

### Этап 3 — Install/Readiness UX

Deliverables:

- `tools doctor --profile`;
- `tools install-plan --profile`;
- Windows-specific install notes;
- local image tool readiness checks.

Tests:

- PATH/env detection;
- missing required env shown without values;
- install plan stable.

### Этап 4 — Profiles and Custom Profiles

Deliverables:

- built-in profiles listed above;
- JSON import/export for custom profiles;
- profile validation.

Status: JSON import for custom search profiles through `--profile-file`, validation and `profiles list/show/export` are implemented. Export writes reusable JSON-wrapper files that can be passed back through `--profile-file`.

Tests:

- invalid repo/profile rejected;
- target kind compatibility checked.

### Этап 5 — Image Pipeline

Deliverables:

- `search image <path>`;
- ExifTool/ImageMagick/Tesseract/zbarimg local tool adapters;
- OCR/QR/metadata seed extraction;
- derived targets fan-out into normal search.

Tests:

- sample image fixtures;
- OCR text -> URL/email/phone extraction;
- EXIF GPS redaction/flagging rules.

### Этап 6 — UI Execution Window

Deliverables:

- local backend server or controlled desktop runner;
- toolbox can execute queued commands through backend;
- visible queue, logs, status and report links.
- saved case browser for case list/detail/graph/index through backend.

Notes:

- current static HTML is safe for command generation;
- execution UI uses a local backend because browsers cannot safely run shell commands directly;
- backend accepts structured unified `search` payloads only, not arbitrary shell commands.

## First implementation order

1. Done: add `search --plan-only` for phone/email/username/person/domain/url/image/social/ru-ua.
2. Done: add built-in `phone-full`, `email-full`, `image-full`, `all-safe` and related profiles.
3. Done: add `tools doctor/install-plan/env --profile`.
4. Done: add fan-out execution for ready non-restricted adapters.
5. Done: add image local tool execution and derived seed extraction.
6. Done for stable routes: replace toolbox command cards with `search` plan/execution commands where high-level routing is stable.
7. Done: add `toolbox --serve` local backend for queued unified search execution, logs and report access.
8. Done: add `--profile-file` JSON import and validation for custom search profiles in `search` and `tools doctor/install-plan/env`.
9. Done: add `profiles list/show/export` for built-in and custom search profiles.
10. Done: persist workflow/profile/adapter policy metadata in saved SQLite cases for `search --case-db` and `investigate --case-db`.
11. Done: add served toolbox Case Browser for saved cases, case detail, graph summary/focus and cross-case index.
12. Done: add `--scope-note` for `search` and `investigate` so saved case metadata records the operator's scope/context note.
13. Done: add bounded SVG case graph visualization in served toolbox Case Browser and pass `scope_note` from the structured backend payload.
14. Done: make served toolbox graph nodes clickable/keyboard-focusable so one entity can drive focus-neighbor analysis from the same window.
15. Done: add cross-case weighted path analysis through `case-path`, `/api/case-path` and toolbox Path view.
16. Done: add bounded cross-case network analysis through `case-network`, `/api/case-network` and toolbox Network view.
17. Done: add safe saved-case management through filtered `cases`, `case-update`, `case-delete`, `/api/cases/<id>/update`, `/api/cases/<id>/delete` and toolbox Case Browser controls.
18. Done: add guarded custom search profiles in served toolbox through `Profile file`, `Custom profile`, `/api/profiles` and `/api/search --profile-file` command construction.
19. Done: add minimal served toolbox profile editor through `/api/profiles/save`, `/api/profiles/delete`, structured profile fields and canonical validated JSON writes.
20. Done: make `search --execute-adapters` respect `profile.native_kinds`, so custom adapter-only profiles do not run hidden native modules outside the selected profile.
21. Done: expose profile readiness/install/env views in served toolbox through `/api/tools` and Tools/Install/Env controls.
22. Done: add `derived_target_kinds` and email -> domain fan-out so `email-full`/`safe`/`all-safe` route the email domain through domain/web search planning and execution.
23. Done: add URL host -> domain fan-out so `web-full`/`passive-recon`/`safe`/`all-safe` route URL seeds through domain/web search planning and execution.
24. Done: add email local-part -> username fan-out so `email-full`/`safe`/`all-safe` route email seeds through username/profile search planning and execution when the local-part is handle-like.
25. Done: use hostname-based `search auto` routing for Instagram, Telegram and supported RU social URLs, avoiding substring false positives and sending platform URLs to platform modules.
26. Done: add `wrong_executable` readiness and declarative identity probes for Subfinder, ProjectDiscovery `httpx`, Amass, theHarvester, BBOT and PhoneInfoga so unrelated binaries are not treated as ready adapters.
27. Done: support venv-backed manual checkout adapters through `BLACKBIRD_PYTHON` and `SPIDERFOOT_PYTHON`, while preserving `python` as the default fallback.
28. Done: verify a user-local all-safe toolchain where pipx tools, Go tools, portable image tools and manual GitHub checkouts all report `ready` in `tools doctor --profile all-safe`.
29. Done: add Windows runtime env refresh so CLI/toolbox readiness sees newly installed user-local `pipx`, Go, portable binaries and configured OSINT env variables without restarting the current terminal.
30. Done: add DetectDee executable route and parser for username/email/phone profiles; readiness uses `DetectDee` in `PATH` plus `DETECTDEE_DATA`, and execution only uses upstream detect mode.
31. Done: add pwnedOrNot stdout parser for safe `-n` breach lookups, including HIBP breach summary/rows and credential-output redaction guard.
32. Done: add SpiderFoot phone/email/username mode examples and target provenance metadata for parsed SpiderFoot events.
33. Done: add ExifTool JSON local image parser, structured metadata findings and derived seed extraction for GPS/camera/date/contact clues.
34. Done: add Tesseract OCR text parser with structured OCR metadata and derived seed extraction.
35. Done: add zbarimg raw payload parser for QR/barcode clues and derived seed extraction.
36. Done: add Argus per-target parser fixtures and target provenance metadata for parsed Argus URL/email/phone/subdomain/IP/port/technology signals.
37. Done: add Yark archive JSON parser, safe temporary archive execution route and generated `yark.json` ingestion for YouTube channel/video archive clues.

## Definition of done

Goal is complete only when:

- one CLI command can accept phone/email/username/person/domain/url/image/social seeds;
- for each seed type, the system automatically selects all compatible native modules and adapters;
- the operator does not need to manually call each upstream tool;
- missing tools/config are reported clearly;
- ready tools can execute and parse into unified findings;
- reports include per-tool provenance, entities, graph and case storage;
- tests cover planning, execution, parser normalization, redaction and docs;
- toolbox exposes the unified `search` flows and saved-case management instead of forcing separate low-level commands.
