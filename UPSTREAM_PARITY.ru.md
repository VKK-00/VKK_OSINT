# Карта 1:1 functional parity

Цель: собрать функциональность OSINT-проектов из текущего snapshot в единую систему `osint_toolkit`.

Рабочее правило: для каждого выбранного upstream-проекта должен быть один из трёх статусов — native-покрытие поведения, внешний adapter к upstream CLI/API или restricted/excluded решение с причиной. Нельзя считать функциональность перенесённой, пока входы, результат, confidence/status и ограничения не описаны в этой карте.

Под “1:1” здесь фиксируется не буквальное копирование файлов, а функциональная совместимость:

- одинаковый класс входных данных;
- сопоставимый тип результата;
- единый формат `Finding`;
- возможность native-реализации или запуска upstream через adapter;
- явная фиксация gap, если поведение upstream ещё не покрыто.

Буквальное копирование кода допустимо только после проверки лицензии и совместимости с лицензией этого проекта. Для GPL/AGPL или проектов с неясной лицензией предпочтительный путь — внешний adapter.

## Уже реализовано

### Username / social profile discovery

Команда:

```powershell
python -m osint_toolkit scan person "<name>"
python -m osint_toolkit scan username <username>
python -m osint_toolkit scan username <username> --live
```

Покрытие:

- person-name expansion в username-кандидаты;
- RU/UA/кириллическая transliteration для username candidates;
- 38 публичных URL-шаблонов профилей;
- platform-specific username rules и `skipped` findings для заведомо несовместимых платформ;
- content markers для части live username checks: profile marker -> `candidate/high`, soft-404 marker -> `not_found/high`;
- dry-run без сетевых запросов;
- live HTTP checks по явному `--live`;
- единый результат `Finding`;
- RU-фильтр для VK/OK/Habr и глобальных платформ.
- executable adapter для `soxoj/maigret`: `maigret <username> --json ndjson [--tags ru|ua]`;
- parser для Maigret NDJSON/simple JSON/CSV reports: `Claimed` -> `candidate`, `Available` -> `not_found`, `Unknown` -> `error`, `Illegal` -> `skipped`;
- executable target-specific adapter для `kaifcodec/user-scanner`: `user-scanner -u <username> -f json`;
- executable RU/UA-aware adapter для `snooppr/snoop`: `snoop --no-func --found-print [--include RU|UA] <username>`;
- parser для Snoop stdout/CSV results: `найден!` -> `candidate`, `Увы!` -> `not_found`, `блок`/ошибки -> `error`;
- `investigate --person` автоматически прогоняет derived username targets через native username scan и совместимые adapters при `--include-adapters`.

Связанные upstream-проекты:

- `sherlock-project/sherlock`
- `soxoj/maigret`
- `WebBreacher/WhatsMyName`
- `thewhiteh4t/nexfil`
- `p1ngul1n0/blackbird`
- `iojw/socialscan`
- `Yvesssn/DetectDee`
- `snooppr/snoop`
- `ibnaleem/gosearch`
- `Alfredredbird/tookie-osint`

Gap до полного 1:1:

- site dataset расширен до 38 шаблонов, но это ещё не полный upstream dataset Sherlock/Maigret/WhatsMyName;
- per-site rules покрывают username syntax/length и часть title/body content markers, но не все upstream error rules;
- нет rate-limit/backoff правил;
- username permutation/alias strategy пока базовая: нет словарей никнеймов, исторических alias и platform-specific username rules;
- content-based confidence пока частичный: нет полного набора marker rules из upstream datasets;
- Maigret подключён adapter-first; web UI, PDF/HTML/XMind reports, recursive policy tuning, proxies/Tor/I2P и AI mode пока не перенесены в native UI;
- Snoop подключён adapter-first, но локальная установка/обновление Snoop пока остаются операторским действием;
- нет сохранения истории запусков.

## Следующие native/adapters группы

### Email OSINT

Связанные upstream-проекты:

- `alpkeskin/mosint`
- `khast3x/h8mail`
- `thewhiteh4t/pwnedOrNot`
- `kaifcodec/user-scanner`
- `megadose/holehe`
- `martinvigo/email2phonenumber`
- `laramies/theHarvester`

Уже реализовано:

- `python -m osint_toolkit scan email <email>`;
- синтаксическая проверка;
- извлечение домена;
- live domain resolution по явному `--live`;
- MX/TXT lookup через системный `nslookup` по явному `--live`;
- SPF classifier поверх доменного TXT: наличие записи, multiple-record warning, `all` policy и include/redirect counts;
- DMARC classifier через `_dmarc.<domain>` TXT: наличие записи, multiple-record warning, `p=`, `sp=`, alignment, percent и report URI tags;
- executable adapter target для `khast3x/h8mail`: `h8mail -t <email> --hide -j <temp.json>`;
- parser для h8mail upstream JSON `{targets: [{target, pwn_num, data}]}`: breach count, related emails, usernames, source labels и paste URLs нормализуются в `Finding`/entities, password/hash/token-like values редактируются и не попадают в evidence;
- executable target-specific adapter для `kaifcodec/user-scanner`: `user-scanner -e <email> -f json`;
- parser для `user-scanner` JSON/verbose results: `Registered`/`Found` -> `candidate`, `Available`/`Not Found`/`Not Registered` -> `not_found`, `Error` -> `error`.

Gap:

- breach lookup пока выполняется только через внешний h8mail adapter, если upstream CLI установлен и оператор явно запускает `--execute`;
- нет API enrichment;
- нет локального кэша;
- нет NS/additional TXT classifiers;
- нет restricted account-enumeration режима.

План:

1. Native: расширить DNS слой до NS/additional TXT classifiers и richer email security findings.
2. Adapter: `mosint`, `h8mail`, `pwnedOrNot`, `user-scanner`.
3. Restricted adapter: `holehe`, `email2phonenumber`, любые recovery/account-enumeration flows.

Причина restricted-слоя: email-to-account и email-to-phone могут раскрывать чувствительные персональные данные и часто зависят от password recovery поведения платформ.

### Phone OSINT

Связанные upstream-проекты:

- `sundowndev/phoneinfoga`
- `AzizKpln/Moriarty-Project`
- `megadose/ignorant`
- `TermuxHackz/X-osint`
- `martinvigo/email2phonenumber`

Уже реализовано:

- `python -m osint_toolkit scan phone <number>`;
- E.164-like нормализация;
- базовый country-prefix signal для `+380`, `+7` и нескольких глобальных префиксов.

Gap:

- нет carrier/type lookup;
- нет reputation lookup;
- нет внешних API;
- нет PhoneInfoga parity adapter.

План:

1. Native: нормализация номера, country code, форматирование, базовая валидация.
2. Adapter: `phoneinfoga`.
3. Restricted adapter: phone-to-account checks.

### Instagram / social-platform modules

Связанные upstream-проекты:

- `Datalux/Osintgram`
- `instaloader/instaloader`
- `megadose/toutatis`
- `0x0be/yesitsme`
- `vaguileradiaz/tinfoleak`
- `Owez/yark`

План:

1. Adapter-first: использовать upstream CLI для platform-specific edge cases.
2. Native: только публичные profile URL checks, metadata wrappers и output normalization.
3. Добавить `Finding` поля для platform, account id, display name, public counters, media URL, timestamp.

### Telegram / RU-UA

Связанные upstream-проекты и ресурсы:

- `ItIsMeCall911/Awesome-Telegram-OSINT`
- `The-Osint-Toolbox/Telegram-OSINT`
- `snooppr/snoop`
- `cipher387/API-s-for-OSINT`
- `cipher387/osint_stuff_tool_collection`
- `Astrosp/Awesome-OSINT-List`
- `Jieyab89/OSINT-Cheat-sheet`
- `BigBodyCobain/Shadowbroker`

Уже реализовано:

- `python -m osint_toolkit scan telegram <handle-or-url>`;
- normalization for `@handle`, `t.me/<handle>` and public post URLs;
- optional live t.me metadata by explicit `--live`;
- `python -m osint_toolkit scan ru-ua all`;
- region filters `--region ru` and `--region ua`;
- curated source pack for DeepStateMap, Liveuamap, TGStat RU, VK, OK, Yandex, Mail.ru, Geocam.ru and paste.in.ua.

Gap:

- нет Telegram API integration;
- нет message export/archive;
- нет channel graph;
- нет VK/OK/Yandex API adapters;
- нет automated refresh from upstream lists.

План:

1. Native: Telegram public URL normalization: `t.me/<name>`, post URLs, channel/group distinction where public.
2. Adapter/resources: TGStat, VK/OK/Yandex-oriented entries as source records.
3. RU/UA source packs: separate maps/conflict resources, platform resources, transport/geospatial resources.

### Web / domain / document recon

Связанные upstream-проекты:

- `lissy93/web-check`
- `s0md3v/Photon`
- `smicallef/spiderfoot`
- `laramies/theHarvester`
- `owasp-amass/amass`
- `projectdiscovery/subfinder`
- `projectdiscovery/httpx`
- `blacklanternsecurity/bbot`
- `jasonxtn/Argus`

Уже реализовано:

- `python -m osint_toolkit scan domain <domain>`;
- live DNS resolution;
- HTTPS/HTTP status, redirect final URL, title and content-type;
- presence list for common security headers.

Gap:

- нет subdomain enumeration;
- нет WHOIS/RDAP;
- нет certificate transparency;
- нет crawler/email extraction;
- нет Amass/Subfinder/httpx/SpiderFoot adapters.

План:

1. Native: HTTP status, redirects, title, basic headers.
2. Adapter: `httpx`, `theHarvester`, `spiderfoot`, `amass`, `subfinder`.
3. Normalize domains, URLs, emails, subdomains into shared entity model.

## External adapter runner

Команда:

```powershell
python -m osint_toolkit run-adapter <repository> <target_kind> <target_value>
python -m osint_toolkit run-adapter <repository> <target_kind> <target_value> --execute
python -m osint_toolkit adapter-setup <repository>
```

Уже реализовано:

- dry-run command rendering from `AdapterSpec.command_template` and target-specific `AdapterSpec.command_templates`;
- explicit `--execute`;
- executable lookup in `PATH`;
- no shell execution;
- timeout handling;
- restricted adapter guard via `--allow-restricted`;
- `run_adapter_findings()` returns summary + parsed findings;
- stdout parser for common URL/email/phone/key-value lines from Sherlock/Maigret/Nexfil/Mosint/PhoneInfoga-like output;
- generated report ingestion: adapters can run with a temporary output folder or temporary output file and feed generated files back into `parse_adapter_output()`;
- adapter-specific parser for h8mail JSON report rows with credential-value redaction;
- adapter-specific parser for Maigret NDJSON/simple JSON and CSV report rows;
- adapter-specific parser for `user-scanner` JSON and verbose line output;
- adapter-specific parser for Snoop stdout and CSV report rows;
- install/config/readiness metadata in `AdapterSpec`;
- `adapter-setup` command for setup plans, docs URLs, PATH/env readiness.

Gap:

- нет автоматической установки upstream CLI;
- нет богатого parser-слоя для JSON/CSV/HTML exports каждого инструмента, кроме уже покрытых h8mail JSON, Maigret JSON/CSV, `user-scanner` JSON/verbose и Snoop stdout/CSV;
- базовая нормализация `Finding` -> `Entity` уже есть, но нет full adapter-specific parsers для complex outputs;
- per-adapter config/API key handling пока только описывается metadata, без secure secret store.

## Case investigation runner

Команда:

```powershell
python -m osint_toolkit investigate --person "<name>" --include-adapters --adapter-profile username-full
python -m osint_toolkit investigate --username <name> --email <email> --domain <domain>
python -m osint_toolkit investigate --username <name> --include-adapters --out reports/case.md
python -m osint_toolkit investigate --username <name> --include-adapters --adapter-profile username-full
python -m osint_toolkit investigate --username <name> --include-adapters --adapter sherlock-project/sherlock
python -m osint_toolkit investigate --username <name> --include-adapters --execute-adapters --adapter-limit 1
python -m osint_toolkit investigate --username <name> --case-db cases.sqlite --case-id case-001
python -m osint_toolkit cases --case-db cases.sqlite
python -m osint_toolkit case-show --case-db cases.sqlite case-001
python -m osint_toolkit case-graph --case-db cases.sqlite case-001
python -m osint_toolkit case-graph --case-db cases.sqlite case-001 --entity-kind email --entity-value person@example.com
python -m osint_toolkit case-index --case-db cases.sqlite --kind domain --min-cases 2
python -m osint_toolkit case-index --case-db cases.sqlite --kind email --value person@example.com
```

Уже реализовано:

- несколько seed values в одном запуске;
- person seed expansion into username candidates;
- единый native scan через `Engine`;
- optional adapter dry-runs;
- reusable adapter profiles such as `username-full`, `email-safe`, `phone-safe` and `username-ru-ua`;
- repeated `--adapter <repository>` allowlist for one case;
- explicit executed adapter ingestion via `--execute-adapters`;
- Markdown/JSON report;
- Entity Summary from targets, finding URLs, evidence and metadata;
- Graph Edges for base entity relations;
- SQLite persistence for cases, targets, entities, edges and findings;
- list/show saved cases through CLI;
- saved graph summary: node/edge counts, relation counts, entity kind counts and top connected nodes;
- focus-neighbor query for one saved entity;
- cross-case entity index and exact saved-case lookup by entity;
- parsed executed adapter outputs can enter investigation entities, graph edges and case store;
- review checklist in every Markdown report.

Gap:

- graph edges пока базовые, без weighted path finding и full cross-case edge graph;
- нет пользовательских adapter profiles и persistent per-case adapter policy;
- нет UI для просмотра кейса и интерактивного графа.

## Adapter doctor

Команда:

```powershell
python -m osint_toolkit doctor
```

Уже реализовано:

- executable lookup in `PATH`;
- statuses: available, missing, not_configured, restricted;
- table/Markdown/CSV/JSON output.

## Adapter statuses

`python -m osint_toolkit adapters` is the executable status view. Keep `osint_toolkit/adapters.py` as the machine-readable source and this file as the human-readable roadmap.

Statuses:

- `partial_native`: part of the functionality exists in native modules.
- `planned`: external adapter or native import is needed.
- `restricted`: possible only with explicit operator confirmation and additional safeguards.

## Acceptance checklist for goal completion

The full objective is not complete until:

- every selected upstream project has a native module, external adapter, dataset importer, or documented excluded/restricted decision;
- core target types are implemented: username, email, phone, URL/domain, Telegram, Instagram/social platform, RU/UA source pack;
- results share one schema and can be exported as table, Markdown, CSV and JSON;
- tests cover dry-run, parsing, output, adapter manifests and at least safe live smoke checks;
- docs explain installation, usage, parity status and license boundaries.
