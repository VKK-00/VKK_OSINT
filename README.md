# OSINT Toolkit

Локальный CLI-инструмент и заготовка единой OSINT-системы на основе собранного каталога GitHub OSINT-проектов.

Цель проекта — не просто список ссылок, а единое ядро, которое постепенно покрывает функционал upstream-проектов 1:1 на уровне поведения:

- native-модулями внутри `osint_toolkit`;
- адаптерами к внешним CLI/API там, где проект большой, написан на другом языке или его лицензию нельзя просто смешивать с этим кодом;
- единым форматом результатов `Finding`;
- общей CLI-оболочкой.

“1:1” в этом проекте означает: одинаковый класс входных данных, сопоставимый результат, единый статус/confidence и явный gap, если часть upstream-поведения ещё не покрыта. Буквальное копирование исходников возможно только после проверки лицензии; иначе используется adapter или своя реализация того же поведения.

Рабочая карта parity: [UPSTREAM_PARITY.ru.md](UPSTREAM_PARITY.ru.md).

Текущий первый слой уже умеет:

- искать по каталогу top-100 OSINT-репозиториев;
- находить проекты, связанные с OSINT по лицам;
- находить проекты и ресурсы, связанные с РФ, Украиной и русскоязычными платформами;
- разворачивать имя человека в username-кандидаты с RU/UA transliteration;
- выполнять native username profile checks по 38 публичным URL-шаблонам с platform-specific username rules и content markers;
- выполнять baseline email checks: синтаксис, live domain resolution, MX/TXT lookup, SPF и DMARC policy classification;
- выполнять baseline phone checks: E.164-like нормализация и префикс региона;
- выполнять baseline domain recon: DNS resolution, HTTP/HTTPS metadata и security header presence;
- нормализовать Telegram handles/t.me URLs и по `--live` получать public metadata;
- выдавать RU/UA source pack: конфликтные карты, Telegram/RU platforms, geospatial и pastebin источники;
- получать базовые web metadata по URL;
- показывать карту upstream-адаптеров и dry-run/execute запускать настроенные внешние CLI;
- включать executed adapter outputs в единый investigation report, entities, graph и case store;
- читать generated JSON reports внешних adapters, если upstream CLI пишет машинный вывод в файл;
- запускать Mosint adapter в `--silent --output <json>` режиме и разбирать его upstream JSON report;
- запускать h8mail adapter в `--hide -j <json>` режиме и разбирать его upstream JSON report без переноса credential values в evidence;
- запускать Maigret adapter в `--json ndjson` режиме и разбирать его dossier findings;
- запускать Snoop adapter с RU/UA `--include` фильтром и разбирать его stdout/CSV-отчёты;
- получать безопасный workflow под задачу;
- генерировать Markdown-brief для кейса.
- сохранять расследования в SQLite и анализировать graph edges сохранённого кейса.
- строить cross-case индекс сущностей по сохранённым расследованиям.

## Быстрый старт

```powershell
python -m osint_toolkit stats
python -m osint_toolkit catalog --kind people --direct-only --limit 10
python -m osint_toolkit catalog --kind ru-ua --level direct_ru_ua
python -m osint_toolkit scan person "Ivan Petrenko" --limit 8
python -m osint_toolkit scan username exampleuser --limit 8
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
python -m osint_toolkit run-adapter alpkeskin/mosint email person@example.com
python -m osint_toolkit run-adapter khast3x/h8mail email person@example.com
python -m osint_toolkit run-adapter soxoj/maigret username example_user --region ua
python -m osint_toolkit run-adapter snooppr/snoop username example_user --region ua
python -m osint_toolkit investigate --person "Ivan Petrenko" --include-adapters --adapter-profile username-full --adapter-limit 2
python -m osint_toolkit investigate --username example_user --domain example.com --telegram "@durov" --include-adapters
python -m osint_toolkit investigate --username example_user --include-adapters --adapter-profile username-full --adapter-limit 2
python -m osint_toolkit investigate --username example_user --include-adapters --adapter soxoj/maigret
python -m osint_toolkit investigate --username example_user --include-adapters --execute-adapters --adapter-limit 1
python -m osint_toolkit investigate --title "case one" --email person@example.com --case-db cases.sqlite --case-id case-one
python -m osint_toolkit cases --case-db cases.sqlite
python -m osint_toolkit case-show --case-db cases.sqlite case-one --format markdown
python -m osint_toolkit case-graph --case-db cases.sqlite case-one
python -m osint_toolkit case-graph --case-db cases.sqlite case-one --entity-kind email --entity-value person@example.com
python -m osint_toolkit case-index --case-db cases.sqlite --kind domain --min-cases 2
python -m osint_toolkit case-index --case-db cases.sqlite --kind email --value person@example.com
python -m osint_toolkit recommend username --region ru --limit 8
python -m osint_toolkit brief --task telegram --region ua --target-value "public channel" --out reports/telegram_ua.md
```

После установки в editable-режиме можно использовать console script:

```powershell
python -m pip install -e .
osint-toolkit stats
```

## Команды

### `stats`

Показывает размер каталога и распределение по уровням связи.

```powershell
python -m osint_toolkit stats
```

### `catalog`

Фильтрует каталог.

```powershell
python -m osint_toolkit catalog --kind people --query instagram --limit 5
python -m osint_toolkit catalog --kind ru-ua --format markdown
python -m osint_toolkit catalog --kind relevant --min-stars 5000
```

`--kind`:

- `all` — все 100 проектов;
- `people` — проекты с person-OSINT связью;
- `ru-ua` — проекты с РФ/Украина/ru-platform связью;
- `relevant` — объединение people + ru-ua.

### `show`

Показывает карточку репозитория.

```powershell
python -m osint_toolkit show sherlock-project/sherlock
```

### `scan`

Запускает native-модули единой системы. По умолчанию это dry-run: CLI показывает, что будет проверено, но не делает сетевые запросы. Для реальной проверки публичных URL нужно явно добавить `--live`.

```powershell
python -m osint_toolkit scan person "Ivan Petrenko" --limit 10
python -m osint_toolkit scan username exampleuser --limit 10
python -m osint_toolkit scan username exampleuser --region ru --live --limit 10
python -m osint_toolkit scan email person@example.com --live --format json
python -m osint_toolkit scan phone +380441234567
python -m osint_toolkit scan domain example.com --live
python -m osint_toolkit scan telegram "@durov" --live
python -m osint_toolkit scan ru-ua all --region ru --format markdown
python -m osint_toolkit scan url https://example.com --live --format json
```

Native person module делает safe username expansion: нормализует имя, транслитерирует RU/UA/кириллические символы и генерирует кандидаты вроде `ivanpetrenko`, `ivan.petrenko`, `ipetrenko`. Это не подтверждение аккаунтов, а список кандидатов для проверки через username scan и adapters.

Сейчас native username module покрывает Sherlock/Maigret/WhatsMyName-подобный слой публичных profile URL checks: 38 URL-шаблонов, RU-фильтр, platform-specific username rules и часть content markers. Если username не подходит конкретной платформе, finding получает `status=skipped`, а не строит заведомо неверный URL. В `--live` режиме title/body markers могут повысить confidence до `high` для profile marker или перевести soft-404 страницу в `not_found`. Полное 1:1 покрытие требует импорта полного upstream dataset, richer per-site error rules и rate-limit/backoff logic либо подключения внешних CLI через adapters.

Native email/phone modules являются baseline-слоем для Mosint/h8mail/pwnedOrNot/user-scanner/PhoneInfoga-подобных adapters. Email module в `--live` режиме делает domain resolution, MX/TXT lookup через системный `nslookup`, SPF classification по доменному TXT и DMARC classification через `_dmarc.<domain>`. Он не делает breach lookup, account-enumeration и не запускает password recovery flows.

Native domain module является baseline-слоем для web-check/theHarvester/SpiderFoot/Amass/Subfinder-подобного web/domain recon. Он не делает brute force, port scanning или subdomain enumeration.

Native Telegram module покрывает нормализацию `@handle`, `t.me/<handle>` и публичных post URLs. RU/UA source-pack module отдаёт curated источники из текущей разметки top-100.

### `adapters`

Показывает карту интеграции upstream-проектов.

```powershell
python -m osint_toolkit adapters
python -m osint_toolkit adapters --status planned --format markdown
python -m osint_toolkit adapters --status restricted
```

### `adapter-setup`

Показывает readiness, команду установки, ссылку на upstream docs и конфигурационные требования для adapter.

```powershell
python -m osint_toolkit adapter-setup sherlock-project/sherlock
python -m osint_toolkit adapter-setup --status partial_native --format markdown
python -m osint_toolkit adapter-setup --format json
```

Команда не устанавливает внешние инструменты сама. Она даёт проверяемый setup plan, а фактическая установка upstream CLI остаётся отдельным операторским действием.

### `adapter-profiles`

Показывает готовые группы adapters для расследований.

```powershell
python -m osint_toolkit adapter-profiles
python -m osint_toolkit adapter-profiles --format json
```

Текущие профили включают `username-full`, `username-ru-ua`, `email-safe`, `phone-safe` и `url-archive`. `username-full` включает Maigret через `maigret <username> --json ndjson`, а `username-ru-ua` начинается со Snoop и Maigret; при `--region ru|ua` Snoop получает `--include RU|UA`, а Maigret получает `--tags ru|ua`. `email-safe` включает Mosint через `mosint --silent <email> --output <temp.json>`, h8mail через `h8mail -t <email> --hide -j <temp.json>` и `user-scanner` через target-specific JSON-команды `user-scanner -u <username> -f json` и `user-scanner -e <email> -f json`. `phone-safe` включает PhoneInfoga через `phoneinfoga scan -n <number>`; GPL-код PhoneInfoga не копируется внутрь проекта, но stdout/API-like JSON вывод приводится к общим `Finding`/`Entity`/graph signals. Restricted email-to-account/email-to-phone adapters в safe-профили не входят.

### `run-adapter`

Dry-run или явный запуск настроенного upstream CLI adapter. По умолчанию команда не запускается, а только показывается.

```powershell
python -m osint_toolkit run-adapter sherlock-project/sherlock username example_user
python -m osint_toolkit run-adapter sherlock-project/sherlock username example_user --execute
python -m osint_toolkit run-adapter alpkeskin/mosint email person@example.com
python -m osint_toolkit run-adapter khast3x/h8mail email person@example.com
python -m osint_toolkit run-adapter soxoj/maigret username example_user --region ua
python -m osint_toolkit run-adapter snooppr/snoop username example_user --region ua
python -m osint_toolkit run-adapter kaifcodec/user-scanner email person@example.com
python -m osint_toolkit run-adapter kaifcodec/user-scanner username example_user
python -m osint_toolkit run-adapter sundowndev/phoneinfoga phone +380441234567
```

Restricted adapters требуют дополнительный флаг `--allow-restricted`; без него возвращается `restricted`.

При `--execute` поддерживаемые adapters дополнительно проходят через parser. Runner умеет читать stdout/stderr и generated report-файлы из временной output-папки или конкретного output-file аргумента, если upstream CLI пишет машинный вывод не в stdout. Сейчас общий parser извлекает URL, email, E.164-like phone и key/value сигналы из Sherlock/Nexfil-подобного вывода. Для PhoneInfoga есть parser фактического CLI stdout `Results for <scanner>` и REST/API-like JSON: `local`, `numverify`, `googlesearch`, `googlecse` и `ovh` переводятся в `Finding`/entities/graph signals, включая `normalized`, `country`, `carrier`, `line_type`, `location`, `number_range`, `zip_code`, Google dork URL и CSE result URL. Для Mosint есть parser фактического JSON `email`, `verified`, `emailrep`, `breachdirectory`, `haveibeenpwned`, `hunter`, `intelx`, `psbdmp`, social flags, `google_search` и `dns_records`; password/hash/sha1-like values редактируются. Для h8mail есть parser фактического JSON `{targets: [{target, pwn_num, data}]}`: breach count, related emails, usernames, source labels и paste URLs превращаются в `Finding`/entities, а password/hash/token-like values редактируются и не попадают в evidence. Для Maigret есть parser NDJSON/simple JSON/CSV: `Claimed` -> `candidate/high`, `Available` -> `not_found/medium`, `Unknown` -> `error/low`, `Illegal` -> `skipped/high`, а `ids` попадают в metadata `name`, `location`, `country`, `email`, `phone` и `username`. Для `user-scanner` есть JSON/verbose parser со статусами `Registered`, `Found`, `Not Found`, `Available` и `Error`. Для `snooppr/snoop` есть parser stdout-строк и CSV-отчёта: `найден!` превращается в `candidate/high`, `Увы!` в `not_found/medium`, `блок` и ошибки в `error/low`; отрицательные строки сохраняют `checked_url`, но не создают подтверждённый URL/domain.

### `doctor`

Проверяет, какие upstream adapters реально готовы к запуску в текущей системе: есть ли executable в `PATH`, есть ли command template, restricted ли adapter.

```powershell
python -m osint_toolkit doctor
python -m osint_toolkit doctor --status planned --format markdown
```

### `investigate`

Запускает несколько native-модулей по одному кейсу и собирает единый Markdown/JSON отчёт. По умолчанию live-запросы не выполняются.

```powershell
python -m osint_toolkit investigate --person "Ivan Petrenko" --include-adapters --adapter-profile username-full --adapter-limit 2
python -m osint_toolkit investigate --title "example case" --username example_user --email person@example.com --domain example.com
python -m osint_toolkit investigate --username example_user --telegram "@durov" --ru-ua all --region ua --include-adapters --out reports/example_case.md
python -m osint_toolkit investigate --username example_user --include-adapters --adapter-profile username-full --adapter-limit 2
python -m osint_toolkit investigate --username example_user --include-adapters --adapter sherlock-project/sherlock --adapter soxoj/maigret
python -m osint_toolkit investigate --username example_user --include-adapters --execute-adapters --adapter-limit 1 --out reports/example_user.md
python -m osint_toolkit investigate --domain example.com --live --format json
python -m osint_toolkit investigate --title "saved case" --email person@example.com --case-db cases.sqlite --case-id case-001
```

Отчёт содержит `Entity Summary` и `Graph Edges`: нормализованные сущности и связи между ними, например `email -> domain`, `email -> related_email`, `url -> domain`, `telegram -> url`, `phone -> country`.

Если указан `--person`, система генерирует username-кандидаты и автоматически прогоняет их через native username scan; при `--include-adapters` эти derived usernames также попадают в совместимые username adapters. В графе это видно как `person -> username -> url`.

`--include-adapters` по умолчанию добавляет только dry-run команды. `--adapter-profile <name>` добавляет готовую группу adapters, а `--adapter <repository>` можно повторять, чтобы ограничить кейс конкретными upstream adapters. `--execute-adapters` явно запускает настроенные upstream CLI из `PATH`, прогоняет поддерживаемый stdout/stderr через parser и добавляет найденные URL/email/phone/key-value сигналы в тот же `Entity Summary`, `Graph Edges` и SQLite case store. Restricted adapters требуют `--allow-restricted-adapters`.

Если указан `--case-db`, кейс сохраняется в SQLite: targets, findings, entities и graph edges можно открыть позже через `cases`, `case-show`, `case-graph` и `case-index`.

### `cases`, `case-show`, `case-graph` и `case-index`

Работа с сохранёнными расследованиями.

```powershell
python -m osint_toolkit cases --case-db cases.sqlite
python -m osint_toolkit cases --case-db cases.sqlite --format json
python -m osint_toolkit case-show --case-db cases.sqlite case-001
python -m osint_toolkit case-show --case-db cases.sqlite case-001 --format markdown
python -m osint_toolkit case-graph --case-db cases.sqlite case-001
python -m osint_toolkit case-graph --case-db cases.sqlite case-001 --entity-kind telegram --entity-value "@durov" --format json
python -m osint_toolkit case-index --case-db cases.sqlite
python -m osint_toolkit case-index --case-db cases.sqlite --kind domain --min-cases 2 --format markdown
python -m osint_toolkit case-index --case-db cases.sqlite --kind telegram --value "@durov" --format json
```

`case-graph` строит summary по сохранённым `entities` и `edges`: число узлов и связей, счётчики типов отношений, счётчики типов сущностей и самые связанные узлы. Если указать `--entity-kind` и `--entity-value`, команда покажет соседей выбранной сущности.

`case-index` строит индекс сущностей по всем сохранённым кейсам. Без `--value` команда показывает сущности и количество кейсов, где они встречались; с `--kind` и `--value` показывает конкретные кейсы, содержащие эту сущность.

Статусы:

- `partial_native` — часть функционала уже реализована native-кодом.
- `planned` — нужен внешний CLI/API adapter или перенос логики после license review.
- `restricted` — функционал технически возможен, но требует отдельного явного режима из-за высокого privacy/safety риска.

### `recommend`

Подбирает workflow и ресурсы под тип задачи.

```powershell
python -m osint_toolkit recommend email
python -m osint_toolkit recommend phone --limit 6
python -m osint_toolkit recommend ukraine
python -m osint_toolkit recommend telegram --region ru
```

Поддерживаемые задачи:

- `person`
- `username`
- `email`
- `phone`
- `telegram`
- `instagram`
- `russia`
- `ukraine`
- `ru-platforms`

### `brief`

Создаёт Markdown-brief для кейса. Значение `--target-value` сохраняется в отчёте как ввод пользователя, но инструмент не делает запросы по этому значению.

```powershell
python -m osint_toolkit brief --task username --target-value "example_user" --region ru --out reports/example_user.md
```

## Источники данных

По умолчанию CLI ищет CSV-файлы в корне текущего репозитория:

- `top_100_osint_github_2026-06-24.csv`
- `osint_people_ru_ua_2026-06-24.csv`
- `osint_people_projects_2026-06-24.csv`
- `osint_ru_ua_projects_2026-06-24.csv`

Можно указать другую папку:

```powershell
python -m osint_toolkit stats --data-dir C:\path\to\data
```

## Проверки

```powershell
python -m unittest discover -s tests
```

## Границы безопасности

Этот проект является единой OSINT-системой, но не должен превращаться в безконтрольный инструмент массового пробива. Поэтому архитектура разделяет native-модули, внешние adapters и restricted-модули.

В native-код без отдельного режима не переносится:

- массовую проверку аккаунтов по email/телефону;
- обход приватности или ограничений платформ;
- password recovery flows;
- сбор закрытых данных;
- фишинг, credential harvesting или социальную инженерию.

Перед применением любого внешнего инструмента нужно отдельно проверить законность, согласие/основание, правила платформы, качество источника и риск вреда для человека.

`investigate --execute-adapters` запускает внешние CLI так же явно, как `run-adapter --execute`: без shell, с timeout и только если executable найден в `PATH`.
