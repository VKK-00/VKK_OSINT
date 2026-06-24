# OSINT Toolkit

Локальный CLI-инструмент и заготовка единой OSINT-системы на основе собранного каталога GitHub OSINT-проектов.

Цель проекта — не просто список ссылок, а единое ядро, которое постепенно покрывает функционал upstream-проектов:

- native-модулями внутри `osint_toolkit`;
- адаптерами к внешним CLI/API там, где проект большой, написан на другом языке или его лицензию нельзя просто смешивать с этим кодом;
- единым форматом результатов `Finding`;
- общей CLI-оболочкой.

Рабочая карта parity: [UPSTREAM_PARITY.ru.md](UPSTREAM_PARITY.ru.md).

Текущий первый слой уже умеет:

- искать по каталогу top-100 OSINT-репозиториев;
- находить проекты, связанные с OSINT по лицам;
- находить проекты и ресурсы, связанные с РФ, Украиной и русскоязычными платформами;
- выполнять native username profile checks по публичным URL-шаблонам;
- выполнять baseline email checks: синтаксис и live domain resolution;
- выполнять baseline phone checks: E.164-like нормализация и префикс региона;
- выполнять baseline domain recon: DNS resolution, HTTP/HTTPS metadata и security header presence;
- нормализовать Telegram handles/t.me URLs и по `--live` получать public metadata;
- выдавать RU/UA source pack: конфликтные карты, Telegram/RU platforms, geospatial и pastebin источники;
- получать базовые web metadata по URL;
- показывать карту upstream-адаптеров и dry-run/execute запускать настроенные внешние CLI;
- получать безопасный workflow под задачу;
- генерировать Markdown-brief для кейса.

## Быстрый старт

```powershell
python -m osint_toolkit stats
python -m osint_toolkit catalog --kind people --direct-only --limit 10
python -m osint_toolkit catalog --kind ru-ua --level direct_ru_ua
python -m osint_toolkit scan username example_user --limit 8
python -m osint_toolkit scan username example_user --region ru --live --limit 5
python -m osint_toolkit scan email person@example.com --live
python -m osint_toolkit scan phone +380441234567
python -m osint_toolkit scan domain example.com --live
python -m osint_toolkit scan telegram "@durov"
python -m osint_toolkit scan ru-ua all --region ua
python -m osint_toolkit scan url https://example.com --live
python -m osint_toolkit adapters
python -m osint_toolkit doctor
python -m osint_toolkit run-adapter sherlock-project/sherlock username example_user
python -m osint_toolkit investigate --username example_user --domain example.com --telegram "@durov" --include-adapters
python -m osint_toolkit investigate --title "case one" --email person@example.com --case-db cases.sqlite --case-id case-one
python -m osint_toolkit cases --case-db cases.sqlite
python -m osint_toolkit case-show --case-db cases.sqlite case-one --format markdown
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
python -m osint_toolkit scan username example_user --limit 10
python -m osint_toolkit scan username example_user --region ru --live --limit 10
python -m osint_toolkit scan email person@example.com --live --format json
python -m osint_toolkit scan phone +380441234567
python -m osint_toolkit scan domain example.com --live
python -m osint_toolkit scan telegram "@durov" --live
python -m osint_toolkit scan ru-ua all --region ru --format markdown
python -m osint_toolkit scan url https://example.com --live --format json
```

Сейчас native username module покрывает Sherlock/Maigret/WhatsMyName-подобный слой публичных profile URL checks. Полное 1:1 покрытие требует импорта upstream datasets и error rules либо подключения внешних CLI через adapters.

Native email/phone modules являются baseline-слоем для Mosint/h8mail/pwnedOrNot/PhoneInfoga-подобных adapters. Они не делают account-enumeration и не запускают password recovery flows.

Native domain module является baseline-слоем для web-check/theHarvester/SpiderFoot/Amass/Subfinder-подобного web/domain recon. Он не делает brute force, port scanning или subdomain enumeration.

Native Telegram module покрывает нормализацию `@handle`, `t.me/<handle>` и публичных post URLs. RU/UA source-pack module отдаёт curated источники из текущей разметки top-100.

### `adapters`

Показывает карту интеграции upstream-проектов.

```powershell
python -m osint_toolkit adapters
python -m osint_toolkit adapters --status planned --format markdown
python -m osint_toolkit adapters --status restricted
```

### `run-adapter`

Dry-run или явный запуск настроенного upstream CLI adapter. По умолчанию команда не запускается, а только показывается.

```powershell
python -m osint_toolkit run-adapter sherlock-project/sherlock username example_user
python -m osint_toolkit run-adapter sherlock-project/sherlock username example_user --execute
python -m osint_toolkit run-adapter sundowndev/phoneinfoga phone +380441234567
```

Restricted adapters требуют дополнительный флаг `--allow-restricted`; без него возвращается `restricted`.

При `--execute` поддерживаемые adapters дополнительно проходят через базовый stdout parser. Сейчас он извлекает URL, email, E.164-like phone и key/value сигналы из Sherlock/Maigret/Nexfil/Snoop/Mosint/PhoneInfoga-подобного вывода и возвращает их как обычные `Finding`.

### `doctor`

Проверяет, какие upstream adapters реально готовы к запуску в текущей системе: есть ли executable в `PATH`, есть ли command template, restricted ли adapter.

```powershell
python -m osint_toolkit doctor
python -m osint_toolkit doctor --status planned --format markdown
```

### `investigate`

Запускает несколько native-модулей по одному кейсу и собирает единый Markdown/JSON отчёт. По умолчанию live-запросы не выполняются.

```powershell
python -m osint_toolkit investigate --title "example case" --username example_user --email person@example.com --domain example.com
python -m osint_toolkit investigate --username example_user --telegram "@durov" --ru-ua all --region ua --include-adapters --out reports/example_case.md
python -m osint_toolkit investigate --domain example.com --live --format json
python -m osint_toolkit investigate --title "saved case" --email person@example.com --case-db cases.sqlite --case-id case-001
```

Отчёт содержит `Entity Summary`: нормализованные email, phone, domain, URL, Telegram handle, country/region и другие сущности, извлечённые из входных seed values, native findings и adapter dry-runs. Это общий слой для будущего case graph.

Если указан `--case-db`, кейс сохраняется в SQLite: targets, findings и entities можно открыть позже через `cases` и `case-show`.

### `cases` и `case-show`

Работа с сохранёнными расследованиями.

```powershell
python -m osint_toolkit cases --case-db cases.sqlite
python -m osint_toolkit cases --case-db cases.sqlite --format json
python -m osint_toolkit case-show --case-db cases.sqlite case-001
python -m osint_toolkit case-show --case-db cases.sqlite case-001 --format markdown
```

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
