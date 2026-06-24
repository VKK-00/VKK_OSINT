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
- получать базовые web metadata по URL;
- показывать карту upstream-адаптеров для дальнейшего 1:1 functional parity;
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
python -m osint_toolkit scan url https://example.com --live
python -m osint_toolkit adapters
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
python -m osint_toolkit scan url https://example.com --live --format json
```

Сейчас native username module покрывает Sherlock/Maigret/WhatsMyName-подобный слой публичных profile URL checks. Полное 1:1 покрытие требует импорта upstream datasets и error rules либо подключения внешних CLI через adapters.

Native email/phone modules являются baseline-слоем для Mosint/h8mail/pwnedOrNot/PhoneInfoga-подобных adapters. Они не делают account-enumeration и не запускают password recovery flows.

### `adapters`

Показывает карту интеграции upstream-проектов.

```powershell
python -m osint_toolkit adapters
python -m osint_toolkit adapters --status planned --format markdown
python -m osint_toolkit adapters --status restricted
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
