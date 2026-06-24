# Анализ проекта

## Цель проекта

Создать собственную единую OSINT-систему на основе уже собранного каталога GitHub OSINT-проектов.

Целевая модель — функциональная совместимость с upstream-проектами в одном интерфейсе: часть возможностей переносится в native-модули, часть подключается через внешние CLI/API adapters, а высокорисковые механики выносятся в restricted-слой.

## Что делает проект

Проект хранит датированные CSV/Markdown/JSON-срезы GitHub OSINT-проектов и предоставляет Python CLI/engine поверх этих данных.

CLI работает в трёх режимах:

- catalog/recommend/brief — работа с curated-каталогом;
- scan/adapters — единое ядро выполнения и карта функциональной совместимости upstream-проектов;
- investigate — объединение нескольких seed values, native findings, adapter dry-runs и нормализованных сущностей в один отчёт.

Первый native-слой уже выполняет:

- username public profile checks по URL-шаблонам, совместимые по классу задачи с Sherlock/Maigret/WhatsMyName/Nexfil;
- email baseline checks: синтаксис и live domain resolution;
- phone baseline checks: нормализация, E.164-like validation и country-prefix signal;
- domain baseline recon: DNS resolution, HTTP/HTTPS metadata и presence security headers;
- Telegram baseline: handle/post URL normalization и optional live public metadata;
- RU/UA source pack: curated карты, Telegram/RU platforms, geospatial и pastebin источники;
- базовый web metadata scan по URL, совместимый с начальным web-check слоем;
- external adapter dry-run/execute runner для настроенных upstream CLI;
- adapter doctor: проверка фактической доступности upstream CLI в `PATH`;
- investigation runner: один кейс, несколько seed-типов, entity summary, единый Markdown/JSON отчёт;
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
- `osint_toolkit/modules/email.py`
  - `EmailScanModule` — базовая проверка email: синтаксис и доменное разрешение.
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
  - `AdapterSpec` — карта upstream-проектов, лицензий, режима интеграции и текущего статуса.
- `osint_toolkit/adapter_runner.py`
  - `run_adapter()` — dry-run или явный запуск внешнего CLI adapter без shell.
- `osint_toolkit/doctor.py`
  - `inspect_adapters()` — диагностика доступности upstream adapters.
- `osint_toolkit/entities.py`
  - `Entity` — нормализованная сущность кейса: email, phone, domain, URL, Telegram handle, country/region и т.д.
  - `entities_from_targets()` — извлечение сущностей из seed values.
  - `entities_from_findings()` — извлечение сущностей из native и adapter findings.
  - `merge_entities()` — дедупликация сущностей с учётом confidence.
- `osint_toolkit/investigation.py`
  - `run_investigation()` — multi-target native scan + optional adapter dry-runs + entity summary.
  - `render_investigation_markdown()` — единый отчёт по кейсу.
- `osint_toolkit/workflows.py`
  - `recommend_projects()` — подбор ресурсов под тип задачи.
  - `render_brief()` — генерация Markdown-brief.
- `osint_toolkit/output.py`
  - форматирование таблиц, Markdown, CSV и JSON.
- `osint_toolkit/cli.py`
  - argparse CLI: `stats`, `catalog`, `show`, `recommend`, `brief`.

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
4. В dry-run модуль возвращает planned findings без сетевых запросов.
5. В live-режиме модуль выполняет публичные HTTP checks и возвращает `Finding`.

Adapter-поток:

1. Пользователь запускает `python -m osint_toolkit run-adapter <repo> <kind> <value>`.
2. `find_adapter()` находит `AdapterSpec`.
3. По умолчанию возвращается planned finding с командой.
4. При `--execute` команда запускается через `subprocess.run()` без shell, только если executable найден в `PATH`.
5. Restricted adapters требуют отдельный `--allow-restricted`.

Investigation-поток:

1. Пользователь запускает `python -m osint_toolkit investigate` с одним или несколькими seed values.
2. CLI превращает каждый seed в `ScanTarget`.
3. `run_investigation()` запускает native scan-модули и, при `--include-adapters`, adapter dry-runs.
4. `entities.py` извлекает и объединяет сущности из входных целей, `Finding.url`, `Finding.evidence` и `Finding.metadata`.
5. Отчёт выводится как Markdown или JSON; Markdown содержит `Entity Summary`, native findings, adapter dry-runs и review checklist.

## Поток данных

Источник истины — локальные CSV-файлы. Код не изменяет эти CSV при обычной работе.

Поток:

Каталог:

`CSV snapshot -> Catalog.load() -> OsintProject[] -> filter/recommend/brief -> console/Markdown output`

Сканирование:

`CLI target -> ScanTarget -> Engine -> ScanModule[] -> Finding[] -> table/Markdown/CSV/JSON`

Адаптеры:

`CLI adapter request -> AdapterSpec -> command_template -> dry-run/external process -> Finding`

Investigation:

`multiple CLI seeds -> ScanTarget[] -> Engine -> Finding[] -> optional adapter dry-runs -> Entity[] -> Markdown/JSON report`

## Внешние интеграции

В рантайме сетевые интеграции есть только в явном live-режиме scan-команд.

Существующие CSV были собраны из GitHub ранее. Каталоговые команды не ходят в GitHub API.

Native live-модули используют публичные HTTP(S) URL checks через стандартную библиотеку Python.

Будущие external adapters должны подключать upstream CLI/API без копирования кода, если лицензия, масштаб или язык проекта делают прямой перенос неразумным.

## Конфигурация, переменные окружения и секреты

Секреты не используются.

Конфигурация:

- `--data-dir` — путь к папке с CSV.
- `--format` — формат вывода для команд `catalog` и `show`.
- `--out` — путь Markdown-файла для `brief`.
- `scan --live` — явное разрешение сетевых проверок.
- `scan --timeout` — HTTP timeout.
- `scan --region` — фильтр URL-шаблонов или workflow по региону.
- `investigate --include-adapters` — добавить dry-run команды совместимых upstream adapters.
- `investigate --format markdown|json` — формат отчёта по кейсу.

## Команды запуска, тестирования, проверки и отладки

Запуск:

```powershell
python -m osint_toolkit stats
python -m osint_toolkit catalog --kind people --direct-only --limit 10
python -m osint_toolkit scan username example_user --limit 10
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
- `Entity` отделён от `Finding`: finding описывает источник и сигнал, entity описывает нормализованный объект для сводки кейса и будущего графа.
- Dry-run используется по умолчанию для scan-команд. Live-сетевые проверки требуют явного `--live`.
- Лицензионно сложные или большие проекты подключаются adapters вместо прямого копирования кода.
- Password recovery flows, email-to-account и phone-to-account механики не переносятся в native-код без restricted-режима.
- Разметка people/ru-ua считается curated-слоем поверх top-100, а не абсолютной классификацией качества.

## Рассмотренные варианты реализации

- Полноценный web UI: отложен, потому что сначала нужно стабилизировать engine/adapters.
- Буквальное копирование кода из всех проектов: не выбрано как первый шаг из-за разных лицензий, языков и масштаба. Целевая альтернатива — 1:1 functional parity через native-compatible modules и external adapters.
- Новая база данных SQLite: пока не нужна, CSV достаточно для каталога; для истории scan-запусков может понадобиться позже.

## Текущие ограничения, риски и открытые вопросы

- Каталог основан на snapshot от 2026-06-24; GitHub stars и актуальность проектов меняются.
- Качество и безопасность внешних репозиториев не аудированы.
- Первый native username module покрывает только URL-template/status-code слой, а не всю логику Sherlock/Maigret: нет полного upstream site dataset, custom error rules, rate-limit logic и enrichment.
- Native email module пока не делает MX lookup, breach lookup или external API enrichment.
- Native phone module пока не делает carrier lookup, reputation lookup или external API enrichment.
- Telegram module пока не использует Telegram API и не получает private/group data.
- RU/UA source pack пока curated вручную из текущего snapshot, без автообновления.
- Adapter runner запускает только те CLI, которые уже установлены в `PATH`; установкой upstream-проектов он пока не занимается.
- Entity summary пока строится только в памяти для одного отчёта; persistent graph/database ещё нет.
- Investigation runner пока не хранит историю кейсов в базе данных; отчёт пишется в файл или stdout.
- Рекомендации и scan-результаты являются техническими сигналами, не юридической или операционной инструкцией.
- Для будущего расширения может понадобиться отдельный ingestion pipeline и повторяемый классификатор.

## Что нужно обновлять при изменениях проекта

- При изменении CSV-схемы обновлять `Catalog.load()` и тесты.
- При добавлении native-модуля обновлять `engine.py`, `cli.py`, README и тесты.
- При подключении upstream-проекта обновлять `adapters.py`, указать лицензию, режим интеграции и parity gap.
- При изменении схемы сущностей обновлять `entities.py`, `investigation.py`, README и тесты JSON/Markdown.
- При добавлении команд обновлять `README.md` и этот анализ.
- При изменении safety-границ обновлять `README.md`, `workflows.py` и тесты brief/recommend.
- При новом snapshot обновлять дату в `catalog.py` или добавить явный выбор snapshot.

## Журнал существенных изменений анализа

- 2026-06-24: добавлен Python CLI `osint_toolkit` поверх существующих OSINT snapshot CSV.
- 2026-06-24: цель уточнена до единой OSINT-системы с 1:1 functional parity; добавлены engine, native scan modules и adapter manifest.
- 2026-06-24: добавлен report-level entity summary для объединения seed values, native findings и adapter dry-runs в расследовании.
