# OSINT Toolkit

Локальный CLI-инструмент и заготовка единой OSINT-системы на основе собранного каталога GitHub OSINT-проектов.

Цель проекта — не просто список ссылок, а единое ядро, которое постепенно покрывает функционал upstream-проектов 1:1 на уровне поведения:

- native-модулями внутри `osint_toolkit`;
- адаптерами к внешним CLI/API там, где проект большой, написан на другом языке или его лицензию нельзя просто смешивать с этим кодом;
- единым форматом результатов `Finding`;
- общей CLI-оболочкой.

“1:1” в этом проекте означает: одинаковый класс входных данных, сопоставимый результат, единый статус/confidence и явный gap, если часть upstream-поведения ещё не покрыта. Adapter здесь не заглушка: это запуск реального upstream CLI/API и приведение его вывода к общей модели. Буквальное копирование исходников возможно только после проверки лицензии; иначе используется adapter или своя реализация того же поведения.

Рабочая карта parity: [UPSTREAM_PARITY.ru.md](UPSTREAM_PARITY.ru.md).

План глубокой интеграции “один ввод -> все подходящие сервисы -> единый отчёт”: [DEEP_INTEGRATION_PLAN.ru.md](DEEP_INTEGRATION_PLAN.ru.md).

Текущий первый слой уже умеет:

- искать по каталогу top-100 OSINT-репозиториев;
- находить проекты, связанные с OSINT по лицам;
- находить проекты и ресурсы, связанные с РФ, Украиной и русскоязычными платформами;
- разворачивать имя человека в username-кандидаты с RU/UA transliteration, common given-name aliases, initials, reversible name order и handle suffixes;
- выполнять native username profile checks по 2014 активным URL/check-шаблонам: 38 curated правил, встроенный Sherlock `data.json`, WhatsMyName `wmn-data.json` GET/POST entries и sanitized Maigret site rules с platform-specific username rules, content/status/response-url markers, custom headers, POST bodies и probe/profile URL metadata;
- выполнять baseline email checks: синтаксис, live domain resolution, MX/NS/TXT lookup, SPF, DMARC, MTA-STS, TLS-RPT, BIMI и публичные TXT service signals;
- выполнять baseline phone checks: E.164-like нормализация и префикс региона;
- выполнять baseline domain recon: DNS resolution, HTTP/HTTPS metadata, bounded same-site crawler, robots/sitemap discovery, public email/phone/social link extraction, security header presence, certificate transparency subdomain discovery, RDAP registration lookup и raw WHOIS registration fallback;
- нормализовать Telegram handles/t.me URLs и по `--live` получать public metadata;
- нормализовать Instagram username/profile/media URLs и по `--live` получать public profile/media metadata без login/session flows;
- нормализовать VK/OK/Yandex/Mail.ru public profile identifiers через `scan social` и по `--live` получать public page metadata без API/login/session flows;
- выдавать RU/UA source pack: конфликтные карты, Telegram/RU platforms, geospatial и pastebin источники;
- получать базовые web metadata, public email extraction, robots/sitemap discovery и bounded same-site crawl по URL;
- показывать карту upstream-адаптеров и dry-run/execute запускать настроенные внешние CLI;
- включать executed adapter outputs в единый investigation report, entities, graph и case store;
- читать generated JSON reports внешних adapters, если upstream CLI пишет машинный вывод в файл;
- запускать Mosint adapter в `--silent --output <json>` режиме и разбирать его upstream JSON report;
- запускать h8mail adapter в `--hide -j <json>` режиме и разбирать его upstream JSON report без переноса credential values в evidence;
- запускать Maigret adapter в `--json ndjson` режиме и разбирать его dossier findings;
- запускать Snoop adapter с RU/UA `--include` фильтром и разбирать его stdout/CSV-отчёты;
- запускать Social Analyzer adapter в fast JSON mode с optional RU/UA `--countries` фильтром и разбирать `detected`/`unknown`/`failed` profiles;
- запускать Blackbird adapter из upstream checkout через `BLACKBIRD_PYTHON`/`BLACKBIRD_DIR`, читать свежие JSON exports и stdout profile hits для username/email account discovery;
- запускать DetectDee adapter для username/email/phone через upstream `DetectDee detect -n|-e|-p ... -f <DETECTDEE_DATA>` и разбирать generated result/stdout profile hits;
- запускать Subfinder, httpx, пассивный Amass, theHarvester, BBOT, SpiderFoot и Argus recon adapters и нормализовать subdomains/emails/phones/URLs/IPs/ports/technologies/HTTP probe results в общий graph;
- запускать SpiderFoot adapter из isolated upstream venv через `SPIDERFOOT_PYTHON`/`SPIDERFOOT_SF_PATH`;
- строить unified `search` fan-out: один seed автоматически разворачивается в native checks, совместимые adapters, readiness/install hints и local image tools, а `--execute-adapters` запускает ready non-restricted adapters в единый report/case;
- генерировать локальное HTML-окно `toolbox` с направлениями OSINT, seed-полями и copy-ready командами для фото-зацепок, OCR, EXIF/metadata, QR/barcodes, reverse image portals, лиц/username, email, телефона, домена/URL, РФ/Украины, кейсов, графов и adapters;
- запускать unified `search` jobs из toolbox через локальный token-protected backend без передачи произвольных shell-команд из браузера;
- получать безопасный workflow под задачу;
- генерировать Markdown-brief для кейса.
- сохранять расследования в SQLite и анализировать graph edges сохранённого кейса.
- строить cross-case индекс сущностей и weighted paths по сохранённым расследованиям.

## Быстрый старт

```powershell
python -m osint_toolkit stats
python -m osint_toolkit toolbox --out osint_toolbox.html
python -m osint_toolkit toolbox --serve --open
python -m osint_toolkit search phone +380441234567 --profile phone-full --plan-only
python -m osint_toolkit search phone +380441234567 --profile phone-full --execute-adapters --adapter-limit 3 --out reports/phone.md --case-db cases.sqlite --case-id phone-001 --scope-note "internal validation scope"
python -m osint_toolkit search email person@example.com --profile email-full --plan-only --format markdown
python -m osint_toolkit search auto https://vk.com/example --profile auto --plan-only --format json
python -m osint_toolkit search auto https://t.me/durov --profile auto --plan-only --format json
python -m osint_toolkit search auto https://instagram.com/example --profile auto --plan-only --format json
python -m osint_toolkit search image C:\evidence\photo.jpg --profile image-full --execute-adapters --out reports/photo.md --case-db cases.sqlite --case-id photo-001 --scope-note "image source context review"
python -m osint_toolkit tools doctor --profile all-safe
python -m osint_toolkit search email person@example.com --profile case-email-safe --profile-file profiles\case_profiles.json --plan-only
python -m osint_toolkit profiles list --format markdown
python -m osint_toolkit profiles export email-full --out profiles\email-full.json
python -m osint_toolkit catalog --kind people --direct-only --limit 10
python -m osint_toolkit catalog --kind ru-ua --level direct_ru_ua
python -m osint_toolkit scan person "Ivan Petrenko" --limit 8
python -m osint_toolkit scan username exampleuser --limit 8
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
python -m osint_toolkit run-adapter alpkeskin/mosint email person@example.com
python -m osint_toolkit run-adapter khast3x/h8mail email person@example.com
python -m osint_toolkit run-adapter soxoj/maigret username example_user --region ua
python -m osint_toolkit run-adapter snooppr/snoop username example_user --region ua
python -m osint_toolkit run-adapter qeeqbox/social-analyzer username example_user --region ua
python -m osint_toolkit run-adapter p1ngul1n0/blackbird username example_user
python -m osint_toolkit run-adapter projectdiscovery/subfinder domain example.com
python -m osint_toolkit run-adapter projectdiscovery/httpx domain example.com
python -m osint_toolkit run-adapter laramies/theHarvester domain example.com
python -m osint_toolkit run-adapter blacklanternsecurity/bbot domain example.com
python -m osint_toolkit run-adapter smicallef/spiderfoot domain example.com
python -m osint_toolkit run-adapter jasonxtn/argus domain example.com
python -m osint_toolkit investigate --person "Ivan Petrenko" --include-adapters --adapter-profile username-full --adapter-limit 2
python -m osint_toolkit investigate --domain example.com --include-adapters --adapter-profile domain-recon --adapter-limit 6
python -m osint_toolkit investigate --domain example.com --include-adapters --adapter-profile broad-recon --adapter-limit 3
python -m osint_toolkit investigate --username example_user --domain example.com --telegram "@durov" --instagram "@exampleuser" --social vk:exampleuser --include-adapters
python -m osint_toolkit investigate --username example_user --include-adapters --adapter-profile username-full --adapter-limit 2
python -m osint_toolkit investigate --username example_user --include-adapters --adapter soxoj/maigret
python -m osint_toolkit investigate --username example_user --include-adapters --execute-adapters --adapter-limit 1
python -m osint_toolkit investigate --title "case one" --email person@example.com --case-db cases.sqlite --case-id case-one --scope-note "internal validation scope"
python -m osint_toolkit cases --case-db cases.sqlite
python -m osint_toolkit cases --case-db cases.sqlite --workflow search --profile email-full --scope-query "validation"
python -m osint_toolkit case-update --case-db cases.sqlite case-one --title "case one reviewed" --scope-note "reviewed scope"
python -m osint_toolkit case-show --case-db cases.sqlite case-one --format markdown
python -m osint_toolkit case-graph --case-db cases.sqlite case-one
python -m osint_toolkit case-graph --case-db cases.sqlite case-one --entity-kind email --entity-value person@example.com
python -m osint_toolkit case-index --case-db cases.sqlite --kind domain --min-cases 2
python -m osint_toolkit case-index --case-db cases.sqlite --kind email --value person@example.com
python -m osint_toolkit case-path --case-db cases.sqlite --from-kind email --from-value person@example.com --to-kind url --to-value https://example.com/profile
python -m osint_toolkit case-network --case-db cases.sqlite --kind domain --format markdown
python -m osint_toolkit case-delete --case-db cases.sqlite case-one --yes
python -m osint_toolkit recommend username --region ru --limit 8
python -m osint_toolkit brief --task telegram --region ua --target-value "public channel" --out reports/telegram_ua.md
```

После установки в editable-режиме можно использовать console script:

```powershell
python -m pip install -e .
osint-toolkit stats
```

## Команды

### `search`

Строит единый fan-out план для одного seed: native checks, совместимые adapters, readiness внешних CLI/env, local image tools, install hints и restricted/excluded notices. С `--execute-adapters` запускает только ready non-restricted adapters из этого же плана и пишет unified investigation report.

```powershell
python -m osint_toolkit search phone +380441234567 --profile phone-full --plan-only
python -m osint_toolkit search phone +380441234567 --profile phone-full --execute-adapters --adapter-limit 3 --out reports/phone.md --case-db cases.sqlite --case-id phone-001 --scope-note "internal validation scope"
python -m osint_toolkit search email person@example.com --profile email-full --plan-only --format markdown
python -m osint_toolkit search email person@example.com --profile email-full --execute-adapters --adapter-limit 3 --format json
python -m osint_toolkit search username example_user --profile username-full --region ua --plan-only
python -m osint_toolkit search domain example.com --profile passive-recon --plan-only
python -m osint_toolkit search url https://example.com --profile web-full --plan-only
python -m osint_toolkit search image C:\evidence\photo.jpg --profile image-full --plan-only
python -m osint_toolkit search image C:\evidence\photo.jpg --profile image-full --execute-adapters --out reports/photo.md --case-db cases.sqlite --case-id photo-001 --scope-note "image source context review"
python -m osint_toolkit search phone +380441234567 --profile phone-full --include-restricted --plan-only --format json
python -m osint_toolkit tools doctor --profile all-safe --format markdown
python -m osint_toolkit tools install-plan --profile image-full --format markdown
python -m osint_toolkit tools env --profile email-full --format json
```

Без `--execute-adapters` команда показывает план и ничего не запускает. `--execute-adapters` использует readiness из плана, запускает только `ready` adapters, не запускает `missing`/`config_missing`/`not_configured`/`excluded`/`restricted` entries и сохраняет результат через тот же investigation/case-store слой. Native execution тоже следует профилю: запускаются только target kinds из `native_kinds`, поэтому custom adapter-only profiles не запускают built-in native checks скрыто. Для `email-full`, `safe` и `all-safe` email seed выводит derived domain target из домена адреса и username target из валидного local-part; для URL seed профили `web-full`, `passive-recon`, `safe` и `all-safe` выводят host как derived domain target. Такие derived targets маршрутизируются через default domain/web fan-out. Если указан `--case-db`, `--scope-note` сохраняет в metadata текстовый контекст/рамки проверки без отдельной таблицы. Для `image` этот же execution mode запускает ready local tools: PowerShell hash/baseline, ExifTool JSON, ImageMagick, Tesseract и zbarimg, извлекает URL/email/phone/username/domain clues и маршрутизирует derived seeds в обычный `search` fan-out. ExifTool JSON нормализует camera/GPS/date/source metadata, Tesseract OCR text и zbarimg QR/barcode payloads получают structured parser findings. Face-ID не выполняется.

Custom search profiles можно подключать через JSON-файл, чтобы сохранить свой набор native modules, adapter profiles, отдельных repositories и local image tools:

```json
{
  "profiles": [
    {
      "name": "case-email-safe",
      "title": "Case email safe",
      "description": "Case-specific safe email profile.",
      "target_kinds": ["email"],
      "native_kinds": ["email"],
      "derived_target_kinds": ["domain", "username"],
      "adapter_profiles": ["email-safe"],
      "adapter_repositories": ["p1ngul1n0/blackbird"],
      "excluded_repositories": ["megadose/holehe"],
      "note": "Case scope reviewed."
    }
  ]
}
```

```powershell
python -m osint_toolkit search email person@example.com --profile case-email-safe --profile-file profiles\case_profiles.json --plan-only
python -m osint_toolkit tools doctor --profile case-email-safe --profile-file profiles\case_profiles.json --format markdown
```

Файл принимает либо объект с `profiles`, либо top-level JSON-list. Валидатор не даёт изменённым custom entries переопределять built-in profiles и отклоняет неизвестные `target_kinds`, `adapter_profiles`, repositories, local tools и лишние поля. Точный экспорт built-in profile принимается обратно как безопасный no-op, чтобы exported files можно было использовать без ручной чистки.

В `toolbox --serve` тот же механизм доступен из одного окна: заполни `Profile file` путём внутри рабочей папки backend, укажи `Custom profile` и нажми `Профили` для проверки `/api/profiles`, `Tools`/`Install`/`Env` для `/api/tools` readiness или `Запустить search` для `/api/search`. Мини-редактор профиля сохраняет и удаляет custom profiles через `/api/profiles/save` и `/api/profiles/delete`; backend пишет canonical JSON только после валидации и не читает/пишет profile files вне рабочей папки.

### `profiles`

Управление search profiles из CLI: посмотреть built-ins, подключить custom JSON, показать один profile или экспортировать reusable JSON.

```powershell
python -m osint_toolkit profiles list --format markdown
python -m osint_toolkit profiles list --profile-file profiles\case_profiles.json --format json
python -m osint_toolkit profiles show image-full --format markdown
python -m osint_toolkit profiles show case-email-safe --profile-file profiles\case_profiles.json --format json
python -m osint_toolkit profiles export email-full --out profiles\email-full.json
```

### `tools`

Profile-level readiness helpers для сценария “не подключать каждый сервис отдельно”:

```powershell
python -m osint_toolkit tools doctor --profile all-safe --format markdown
python -m osint_toolkit tools install-plan --profile phone-full --format markdown
python -m osint_toolkit tools env --profile email-full --format json
```

`tools doctor` показывает readiness adapters и local tools по профилю. `tools install-plan` генерирует install/config actions для missing/config tools, но ничего не устанавливает автоматически и не предлагает excluded/restricted adapters как обычную установку. `tools env` выводит только имена required/optional env variables, без значений.

На Windows CLI и served toolbox автоматически перечитывают user/machine `PATH` и известные OSINT env variable names из системного окружения. Это нужно, чтобы только что установленные через `pipx`, Go или portable folders инструменты не отображались как `missing` в уже открытом терминале.

### `toolbox`

Генерирует одно локальное HTML-окно для ручной работы оператора: слева seed-поля, справа направления OSINT и кнопки, которые собирают copy-ready команды текущего CLI. В served mode окно также запускает unified `search` jobs, передаёт `scope_note`, читает saved cases/graph/index и рисует кликабельный SVG-граф связей через локальный backend.

```powershell
python -m osint_toolkit toolbox --out osint_toolbox.html
python -m osint_toolkit toolbox --out osint_toolbox.html --open
python -m osint_toolkit toolbox --serve --open
python -m osint_toolkit toolbox --serve --port 8766 --out osint_toolbox.html
```

В окно вынесены направления:

- фото/изображение как источник небиометрических public clues;
- локальный file baseline/hash, ExifTool JSON metadata parser, ImageMagick, Tesseract OCR text parser, zbarimg QR/barcode parser и reverse image search portals;
- лицо, username, Instagram, Telegram и RU social identifiers;
- email и телефон;
- домен, URL, passive/broad web recon;
- РФ/Украина;
- SQLite cases, SVG graph и cross-case index;
- каталог, adapter readiness/setup и reusable adapter profiles.

Static `toolbox --out` не загружает фото автоматически и не запускает команды из браузера: он собирает команды для ручного запуска. `toolbox --serve` поднимает локальный `127.0.0.1` backend с per-session token и принимает только структурированные payloads: `/api/search` для запуска unified jobs, `/api/profiles`/`/api/profiles/save`/`/api/profiles/delete` для built-in/custom search profile listing and editing, `/api/tools` для profile readiness/install/env views, `/api/cases`, `/api/cases/<id>`, `/api/cases/<id>/graph`, `/api/cases/<id>/update`, `/api/cases/<id>/delete`, `/api/case-index`, `/api/case-path`, `/api/case-network` для saved SQLite cases внутри рабочей папки backend. Case Browser строит bounded SVG-визуализацию из сохранённых `entities`/`edges`, фильтрует cases по workflow/profile/scope, меняет только allowlisted поля title/scope_note и удаляет кейс только при typed confirmation; unified runner принимает `profile_file` только внутри рабочей папки backend и typed `custom_profile`. Клик по узлу заполняет focus entity и вызывает graph summary/focus-neighbor analysis, `Path` ищет weighted shortest path между source/target entities, а `Network` показывает общий bounded graph по нескольким saved cases с фильтрами kind/relation. Произвольный shell из браузера не исполняется. Для фото served mode запускает тот же `search image ... --execute-adapters`: ready local tools, derived seeds, report/case. Reverse image search остаётся ручной загрузкой на внешние сайты для источника, дублей и контекста изображения, а не для face-ID.

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
python -m osint_toolkit scan person "Volodymyr Zelenskyy" --person-alias ze-team --person-alias-file aliases.txt --limit 16
python -m osint_toolkit scan username exampleuser --limit 10
python -m osint_toolkit scan username exampleuser --region ru --live --limit 10 --http-retries 2 --request-delay 0.2
python -m osint_toolkit scan email person@example.com --live --format json
python -m osint_toolkit scan phone +380441234567
python -m osint_toolkit scan domain example.com --live --crawl-pages 5 --crawl-depth 1
python -m osint_toolkit scan telegram "@durov" --live
python -m osint_toolkit scan instagram "@exampleuser" --live --format json
python -m osint_toolkit scan social vk:exampleuser --live --format json
python -m osint_toolkit scan social https://ok.ru/profile/1234567890 --format json
python -m osint_toolkit scan social mailru:exampleuser --format json
python -m osint_toolkit scan social yandex:q/exampleuser --format json
python -m osint_toolkit scan ru-ua all --region ru --format markdown
python -m osint_toolkit scan url https://example.com --live --crawl-pages 5 --crawl-depth 1 --format json
```

Native person module делает safe username expansion: нормализует имя, транслитерирует RU/UA/кириллические символы и генерирует bounded список кандидатов, по умолчанию до 24 вариантов, например `ivanpetrenko`, `ivan.petrenko`, `ipetrenko`, `vanyapetrenko` и `ivanpetrenkoofficial`. Оператор может добавить известные никнеймы и исторические варианты через повторяемый `--person-alias` или UTF-8 файл `--person-alias-file` со строками или comma-separated aliases. Это не подтверждение аккаунтов, а список кандидатов для проверки через username scan и adapters.

Сейчас native username module покрывает Sherlock/Maigret/WhatsMyName-подобный слой публичных profile URL checks: 38 curated URL-шаблонов, 479 валидных записей из Sherlock `data.json` включая 3 POST-checks и 27 response-url rules, 718 entries из WhatsMyName `wmn-data.json` включая 22 POST-checks и 1423 sanitized Maigret site rules; после дедупликации одинаковых URL активно 2014 check-шаблонов, включая 23 active POST checks и 26 active response-url checks. Curated правила идут первыми. Одинаковые URL удаляются, а альтернативные проверки одного сайта сохраняются с суффиксом источника, например `GitLab (WhatsMyName)`, `AniList (WhatsMyName)` или `Instagram (Maigret)`. Если username не подходит конкретной платформе, finding получает `status=skipped`, а не строит заведомо неверный URL. В `--live` режиме title/body markers, Sherlock `errorUrl` response-url rules, Sherlock/WMN POST bodies, WMN `e_string`/`m_string`, WMN `e_code`/`m_code`, Maigret `presenseStrs`/`absenceStrs`, status rules, custom headers, retry по 429/temporary 5xx, `Retry-After` и операторский `--request-delay` используются для более близкой к upstream классификации. Оставшийся gap до полного 1:1: Maigret engine templates/activation/recursive policy/reporting logic, оставшиеся Sherlock WAF/error-handling нюансы, richer per-site rules и site-specific rate-limit policy либо запуск внешних CLI через adapters.

Native email/phone modules являются baseline-слоем для Mosint/h8mail/pwnedOrNot/user-scanner/PhoneInfoga-подобных adapters. Email module в `--live` режиме делает domain resolution, MX/NS/TXT lookup через системный `nslookup`, SPF classification по доменному TXT, DMARC через `_dmarc.<domain>`, MTA-STS через `_mta-sts.<domain>`, TLS-RPT через `_smtp._tls.<domain>`, BIMI через `default._bimi.<domain>` и распознаёт публичные TXT service signals вроде Google/Microsoft/Yandex/Mail.ru verification markers. Он не делает breach lookup, account-enumeration и не запускает password recovery flows.

Native domain module является baseline-слоем для web-check/Photon/theHarvester/SpiderFoot/Amass/Subfinder/BBOT/Argus-подобного web/domain recon. В `--live` режиме он делает DNS resolution, HTTP/HTTPS metadata, public email extraction из уже загруженных landing pages, bounded same-site crawler (`--crawl-pages`, `--crawl-depth`), robots.txt/sitemap discovery, security header presence, certificate transparency lookup через `crt.sh`, RDAP lookup через `rdap.org` и raw WHOIS lookup через port 43 для поддерживаемых TLD. CT names попадают как `subdomain` entities и graph edges `domain -> subdomain`; RDAP/WHOIS registrar/nameservers попадают как `registrar`/`nameserver` entities и graph edges `domain -> registrar|nameserver`; WHOIS servers попадают как `whois-server` entities; найденные emails/phones/social URLs/sitemap URLs/robots disallow paths попадают как `email`/`phone`/`url`/`web-path` entities и graph edges `domain|url -> email|phone|url|web-path`. Широкое passive enumeration и HTTP probing подключаются через `domain-recon` adapters: `subfinder -d <domain> -oJ -silent`, `httpx -u <domain-or-url> -json -silent ...`, пассивный `amass enum -passive -nocolor -d <domain>`, `theHarvester -d <domain> -b all -f <output.json>`, `bbot -t <target> -p subdomain-enum -rf passive --output <dir> --name osint-toolkit` и `python <SPIDERFOOT_SF_PATH> -s <target> -u passive -o json -q`. Более широкие recon suites подключаются через `broad-recon`, включая интерактивный Argus сценарий `set target <target>`, `runall infra`, `viewout`, `exit`. Он не делает brute force, port scanning, JavaScript rendering, form submission, authentication, screenshots, API endpoint scanning, broader BBOT/SpiderFoot/Argus use cases или активные Amass modes по умолчанию. WHOIS raw text не копируется в evidence: сохраняются только доменные поля вроде registrar, nameservers, statuses и dates.

Native URL scan использует тот же bounded crawler: стартовая страница извлекает title/status/content-type, crawler читает `robots.txt`, `Sitemap:` directives и `/sitemap.xml`, затем до заданного лимита обходит same-site HTTP(S)-ссылки и собирает public email, E.164-like phone values, external links и social links. По умолчанию лимиты небольшие: 5 страниц и глубина 1.

Native Telegram module покрывает нормализацию `@handle`, `t.me/<handle>` и публичных post URLs. Native Instagram module покрывает нормализацию `@username`, `instagram.com/<username>/` и публичных media URLs `/p/`, `/reel/`, `/reels/`, `/tv/`; в `--live` режиме он извлекает только публичные page metadata: display name, account id, canonical/profile/media/external URLs, public counters и privacy/verification flags, если они есть в HTML/JSON страницы. Native social module покрывает RU social public profile wrappers для VK, OK, Yandex и Mail.ru: `vk:<identifier>`, `ok:<identifier>`, `mailru:<identifier>`, `mailru:<namespace>/<identifier>`, `yandex:q/<identifier>`, `yandex:market/<identifier>`, `yandex:reviews/<identifier>`, `yandex:zen/<identifier>` и прямые public URLs нормализуются в `social-profile` entities, а live-режим извлекает только public title/meta/canonical/image fields. Эти social-модули не делают login/session handling, private data access, follower scraping, comments/messages export, API-token enrichment или обход rate limits. RU/UA source-pack module отдаёт curated источники из текущей разметки top-100.

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

Команда не устанавливает внешние инструменты сама. Она даёт проверяемый setup plan, а фактическая установка upstream CLI остаётся отдельным операторским действием или отдельным installer/runbook шагом. Для SpiderFoot нужно указать `SPIDERFOOT_SF_PATH` — путь к локальному upstream `sf.py`; если он установлен в отдельный venv, укажи `SPIDERFOOT_PYTHON`, иначе будет использован `python`. Для Social Analyzer нужно указать `SOCIAL_ANALYZER_APP_JS` — путь к локальному upstream `app.js` после `npm install`. Для Blackbird нужно указать `BLACKBIRD_DIR` — путь к локальному upstream checkout с `blackbird.py`, установленными requirements и его `results/` папкой; если он установлен в отдельный venv, укажи `BLACKBIRD_PYTHON`, иначе будет использован `python`. Для DetectDee нужно, чтобы `DetectDee` был в `PATH`, а `DETECTDEE_DATA` указывал на upstream `data.json`; adapter использует только режим `detect`, без screenshot, ChatGPT token и credential-stuffing flows. Для неоднозначных CLI readiness может выполнять allowlisted identity probe: сейчас это Subfinder, ProjectDiscovery `httpx`, Amass, theHarvester, BBOT и PhoneInfoga. Если PATH указывает на одноимённый, но не тот executable, статус будет `wrong_executable`, и такой adapter не попадёт в execution allowlist.

### `adapter-profiles`

Показывает готовые группы adapters для расследований.

```powershell
python -m osint_toolkit adapter-profiles
python -m osint_toolkit adapter-profiles --format json
```

Текущие профили включают `username-full`, `username-ru-ua`, `email-safe`, `phone-safe`, `url-archive`, `domain-recon` и `broad-recon`. `username-full` включает Sherlock через `sherlock <username> --no-color --print-all --csv --txt --folderoutput <tempdir>`, Maigret через `maigret <username> --json ndjson`, Social Analyzer через `node <SOCIAL_ANALYZER_APP_JS> --username <username> --output json --mode fast --method all --filter good,maybe --profiles detected`, Blackbird через `<BLACKBIRD_PYTHON|python> blackbird.py --username <username> --json --no-update`, DetectDee через `DetectDee detect -n <username> -f <DETECTDEE_DATA>`, Nexfil через изолированный temporary workdir с autosaved TXT reports, `instaloader profile <profile>` для Instagram edge cases, Snoop и `user-scanner`; `username-ru-ua` начинается со Snoop, Maigret, Social Analyzer и Sherlock. При `--region ru|ua` Snoop получает `--include RU|UA`, Maigret получает `--tags ru|ua`, а Social Analyzer получает `--countries ru|ua`. `email-safe` включает Mosint через `mosint --silent <email> --output <temp.json>`, h8mail через `h8mail -t <email> --hide -j <temp.json>`, pwnedOrNot через `pwnedornot -e <email> -n`, `user-scanner` через target-specific JSON-команды `user-scanner -u <username> -f json` и `user-scanner -e <email> -f json`, а также Blackbird через `<BLACKBIRD_PYTHON|python> blackbird.py --email <email> --json --no-update`. `phone-safe` включает PhoneInfoga через `phoneinfoga scan -n <number>`; GPL-код PhoneInfoga не копируется внутрь проекта, но stdout/API-like JSON вывод приводится к общим `Finding`/`Entity`/graph signals. Full phone/email/username profiles также могут включать DetectDee, если `DetectDee` и `DETECTDEE_DATA` готовы. `url-archive` включает Owez/yark через `yark new <archive_name> <channel_url>` во временной директории; generated `yark.json` разбирается в channel summary, video findings, YouTube URLs и description clues. `domain-recon` включает Subfinder, httpx, пассивный Amass, theHarvester, BBOT в passive `subdomain-enum` режиме и SpiderFoot через `<SPIDERFOOT_PYTHON|python> <SPIDERFOOT_SF_PATH> ...` в passive use-case режиме. `broad-recon` группирует BBOT, SpiderFoot и интерактивный Argus для более широких recon suites; запуск остаётся dry-run до явного `--execute-adapters`. Restricted email-to-account/email-to-phone adapters в safe-профили не входят.

### `run-adapter`

Dry-run или явный запуск настроенного upstream CLI adapter. По умолчанию команда не запускается, а только показывается.

```powershell
python -m osint_toolkit run-adapter sherlock-project/sherlock username example_user
python -m osint_toolkit run-adapter sherlock-project/sherlock username example_user --execute
python -m osint_toolkit run-adapter alpkeskin/mosint email person@example.com
python -m osint_toolkit run-adapter khast3x/h8mail email person@example.com
python -m osint_toolkit run-adapter soxoj/maigret username example_user --region ua
python -m osint_toolkit run-adapter snooppr/snoop username example_user --region ua
python -m osint_toolkit run-adapter qeeqbox/social-analyzer username example_user --region ua
python -m osint_toolkit run-adapter p1ngul1n0/blackbird username example_user
python -m osint_toolkit run-adapter p1ngul1n0/blackbird email person@example.com
python -m osint_toolkit run-adapter thewhiteh4t/pwnedOrNot email person@example.com
python -m osint_toolkit run-adapter thewhiteh4t/nexfil username example_user
python -m osint_toolkit run-adapter instaloader/instaloader instagram https://www.instagram.com/exampleuser/
python -m osint_toolkit run-adapter kaifcodec/user-scanner email person@example.com
python -m osint_toolkit run-adapter kaifcodec/user-scanner username example_user
python -m osint_toolkit run-adapter sundowndev/phoneinfoga phone +380441234567
python -m osint_toolkit run-adapter projectdiscovery/subfinder domain example.com
python -m osint_toolkit run-adapter projectdiscovery/httpx domain example.com
python -m osint_toolkit run-adapter owasp-amass/amass domain example.com
python -m osint_toolkit run-adapter laramies/theHarvester domain example.com
python -m osint_toolkit run-adapter blacklanternsecurity/bbot domain example.com
python -m osint_toolkit run-adapter smicallef/spiderfoot domain example.com
python -m osint_toolkit run-adapter jasonxtn/argus domain example.com
```

Restricted adapters требуют дополнительный флаг `--allow-restricted`; без него возвращается `restricted`.

При `--execute` поддерживаемые adapters дополнительно проходят через parser. Runner умеет читать stdout/stderr и generated report-файлы из временной output-папки, временной рабочей папки, upstream checkout `results/` или конкретного output-file аргумента; интерактивным adapters он может передавать scripted stdin. Для Sherlock есть parser stdout и CSV/TXT reports: `Claimed` -> `candidate/high`, `Available` -> `not_found/medium`, `Unknown`/`WAF` -> `error/low`, `Illegal` -> `skipped/high`; отрицательные строки сохраняют `checked_url`, но не создают подтверждённый URL/domain. Для Nexfil есть parser stdout/autosaved TXT reports: найденные profile URL становятся `candidate/high`, а `Total Hits`, `Total Timeouts`, `Total Errors` сохраняются как summary metadata. Для PhoneInfoga есть parser фактического CLI stdout `Results for <scanner>` и REST/API-like JSON: `local`, `numverify`, `googlesearch`, `googlecse` и `ovh` переводятся в `Finding`/entities/graph signals, включая `normalized`, `country`, `carrier`, `line_type`, `location`, `number_range`, `zip_code`, Google dork URL и CSE result URL. Для DetectDee есть parser generated output/stdout строк `identity, site, url` и `[+] identity site: url`; найденные URL становятся `candidate/medium` с metadata `site_name`, `identity`, `profile_url` и исходным target kind. Для Mosint есть parser фактического JSON `email`, `verified`, `emailrep`, `breachdirectory`, `haveibeenpwned`, `hunter`, `intelx`, `psbdmp`, social flags, `google_search` и `dns_records`; password/hash/sha1-like values редактируются. Для h8mail есть parser фактического JSON `{targets: [{target, pwn_num, data}]}`: breach count, related emails, usernames, source labels и paste URLs превращаются в `Finding`/entities, а password/hash/token-like values редактируются и не попадают в evidence. Для pwnedOrNot есть parser upstream stdout `Checking Breach status`, `Total Breaches` и `Breach/Domain/Date/BreachedInfo` rows: HIBP breach summary и breach rows превращаются в `Finding`/entities, а dump/password output редактируется как credential-exposure без переноса значений. Для Maigret есть parser NDJSON/simple JSON/CSV: `Claimed` -> `candidate/high`, `Available` -> `not_found/medium`, `Unknown` -> `error/low`, `Illegal` -> `skipped/high`, а `ids` попадают в metadata `name`, `location`, `country`, `email`, `phone` и `username`. Для Social Analyzer есть parser JSON `detected`/`unknown`/`failed`: `detected` превращается в `candidate` с confidence по `status`/`rate`, `unknown` в `not_found` с `checked_url`, `failed` в `error`; URL профиля, platform domain, social username, country/type/language/title и счётчик metadata сохраняются в finding metadata/entities. Для Blackbird есть parser JSON export и stdout found-lines: `FOUND` -> `candidate/high`, `NOT-FOUND` -> `not_found/medium`, `ERROR` -> `error/low`; site/category/profile URL, platform domain, target email/username и extracted metadata вроде name/location/profile image попадают в metadata/entities. Для `user-scanner` есть JSON/verbose parser со статусами `Registered`, `Found`, `Not Found`, `Available` и `Error`. Для `snooppr/snoop` есть parser stdout-строк и CSV-отчёта: `найден!` превращается в `candidate/high`, `Увы!` в `not_found/medium`, `блок` и ошибки в `error/low`; отрицательные строки сохраняют `checked_url`, но не создают подтверждённый URL/domain. Для `projectdiscovery/subfinder` есть parser JSONL/plain output в `subdomain` findings; для `projectdiscovery/httpx` parser JSONL/plain output сохраняет URL, HTTP status, title, webserver, tech, content-type, response-time, IP/CNAME и error state; для `owasp-amass/amass` parser пассивного stdout/JSON-like output извлекает subdomains без включения активных/bruteforce режимов по умолчанию. Для `laramies/theHarvester` runner добавляет `-f <temp.json>`, читает generated JSON report и parser нормализует `emails`, `hosts`, `vhosts`, `interesting_urls`, `trello_urls`, `ips`, `asns` и people fields. Для `blacklanternsecurity/bbot` runner добавляет `--output <tempdir> --name osint-toolkit`, читает generated JSON/NDJSON events и parser нормализует `DNS_NAME`, `EMAIL_ADDRESS`, `URL`, `IP_ADDRESS`, `OPEN_TCP_PORT`, `TECHNOLOGY`, `FINDING` и `VULNERABILITY`. Для `smicallef/spiderfoot` runner требует `SPIDERFOOT_SF_PATH`, запускает `python <sf.py> -s <target> -u passive -o json -q`, читает JSON stdout и parser нормализует `INTERNET_NAME`, `DOMAIN_NAME`, `EMAILADDR`, `WEBLINK`, `IP_ADDRESS`, `TCP_PORT_OPEN`, `PHONE_NUMBER`, `HUMAN_NAME`, `TECHNOLOGY`, ASN и vulnerability/finding events. Для `jasonxtn/argus` runner запускает `argus`, передаёт stdin-сценарий `set target`, `runall infra`, `viewout`, `exit` и parser нормализует URL, email, phone, host/subdomain, IP, port и technology signals.

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
python -m osint_toolkit investigate --person "Volodymyr Zelenskyy" --person-alias ze-team --include-adapters --adapter-profile username-full --adapter-limit 2
python -m osint_toolkit investigate --title "example case" --username example_user --email person@example.com --domain example.com
python -m osint_toolkit investigate --username example_user --telegram "@durov" --instagram "@exampleuser" --social vk:exampleuser --ru-ua all --region ua --include-adapters --out reports/example_case.md
python -m osint_toolkit investigate --username example_user --include-adapters --adapter-profile username-full --adapter-limit 2
python -m osint_toolkit investigate --username example_user --include-adapters --adapter sherlock-project/sherlock --adapter soxoj/maigret
python -m osint_toolkit investigate --username example_user --include-adapters --execute-adapters --adapter-limit 1 --out reports/example_user.md
python -m osint_toolkit investigate --domain example.com --live --format json
python -m osint_toolkit investigate --title "saved case" --email person@example.com --case-db cases.sqlite --case-id case-001 --scope-note "internal validation scope"
```

Отчёт содержит `Entity Summary` и `Graph Edges`: нормализованные сущности и связи между ними, например `email -> domain`, `email -> related_email`, `domain -> email`, `domain -> phone`, `domain -> discovered URL`, `domain -> social URL`, `domain -> sitemap URL`, `domain -> robots disallow path`, `domain -> subdomain`, `domain -> registrar`, `domain -> nameserver`, `domain -> whois server`, `url -> domain`, `telegram -> url`, `instagram -> url`, `instagram -> display name/account id/platform`, `social -> social-profile/platform/display name/account id/public URL`, `phone -> country`.

Если указан `--person`, система генерирует username-кандидаты и автоматически прогоняет их через native username scan; при `--include-adapters` эти derived usernames также попадают в совместимые username adapters. В графе это видно как `person -> username -> url`.

`--include-adapters` по умолчанию добавляет только dry-run команды. `--adapter-profile <name>` добавляет готовую группу adapters, а `--adapter <repository>` можно повторять, чтобы ограничить кейс конкретными upstream adapters. `--execute-adapters` явно запускает настроенные upstream CLI из `PATH`, прогоняет поддерживаемый stdout/stderr через parser и добавляет найденные URL/email/phone/key-value сигналы в тот же `Entity Summary`, `Graph Edges` и SQLite case store. Restricted adapters требуют `--allow-restricted-adapters`.

Если указан `--case-db`, кейс сохраняется в SQLite: targets, findings, entities, graph edges и case metadata можно открыть позже через `cases`, `case-show`, `case-graph` и `case-index`. `--scope-note` добавляет в metadata текстовый контекст/рамки проверки. Для `search` metadata фиксирует requested/search profile, profile file, execute flags и реально запущенные adapters/local tools; для `investigate` — adapter profiles, allowlist и execute flags.

### `cases`, `case-show`, `case-update`, `case-delete`, `case-graph`, `case-index`, `case-path` и `case-network`

Работа с сохранёнными расследованиями.

```powershell
python -m osint_toolkit cases --case-db cases.sqlite
python -m osint_toolkit cases --case-db cases.sqlite --workflow search --profile email-full --scope-query "internal"
python -m osint_toolkit cases --case-db cases.sqlite --format json
python -m osint_toolkit case-show --case-db cases.sqlite case-001
python -m osint_toolkit case-show --case-db cases.sqlite case-001 --format markdown
python -m osint_toolkit case-update --case-db cases.sqlite case-001 --title "reviewed case" --scope-note "reviewed scope" --format markdown
python -m osint_toolkit case-delete --case-db cases.sqlite case-001 --yes --format json
python -m osint_toolkit case-graph --case-db cases.sqlite case-001
python -m osint_toolkit case-graph --case-db cases.sqlite case-001 --entity-kind telegram --entity-value "@durov" --format json
python -m osint_toolkit case-index --case-db cases.sqlite
python -m osint_toolkit case-index --case-db cases.sqlite --kind domain --min-cases 2 --format markdown
python -m osint_toolkit case-index --case-db cases.sqlite --kind telegram --value "@durov" --format json
python -m osint_toolkit case-path --case-db cases.sqlite --from-kind email --from-value person@example.com --to-kind url --to-value https://example.com/profile --format markdown
python -m osint_toolkit case-network --case-db cases.sqlite --kind domain --relation email_domain --format json
```

`cases` показывает свежие saved cases и поддерживает metadata filters: `--workflow`, `--profile`, `--scope-query`.

`case-show` в JSON/Markdown показывает `metadata`: workflow, profile/policy, `scope_note` и execution flags, если кейс был сохранён через `search --case-db` или `investigate --case-db`.

`case-update` меняет только безопасные поля управления кейсом: title и `scope_note`. Findings, targets, entities и graph edges не пересчитываются и не переписываются.

`case-delete` удаляет один saved case из SQLite вместе с дочерними targets/entities/findings/edges через cascade. CLI требует `--yes`, а served toolbox требует typed confirmation, совпадающий с `Case ID`.

`case-graph` строит summary по сохранённым `entities` и `edges`: число узлов и связей, счётчики типов отношений, счётчики типов сущностей и самые связанные узлы. Если указать `--entity-kind` и `--entity-value`, команда покажет соседей выбранной сущности.

`case-index` строит индекс сущностей по всем сохранённым кейсам. Без `--value` команда показывает сущности и количество кейсов, где они встречались; с `--kind` и `--value` показывает конкретные кейсы, содержащие эту сущность.

`case-path` объединяет graph edges из сохранённых кейсов и ищет weighted shortest path между двумя сущностями. Каждый шаг показывает `case_id`, relation, direction, confidence, source и weight.

`case-network` строит bounded общий граф по нескольким saved cases: агрегирует одинаковые edges, считает degree/case_count, поддерживает фильтры `--kind` и `--relation`, а также лимиты `--case-limit`, `--node-limit`, `--edge-limit` и `--min-degree`.

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

Встроенные package resources:

- `osint_toolkit/resources/sherlock_data.json` — snapshot Sherlock `sherlock_project/resources/data.json`, commit `206068d`, MIT license.
- `osint_toolkit/resources/whatsmyname_wmn_data.json` — snapshot WhatsMyName `wmn-data.json`, commit `7c44595`, CC BY-SA 4.0 license.
- `osint_toolkit/resources/maigret_sites.json` — sanitized projection of Maigret `maigret/resources/data.json`, commit `2484509`, MIT license.
- `osint_toolkit/resources/THIRD_PARTY_NOTICES.txt` — notice по скопированному upstream dataset.

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
