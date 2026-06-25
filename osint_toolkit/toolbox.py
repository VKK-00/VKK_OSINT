from __future__ import annotations

from dataclasses import dataclass
from html import escape
from pathlib import Path

from .adapters import AdapterProfile, list_adapter_profiles
from .search import TARGET_KINDS, list_search_profiles


@dataclass(frozen=True)
class ToolboxCommand:
    title: str
    description: str
    command_template: str
    required_inputs: tuple[str, ...] = ()
    badges: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class ToolboxSection:
    slug: str
    title: str
    description: str
    commands: tuple[ToolboxCommand, ...]
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolboxInput:
    name: str
    label: str
    placeholder: str
    input_type: str = "text"


TOOLBOX_INPUTS: tuple[ToolboxInput, ...] = (
    ToolboxInput("title", "Название кейса", "photo clue review"),
    ToolboxInput("image_path", "Путь к фото", r"C:\path\to\photo.jpg"),
    ToolboxInput("person", "Имя", "Ivan Petrenko"),
    ToolboxInput("username", "Username / handle", "example_user"),
    ToolboxInput("email", "Email", "person@example.com", "email"),
    ToolboxInput("phone", "Телефон", "+380441234567"),
    ToolboxInput("domain", "Домен", "example.com"),
    ToolboxInput("url", "URL", "https://example.com/profile"),
    ToolboxInput("telegram", "Telegram", "@public_channel"),
    ToolboxInput("instagram", "Instagram", "@exampleuser"),
    ToolboxInput("social", "Соцсеть RU/UA", "vk:exampleuser или https://ok.ru/profile/..."),
    ToolboxInput("ruua", "RU/UA seed", "all"),
    ToolboxInput("region", "Регион", "ua"),
    ToolboxInput("profile_file", "Profile file", r"profiles\case_profiles.json"),
    ToolboxInput("custom_profile", "Custom profile", "case-email-safe"),
    ToolboxInput("profile_title", "Profile title", "Case email safe"),
    ToolboxInput("profile_description", "Profile description", "Case-specific safe email profile"),
    ToolboxInput("profile_target_kinds", "Profile targets", "email"),
    ToolboxInput("profile_native_kinds", "Profile native", "email"),
    ToolboxInput("profile_derived_targets", "Profile derived targets", "domain, username"),
    ToolboxInput("profile_adapter_profiles", "Profile adapter groups", "email-safe"),
    ToolboxInput("profile_repositories", "Profile repositories", "p1ngul1n0/blackbird"),
    ToolboxInput("profile_local_tools", "Profile local tools", "powershell-file-baseline"),
    ToolboxInput("profile_excluded", "Profile excluded repos", "megadose/holehe"),
    ToolboxInput("profile_note", "Profile note", "Case scope reviewed"),
    ToolboxInput("adapter_limit", "Лимит adapters", "3", "number"),
    ToolboxInput("case_db", "SQLite case DB", "cases.sqlite"),
    ToolboxInput("case_id", "Case ID", "case-001"),
    ToolboxInput("scope_note", "Scope note", "internal validation scope"),
    ToolboxInput("workflow_filter", "Workflow filter", "search"),
    ToolboxInput("profile_filter", "Profile filter", "email-full"),
    ToolboxInput("scope_query", "Scope contains", "internal validation"),
    ToolboxInput("delete_confirm", "Delete confirm", "case-001"),
    ToolboxInput("entity_kind", "Entity kind", "domain"),
    ToolboxInput("entity_value", "Entity value", "example.com"),
    ToolboxInput("relation", "Relation filter", "email_domain"),
    ToolboxInput("graph_filter", "Graph contains", "example.com"),
    ToolboxInput("target_entity_kind", "Target entity kind", "url"),
    ToolboxInput("target_entity_value", "Target entity value", "https://example.com/profile"),
    ToolboxInput("out", "Файл отчета", "reports/case.md"),
)

INPUT_LABELS = {field.name: field.label for field in TOOLBOX_INPUTS}


def toolbox_sections() -> tuple[ToolboxSection, ...]:
    sections = (
        ToolboxSection(
            slug="photo",
            title="Фото / изображение",
            description=(
                "Маршрут для разбора фото как источника небиометрических "
                "зацепок: metadata, EXIF, OCR, QR/barcodes, текст, username, URL, "
                "домен, телефон, email, логотип, география, public profile links."
            ),
            commands=(
                ToolboxCommand(
                    "Image full search plan",
                    "Единый fan-out план для локальных image tools: hash, EXIF, OCR, QR/barcodes.",
                    'python -m osint_toolkit search image "{image_path}" --profile image-full --plan-only --format markdown',
                    required_inputs=("image_path",),
                    badges=("search", "image-full"),
                    note="Этот route не делает face-ID; он планирует metadata/OCR/QR/hash checks.",
                ),
                ToolboxCommand(
                    "Image local execution",
                    "Запускает ready local image tools, извлекает derived seeds и пишет unified report/case.",
                    (
                        'python -m osint_toolkit search image "{image_path}" '
                        "--profile image-full --execute-adapters --adapter-limit {adapter_limit} "
                        "--out {out} --case-db {case_db} --case-id {case_id} "
                        '[[--scope-note "{scope_note}"]]'
                    ),
                    required_inputs=("image_path", "adapter_limit", "out", "case_db", "case_id"),
                    badges=("execute", "image-full", "local-tools"),
                    note="Face-ID не выполняется; derived URL/email/phone/username/domain seeds идут в обычный search fan-out.",
                ),
                ToolboxCommand(
                    "Локальный baseline файла",
                    "Размер, timestamps и SHA256 без внешних зависимостей.",
                    (
                        'Get-Item -LiteralPath "{image_path}" | '
                        "Select-Object FullName,Length,CreationTimeUtc,LastWriteTimeUtc; "
                        'Get-FileHash -Algorithm SHA256 -LiteralPath "{image_path}"'
                    ),
                    required_inputs=("image_path",),
                    badges=("local", "hash"),
                    note="Это не читает EXIF, но даёт стабильный fingerprint файла.",
                ),
                ToolboxCommand(
                    "EXIF / metadata через ExifTool",
                    "Читает EXIF, GPS, XMP/IPTC и embedded metadata, если установлен `exiftool`.",
                    'exiftool -json -a -u -g1 -ee "{image_path}"',
                    required_inputs=("image_path",),
                    badges=("exiftool", "metadata"),
                    note="Перед передачей отчёта наружу отдельно проверь GPS и приватные metadata.",
                ),
                ToolboxCommand(
                    "ImageMagick identify",
                    "Формат, размеры, цветовые профили, signature и technical metadata.",
                    'magick identify -verbose "{image_path}"',
                    required_inputs=("image_path",),
                    badges=("imagemagick", "metadata"),
                ),
                ToolboxCommand(
                    "OCR через Tesseract",
                    "Извлекает видимый текст для дальнейшей проверки username, URL, email и телефонов.",
                    'tesseract "{image_path}" stdout -l eng+rus+ukr',
                    required_inputs=("image_path",),
                    badges=("ocr", "tesseract"),
                    note="После OCR перенеси найденные handles, URLs, emails или телефоны в seed-поля.",
                ),
                ToolboxCommand(
                    "QR / barcode scan",
                    "Извлекает QR-коды и barcodes, если установлен `zbarimg`.",
                    'zbarimg --raw "{image_path}"',
                    required_inputs=("image_path",),
                    badges=("qr", "barcode"),
                ),
                ToolboxCommand(
                    "Reverse image search portals",
                    "Открывает страницы ручной загрузки для поиска источника, дублей и контекста изображения.",
                    (
                        'Start-Process "https://lens.google.com/upload"; '
                        'Start-Process "https://tineye.com/"; '
                        'Start-Process "https://yandex.com/images/search"; '
                        'Start-Process "https://www.bing.com/images/search?view=detailv2&iss=sbi"'
                    ),
                    badges=("reverse image", "manual upload"),
                    note="Используй для source/context search, не для биометрической идентификации человека.",
                ),
                ToolboxCommand(
                    "Кейс из всех зацепок с фото",
                    "Собирает один investigation report из уже извлечённых seed-полей.",
                    (
                        'python -m osint_toolkit investigate --title "{title}" '
                        '[[--username {username}]] [[--email {email}]] '
                        '[[--phone {phone}]] [[--domain {domain}]] [[--url {url}]] '
                        '[[--telegram {telegram}]] [[--instagram {instagram}]] '
                        '[[--social {social}]] [[--ru-ua {ruua}]] [[--region {region}]] '
                        '--include-adapters '
                        '--adapter-profile username-full --adapter-limit {adapter_limit} '
                        '--out {out}'
                    ),
                    required_inputs=("title", "adapter_limit", "out"),
                    badges=("case", "multi-seed", "dry-run adapters"),
                    note=(
                        "Заполняй только те поля, которые реально извлечены с изображения. "
                        "Нужен хотя бы один seed: username, email, phone, domain, URL или social."
                    ),
                ),
                ToolboxCommand(
                    "Проверить handle с изображения",
                    "Публичная проверка username по native rules с небольшим rate delay.",
                    (
                        "python -m osint_toolkit scan username {username} "
                        "--region {region} --live --limit 20 --http-retries 2 "
                        "--request-delay 0.2 --format markdown"
                    ),
                    required_inputs=("username", "region"),
                    badges=("username", "live"),
                ),
                ToolboxCommand(
                    "Проверить URL или домен с изображения",
                    "Bounded URL/domain crawl для публичных контактов, ссылок и social URLs.",
                    (
                        "python -m osint_toolkit scan url {url} --live "
                        "--crawl-pages 5 --crawl-depth 1 --format markdown"
                    ),
                    required_inputs=("url",),
                    badges=("url", "crawl"),
                ),
                ToolboxCommand(
                    "Проверить RU/UA social profile",
                    "Нормализует VK/OK/Yandex/Mail.ru public profile identifiers.",
                    "python -m osint_toolkit scan social {social} --live --format markdown",
                    required_inputs=("social",),
                    badges=("ru/ua", "social"),
                ),
            ),
            notes=(
                "Этот пульт не распознаёт лицо и не устанавливает личность по биометрии.",
                "Фото не загружается в HTML автоматически: локальные команды читают файл только после ручного запуска оператором.",
                "Reverse image search здесь нужен для источника, дублей и контекста изображения, а не для face-ID.",
            ),
        ),
        ToolboxSection(
            slug="person",
            title="Лицо / username / соцсети",
            description="Username expansion, public profile checks и social adapters.",
            commands=(
                ToolboxCommand(
                    "Person full search plan",
                    "Планирует person expansion и все username-compatible tools.",
                    'python -m osint_toolkit search person "{person}" --profile person-full --region {region} --plan-only --format markdown',
                    required_inputs=("person", "region"),
                    badges=("search", "person-full"),
                ),
                ToolboxCommand(
                    "Person ready execution",
                    "Запускает ready non-restricted adapters из person-full плана и пишет unified report/case.",
                    (
                        'python -m osint_toolkit search person "{person}" '
                        "--profile person-full --region {region} --execute-adapters "
                        "--adapter-limit {adapter_limit} --out {out} "
                        "--case-db {case_db} --case-id {case_id} "
                        '[[--scope-note "{scope_note}"]]'
                    ),
                    required_inputs=("person", "region", "adapter_limit", "out", "case_db", "case_id"),
                    badges=("execute", "ready-only"),
                    note="Missing/config/restricted tools остаются видимыми в Fan-out Plan, но не запускаются.",
                ),
                ToolboxCommand(
                    "Username full search plan",
                    "Планирует native username checks, global adapters и broad compatible routes.",
                    (
                        "python -m osint_toolkit search username {username} "
                        "--profile username-full --region {region} --plan-only --format markdown"
                    ),
                    required_inputs=("username", "region"),
                    badges=("search", "username-full"),
                ),
                ToolboxCommand(
                    "Username ready execution",
                    "Запускает ready non-restricted adapters из username-full плана и пишет unified report/case.",
                    (
                        "python -m osint_toolkit search username {username} "
                        "--profile username-full --region {region} --execute-adapters "
                        "--adapter-limit {adapter_limit} --out {out} "
                        "--case-db {case_db} --case-id {case_id} "
                        '[[--scope-note "{scope_note}"]]'
                    ),
                    required_inputs=("username", "region", "adapter_limit", "out", "case_db", "case_id"),
                    badges=("execute", "ready-only"),
                    note="Restricted adapters через search execution не запускаются.",
                ),
                ToolboxCommand(
                    "Имя -> username-кандидаты",
                    "Точечный native-only route для быстрого просмотра кандидатов.",
                    'python -m osint_toolkit scan person "{person}" --limit 24 --format markdown',
                    required_inputs=("person",),
                    badges=("person", "dry-run"),
                ),
                ToolboxCommand(
                    "Username full profile",
                    "Единый case report с broad username adapter profile.",
                    (
                        "python -m osint_toolkit investigate --username {username} "
                        "--region {region} --include-adapters "
                        "--adapter-profile username-full --adapter-limit {adapter_limit} "
                        "--out {out}"
                    ),
                    required_inputs=("username", "region", "adapter_limit", "out"),
                    badges=("username-full", "report"),
                ),
                ToolboxCommand(
                    "Instagram public profile",
                    "Проверяет public Instagram metadata без login/session flows.",
                    "python -m osint_toolkit scan instagram {instagram} --live --format json",
                    required_inputs=("instagram",),
                    badges=("instagram", "live"),
                ),
                ToolboxCommand(
                    "Telegram public seed",
                    "Планирует или проверяет public Telegram seed.",
                    "python -m osint_toolkit scan telegram {telegram} --live --format markdown",
                    required_inputs=("telegram",),
                    badges=("telegram", "live"),
                ),
            ),
        ),
        ToolboxSection(
            slug="email-phone",
            title="Email / телефон",
            description="Email domain/auth signals, safe breach/reputation adapters и PhoneInfoga route.",
            commands=(
                ToolboxCommand(
                    "Email full search plan",
                    "Планирует native email checks и все compatible safe email adapters.",
                    (
                        "python -m osint_toolkit search email {email} "
                        "--profile email-full --plan-only --format markdown"
                    ),
                    required_inputs=("email",),
                    badges=("search", "email-full"),
                ),
                ToolboxCommand(
                    "Email ready execution",
                    "Запускает ready non-restricted adapters из email-full плана и пишет unified report/case.",
                    (
                        "python -m osint_toolkit search email {email} "
                        "--profile email-full --execute-adapters "
                        "--adapter-limit {adapter_limit} --out {out} "
                        "--case-db {case_db} --case-id {case_id} "
                        '[[--scope-note "{scope_note}"]]'
                    ),
                    required_inputs=("email", "adapter_limit", "out", "case_db", "case_id"),
                    badges=("execute", "ready-only"),
                    note="holehe/email2phonenumber остаются restricted/excluded и не запускаются.",
                ),
                ToolboxCommand(
                    "Phone full search plan",
                    "Планирует native phone, PhoneInfoga, broad compatible tools и restricted exclusions.",
                    (
                        "python -m osint_toolkit search phone {phone} "
                        "--profile phone-full --plan-only --format markdown"
                    ),
                    required_inputs=("phone",),
                    badges=("search", "phone-full"),
                ),
                ToolboxCommand(
                    "Phone ready execution",
                    "Запускает ready non-restricted adapters из phone-full плана и пишет unified report/case.",
                    (
                        "python -m osint_toolkit search phone {phone} "
                        "--profile phone-full --execute-adapters "
                        "--adapter-limit {adapter_limit} --out {out} "
                        "--case-db {case_db} --case-id {case_id} "
                        '[[--scope-note "{scope_note}"]]'
                    ),
                    required_inputs=("phone", "adapter_limit", "out", "case_db", "case_id"),
                    badges=("execute", "ready-only"),
                    note="Phone-to-account restricted checks не запускаются через search execution.",
                ),
            ),
        ),
        ToolboxSection(
            slug="domain-url",
            title="Домен / URL / web recon",
            description="DNS, HTTP metadata, bounded crawler, passive recon adapters и broad recon suites.",
            commands=(
                ToolboxCommand(
                    "Passive domain search plan",
                    "Планирует native domain recon и passive upstream adapters.",
                    (
                        "python -m osint_toolkit search domain {domain} "
                        "--profile passive-recon --plan-only --format markdown"
                    ),
                    required_inputs=("domain",),
                    badges=("search", "passive-recon"),
                ),
                ToolboxCommand(
                    "Domain ready execution",
                    "Запускает ready non-restricted adapters из passive-recon плана и пишет unified report/case.",
                    (
                        "python -m osint_toolkit search domain {domain} "
                        "--profile passive-recon --execute-adapters "
                        "--adapter-limit {adapter_limit} --out {out} "
                        "--case-db {case_db} --case-id {case_id} "
                        '[[--scope-note "{scope_note}"]]'
                    ),
                    required_inputs=("domain", "adapter_limit", "out", "case_db", "case_id"),
                    badges=("execute", "ready-only"),
                ),
                ToolboxCommand(
                    "Web full URL search plan",
                    "Планирует native URL recon, archive route и broad compatible adapters.",
                    (
                        "python -m osint_toolkit search url {url} "
                        "--profile web-full --plan-only --format markdown"
                    ),
                    required_inputs=("url",),
                    badges=("search", "web-full"),
                ),
                ToolboxCommand(
                    "URL ready execution",
                    "Запускает ready non-restricted adapters из web-full плана и пишет unified report/case.",
                    (
                        "python -m osint_toolkit search url {url} "
                        "--profile web-full --execute-adapters "
                        "--adapter-limit {adapter_limit} --out {out} "
                        "--case-db {case_db} --case-id {case_id} "
                        '[[--scope-note "{scope_note}"]]'
                    ),
                    required_inputs=("url", "adapter_limit", "out", "case_db", "case_id"),
                    badges=("execute", "ready-only"),
                ),
                ToolboxCommand(
                    "Domain recon adapters",
                    "Subfinder, httpx, passive Amass, theHarvester, BBOT, SpiderFoot.",
                    (
                        "python -m osint_toolkit investigate --domain {domain} "
                        "--include-adapters --adapter-profile domain-recon "
                        "--adapter-limit {adapter_limit} --out {out}"
                    ),
                    required_inputs=("domain", "adapter_limit", "out"),
                    badges=("domain-recon", "passive"),
                ),
                ToolboxCommand(
                    "Broad recon suite",
                    "BBOT, SpiderFoot, Argus в dry-run маршруте до явного запуска.",
                    (
                        "python -m osint_toolkit investigate --domain {domain} "
                        "--include-adapters --adapter-profile broad-recon "
                        "--adapter-limit {adapter_limit} --out {out}"
                    ),
                    required_inputs=("domain", "adapter_limit", "out"),
                    badges=("broad-recon", "scope review"),
                ),
                ToolboxCommand(
                    "BBOT passive web",
                    "BBOT subdomain-enum + web-basic, но только passive modules и без active/deadly/portscan/screenshots.",
                    (
                        "python -m osint_toolkit investigate --domain {domain} "
                        "--include-adapters --adapter-profile bbot-passive-web "
                        "--adapter-limit {adapter_limit} --out {out}"
                    ),
                    required_inputs=("domain", "adapter_limit", "out"),
                    badges=("bbot-passive-web", "passive"),
                ),
            ),
        ),
        ToolboxSection(
            slug="ru-ua",
            title="РФ / Украина",
            description="RU/UA catalog filters, username adapters and public social routes.",
            commands=(
                ToolboxCommand(
                    "RU/UA catalog",
                    "Показывает direct RU/UA entries из curated top-100 snapshot.",
                    (
                        "python -m osint_toolkit catalog --kind ru-ua "
                        "--level direct_ru_ua --format markdown --limit 30"
                    ),
                    badges=("catalog", "ru/ua"),
                ),
                ToolboxCommand(
                    "RU/UA username search plan",
                    "Планирует RU/UA-aware username/social routes с region hints.",
                    (
                        "python -m osint_toolkit search username {username} "
                        "--profile ru-ua-full --region {region} --plan-only --format markdown"
                    ),
                    required_inputs=("username", "region"),
                    badges=("search", "ru-ua-full"),
                ),
                ToolboxCommand(
                    "RU/UA username ready execution",
                    "Запускает ready non-restricted RU/UA-aware adapters и пишет unified report/case.",
                    (
                        "python -m osint_toolkit search username {username} "
                        "--profile ru-ua-full --region {region} --execute-adapters "
                        "--adapter-limit {adapter_limit} --out {out} "
                        "--case-db {case_db} --case-id {case_id} "
                        '[[--scope-note "{scope_note}"]]'
                    ),
                    required_inputs=("username", "region", "adapter_limit", "out", "case_db", "case_id"),
                    badges=("execute", "ru-ua-full"),
                ),
                ToolboxCommand(
                    "RU/UA source scan",
                    "Native route по RU/UA sources.",
                    "python -m osint_toolkit scan ru-ua {ruua} --region {region} --format markdown",
                    required_inputs=("ruua", "region"),
                    badges=("sources", "ru/ua"),
                ),
                ToolboxCommand(
                    "RU social public metadata",
                    "Планирует social public metadata и compatible username adapters.",
                    "python -m osint_toolkit search social {social} --profile social-full --region {region} --plan-only --format markdown",
                    required_inputs=("social", "region"),
                    badges=("search", "social-full"),
                ),
                ToolboxCommand(
                    "RU social ready execution",
                    "Запускает ready non-restricted social-full adapters и пишет unified report/case.",
                    (
                        "python -m osint_toolkit search social {social} "
                        "--profile social-full --region {region} --execute-adapters "
                        "--adapter-limit {adapter_limit} --out {out} "
                        "--case-db {case_db} --case-id {case_id} "
                        '[[--scope-note "{scope_note}"]]'
                    ),
                    required_inputs=("social", "region", "adapter_limit", "out", "case_db", "case_id"),
                    badges=("execute", "social-full"),
                ),
            ),
        ),
        ToolboxSection(
            slug="cases",
            title="Кейсы / граф / индекс",
            description="Сохранение расследований, просмотр графа и cross-case поиск сущностей.",
            commands=(
                ToolboxCommand(
                    "Сохранить mixed case",
                    "Создаёт SQLite case из заполненных seed-полей.",
                    (
                        'python -m osint_toolkit investigate --title "{title}" '
                        '[[--username {username}]] [[--email {email}]] '
                        '[[--phone {phone}]] [[--domain {domain}]] [[--url {url}]] '
                        '[[--telegram {telegram}]] [[--instagram {instagram}]] '
                        '[[--social {social}]] [[--ru-ua {ruua}]] [[--region {region}]] '
                        "--case-db {case_db} --case-id {case_id} "
                        '[[--scope-note "{scope_note}"]] '
                        "--include-adapters --adapter-profile username-full "
                        "--adapter-limit {adapter_limit} --out {out}"
                    ),
                    required_inputs=("title", "case_db", "case_id", "adapter_limit", "out"),
                    badges=("case-db", "report"),
                ),
                ToolboxCommand(
                    "Список кейсов",
                    "Показывает сохранённые кейсы с optional workflow/profile/scope filters.",
                    (
                        "python -m osint_toolkit cases --case-db {case_db} "
                        '[[--workflow {workflow_filter}]] [[--profile {profile_filter}]] '
                        '[[--scope-query "{scope_query}"]] --format markdown'
                    ),
                    required_inputs=("case_db",),
                    badges=("sqlite", "list"),
                ),
                ToolboxCommand(
                    "Обновить кейс",
                    "Меняет title и/или scope_note без изменения findings/entities.",
                    (
                        "python -m osint_toolkit case-update --case-db {case_db} {case_id} "
                        '[[--title "{title}"]] [[--scope-note "{scope_note}"]] --format markdown'
                    ),
                    required_inputs=("case_db", "case_id"),
                    badges=("case", "update"),
                ),
                ToolboxCommand(
                    "Удалить кейс",
                    "Удаляет один saved case после явного подтверждения.",
                    "python -m osint_toolkit case-delete --case-db {case_db} {case_id} --yes --format table",
                    required_inputs=("case_db", "case_id"),
                    badges=("case", "delete"),
                    note="Перед запуском CLI перепроверь Case ID: операция удаляет targets/entities/findings/edges через SQLite cascade.",
                ),
                ToolboxCommand(
                    "Открыть кейс",
                    "Показывает targets, entities, edges и findings одного кейса.",
                    "python -m osint_toolkit case-show --case-db {case_db} {case_id} --format markdown",
                    required_inputs=("case_db", "case_id"),
                    badges=("case", "detail"),
                ),
                ToolboxCommand(
                    "Граф кейса",
                    "Счётчики связей, типов сущностей и top connected nodes.",
                    (
                        "python -m osint_toolkit case-graph --case-db {case_db} {case_id} "
                        "[[--entity-kind {entity_kind} --entity-value {entity_value}]] --format markdown"
                    ),
                    required_inputs=("case_db", "case_id"),
                    badges=("graph", "summary"),
                ),
                ToolboxCommand(
                    "Cross-case индекс",
                    "Ищет повторяющиеся сущности между сохранёнными расследованиями.",
                    (
                        "python -m osint_toolkit case-index --case-db {case_db} "
                        "[[--kind {entity_kind} --value {entity_value}]] --min-cases 2 --format markdown"
                    ),
                    required_inputs=("case_db",),
                    badges=("index", "entities"),
                ),
                ToolboxCommand(
                    "Cross-case path",
                    "Ищет weighted shortest path между двумя сущностями по сохранённым case graphs.",
                    (
                        "python -m osint_toolkit case-path --case-db {case_db} "
                        "--from-kind {entity_kind} --from-value {entity_value} "
                        "--to-kind {target_entity_kind} --to-value {target_entity_value} "
                        "--format markdown"
                    ),
                    required_inputs=("case_db", "entity_kind", "entity_value", "target_entity_kind", "target_entity_value"),
                    badges=("path", "weighted"),
                ),
                ToolboxCommand(
                    "Cross-case network",
                    "Показывает bounded общий граф сущностей и связей по сохранённым кейсам.",
                    (
                        "python -m osint_toolkit case-network --case-db {case_db} "
                        "[[--kind {entity_kind}]] [[--relation {relation}]] --format markdown"
                    ),
                    required_inputs=("case_db",),
                    badges=("network", "bounded"),
                ),
            ),
        ),
        ToolboxSection(
            slug="catalog-adapters",
            title="Каталог / adapters",
            description="Просмотр top-100 catalog, adapter readiness, setup и reusable profiles.",
            commands=(
                ToolboxCommand(
                    "People OSINT catalog",
                    "Проекты из top-100, связанные с people/person OSINT.",
                    "python -m osint_toolkit catalog --kind people --direct-only --format markdown --limit 30",
                    badges=("catalog", "people"),
                ),
                ToolboxCommand(
                    "Adapter profiles",
                    "Показывает готовые группы adapters.",
                    "python -m osint_toolkit adapter-profiles --format markdown",
                    badges=("profiles", "adapters"),
                ),
                ToolboxCommand(
                    "Search profiles from file",
                    "Показывает built-in и custom unified search profiles из JSON-файла.",
                    "python -m osint_toolkit profiles list --profile-file {profile_file} --format markdown",
                    required_inputs=("profile_file",),
                    badges=("profiles", "custom"),
                ),
                ToolboxCommand(
                    "Adapter doctor",
                    "Проверяет, какие upstream CLI реально доступны локально.",
                    "python -m osint_toolkit doctor --format markdown",
                    badges=("readiness", "local"),
                ),
                ToolboxCommand(
                    "Profile tools doctor",
                    "Проверяет adapters и local tools для выбранного unified profile.",
                    "python -m osint_toolkit tools doctor --profile all-safe --format markdown",
                    badges=("tools", "doctor", "profile"),
                ),
                ToolboxCommand(
                    "Profile install plan",
                    "Показывает install/config actions для missing tools профиля.",
                    "python -m osint_toolkit tools install-plan --profile all-safe --format markdown",
                    badges=("tools", "install-plan"),
                    note="Команда ничего не устанавливает автоматически.",
                ),
                ToolboxCommand(
                    "Profile install dry-run",
                    "Показывает, какие allowlisted install commands можно выполнить для missing tools.",
                    "python -m osint_toolkit tools install all-safe --format markdown",
                    badges=("tools", "install"),
                    note="Для реального запуска добавь --execute; runtime_error/config/manual steps не запускаются автоматически.",
                ),
                ToolboxCommand(
                    "Search install missing",
                    "Берёт профиль из seed/search routing и показывает install dry-run для missing tools.",
                    "python -m osint_toolkit search phone {phone} --profile auto --install-missing --format markdown",
                    required_inputs=("phone",),
                    badges=("search", "install"),
                    note="Для реального запуска добавь --execute-install; режим несовместим с --execute-adapters.",
                ),
                ToolboxCommand(
                    "Profile env names",
                    "Показывает required/optional env variable names без значений.",
                    "python -m osint_toolkit tools env --profile all-safe --format markdown",
                    badges=("tools", "env"),
                ),
                ToolboxCommand(
                    "Adapter setup plan",
                    "Показывает install/config hints для adapters.",
                    "python -m osint_toolkit adapter-setup --format markdown",
                    badges=("setup", "docs"),
                ),
            ),
        ),
    )
    return sections + (_adapter_profile_section(),)


def render_toolbox_html(*, backend_url: str = "", backend_auth: str = "") -> str:
    sections = toolbox_sections()
    nav = "\n".join(
        f'<a href="#{escape(section.slug)}">{escape(section.title)}</a>' for section in sections
    )
    inputs = "\n".join(_render_input(field) for field in TOOLBOX_INPUTS)
    backend_kind_options = _render_options(("auto", *TARGET_KINDS), selected="auto")
    backend_profile_options = _render_options(
        ("auto", *(profile.name for profile in list_search_profiles())),
        selected="auto",
    )
    body_sections = "\n".join(_render_section(section) for section in sections)
    input_labels = ", ".join(
        f'"{escape(name)}": "{escape(label)}"' for name, label in INPUT_LABELS.items()
    )
    notice = (
        "Пульт подключён к локальному backend и может запускать только structured unified search jobs. "
        "Фото не загружается в HTML автоматически; face-ID и идентификация личности по лицу не выполняются."
        if backend_url and backend_auth
        else (
            "Пульт работает в static mode: он собирает команды, но не запускает процессы из браузера. "
            "Для запуска из окна используй `python -m osint_toolkit toolbox --serve --open`. "
            "Фото не загружается в HTML автоматически; face-ID и идентификация личности по лицу не выполняются."
        )
    )
    backend_url_js = _js_string(backend_url)
    backend_auth_js = _js_string(backend_auth)
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OSINT Toolkit Control Window</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f8fb;
      --panel: #ffffff;
      --ink: #151923;
      --muted: #5a6575;
      --line: #d7dde7;
      --accent: #0b6f85;
      --accent-ink: #ffffff;
      --warn-bg: #fff6dc;
      --warn-line: #e0b84c;
      --code-bg: #10151f;
      --code-ink: #ecf2ff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--ink);
      line-height: 1.45;
    }}
    header {{
      padding: 24px clamp(16px, 3vw, 40px) 16px;
      background: #ffffff;
      border-bottom: 1px solid var(--line);
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: clamp(28px, 4vw, 44px);
      letter-spacing: 0;
    }}
    h2 {{
      margin: 0 0 8px;
      font-size: 24px;
      letter-spacing: 0;
    }}
    h3 {{
      margin: 0 0 8px;
      font-size: 18px;
      letter-spacing: 0;
    }}
    p {{ margin: 0; color: var(--muted); }}
    nav {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      padding: 12px clamp(16px, 3vw, 40px);
      background: #edf2f7;
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 3;
    }}
    nav a {{
      color: #12324a;
      text-decoration: none;
      font-size: 14px;
      padding: 6px 9px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #ffffff;
    }}
    main {{ padding: 18px clamp(16px, 3vw, 40px) 40px; }}
    .notice {{
      border: 1px solid var(--warn-line);
      background: var(--warn-bg);
      padding: 12px 14px;
      border-radius: 6px;
      margin-bottom: 16px;
      color: #5d4613;
    }}
    .layout {{
      display: grid;
      grid-template-columns: minmax(260px, 360px) minmax(0, 1fr);
      gap: 18px;
      align-items: start;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }}
    .seed-panel {{
      position: sticky;
      top: 70px;
      max-height: calc(100vh - 90px);
      overflow: auto;
    }}
    .fields {{
      display: grid;
      gap: 10px;
      margin-top: 14px;
    }}
    label {{
      display: grid;
      gap: 4px;
      font-size: 13px;
      color: #253041;
      font-weight: 700;
    }}
    input {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 10px;
      font: inherit;
      color: var(--ink);
      background: #ffffff;
    }}
    .command-output {{
      width: 100%;
      min-height: 120px;
      margin-top: 12px;
      border: 1px solid #273348;
      border-radius: 6px;
      padding: 12px;
      color: var(--code-ink);
      background: var(--code-bg);
      font: 13px Consolas, "Courier New", monospace;
      resize: vertical;
    }}
    .copy-row {{
      display: flex;
      gap: 8px;
      margin-top: 8px;
      flex-wrap: wrap;
    }}
    button {{
      border: 1px solid #09596b;
      background: var(--accent);
      color: var(--accent-ink);
      border-radius: 6px;
      padding: 8px 10px;
      font-weight: 700;
      cursor: pointer;
    }}
    button:disabled {{
      opacity: 0.55;
      cursor: not-allowed;
    }}
    button.secondary {{
      border-color: var(--line);
      background: #ffffff;
      color: #1d2a3a;
    }}
    select {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 10px;
      font: inherit;
      color: var(--ink);
      background: #ffffff;
    }}
    .backend-panel {{
      margin-top: 14px;
    }}
    .backend-row {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }}
    .backend-check {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 10px;
      font-size: 13px;
      color: #253041;
      font-weight: 700;
    }}
    .backend-check input {{
      width: auto;
    }}
    .backend-log {{
      width: 100%;
      min-height: 160px;
      margin-top: 10px;
      border: 1px solid #273348;
      border-radius: 6px;
      padding: 10px;
      color: var(--code-ink);
      background: var(--code-bg);
      font: 12px Consolas, "Courier New", monospace;
      white-space: pre-wrap;
      overflow: auto;
    }}
    .backend-jobs {{
      margin-top: 8px;
      display: grid;
      gap: 6px;
      font-size: 13px;
    }}
    .backend-job {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
      background: #f8fafc;
    }}
    .case-panel {{
      margin-top: 14px;
    }}
    .case-list {{
      margin-top: 8px;
      display: grid;
      gap: 6px;
      font-size: 13px;
    }}
    .case-item {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
      background: #f8fafc;
    }}
    .case-graph-summary {{
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      margin-top: 10px;
      font-size: 12px;
    }}
    .graph-pill {{
      border: 1px solid #c8d2df;
      border-radius: 999px;
      padding: 3px 7px;
      background: #f8fafc;
      color: #263448;
    }}
    .case-graph-visual {{
      position: relative;
      min-height: 280px;
      margin-top: 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfdff;
      overflow: hidden;
    }}
    .case-graph-visual svg {{
      display: block;
      width: 100%;
      height: 280px;
    }}
    .case-graph-empty {{
      position: absolute;
      inset: 0;
      display: grid;
      place-items: center;
      padding: 18px;
      text-align: center;
      color: var(--muted);
      font-size: 13px;
    }}
    .case-graph-legend {{
      margin-top: 8px;
      display: grid;
      gap: 4px;
      color: var(--muted);
      font-size: 12px;
    }}
    .graph-edge {{
      stroke: #9aa8b9;
      stroke-width: 1.4;
      opacity: 0.72;
    }}
    .graph-node circle {{
      stroke: #ffffff;
      stroke-width: 2;
      filter: drop-shadow(0 1px 2px rgba(13, 28, 45, 0.24));
    }}
    .graph-node text {{
      font-family: Arial, Helvetica, sans-serif;
      font-size: 10px;
      fill: #162033;
      text-anchor: middle;
      pointer-events: none;
    }}
    .graph-node[data-graph-kind] {{
      cursor: pointer;
    }}
    .graph-node[data-graph-kind]:focus circle,
    .graph-node[data-graph-kind]:hover circle {{
      stroke: #111827;
      stroke-width: 3;
    }}
    .hidden {{ display: none; }}
    section {{
      margin: 0 0 18px;
      scroll-margin-top: 72px;
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 12px;
      margin-top: 12px;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      min-height: 220px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 12px;
    }}
    .badges {{
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      margin: 10px 0 0;
    }}
    .badge {{
      border: 1px solid #b8c4d4;
      border-radius: 999px;
      padding: 3px 7px;
      font-size: 12px;
      color: #233044;
      background: #f5f7fa;
    }}
    .code {{
      white-space: pre-wrap;
      word-break: break-word;
      background: #f0f3f8;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
      color: #1c2635;
      font: 12px Consolas, "Courier New", monospace;
    }}
    .notes {{
      margin-top: 10px;
      padding-left: 18px;
      color: var(--muted);
      font-size: 14px;
    }}
    .notes li {{ margin: 3px 0; }}
    @media (max-width: 900px) {{
      .layout {{ grid-template-columns: 1fr; }}
      .seed-panel {{ position: static; max-height: none; }}
      nav {{ position: static; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>OSINT Toolkit Control Window</h1>
    <p>Одно локальное окно для выбора направления, заполнения seed-полей и копирования команд текущего OSINT Toolkit.</p>
  </header>
  <nav>{nav}</nav>
  <main>
    <div class="notice">
      {escape(notice)}
      Для фото используй только небиометрические public clues: текст, ссылки, username, домены, телефоны, email, логотипы и контекст.
    </div>
    <div class="layout">
      <aside class="panel seed-panel">
        <h2>Seed-поля</h2>
        <p>Заполни только известные значения. Кнопки справа соберут команду под выбранное направление.</p>
        <div class="fields">{inputs}</div>
        <textarea id="commandOutput" class="command-output" spellcheck="false" aria-label="Generated command"></textarea>
        <div class="copy-row">
          <button type="button" id="copyCommand">Копировать</button>
          <button type="button" class="secondary" id="clearCommand">Очистить</button>
        </div>
        <div class="panel backend-panel">
          <h2>Unified Search Runner</h2>
          <p id="backendStatus">Backend: static mode</p>
          <div class="fields">
            <label>Тип seed
              <select id="backendTargetKind">{backend_kind_options}</select>
            </label>
            <label>Seed value
              <input id="backendTargetValue" placeholder="phone/email/username/person/domain/url/image/social">
            </label>
            <div class="backend-row">
              <label>Profile
                <select id="backendProfile">{backend_profile_options}</select>
              </label>
              <label>Region
                <select id="backendRegion">
                  <option value="all">all</option>
                  <option value="ru">ru</option>
                  <option value="ua">ua</option>
                </select>
              </label>
            </div>
            <label class="backend-check">
              <input type="checkbox" id="backendExecute" checked>
              Execute ready tools
            </label>
          </div>
          <div class="copy-row">
            <button type="button" id="runUnifiedSearch">Запустить search</button>
            <button type="button" class="secondary" id="listProfiles">Профили</button>
            <button type="button" class="secondary" id="toolsDoctor">Tools</button>
            <button type="button" class="secondary" id="toolsInstall">Install</button>
            <button type="button" class="secondary" id="toolsInstallRun">Run install</button>
            <button type="button" class="secondary" id="toolsEnv">Env</button>
            <button type="button" class="secondary" id="saveProfile">Save profile</button>
            <button type="button" class="secondary" id="deleteProfile">Delete profile</button>
            <button type="button" class="secondary" id="refreshJobs">Обновить jobs</button>
          </div>
          <div id="backendJobs" class="backend-jobs"></div>
          <pre id="backendLog" class="backend-log"></pre>
        </div>
        <div class="panel case-panel">
          <h2>Case Browser</h2>
          <p>Читает saved cases из SQLite через локальный backend: список, detail, graph, update/delete и cross-case index.</p>
          <div class="copy-row">
            <button type="button" id="loadCases">Cases</button>
            <button type="button" class="secondary" id="showCase">Case detail</button>
            <button type="button" class="secondary" id="updateCase">Update</button>
            <button type="button" class="secondary" id="deleteCase">Delete</button>
            <button type="button" class="secondary" id="showCaseSources">Sources</button>
            <button type="button" class="secondary" id="showCaseGraph">Graph</button>
            <button type="button" class="secondary" id="showCaseIndex">Index</button>
            <button type="button" class="secondary" id="showCasePath">Path</button>
            <button type="button" class="secondary" id="showCaseNetwork">Network</button>
            <button type="button" class="secondary" id="clearGraphFilters">Clear filters</button>
          </div>
          <div id="caseList" class="case-list"></div>
          <div id="caseGraphSummary" class="case-graph-summary"></div>
          <div id="caseGraphVisual" class="case-graph-visual">
            <svg id="caseGraphSvg" viewBox="0 0 760 440" role="img" aria-label="Case graph visualization"></svg>
            <div id="caseGraphEmpty" class="case-graph-empty">Открой кейс или граф, чтобы увидеть связи entities.</div>
          </div>
          <div id="caseGraphLegend" class="case-graph-legend"></div>
          <pre id="caseLog" class="backend-log"></pre>
        </div>
      </aside>
      <div>{body_sections}</div>
    </div>
  </main>
  <script>
    const inputLabels = {{{input_labels}}};
    const inputNames = Object.keys(inputLabels);
    const backendConfig = {{
      url: {backend_url_js},
      auth: {backend_auth_js}
    }};
    let currentCasePayload = null;
    let currentGraphAnalysis = null;
    let currentGraphMode = "case";

    function readValue(name) {{
      const element = document.querySelector(`[data-field="${{name}}"]`);
      return element ? element.value.trim() : "";
    }}

    function fillFields(template) {{
      let command = template;
      for (const name of inputNames) {{
        command = command.replaceAll(`{{${{name}}}}`, readValue(name));
      }}
      return command;
    }}

    function commandWithFields(template) {{
      let command = template.replace(/\\[\\[([^\\]]+)\\]\\]/g, (match, inner) => {{
        const placeholders = [...inner.matchAll(/\\{{([a-z_]+)\\}}/g)].map((item) => item[1]);
        return placeholders.some((name) => !readValue(name)) ? "" : fillFields(inner);
      }});
      command = fillFields(command);
      return command.replace(/\\s+/g, " ").trim();
    }}

    function missingInputs(required) {{
      return required.filter((name) => !readValue(name)).map((name) => inputLabels[name] || name);
    }}

    document.addEventListener("click", (event) => {{
      const button = event.target.closest("[data-command-template]");
      if (!button) return;
      const template = button.getAttribute("data-command-template") || "";
      const required = (button.getAttribute("data-required") || "").split(",").filter(Boolean);
      const missing = missingInputs(required);
      const command = commandWithFields(template);
      const output = document.getElementById("commandOutput");
      output.value = missing.length
        ? `# Заполни поля: ${{missing.join(", ")}}\\n${{command}}`
        : command;
      output.focus();
      output.select();
    }});

    document.getElementById("copyCommand").addEventListener("click", async () => {{
      const output = document.getElementById("commandOutput");
      output.select();
      if (navigator.clipboard) {{
        await navigator.clipboard.writeText(output.value);
      }}
    }});

    document.getElementById("clearCommand").addEventListener("click", () => {{
      document.getElementById("commandOutput").value = "";
    }});

    function backendAvailable() {{
      return Boolean(backendConfig.url && backendConfig.auth);
    }}

    function backendHeaders() {{
      return {{
        "Content-Type": "application/json",
        "X-OSINT-Token": backendConfig.auth
      }};
    }}

    function setBackendLog(value) {{
      document.getElementById("backendLog").textContent = value || "";
    }}

    function setCaseLog(value) {{
      document.getElementById("caseLog").textContent = value || "";
    }}

    function caseDbValue() {{
      return readValue("case_db") || "cases.sqlite";
    }}

    function setFieldValue(name, value) {{
      const element = document.querySelector(`[data-field="${{name}}"]`);
      if (element) element.value = value || "";
    }}

    function backendPayload() {{
      const execute = document.getElementById("backendExecute").checked;
      return {{
        target_kind: document.getElementById("backendTargetKind").value,
        target_value: document.getElementById("backendTargetValue").value.trim(),
        profile: readValue("custom_profile") || document.getElementById("backendProfile").value,
        profile_file: readValue("profile_file"),
        region: document.getElementById("backendRegion").value,
        execute_adapters: execute,
        format: execute ? "markdown" : "markdown",
        adapter_limit: Number(readValue("adapter_limit") || "20"),
        out: readValue("out"),
        case_db: readValue("case_db"),
        case_id: readValue("case_id"),
        scope_note: readValue("scope_note")
      }};
    }}

    function renderJobs(jobs) {{
      const container = document.getElementById("backendJobs");
      container.innerHTML = "";
      for (const job of jobs.slice().reverse().slice(0, 8)) {{
        const item = document.createElement("div");
        item.className = "backend-job";
        const reportLink = job.report_available
          ? ` <button type="button" class="secondary" data-report-job="${{job.id}}">Report</button>`
          : "";
        item.innerHTML = `<strong>${{job.status}}</strong> ${{job.id}}<br>${{job.command_preview || ""}}${{reportLink}}`;
        container.appendChild(item);
      }}
    }}

    async function refreshJobs() {{
      if (!backendAvailable()) return;
      const response = await fetch(`${{backendConfig.url}}/api/jobs`, {{
        headers: {{"X-OSINT-Token": backendConfig.auth}}
      }});
      if (!response.ok) throw new Error(await response.text());
      const jobs = await response.json();
      renderJobs(jobs.jobs || []);
    }}

    async function readJob(jobId) {{
      const response = await fetch(`${{backendConfig.url}}/api/jobs/${{jobId}}`, {{
        headers: {{"X-OSINT-Token": backendConfig.auth}}
      }});
      if (!response.ok) throw new Error(await response.text());
      return response.json();
    }}

    async function pollJob(jobId) {{
      const job = await readJob(jobId);
      setBackendLog([job.status, job.stdout || "", job.stderr || "", job.error || ""].filter(Boolean).join("\\n\\n"));
      await refreshJobs();
      if (["queued", "running"].includes(job.status)) {{
        setTimeout(() => pollJob(jobId).catch((error) => setBackendLog(String(error))), 1000);
      }}
    }}

    async function runUnifiedSearch() {{
      if (!backendAvailable()) {{
        setBackendLog("Backend недоступен. Запусти: python -m osint_toolkit toolbox --serve --open");
        return;
      }}
      const payload = backendPayload();
      if (!payload.target_value) {{
        setBackendLog("Укажи seed value.");
        return;
      }}
      const response = await fetch(`${{backendConfig.url}}/api/search`, {{
        method: "POST",
        headers: backendHeaders(),
        body: JSON.stringify(payload)
      }});
      if (!response.ok) {{
        setBackendLog(await response.text());
        return;
      }}
      const data = await response.json();
      setBackendLog(`queued ${{data.job.id}}\\n${{data.job.command_preview}}`);
      await pollJob(data.job.id);
    }}

    async function readReport(jobId) {{
      const response = await fetch(`${{backendConfig.url}}/api/jobs/${{jobId}}/report`, {{
        headers: {{"X-OSINT-Token": backendConfig.auth}}
      }});
      setBackendLog(await response.text());
    }}

    async function loadBackendProfiles() {{
      const params = {{}};
      const profileFile = readValue("profile_file");
      if (profileFile) params.profile_file = profileFile;
      const data = await fetchCaseJson("/api/profiles", params);
      setBackendLog(JSON.stringify(data, null, 2));
    }}

    async function loadProfileTools(view) {{
      const params = {{
        profile: readValue("custom_profile") || document.getElementById("backendProfile").value,
        view,
        format: "markdown"
      }};
      const profileFile = readValue("profile_file");
      if (profileFile) params.profile_file = profileFile;
      const data = await fetchCaseJson("/api/tools", params);
      setBackendLog(data.content || JSON.stringify(data, null, 2));
    }}

    async function runProfileToolsInstall(execute) {{
      if (execute && !window.confirm("Run allowlisted install commands for missing tools in this profile?")) {{
        return;
      }}
      const payload = {{
        profile: readValue("custom_profile") || document.getElementById("backendProfile").value,
        profile_file: readValue("profile_file"),
        execute,
        format: "markdown"
      }};
      const data = await postBackendJson("/api/tools/install", payload);
      setBackendLog(data.content || JSON.stringify(data, null, 2));
    }}

    function csvList(name) {{
      return readValue(name)
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
    }}

    function profileEditorPayload() {{
      const profileFile = readValue("profile_file");
      const name = readValue("custom_profile");
      const targetKinds = csvList("profile_target_kinds");
      if (!profileFile) throw new Error("Укажи Profile file.");
      if (!name) throw new Error("Укажи Custom profile.");
      if (!targetKinds.length) throw new Error("Укажи Profile targets.");
      const profile = {{
        name,
        target_kinds: targetKinds
      }};
      const title = readValue("profile_title");
      const description = readValue("profile_description");
      const note = readValue("profile_note");
      const nativeKinds = csvList("profile_native_kinds");
      const derivedTargets = csvList("profile_derived_targets");
      const adapterProfiles = csvList("profile_adapter_profiles");
      const repositories = csvList("profile_repositories");
      const localTools = csvList("profile_local_tools");
      const excluded = csvList("profile_excluded");
      if (title) profile.title = title;
      if (description) profile.description = description;
      if (nativeKinds.length) profile.native_kinds = nativeKinds;
      if (derivedTargets.length) profile.derived_target_kinds = derivedTargets;
      if (adapterProfiles.length) profile.adapter_profiles = adapterProfiles;
      if (repositories.length) profile.adapter_repositories = repositories;
      if (localTools.length) profile.local_tools = localTools;
      if (excluded.length) profile.excluded_repositories = excluded;
      if (note) profile.note = note;
      return {{profile_file: profileFile, profile}};
    }}

    async function saveSearchProfile() {{
      const data = await postBackendJson("/api/profiles/save", profileEditorPayload());
      setBackendLog(JSON.stringify(data, null, 2));
    }}

    async function deleteSearchProfile() {{
      const profileFile = readValue("profile_file");
      const profile = readValue("custom_profile");
      if (!profileFile) throw new Error("Укажи Profile file.");
      if (!profile) throw new Error("Укажи Custom profile.");
      const data = await postBackendJson("/api/profiles/delete", {{profile_file: profileFile, profile}});
      setBackendLog(JSON.stringify(data, null, 2));
    }}

    function caseUrl(path, params) {{
      const query = new URLSearchParams(params || {{}});
      return `${{backendConfig.url}}${{path}}?${{query.toString()}}`;
    }}

    async function fetchCaseJson(path, params) {{
      if (!backendAvailable()) {{
        throw new Error("Backend недоступен. Запусти: python -m osint_toolkit toolbox --serve --open");
      }}
      const response = await fetch(caseUrl(path, params), {{
        headers: {{"X-OSINT-Token": backendConfig.auth}}
      }});
      const text = await response.text();
      if (!response.ok) throw new Error(text);
      return JSON.parse(text);
    }}

    async function postBackendJson(path, payload) {{
      if (!backendAvailable()) {{
        throw new Error("Backend недоступен. Запусти: python -m osint_toolkit toolbox --serve --open");
      }}
      const response = await fetch(`${{backendConfig.url}}${{path}}`, {{
        method: "POST",
        headers: backendHeaders(),
        body: JSON.stringify(payload || {{}})
      }});
      const text = await response.text();
      if (!response.ok) throw new Error(text);
      return JSON.parse(text);
    }}

    function renderCaseList(cases) {{
      const container = document.getElementById("caseList");
      container.innerHTML = "";
      for (const item of cases) {{
        const row = document.createElement("div");
        row.className = "case-item";
        const title = document.createElement("strong");
        title.textContent = item.case_id || "";
        const body = document.createElement("div");
        body.textContent = `${{item.title || ""}} · ${{item.saved_at || ""}} · targets ${{item.target_count}} · entities ${{item.entity_count}}`;
        const open = document.createElement("button");
        open.type = "button";
        open.className = "secondary";
        open.dataset.openCase = item.case_id || "";
        open.textContent = "Open";
        row.appendChild(title);
        row.appendChild(document.createElement("br"));
        row.appendChild(body);
        row.appendChild(open);
        container.appendChild(row);
      }}
    }}

    function graphKey(kind, value) {{
      return String(kind || "") + "\\u001f" + String(value || "").toLowerCase();
    }}

    function addGraphNode(nodeMap, kind, value) {{
      const normalizedKind = String(kind || "").trim();
      const normalizedValue = String(value || "").trim();
      if (!normalizedKind || !normalizedValue) return;
      const key = graphKey(normalizedKind, normalizedValue);
      if (!nodeMap.has(key)) {{
        nodeMap.set(key, {{key, kind: normalizedKind, value: normalizedValue, degree: 0, x: 0, y: 0}});
      }}
    }}

    function shortText(value, limit) {{
      const text = String(value || "");
      return text.length > limit ? text.slice(0, Math.max(0, limit - 1)) + "..." : text;
    }}

    function graphColor(kind) {{
      const colors = {{
        email: "#1f77b4",
        domain: "#2ca02c",
        url: "#9467bd",
        username: "#ff7f0e",
        person: "#8c564b",
        phone: "#d62728",
        telegram: "#17becf",
        instagram: "#e377c2",
        "social-profile": "#bcbd22",
        ip: "#7f7f7f",
        technology: "#0b6f85"
      }};
      return colors[kind] || "#4b647f";
    }}

    function graphFilters() {{
      return {{
        kind: readValue("entity_kind").toLowerCase(),
        value: readValue("entity_value").toLowerCase(),
        relation: readValue("relation").toLowerCase(),
        text: readValue("graph_filter").toLowerCase()
      }};
    }}

    function graphHasFilters(filters) {{
      return Boolean(filters && (filters.kind || filters.value || filters.relation || filters.text));
    }}

    function textMatches(value, needle) {{
      return !needle || String(value || "").toLowerCase().includes(needle);
    }}

    function nodeMatchesGraphFilters(kind, value, filters) {{
      if (filters.kind && String(kind || "").toLowerCase() !== filters.kind) return false;
      if (filters.value && !textMatches(value, filters.value)) return false;
      if (filters.text && !(
        textMatches(kind, filters.text) ||
        textMatches(value, filters.text)
      )) return false;
      return true;
    }}

    function edgeMatchesGraphFilters(edge, filters) {{
      if (filters.relation && !textMatches(edge.relation, filters.relation)) return false;
      if (filters.kind) {{
        const sourceKind = String(edge.source_kind || "").toLowerCase();
        const targetKind = String(edge.target_kind || "").toLowerCase();
        if (sourceKind !== filters.kind && targetKind !== filters.kind) return false;
      }}
      if (filters.value) {{
        if (!textMatches(edge.source_value, filters.value) && !textMatches(edge.target_value, filters.value)) return false;
      }}
      if (filters.text) {{
        const fields = [
          edge.source_kind,
          edge.source_value,
          edge.target_kind,
          edge.target_value,
          edge.relation,
          edge.source,
          edge.case_id
        ];
        if (!fields.some((value) => textMatches(value, filters.text))) return false;
      }}
      return true;
    }}

    function collectGraph(casePayload) {{
      const nodeMap = new Map();
      const filters = graphFilters();
      const allEdges = Array.isArray(casePayload && casePayload.edges) ? casePayload.edges : [];
      const allEntities = Array.isArray(casePayload && casePayload.entities) ? casePayload.entities : [];
      const filtered = graphHasFilters(filters);
      const rawEdges = filtered
        ? allEdges.filter((edge) => edgeMatchesGraphFilters(edge, filters))
        : allEdges;
      const rawEntities = filtered
        ? allEntities.filter((entity) => nodeMatchesGraphFilters(entity.kind, entity.value, filters))
        : allEntities;
      for (const entity of rawEntities) {{
        addGraphNode(nodeMap, entity.kind, entity.value);
      }}
      for (const edge of rawEdges) {{
        addGraphNode(nodeMap, edge.source_kind, edge.source_value);
        addGraphNode(nodeMap, edge.target_kind, edge.target_value);
      }}
      const degree = new Map();
      for (const edge of rawEdges) {{
        const sourceKey = graphKey(edge.source_kind, edge.source_value);
        const targetKey = graphKey(edge.target_kind, edge.target_value);
        degree.set(sourceKey, (degree.get(sourceKey) || 0) + 1);
        degree.set(targetKey, (degree.get(targetKey) || 0) + 1);
      }}
      const nodes = Array.from(nodeMap.values());
      for (const node of nodes) {{
        node.degree = degree.get(node.key) || 0;
      }}
      nodes.sort((left, right) => {{
        if (right.degree !== left.degree) return right.degree - left.degree;
        const leftLabel = left.kind + ":" + left.value.toLowerCase();
        const rightLabel = right.kind + ":" + right.value.toLowerCase();
        return leftLabel.localeCompare(rightLabel);
      }});
      const maxNodes = 42;
      const visibleNodes = nodes.slice(0, maxNodes);
      const selectedKeys = new Set(visibleNodes.map((node) => node.key));
      const visibleEdges = rawEdges
        .filter((edge) => selectedKeys.has(graphKey(edge.source_kind, edge.source_value)) && selectedKeys.has(graphKey(edge.target_kind, edge.target_value)))
        .slice(0, 90);
      return {{
        nodes: visibleNodes,
        edges: visibleEdges,
        filters,
        hiddenNodes: Math.max(0, nodes.length - visibleNodes.length),
        hiddenEdges: Math.max(0, rawEdges.length - visibleEdges.length),
        filteredNodes: nodes.length,
        filteredEdges: rawEdges.length
      }};
    }}

    function svgElement(name, attrs) {{
      const element = document.createElementNS("http://www.w3.org/2000/svg", name);
      for (const [key, value] of Object.entries(attrs || {{}})) {{
        element.setAttribute(key, String(value));
      }}
      return element;
    }}

    function clearElement(element) {{
      while (element.firstChild) element.removeChild(element.firstChild);
    }}

    function renderGraphSummary(casePayload, analysis, hiddenNodes, hiddenEdges, filters) {{
      const summary = document.getElementById("caseGraphSummary");
      const legend = document.getElementById("caseGraphLegend");
      summary.innerHTML = "";
      legend.innerHTML = "";
      const pills = [];
      if (analysis) {{
        pills.push("nodes " + analysis.node_count);
        pills.push("edges " + analysis.edge_count);
        if (analysis.focus) pills.push("focus " + analysis.focus.kind + ":" + shortText(analysis.focus.value, 28));
      }} else if (casePayload) {{
        pills.push("entities " + ((casePayload.entities || []).length));
        pills.push("edges " + ((casePayload.edges || []).length));
      }}
      if (hiddenNodes) pills.push("hidden nodes " + hiddenNodes);
      if (hiddenEdges) pills.push("hidden edges " + hiddenEdges);
      if (filters && filters.kind) pills.push("kind " + filters.kind);
      if (filters && filters.value) pills.push("value " + shortText(filters.value, 24));
      if (filters && filters.relation) pills.push("relation " + shortText(filters.relation, 24));
      if (filters && filters.text) pills.push("contains " + shortText(filters.text, 24));
      for (const text of pills) {{
        const item = document.createElement("span");
        item.className = "graph-pill";
        item.textContent = text;
        summary.appendChild(item);
      }}
      if (analysis && analysis.relation_counts) {{
        const relations = Object.entries(analysis.relation_counts)
          .sort((left, right) => right[1] - left[1])
          .slice(0, 6);
        for (const [relation, count] of relations) {{
          const row = document.createElement("div");
          row.textContent = relation + ": " + count;
          legend.appendChild(row);
        }}
      }}
      if (analysis && Array.isArray(analysis.neighbors) && analysis.neighbors.length) {{
        const row = document.createElement("div");
        row.textContent = "focus neighbors: " + analysis.neighbors.length;
        legend.appendChild(row);
      }}
      const hint = document.createElement("div");
      hint.textContent = currentGraphMode === "network"
        ? "Click graph nodes to set source/target for Path."
        : "Click a graph node to focus neighbors.";
      legend.appendChild(hint);
    }}

    function focusGraphNode(kind, value) {{
      if (!kind || !value) return;
      if (currentGraphMode === "network") {{
        const sourceKind = readValue("entity_kind");
        const sourceValue = readValue("entity_value");
        if (!sourceKind || !sourceValue || (sourceKind === kind && sourceValue === value)) {{
          setFieldValue("entity_kind", kind);
          setFieldValue("entity_value", value);
          setCaseLog(`Selected source entity: ${{kind}}:${{value}}`);
        }} else {{
          setFieldValue("target_entity_kind", kind);
          setFieldValue("target_entity_value", value);
          setCaseLog(`Selected target entity: ${{kind}}:${{value}}`);
        }}
        return;
      }}
      setFieldValue("entity_kind", kind);
      setFieldValue("entity_value", value);
      showCaseGraph().catch((error) => setCaseLog(String(error)));
    }}

    function renderCaseGraph(casePayload, analysis) {{
      const svg = document.getElementById("caseGraphSvg");
      const empty = document.getElementById("caseGraphEmpty");
      clearElement(svg);
      if (!casePayload) {{
        renderGraphSummary(null, null, 0, 0, graphFilters());
        svg.classList.add("hidden");
        empty.textContent = "Открой кейс или граф, чтобы увидеть связи entities.";
        empty.classList.remove("hidden");
        return;
      }}
      const graph = collectGraph(casePayload);
      renderGraphSummary(casePayload, analysis, graph.hiddenNodes, graph.hiddenEdges, graph.filters);
      if (!graph.nodes.length) {{
        svg.classList.add("hidden");
        empty.textContent = graphHasFilters(graph.filters)
          ? "Фильтры не нашли visible entities/edges в текущем графе."
          : "В кейсе пока нет entities/edges для визуализации.";
        empty.classList.remove("hidden");
        return;
      }}
      svg.classList.remove("hidden");
      empty.classList.add("hidden");

      const defs = svgElement("defs", {{}});
      const marker = svgElement("marker", {{
        id: "caseGraphArrow",
        markerWidth: "10",
        markerHeight: "10",
        refX: "8",
        refY: "3",
        orient: "auto",
        markerUnits: "strokeWidth"
      }});
      marker.appendChild(svgElement("path", {{d: "M0,0 L0,6 L9,3 z", fill: "#9aa8b9"}}));
      defs.appendChild(marker);
      svg.appendChild(defs);

      const centerX = 380;
      const centerY = 220;
      const radiusX = 300;
      const radiusY = 150;
      graph.nodes.forEach((node, index) => {{
        if (index === 0) {{
          node.x = centerX;
          node.y = centerY;
          return;
        }}
        const total = Math.max(1, graph.nodes.length - 1);
        const angle = -Math.PI / 2 + (2 * Math.PI * (index - 1)) / total;
        node.x = centerX + Math.cos(angle) * radiusX;
        node.y = centerY + Math.sin(angle) * radiusY;
      }});
      const nodesByKey = new Map(graph.nodes.map((node) => [node.key, node]));

      for (const edge of graph.edges) {{
        const source = nodesByKey.get(graphKey(edge.source_kind, edge.source_value));
        const target = nodesByKey.get(graphKey(edge.target_kind, edge.target_value));
        if (!source || !target) continue;
        const line = svgElement("line", {{
          class: "graph-edge",
          x1: source.x,
          y1: source.y,
          x2: target.x,
          y2: target.y,
          "marker-end": "url(#caseGraphArrow)"
        }});
        const title = svgElement("title", {{}});
        title.textContent = (edge.relation || "edge") + " · " + (edge.confidence || "") + " · " + (edge.source || "");
        line.appendChild(title);
        svg.appendChild(line);
      }}

      for (const node of graph.nodes) {{
        const group = svgElement("g", {{
          class: "graph-node",
          "data-graph-kind": node.kind,
          "data-graph-value": node.value,
          role: "button",
          tabindex: "0"
        }});
        group.appendChild(svgElement("circle", {{
          cx: node.x,
          cy: node.y,
          r: node.degree > 1 ? 18 : 15,
          fill: graphColor(node.kind)
        }}));
        const label = svgElement("text", {{x: node.x, y: node.y + 32}});
        const kind = svgElement("tspan", {{x: node.x, dy: "0"}});
        kind.textContent = shortText(node.kind, 18);
        const value = svgElement("tspan", {{x: node.x, dy: "12"}});
        value.textContent = shortText(node.value, 28);
        label.appendChild(kind);
        label.appendChild(value);
        const title = svgElement("title", {{}});
        title.textContent = node.kind + ":" + node.value + " · degree " + node.degree;
        group.appendChild(title);
        group.appendChild(label);
        svg.appendChild(group);
      }}
    }}

    function renderCasePath(path) {{
      const summary = document.getElementById("caseGraphSummary");
      const legend = document.getElementById("caseGraphLegend");
      summary.innerHTML = "";
      legend.innerHTML = "";
      const pills = [
        "path " + (path.found ? "found" : "not found"),
        "hops " + (path.hop_count || 0),
        "weight " + (path.total_weight ?? "n/a"),
        "cases " + (path.case_count || 0)
      ];
      for (const text of pills) {{
        const item = document.createElement("span");
        item.className = "graph-pill";
        item.textContent = text;
        summary.appendChild(item);
      }}
      const steps = Array.isArray(path.steps) ? path.steps : [];
      if (!steps.length) {{
        const row = document.createElement("div");
        row.textContent = "No path steps.";
        legend.appendChild(row);
        return;
      }}
      for (const step of steps) {{
        const row = document.createElement("div");
        const from = `${{step.from?.kind || ""}}:${{step.from?.value || ""}}`;
        const to = `${{step.to?.kind || ""}}:${{step.to?.value || ""}}`;
        row.textContent = `${{step.case_id}} · ${{from}} --${{step.relation}}/${{step.direction}}--> ${{to}}`;
        legend.appendChild(row);
      }}
    }}

    async function loadCases(writeLog = true) {{
      const params = {{
        case_db: caseDbValue(),
        limit: "50"
      }};
      const workflow = readValue("workflow_filter");
      const profile = readValue("profile_filter");
      const scopeQuery = readValue("scope_query");
      if (workflow) params.workflow = workflow;
      if (profile) params.profile = profile;
      if (scopeQuery) params.scope_query = scopeQuery;
      const data = await fetchCaseJson("/api/cases", params);
      renderCaseList(data.cases || []);
      if (writeLog) setCaseLog(JSON.stringify(data, null, 2));
      return data;
    }}

    async function showCase() {{
      const caseId = readValue("case_id");
      if (!caseId) throw new Error("Укажи Case ID.");
      const data = await fetchCaseJson(`/api/cases/${{encodeURIComponent(caseId)}}`, {{
        case_db: caseDbValue()
      }});
      currentCasePayload = data;
      currentGraphAnalysis = null;
      currentGraphMode = "case";
      renderCaseGraph(currentCasePayload, currentGraphAnalysis);
      setCaseLog(JSON.stringify(data, null, 2));
    }}

    async function updateCase() {{
      const caseId = readValue("case_id");
      if (!caseId) throw new Error("Укажи Case ID.");
      const payload = {{case_db: caseDbValue()}};
      const title = readValue("title");
      const scopeNote = readValue("scope_note");
      if (title) payload.title = title;
      if (scopeNote) payload.scope_note = scopeNote;
      if (!payload.title && !payload.scope_note) {{
        throw new Error("Укажи новое название кейса и/или Scope note.");
      }}
      const data = await postBackendJson(`/api/cases/${{encodeURIComponent(caseId)}}/update`, payload);
      currentCasePayload = data;
      currentGraphAnalysis = null;
      currentGraphMode = "case";
      renderCaseGraph(currentCasePayload, currentGraphAnalysis);
      setCaseLog(JSON.stringify(data, null, 2));
      await loadCases(false);
    }}

    async function deleteCase() {{
      const caseId = readValue("case_id");
      if (!caseId) throw new Error("Укажи Case ID.");
      const confirm = readValue("delete_confirm");
      if (confirm !== caseId) {{
        throw new Error("Для удаления поле Delete confirm должно точно совпадать с Case ID.");
      }}
      const data = await postBackendJson(`/api/cases/${{encodeURIComponent(caseId)}}/delete`, {{
        case_db: caseDbValue(),
        confirm
      }});
      currentCasePayload = null;
      currentGraphAnalysis = null;
      renderCaseGraph(null, null);
      setCaseLog(JSON.stringify(data, null, 2));
      await loadCases(false);
    }}

    async function showCaseGraph() {{
      const caseId = readValue("case_id");
      if (!caseId) throw new Error("Укажи Case ID.");
      const params = {{
        case_db: caseDbValue(),
        limit: "50"
      }};
      const entityKind = readValue("entity_kind");
      const entityValue = readValue("entity_value");
      if (entityKind && entityValue) {{
        params.entity_kind = entityKind;
        params.entity_value = entityValue;
      }}
      const caseParams = {{case_db: caseDbValue()}};
      const [caseData, graphData] = await Promise.all([
        fetchCaseJson(`/api/cases/${{encodeURIComponent(caseId)}}`, caseParams),
        fetchCaseJson(`/api/cases/${{encodeURIComponent(caseId)}}/graph`, params)
      ]);
      currentCasePayload = caseData;
      currentGraphAnalysis = graphData;
      currentGraphMode = "case";
      renderCaseGraph(currentCasePayload, currentGraphAnalysis);
      setCaseLog(JSON.stringify({{case: caseData, graph: graphData}}, null, 2));
    }}

    async function showCaseSources() {{
      const caseId = readValue("case_id");
      if (!caseId) throw new Error("Укажи Case ID.");
      const data = await fetchCaseJson(`/api/cases/${{encodeURIComponent(caseId)}}/sources`, {{
        case_db: caseDbValue(),
        format: "markdown"
      }});
      setCaseLog(data.content || JSON.stringify(data, null, 2));
    }}

    async function showCaseIndex() {{
      const params = {{
        case_db: caseDbValue(),
        min_cases: "1",
        limit: "50"
      }};
      const entityKind = readValue("entity_kind");
      const entityValue = readValue("entity_value");
      if (entityKind) params.kind = entityKind;
      if (entityKind && entityValue) params.value = entityValue;
      const data = await fetchCaseJson("/api/case-index", params);
      setCaseLog(JSON.stringify(data, null, 2));
    }}

    async function showCasePath() {{
      const sourceKind = readValue("entity_kind");
      const sourceValue = readValue("entity_value");
      const targetKind = readValue("target_entity_kind");
      const targetValue = readValue("target_entity_value");
      if (!sourceKind || !sourceValue || !targetKind || !targetValue) {{
        throw new Error("Укажи source Entity kind/value и target Entity kind/value.");
      }}
      const data = await fetchCaseJson("/api/case-path", {{
        case_db: caseDbValue(),
        from_kind: sourceKind,
        from_value: sourceValue,
        to_kind: targetKind,
        to_value: targetValue,
        case_limit: "100",
        max_depth: "6"
      }});
      renderCasePath(data);
      setCaseLog(JSON.stringify(data, null, 2));
    }}

    async function showCaseNetwork() {{
      const params = {{
        case_db: caseDbValue(),
        case_limit: "100",
        node_limit: "60",
        edge_limit: "120",
        min_degree: "1"
      }};
      const entityKind = readValue("entity_kind");
      const relation = readValue("relation");
      if (entityKind) params.kind = entityKind;
      if (relation) params.relation = relation;
      const data = await fetchCaseJson("/api/case-network", params);
      const graphPayload = {{
        entities: Array.isArray(data.nodes) ? data.nodes.map((node) => ({{kind: node.kind, value: node.value}})) : [],
        edges: Array.isArray(data.edges) ? data.edges : []
      }};
      currentCasePayload = graphPayload;
      currentGraphAnalysis = data;
      currentGraphMode = "network";
      renderCaseGraph(currentCasePayload, currentGraphAnalysis);
      setCaseLog(JSON.stringify(data, null, 2));
    }}

    async function clearGraphFilters() {{
      setFieldValue("entity_kind", "");
      setFieldValue("entity_value", "");
      setFieldValue("relation", "");
      setFieldValue("graph_filter", "");
      if (currentGraphMode === "network" && backendAvailable()) {{
        await showCaseNetwork();
        return;
      }}
      renderCaseGraph(currentCasePayload, currentGraphAnalysis);
      setCaseLog("Graph filters cleared.");
    }}

    document.getElementById("runUnifiedSearch").addEventListener("click", () => {{
      runUnifiedSearch().catch((error) => setBackendLog(String(error)));
    }});

    document.getElementById("refreshJobs").addEventListener("click", () => {{
      refreshJobs().catch((error) => setBackendLog(String(error)));
    }});

    document.getElementById("listProfiles").addEventListener("click", () => {{
      loadBackendProfiles().catch((error) => setBackendLog(String(error)));
    }});

    document.getElementById("toolsDoctor").addEventListener("click", () => {{
      loadProfileTools("doctor").catch((error) => setBackendLog(String(error)));
    }});

    document.getElementById("toolsInstall").addEventListener("click", () => {{
      runProfileToolsInstall(false).catch((error) => setBackendLog(String(error)));
    }});

    document.getElementById("toolsInstallRun").addEventListener("click", () => {{
      runProfileToolsInstall(true).catch((error) => setBackendLog(String(error)));
    }});

    document.getElementById("toolsEnv").addEventListener("click", () => {{
      loadProfileTools("env").catch((error) => setBackendLog(String(error)));
    }});

    document.getElementById("saveProfile").addEventListener("click", () => {{
      saveSearchProfile().catch((error) => setBackendLog(String(error)));
    }});

    document.getElementById("deleteProfile").addEventListener("click", () => {{
      deleteSearchProfile().catch((error) => setBackendLog(String(error)));
    }});

    document.addEventListener("click", (event) => {{
      const button = event.target.closest("[data-report-job]");
      if (!button) return;
      readReport(button.getAttribute("data-report-job")).catch((error) => setBackendLog(String(error)));
    }});

    document.getElementById("loadCases").addEventListener("click", () => {{
      loadCases().catch((error) => setCaseLog(String(error)));
    }});

    document.getElementById("showCase").addEventListener("click", () => {{
      showCase().catch((error) => setCaseLog(String(error)));
    }});

    document.getElementById("updateCase").addEventListener("click", () => {{
      updateCase().catch((error) => setCaseLog(String(error)));
    }});

    document.getElementById("deleteCase").addEventListener("click", () => {{
      deleteCase().catch((error) => setCaseLog(String(error)));
    }});

    document.getElementById("showCaseSources").addEventListener("click", () => {{
      showCaseSources().catch((error) => setCaseLog(String(error)));
    }});

    document.getElementById("showCaseGraph").addEventListener("click", () => {{
      showCaseGraph().catch((error) => setCaseLog(String(error)));
    }});

    document.getElementById("showCaseIndex").addEventListener("click", () => {{
      showCaseIndex().catch((error) => setCaseLog(String(error)));
    }});

    document.getElementById("showCasePath").addEventListener("click", () => {{
      showCasePath().catch((error) => setCaseLog(String(error)));
    }});

    document.getElementById("showCaseNetwork").addEventListener("click", () => {{
      showCaseNetwork().catch((error) => setCaseLog(String(error)));
    }});

    document.getElementById("clearGraphFilters").addEventListener("click", () => {{
      clearGraphFilters().catch((error) => setCaseLog(String(error)));
    }});

    document.addEventListener("click", (event) => {{
      const button = event.target.closest("[data-open-case]");
      if (!button) return;
      setFieldValue("case_id", button.getAttribute("data-open-case"));
      showCase().catch((error) => setCaseLog(String(error)));
    }});

    document.addEventListener("click", (event) => {{
      const node = event.target.closest("[data-graph-kind]");
      if (!node) return;
      focusGraphNode(node.getAttribute("data-graph-kind"), node.getAttribute("data-graph-value"));
    }});

    document.addEventListener("keydown", (event) => {{
      if (!["Enter", " "].includes(event.key)) return;
      const node = event.target.closest("[data-graph-kind]");
      if (!node) return;
      event.preventDefault();
      focusGraphNode(node.getAttribute("data-graph-kind"), node.getAttribute("data-graph-value"));
    }});

    if (backendAvailable()) {{
      document.getElementById("backendStatus").textContent = `Backend: ${{backendConfig.url}}`;
      refreshJobs().catch(() => {{}});
    }} else {{
      document.getElementById("runUnifiedSearch").disabled = true;
      document.getElementById("listProfiles").disabled = true;
      document.getElementById("toolsDoctor").disabled = true;
      document.getElementById("toolsInstall").disabled = true;
      document.getElementById("toolsInstallRun").disabled = true;
      document.getElementById("toolsEnv").disabled = true;
      document.getElementById("saveProfile").disabled = true;
      document.getElementById("deleteProfile").disabled = true;
      document.getElementById("refreshJobs").disabled = true;
      document.getElementById("loadCases").disabled = true;
      document.getElementById("showCase").disabled = true;
      document.getElementById("updateCase").disabled = true;
      document.getElementById("deleteCase").disabled = true;
      document.getElementById("showCaseSources").disabled = true;
      document.getElementById("showCaseGraph").disabled = true;
      document.getElementById("showCaseIndex").disabled = true;
      document.getElementById("showCasePath").disabled = true;
      document.getElementById("showCaseNetwork").disabled = true;
      document.getElementById("clearGraphFilters").disabled = true;
    }}
  </script>
</body>
</html>
"""


def write_toolbox(output_path: str | Path, *, backend_url: str = "", backend_auth: str = "") -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_toolbox_html(backend_url=backend_url, backend_auth=backend_auth), encoding="utf-8")
    return path


def _adapter_profile_section() -> ToolboxSection:
    commands = tuple(_command_for_profile(profile) for profile in list_adapter_profiles())
    return ToolboxSection(
        slug="adapter-profiles-one-click",
        title="Готовые adapter profiles",
        description="Отдельные кнопки для всех текущих reusable adapter profiles из manifest.",
        commands=commands,
        notes=("Все команды остаются dry-run по adapters, пока оператор явно не добавит execute-флаги.",),
    )


def _command_for_profile(profile: AdapterProfile) -> ToolboxCommand:
    seed_flag, required = _profile_seed(profile)
    command = (
        f"python -m osint_toolkit investigate {seed_flag} "
        f"--include-adapters --adapter-profile {profile.name} "
        "--adapter-limit {adapter_limit} --out {out}"
    )
    if "username" in profile.target_kinds:
        command = command.replace(" investigate ", " investigate --region {region} ", 1)
        required = required + ("region",)
    repositories = ", ".join(profile.repositories)
    note = profile.note
    if repositories:
        note = f"{note} Repositories: {repositories}".strip()
    return ToolboxCommand(
        title=profile.name,
        description=profile.description,
        command_template=command,
        required_inputs=required + ("adapter_limit", "out"),
        badges=profile.target_kinds,
        note=note,
    )


def _profile_seed(profile: AdapterProfile) -> tuple[str, tuple[str, ...]]:
    if "domain" in profile.target_kinds:
        return "--domain {domain}", ("domain",)
    if "username" in profile.target_kinds:
        return "--username {username}", ("username",)
    if "email" in profile.target_kinds:
        return "--email {email}", ("email",)
    if "phone" in profile.target_kinds:
        return "--phone {phone}", ("phone",)
    if "url" in profile.target_kinds:
        return "--url {url}", ("url",)
    return "--username {username}", ("username",)


def _render_input(field: ToolboxInput) -> str:
    return (
        f'<label>{escape(field.label)}'
        f'<input data-field="{escape(field.name)}" type="{escape(field.input_type)}" '
        f'placeholder="{escape(field.placeholder)}"></label>'
    )


def _render_options(values: tuple[str, ...], *, selected: str = "") -> str:
    options = []
    for value in values:
        marker = " selected" if value == selected else ""
        options.append(f'<option value="{escape(value, quote=True)}"{marker}>{escape(value)}</option>')
    return "\n".join(options)


def _js_string(value: str) -> str:
    import json

    return json.dumps(value, ensure_ascii=False)


def _render_section(section: ToolboxSection) -> str:
    notes = ""
    if section.notes:
        notes = "<ul class=\"notes\">" + "".join(
            f"<li>{escape(note)}</li>" for note in section.notes
        ) + "</ul>"
    cards = "\n".join(_render_command_card(command) for command in section.commands)
    return f"""
<section id="{escape(section.slug)}">
  <h2>{escape(section.title)}</h2>
  <p>{escape(section.description)}</p>
  {notes}
  <div class="cards">{cards}</div>
</section>
"""


def _render_command_card(command: ToolboxCommand) -> str:
    badges = "".join(f'<span class="badge">{escape(badge)}</span>' for badge in command.badges)
    note = f"<p>{escape(command.note)}</p>" if command.note else ""
    return f"""
<article class="card">
  <div>
    <h3>{escape(command.title)}</h3>
    <p>{escape(command.description)}</p>
    <div class="badges">{badges}</div>
  </div>
  <div>
    <div class="code">{escape(command.command_template)}</div>
    {note}
    <button type="button" data-command-template="{escape(command.command_template, quote=True)}" data-required="{escape(','.join(command.required_inputs), quote=True)}">Собрать команду</button>
  </div>
</article>
"""
