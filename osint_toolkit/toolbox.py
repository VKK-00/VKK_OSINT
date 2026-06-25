from __future__ import annotations

from dataclasses import dataclass
from html import escape
from pathlib import Path

from .adapters import AdapterProfile, list_adapter_profiles


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
    ToolboxInput("adapter_limit", "Лимит adapters", "3", "number"),
    ToolboxInput("case_db", "SQLite case DB", "cases.sqlite"),
    ToolboxInput("case_id", "Case ID", "case-001"),
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
                    'exiftool -a -u -g1 -ee "{image_path}"',
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
                    "Собирает один investigation report из заполненных seed-полей.",
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
                    "Имя -> username-кандидаты",
                    "Генерирует bounded список username-кандидатов из имени.",
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
                    "Email baseline",
                    "MX/NS/TXT, SPF, DMARC, MTA-STS, TLS-RPT, BIMI и public service signals.",
                    "python -m osint_toolkit scan email {email} --live --format markdown",
                    required_inputs=("email",),
                    badges=("email", "live"),
                ),
                ToolboxCommand(
                    "Email safe adapters",
                    "Mosint, h8mail, pwnedOrNot, user-scanner, Blackbird через safe profile.",
                    (
                        "python -m osint_toolkit investigate --email {email} "
                        "--include-adapters --adapter-profile email-safe "
                        "--adapter-limit {adapter_limit} --out {out}"
                    ),
                    required_inputs=("email", "adapter_limit", "out"),
                    badges=("email-safe", "report"),
                ),
                ToolboxCommand(
                    "Телефон baseline",
                    "Локальная нормализация и безопасный phone route.",
                    "python -m osint_toolkit scan phone {phone} --format markdown",
                    required_inputs=("phone",),
                    badges=("phone", "dry-run"),
                ),
                ToolboxCommand(
                    "PhoneInfoga route",
                    "Phone safe adapter profile, dry-run до явного execute.",
                    (
                        "python -m osint_toolkit investigate --phone {phone} "
                        "--include-adapters --adapter-profile phone-safe "
                        "--adapter-limit {adapter_limit} --out {out}"
                    ),
                    required_inputs=("phone", "adapter_limit", "out"),
                    badges=("phone-safe", "report"),
                ),
            ),
        ),
        ToolboxSection(
            slug="domain-url",
            title="Домен / URL / web recon",
            description="DNS, HTTP metadata, bounded crawler, passive recon adapters и broad recon suites.",
            commands=(
                ToolboxCommand(
                    "Домен baseline",
                    "DNS, HTTP metadata, emails/phones/social URLs, robots/sitemap, CT, RDAP/WHOIS.",
                    (
                        "python -m osint_toolkit scan domain {domain} --live "
                        "--crawl-pages 5 --crawl-depth 1 --format markdown"
                    ),
                    required_inputs=("domain",),
                    badges=("domain", "live"),
                ),
                ToolboxCommand(
                    "URL baseline",
                    "Bounded same-site crawl стартовой страницы.",
                    (
                        "python -m osint_toolkit scan url {url} --live "
                        "--crawl-pages 5 --crawl-depth 1 --format json"
                    ),
                    required_inputs=("url",),
                    badges=("url", "crawl"),
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
                    "RU/UA username profile",
                    "Snoop, Maigret, Social Analyzer и Sherlock с region hints.",
                    (
                        "python -m osint_toolkit investigate --username {username} "
                        "--region {region} --include-adapters "
                        "--adapter-profile username-ru-ua --adapter-limit {adapter_limit} "
                        "--out {out}"
                    ),
                    required_inputs=("username", "region", "adapter_limit", "out"),
                    badges=("username-ru-ua", "report"),
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
                    "VK/OK/Yandex/Mail.ru public metadata wrapper.",
                    "python -m osint_toolkit scan social {social} --live --format json",
                    required_inputs=("social",),
                    badges=("vk/ok/yandex/mail.ru", "public"),
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
                        "--include-adapters --adapter-profile username-full "
                        "--adapter-limit {adapter_limit} --out {out}"
                    ),
                    required_inputs=("title", "case_db", "case_id", "adapter_limit", "out"),
                    badges=("case-db", "report"),
                ),
                ToolboxCommand(
                    "Список кейсов",
                    "Показывает сохранённые кейсы.",
                    "python -m osint_toolkit cases --case-db {case_db} --format markdown",
                    required_inputs=("case_db",),
                    badges=("sqlite", "list"),
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
                    "python -m osint_toolkit case-graph --case-db {case_db} {case_id} --format markdown",
                    required_inputs=("case_db", "case_id"),
                    badges=("graph", "summary"),
                ),
                ToolboxCommand(
                    "Cross-case индекс",
                    "Ищет повторяющиеся сущности между сохранёнными расследованиями.",
                    "python -m osint_toolkit case-index --case-db {case_db} --min-cases 2 --format markdown",
                    required_inputs=("case_db",),
                    badges=("index", "entities"),
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
                    "Adapter doctor",
                    "Проверяет, какие upstream CLI реально доступны локально.",
                    "python -m osint_toolkit doctor --format markdown",
                    badges=("readiness", "local"),
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


def render_toolbox_html() -> str:
    sections = toolbox_sections()
    nav = "\n".join(
        f'<a href="#{escape(section.slug)}">{escape(section.title)}</a>' for section in sections
    )
    inputs = "\n".join(_render_input(field) for field in TOOLBOX_INPUTS)
    body_sections = "\n".join(_render_section(section) for section in sections)
    input_labels = ", ".join(
        f'"{escape(name)}": "{escape(label)}"' for name, label in INPUT_LABELS.items()
    )
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
    button.secondary {{
      border-color: var(--line);
      background: #ffffff;
      color: #1d2a3a;
    }}
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
      Пульт не запускает команды из браузера, не загружает фото и не делает идентификацию личности по лицу.
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
      </aside>
      <div>{body_sections}</div>
    </div>
  </main>
  <script>
    const inputLabels = {{{input_labels}}};
    const inputNames = Object.keys(inputLabels);

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
  </script>
</body>
</html>
"""


def write_toolbox(output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_toolbox_html(), encoding="utf-8")
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
