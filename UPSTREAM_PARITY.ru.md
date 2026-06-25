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

### Unified profile installer/control plane

Команды:

```powershell
python -m osint_toolkit tools doctor --profile all-safe
python -m osint_toolkit tools install all-safe --execute
python -m osint_toolkit toolbox --serve --open
```

Покрытие:

- profile-aware readiness для adapters и local image tools;
- dry-run installer results для missing tools;
- explicit execute только для allowlisted package-manager commands (`pipx`, `go`, `winget`, `choco`);
- served toolbox endpoint `/api/tools/install` и кнопки `Install`/`Run install` для запуска того же installer layer из одного окна;
- custom `profile_file` path guard внутри рабочей папки backend;
- `config_missing`, `runtime_error`, manual и restricted steps не превращаются в автоматическую установку.

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
- curated common given-name aliases, initials, reversible name order и handle suffixes для person-derived username candidates;
- operator-provided aliases через `--person-alias` и UTF-8 alias dictionaries через `--person-alias-file`;
- 2014 активных публичных URL/check-шаблонов профилей: 38 curated правил, 479 валидных записей из Sherlock `data.json`, 718 WhatsMyName `wmn-data.json` GET/POST entries и 1423 sanitized Maigret site rules после дедупликации одинаковых URL;
- platform-specific username rules и `skipped` findings для заведомо несовместимых платформ;
- content markers и response-url rules для части live username checks: profile marker -> `candidate/high`, soft-404 marker или Sherlock `errorUrl` redirect -> `not_found/high`;
- native import Sherlock `sherlock_project/resources/data.json` как package resource с MIT notice; 3 POST-checks используют `request_payload`, 27 `response_url` rules используют `errorUrl`; curated локальные правила имеют приоритет над upstream-дублями;
- native import WhatsMyName `wmn-data.json` как package resource с CC BY-SA 4.0 notice; `e_string`, `m_string`, `e_code`, `m_code`, custom headers и POST bodies используются в live classifier;
- native import sanitized Maigret site rules как package resource с MIT notice; `urlProbe`, public `profile_url`, regex rules, `presenseStrs`, `absenceStrs`, tags и safe headers используются в native checks;
- dry-run без сетевых запросов;
- live HTTP checks по явному `--live`;
- HTTP retry/backoff для 429 и temporary 5xx с поддержкой `Retry-After`, `--http-retries`, `--http-backoff` и `--request-delay` для больших username live runs;
- единый результат `Finding`;
- RU-фильтр для VK/OK/Habr и глобальных платформ.
- executable adapter для `soxoj/maigret`: `maigret <username> --json ndjson [--tags ru|ua]`;
- parser для Maigret NDJSON/simple JSON/CSV reports: `Claimed` -> `candidate`, `Available` -> `not_found`, `Unknown` -> `error`, `Illegal` -> `skipped`; site metadata, probe URL, rank/similarity flags, tags и `ids` dossier fields нормализуются в unified metadata/entities/graph;
- executable target-specific adapter для `kaifcodec/user-scanner`: `user-scanner -u <username> -f json`;
- executable RU/UA-aware adapter для `snooppr/snoop`: `snoop --no-func --found-print [--include RU|UA] <username>`;
- parser для Snoop stdout/CSV results: `найден!` -> `candidate`, `Увы!` -> `not_found`, `блок`/ошибки -> `error`;
- executable adapter для `qeeqbox/social-analyzer`: `node <SOCIAL_ANALYZER_APP_JS> --username <username> --output json --mode fast --method all --filter good,maybe --profiles detected [--countries ru|ua]`;
- parser для Social Analyzer JSON `detected`/`unknown`/`failed`: `detected` -> `candidate`, `unknown` -> `not_found`, `failed` -> `error`, с сохранением rate/status, site, profile URL, checked URL и public metadata;
- executable adapter для `p1ngul1n0/blackbird`: `<BLACKBIRD_PYTHON|python> blackbird.py --username <username> --json --no-update --timeout 30` из `BLACKBIRD_DIR`;
- parser для Blackbird JSON exports/stdout found-lines: `FOUND` -> `candidate`, `NOT-FOUND` -> `not_found`, `ERROR` -> `error`, с сохранением site/category/profile URL/platform domain и extracted metadata;
- executable adapter для `Yvesssn/DetectDee`: `DetectDee detect -n <username> -f <DETECTDEE_DATA> -o <temp>`;
- parser для DetectDee generated result/stdout rows: identity, site и profile URL нормализуются в `candidate` findings;
- executable adapter для `iojw/socialscan`: `socialscan <username-or-email> --json <temp.json>`;
- parser для Socialscan generated JSON: `taken/reserved` -> `candidate`, `available` -> `not_found`, invalid query -> `skipped`, upstream/platform failures -> `error`;
- executable adapter для `sherlock-project/sherlock`: при `--execute` добавляются `--no-color --print-all --csv --txt --folderoutput <tempdir>`;
- parser для Sherlock stdout и CSV/TXT reports: `Claimed` -> `candidate`, `Available` -> `not_found`, `Unknown`/`WAF` -> `error`, `Illegal` -> `skipped`;
- executable adapter для `thewhiteh4t/nexfil`: `nexfil -u <username>` запускается в isolated temporary workdir/HOME;
- parser для Nexfil stdout/autosaved TXT reports: найденные URL -> `candidate`, `Total Hits/Timeouts/Errors` -> summary metadata;
- `investigate --person` автоматически прогоняет derived username targets через native username scan и совместимые adapters при `--include-adapters`.

Связанные upstream-проекты:

- `sherlock-project/sherlock`
- `soxoj/maigret`
- `WebBreacher/WhatsMyName`
- `qeeqbox/social-analyzer`
- `thewhiteh4t/nexfil`
- `p1ngul1n0/blackbird`
- `iojw/socialscan`
- `Yvesssn/DetectDee`
- `snooppr/snoop`
- `ibnaleem/gosearch`
- `Alfredredbird/tookie-osint`

Gap до полного 1:1:

- Sherlock GET/POST site dataset, WhatsMyName GET/POST dataset и sanitized Maigret site rules импортированы в native username layer;
- Maigret engine templates, activation flows, recursive policy tuning, report generation, proxies/Tor/I2P and AI mode пока остаются adapter-only;
- per-site rules покрывают username syntax/length, часть title/body content markers и Sherlock response-url `errorUrl`; есть базовый retry/backoff, но ещё не вся WAF/error-handling логика и site-specific rate-limit tuning;
- username permutation/alias strategy уже покрывает common given-name aliases, handle suffixes и operator-provided alias dictionaries, но пока нет bundled historical alias datasets и platform-specific alias scoring;
- content-based confidence пока частичный: нет полного набора marker rules из upstream datasets;
- Maigret подключён hybrid: sanitized site rules импортированы native, NDJSON/simple JSON/CSV dossier parser покрывает site metadata и основные `ids` profile/contact fields, а web UI, PDF/HTML/XMind reports, recursive policy tuning, proxies/Tor/I2P и AI mode пока не перенесены в native UI;
- Snoop подключён adapter-first; Windows release binary может быть установлен user-local, но обновление остаётся upstream/operator-managed действием;
- Social Analyzer подключён adapter-first через фактический upstream Node app.js и JSON output; локальная установка, Node >= 20.18.1, web/API UI, screenshots/OCR, slow/special modes и полный metadata/screenshot pipeline остаются операторским/upstream слоем;
- Blackbird подключён adapter-first через фактический upstream checkout `BLACKBIRD_DIR`; JSON exports и stdout hits нормализуются, но upstream AI profiling, PDF/CSV/DUMP exports, proxy/permutation options и enhanced Instagram session metadata пока не вынесены в отдельные native UI-параметры;
- нет сохранения истории запусков.

## Следующие native/adapters группы

### Email OSINT

Связанные upstream-проекты:

- `alpkeskin/mosint`
- `khast3x/h8mail`
- `thewhiteh4t/pwnedOrNot`
- `kaifcodec/user-scanner`
- `p1ngul1n0/blackbird`
- `megadose/holehe`
- `martinvigo/email2phonenumber`
- `laramies/theHarvester`

Уже реализовано:

- `python -m osint_toolkit scan email <email>`;
- синтаксическая проверка;
- извлечение домена;
- live domain resolution по явному `--live`;
- MX/NS/TXT lookup через системный `nslookup` по явному `--live`;
- SPF classifier поверх доменного TXT: наличие записи, multiple-record warning, `all` policy и include/redirect counts;
- DMARC classifier через `_dmarc.<domain>` TXT: наличие записи, multiple-record warning, `p=`, `sp=`, alignment, percent и report URI tags;
- additional TXT classifiers для `_mta-sts.<domain>` MTA-STS, `_smtp._tls.<domain>` TLS-RPT и `default._bimi.<domain>` BIMI;
- public TXT service signals для root-domain TXT: Google/Microsoft/Yandex/Mail.ru и другие verification markers без раскрытия token values в signal finding;
- executable adapter target для `alpkeskin/mosint`: `mosint --silent <email> --output <temp.json>`;
- parser для Mosint upstream JSON: verification, EmailRep, BreachDirectory, HaveIBeenPwned, Hunter related emails/domains, Google/Paste URLs, social flags, DNS records и ipapi metadata нормализуются в `Finding`/entities; password/hash/sha1-like values редактируются;
- executable adapter target для `khast3x/h8mail`: `h8mail -t <email> --hide -j <temp.json>`;
- parser для h8mail upstream JSON `{targets: [{target, pwn_num, data}]}`: breach count, related emails, usernames, source labels и paste URLs нормализуются в `Finding`/entities, password/hash/token-like values редактируются и не попадают в evidence;
- executable target-specific adapter для `kaifcodec/user-scanner`: `user-scanner -e <email> -f json`;
- parser для `user-scanner` JSON/verbose results: `Registered`/`Found` -> `candidate`, `Available`/`Not Found`/`Not Registered` -> `not_found`, `Error` -> `error`.
- executable adapter для `thewhiteh4t/pwnedOrNot`: `pwnedornot -e <email> -n`, чтобы по умолчанию не запрашивать password dump payloads;
- parser для pwnedOrNot stdout: breach status, total breaches, `Breach`/`Domain`/`Date`/`BreachedInfo` rows и API errors нормализуются в `Finding`/entities; dump/password output помечается как credential-exposure с redaction;
- executable target-specific adapter для `p1ngul1n0/blackbird`: `<BLACKBIRD_PYTHON|python> blackbird.py --email <email> --json --no-update --timeout 30`;
- parser для Blackbird email JSON exports/stdout found-lines: found account URLs, site/category, platform domains и extracted metadata нормализуются в `Finding`/entities;
- executable adapter для `Yvesssn/DetectDee`: `DetectDee detect -e <email> -f <DETECTDEE_DATA> -o <temp>`;
- parser для DetectDee email result rows: identity, site и profile URL нормализуются в `Finding`/entities без использования upstream screenshot/token/credential-stuffing flows.

Gap:

- breach/API enrichment пока выполняется только через внешние Mosint/h8mail adapters, если upstream CLI установлен, Mosint config/API keys настроены и оператор явно запускает `--execute`;
- нет локального кэша;
- нет restricted account-enumeration режима.

План:

1. Native: дальше расширять DNS слой до richer provider attribution и optional CT/domain correlation.
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
- `Yvesssn/DetectDee`

Уже реализовано:

- `python -m osint_toolkit scan phone <number>`;
- E.164-like нормализация;
- базовый country-prefix signal для `+380`, `+7` и нескольких глобальных префиксов.
- `sundowndev/phoneinfoga` как safe external adapter через `phoneinfoga scan -n <number>`;
- parser фактического PhoneInfoga CLI stdout `Results for <scanner>` и REST/API-like JSON для `local`, `numverify`, `googlesearch`, `googlecse`, `ovh`;
- graph/entities mapping для `normalized`, `country`, `country_code`, `carrier`, `line_type`, `location`, `number_range`, `zip_code`, Google dork URL и CSE result URL;
- `Yvesssn/DetectDee` как executable adapter через `DetectDee detect -p <number> -f <DETECTDEE_DATA> -o <temp>`;
- parser DetectDee phone result rows: identity, site и profile URL нормализуются как account-like candidate hits.

Gap:

- нет carrier/type lookup;
- нет reputation lookup;
- нет внешних API;
- GPL-код PhoneInfoga не копируется в native Python-код; паритет делается через внешний CLI/API output ingestion, чтобы не смешивать copyleft-код с основным пакетом.
- DetectDee подключён только в upstream `detect` mode; screenshot, ChatGPT token и credential-stuffing upstream flows не включены в adapter.

План:

1. Native: нормализация номера, country code, форматирование, базовая валидация.
2. Adapter: расширять `phoneinfoga` parser при появлении новых scanner output fields.
3. Restricted adapter: phone-to-account checks.

### Instagram / social-platform modules

Связанные upstream-проекты:

- `Datalux/Osintgram`
- `instaloader/instaloader`
- `megadose/toutatis`
- `0x0be/yesitsme`
- `vaguileradiaz/tinfoleak`
- `Owez/yark`

Уже реализовано:

- `python -m osint_toolkit scan instagram <username-or-url>`;
- normalization for `@username`, `instagram.com/<username>/` profile URLs and public `/p/`, `/reel/`, `/reels/`, `/tv/` media URLs;
- dry-run без сетевых запросов;
- optional live public page metadata by explicit `--live`;
- native `Finding` metadata fields for platform, normalized Instagram username, display name, account id, profile/media/canonical/external URLs, public counters, privacy/verification flags and HTTP attempt metadata;
- `instagram` entities, profile/media URL entities and graph edges for normalized Instagram account, platform, display name, account id and public URLs;
- executable adapter target для `instaloader/instaloader`: `instaloader profile <profile>`; для `instagram` target profile name нормализуется из `@handle` или profile URL.

Gap:

- no login/session handling, private data access, follower/following scraping, comments/messages export or password-recovery/account-enumeration flows;
- no full Osintgram/Toutatis/tinfoleak feature parity; those remain adapter/restricted candidates after scope and platform-terms review;
- public HTML/metadata extraction is best-effort because Instagram changes markup and may rate-limit or return login walls;
- no media archive ingestion yet beyond normalizing public media URL targets.

План:

1. Native: расширять только safe public metadata wrappers and output normalization.
2. Adapter-first: использовать upstream CLI для platform-specific edge cases, если CLI установлен и оператор явно запускает adapter.
3. Restricted: private/session/account-enumeration функции не переносить в native-код без отдельного safety design.

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
- curated source pack for DeepStateMap, Liveuamap, TGStat RU, VK, OK, Yandex, Mail.ru, Geocam.ru and paste.in.ua;
- `python -m osint_toolkit scan social <ru-platform-identifier-or-url>`;
- native public VK/OK/Yandex/Mail.ru profile URL normalization for `vk:<identifier>`, `ok:<identifier>`, `mailru:<identifier>`, `mailru:<namespace>/<identifier>`, `yandex:q/<identifier>`, `yandex:market/<identifier>`, `yandex:reviews/<identifier>`, `yandex:zen/<identifier>`, `vk.com/<identifier>`, `ok.ru/<identifier>`, `ok.ru/profile/<id>`, `my.mail.ru/<namespace>/<identifier>`, `yandex.ru/q/profile/<identifier>`, `market.yandex.ru/user/<identifier>`, `reviews.yandex.ru/user/<identifier>` and `zen.yandex.ru/user/<identifier>`;
- optional live public page metadata by explicit `--live`: display name, description, canonical/profile-image URL, account id when public URL exposes it, platform and platform domain;
- RU social profile metadata creates `social-profile`, `platform`, `username`, `account-id`, `name`, `url` and `domain` entities plus graph edges from the `social` seed to normalized profile/platform/public URLs.

Gap:

- нет Telegram API integration;
- нет message export/archive;
- нет channel graph;
- нет VK/OK/Yandex API adapters;
- нет login/session/API-token enrichment for VK/OK/Yandex/Mail.ru, private profile access, follower scraping, messages/comments export or platform rate-limit bypass;
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
- public email extraction from fetched landing page HTML/text;
- bounded same-site crawler for URL/domain live scans with operator limits `--crawl-pages` and `--crawl-depth`;
- robots.txt discovery for `Sitemap:` directives and public `Disallow` paths;
- sitemap XML/text discovery with same-site URL normalization and bounded queue integration;
- crawler extraction of same-site URLs, external URLs, social URLs, public emails and E.164-like phone values;
- presence list for common security headers;
- certificate transparency lookup via `crt.sh` JSON in live mode;
- CT-derived `subdomain` entities and graph edges `domain -> subdomain`;
- RDAP registration lookup via `rdap.org` JSON in live mode;
- RDAP-derived `registrar`/`nameserver` entities and graph edges `domain -> registrar|nameserver`;
- raw WHOIS lookup via TCP port 43 for common/global and RU/UA-relevant TLDs;
- WHOIS-derived registrar, nameserver, domain status, date and WHOIS server metadata without copying contact-like raw text into evidence;
- crawler-derived `url`/`email`/`phone`/`web-path` entities and graph edges for discovered/internal/external/social links, sitemap URLs, robots disallow paths and page contacts.
- executable adapter target для `projectdiscovery/subfinder`: `subfinder -d <domain> -oJ -silent`;
- parser для Subfinder JSONL/plain output: `host`/subdomain values превращаются в `subdomain` findings, entities и graph edges `domain -> subdomain`;
- executable adapter target для `projectdiscovery/httpx`: `httpx -u <domain-or-url> -json -silent -status-code -title -tech-detect ...`;
- parser для httpx JSONL/plain output: URL, HTTP status, title, webserver, tech, content-type, response-time, IP/CNAME и error state нормализуются в `Finding`/entities;
- executable passive adapter target для `owasp-amass/amass`: `amass enum -passive -nocolor -d <domain>`;
- parser для Amass passive stdout/JSON-like output: FQDN/subdomain values превращаются в `subdomain` findings без включения active/bruteforce modes;
- executable adapter target для `laramies/theHarvester`: `theHarvester -d <domain> -b all -f <temp.json>`;
- parser для theHarvester generated JSON/stdout output: `emails`, `hosts`, `vhosts`, `interesting_urls`, `trello_urls`, `api_endpoints`, `ips`, `asns` и people fields нормализуются в `Finding`/entities/graph signals; `resource/type/source` rows, `*_by_source` maps и nested `source_results` сохраняют provider/source в `source_label`;
- executable adapter target для `blacklanternsecurity/bbot`: `bbot -t <target> -p subdomain-enum -rf passive -o <tempdir> -n osint-toolkit`;
- explicit broader passive adapter variant для `blacklanternsecurity/bbot-passive-web`: `bbot -t <target> -p subdomain-enum web-basic -rf passive -ef active aggressive deadly portscan web-screenshots -o <tempdir> -n osint-toolkit`;
- parser для BBOT generated JSON/NDJSON/stdout events: `DNS_NAME`, `EMAIL_ADDRESS`, `URL`, `IP_ADDRESS`, `OPEN_TCP_PORT`, `TECHNOLOGY`, `FINDING` и `VULNERABILITY` нормализуются в `Finding`/entities/graph signals;
- executable adapter target для `smicallef/spiderfoot`: `<SPIDERFOOT_PYTHON|python> <SPIDERFOOT_SF_PATH> -s <target> -u passive -o json -q`;
- parser для SpiderFoot JSON/stdout events: `INTERNET_NAME`, `DOMAIN_NAME`, `EMAILADDR`, `WEBLINK`, `IP_ADDRESS`, `TCP_PORT_OPEN`, `PHONE_NUMBER`, `HUMAN_NAME`, `TECHNOLOGY`, ASN и vulnerability/finding events нормализуются в `Finding`/entities/graph signals; покрыты examples для domain, email, phone и username target modes с `target_kind`/`target_value` provenance metadata;
- executable interactive adapter target для `jasonxtn/argus`: `argus` со stdin-сценарием `set target <target>`, `runall infra`, `viewout`, `exit`;
- parser для Argus stdout/cache-like output: URL, email, phone, host/subdomain, IP, port и technology signals нормализуются в `Finding`/entities/graph signals; покрыты examples для domain, email, phone и username target modes с `target_kind`/`target_value` provenance metadata;
- adapter profile `domain-recon` для Subfinder/httpx/passive Amass/theHarvester/BBOT/SpiderFoot.
- adapter profile `bbot-passive-web` для более широкого passive BBOT route без active/aggressive/deadly/portscan/screenshot flags.
- adapter profile `broad-recon` для BBOT/SpiderFoot/Argus как более широких recon suites.

Gap:

- нет native brute-force/passive subdomain enumeration за пределами crt.sh; passive enumeration сейчас покрывается external adapters;
- raw WHOIS full-text export is intentionally not included in reports; parser keeps domain-level fields only by default;
- crawler bounded и mostly HTML/XML/text-only: нет JavaScript rendering, form submission, full robots policy enforcement, authentication, headless browser или broad SpiderFoot/Photon-style crawling;
- нет SpiderFoot web/API server connector и full module policy mapping;
- нет активных Amass/bruteforce modes, BBOT active/deadly/portscan/screenshot modules, broader SpiderFoot/Argus use cases, theHarvester screenshots или API endpoint scans по умолчанию.

План:

1. Native: дальше расширять passive domain recon: richer document metadata extraction, optional sitemap/robots policy tuning and more TLD-specific WHOIS parsing.
2. Adapter: следующий слой — SpiderFoot API/server connector, richer BBOT/SpiderFoot/Argus presets/output modules и более богатые generated report parsers.
3. Normalize domains, URLs, emails, phones, subdomains, IPs, ports and technologies into shared entity model.

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
- required environment variables guard before external process execution;
- no shell execution;
- timeout handling;
- restricted adapter guard via `--allow-restricted`;
- `run_adapter_findings()` returns summary + parsed findings;
- adapter summary findings and parsed adapter findings include execution provenance metadata: command, execution route, executable path, return code, start/end timestamps, duration, timeout, generated output count and parser version;
- source summary rows surface execution provenance as runs, routes, return codes, total duration, generated output files and parser versions in Markdown/table/CSV/JSON reports;
- stdout parser for common URL/email/phone/key-value lines from generic adapter output;
- scripted stdin support for interactive CLI adapters;
- generated report ingestion: adapters can run with a temporary output folder, temporary output file or isolated temporary working directory and feed generated files back into `parse_adapter_output()`;
- upstream checkout output ingestion: adapters can run from a configured working directory and ingest only fresh or changed generated files under that checkout, used by Blackbird `BLACKBIRD_DIR/results`;
- adapter-specific parser for Sherlock stdout and generated CSV/TXT report rows;
- adapter-specific parser for Nexfil stdout and autosaved TXT report rows;
- adapter-specific parser for Mosint JSON report rows with credential-value redaction;
- adapter-specific parser for h8mail JSON report rows with credential-value redaction;
- adapter-specific parser for pwnedOrNot stdout breach rows with credential-output redaction guard;
- adapter-specific parser for Maigret NDJSON/simple JSON and CSV report rows;
- adapter-specific parser for `user-scanner` JSON and verbose line output;
- adapter-specific parser for Snoop stdout and CSV report rows;
- adapter-specific parser for Social Analyzer JSON detected/unknown/failed profile rows;
- adapter-specific parser for Socialscan generated JSON availability/usage rows;
- adapter-specific parser for Blackbird JSON exports and stdout found profile rows;
- adapter-specific parser for DetectDee generated result/stdout profile rows;
- adapter-specific parser for PhoneInfoga CLI sections and REST/API-like JSON scanner outputs;
- adapter-specific parser for Subfinder JSONL/plain subdomain output;
- adapter-specific parser for httpx JSONL/plain HTTP probe output;
- adapter-specific parser for passive Amass stdout/JSON-like subdomain output;
- adapter-specific parser for theHarvester generated JSON/stdout domain recon output, including `source_label` preservation for stash/API-style rows and source maps;
- adapter-specific parser for BBOT generated JSON/NDJSON/stdout event output;
- adapter-specific parser for SpiderFoot JSON/stdout event output with domain/email/phone/username target fixtures;
- adapter-specific parser for Argus interactive stdout/cache-like output;
- adapter-specific parser for Owez/yark generated `yark.json` archive output and temporary archive execution route;
- adapter profile `domain-recon` for passive domain/web upstream adapters;
- adapter profile `bbot-passive-web` for the explicit broader passive BBOT `subdomain-enum web-basic` route;
- adapter profile `broad-recon` for broad recon suites BBOT/SpiderFoot/Argus;
- install/config/readiness metadata in `AdapterSpec`;
- `wrong_executable` readiness for known executable-name collisions through declarative probes for Subfinder, ProjectDiscovery `httpx`, Amass, theHarvester, BBOT and PhoneInfoga;
- `runtime_error` readiness for installed executables that pass help probes but fail a non-network startup probe;
- BBOT Docker fallback route: when native BBOT fails on Windows/POSIX-only startup dependencies and Docker is available, readiness/execution switch to `docker run --rm -v <output_dir>:/root/.bbot/scans -v <config_dir>:/root/.config/bbot blacklanternsecurity/bbot:stable ...`;
- `adapter-setup` command for setup plans, docs URLs, PATH/env readiness.
- `tools install <profile>` dry-run/`--execute` installer layer for allowlisted missing tools (`pipx`, `go`, `winget`, `choco`) without auto-running config/runtime/manual/restricted steps.

Gap:

- нет full auto-installer для manual checkout/venv/API-key flows; `tools install <profile>` покрывает только allowlisted missing commands, а текущая dev/toolbox машина может быть приведена к `all-safe` ready через user-local `pipx`, Go binaries, portable image tools и venv-backed manual checkouts;
- нет богатого parser-слоя для JSON/CSV/HTML exports каждого инструмента, кроме уже покрытых Sherlock stdout/CSV/TXT, Nexfil stdout/TXT, Mosint JSON, h8mail JSON, pwnedOrNot stdout, Maigret JSON/CSV dossier fields, `user-scanner` JSON/verbose, Snoop stdout/CSV, Social Analyzer JSON, Socialscan generated JSON, Blackbird JSON/stdout, DetectDee generated result/stdout, PhoneInfoga CLI/API output, Subfinder, httpx, passive Amass, theHarvester с source attribution для поддержанных JSON shapes, BBOT events, SpiderFoot events, Argus stdout/cache-like output, Yark generated `yark.json` archive output, ExifTool JSON local image metadata, Tesseract OCR text и zbarimg QR/barcode payloads;
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
python -m osint_toolkit cases --case-db cases.sqlite --workflow search --profile email-full --scope-query internal
python -m osint_toolkit case-update --case-db cases.sqlite case-001 --title "reviewed case" --scope-note "reviewed scope"
python -m osint_toolkit case-show --case-db cases.sqlite case-001
python -m osint_toolkit case-show --case-db cases.sqlite case-001 --format csv
python -m osint_toolkit case-sources --case-db cases.sqlite case-001
python -m osint_toolkit case-graph --case-db cases.sqlite case-001
python -m osint_toolkit case-graph --case-db cases.sqlite case-001 --entity-kind email --entity-value person@example.com
python -m osint_toolkit case-index --case-db cases.sqlite --kind domain --min-cases 2
python -m osint_toolkit case-index --case-db cases.sqlite --kind email --value person@example.com
python -m osint_toolkit case-path --case-db cases.sqlite --from-kind email --from-value person@example.com --to-kind url --to-value https://example.com/profile
python -m osint_toolkit case-network --case-db cases.sqlite --kind domain
python -m osint_toolkit case-delete --case-db cases.sqlite case-001 --yes
```

Уже реализовано:

- несколько seed values в одном запуске;
- person seed expansion into username candidates;
- единый native scan через `Engine`;
- optional adapter dry-runs;
- reusable adapter profiles such as `username-full`, `email-safe`, `phone-safe` and `username-ru-ua`; username/email profiles now include Blackbird where lawful scope allows execution;
- repeated `--adapter <repository>` allowlist for one case;
- explicit executed adapter ingestion via `--execute-adapters`;
- profile-scoped native execution for `search --execute-adapters` through `profile.native_kinds`;
- derived email-domain fan-out for `search email ... --profile email-full|safe|all-safe`;
- derived email-local-part username fan-out for `search email ... --profile email-full|safe|all-safe`;
- derived URL-host domain fan-out for `search url ... --profile web-full|passive-recon|safe|all-safe`;
- hostname-based `search auto` routing for Instagram, Telegram and supported RU social URLs;
- Markdown/JSON report;
- Entity Summary from targets, finding URLs, evidence and metadata;
- Graph Edges for base entity relations;
- SQLite persistence for cases, targets, entities, edges and findings;
- per-case workflow/profile/adapter/scope policy metadata stored in SQLite and visible through `case-show`;
- list/show saved cases through CLI;
- flat saved-case findings export through `case-show --format csv`, including `case_id`, collection and `metadata_json` provenance;
- saved-case source summary through CLI `case-sources`, served `/api/cases/<id>/sources` and toolbox `Sources`, including per-source counts, status/confidence/signal mix and adapter/local-tool execution provenance when present;
- saved graph summary: node/edge counts, relation counts, entity kind counts and top connected nodes;
- focus-neighbor query for one saved entity;
- cross-case entity index and exact saved-case lookup by entity;
- cross-case weighted shortest path between two saved entities with per-hop case/relation/source provenance;
- bounded cross-case network view with aggregated edges, degree/case_count and kind/relation filters;
- basic safe case management: filtered case list by workflow/profile/scope, title/scope_note update and explicit confirmed delete;
- served toolbox custom search profiles: guarded profile-file loading, `/api/profiles` listing, `/api/profiles/save|delete` minimal editor and `/api/search` execution with typed custom profile names;
- served toolbox profile tool readiness: `/api/tools` doctor/install/env views from the same selected profile and guarded profile file;
- parsed executed adapter outputs can enter investigation entities, graph edges and case store;
- static local `toolbox` HTML command window with OSINT directions, seed fields, image metadata/OCR/QR/reverse-search routes, cases/graph/index routes and adapter profile buttons;
- served toolbox Case Browser for saved cases, case detail, source summaries, safe title/scope update, typed-confirm delete, clickable bounded SVG case graph, graph summary/focus and cross-case index through token-protected allowlisted endpoints;
- served toolbox graph exploration filters for entity kind/value, relation and free-text `Graph contains` over the bounded SVG case/cross-case graph;
- review checklist in every Markdown report.

Gap:

- graph edges пока базовые, без advanced cross-case graph layout/analytics UI;
- есть custom search profiles через `search/tools --profile-file`, CLI management `profiles list/show/export`, guarded served toolbox profile editor и `/api/tools` readiness views; saved cases persist workflow/profile/adapter/scope policy metadata, но adapter profiles в `adapters.py` остаются статическим manifest-layer и нет enforcement для per-case policy;
- нет продвинутого graph exploration UI; `toolbox --serve` уже умеет запускать unified search, передавать scope note/custom profile file, читать/filter/update/delete saved cases, graph/index/path/network, рисовать clickable bounded SVG case/cross-case graph, фильтровать visible graph и делать focus-neighbor запрос кликом по узлу, но static `toolbox --out` остаётся command/portal window и не делает face-ID.

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
