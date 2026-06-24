# Карта 1:1 functional parity

Цель: собрать функциональность OSINT-проектов из текущего snapshot в единую систему `osint_toolkit`.

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
python -m osint_toolkit scan username <username>
python -m osint_toolkit scan username <username> --live
```

Покрытие:

- публичные URL-шаблоны профилей;
- dry-run без сетевых запросов;
- live HTTP checks по явному `--live`;
- единый результат `Finding`;
- RU-фильтр для VK/OK/Habr и глобальных платформ.

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

- нет полного upstream site dataset;
- нет per-site error rules;
- нет rate-limit/backoff правил;
- нет username permutation/alias strategy;
- нет confidence model на основе контента страницы;
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

План:

1. Native: нормализация email, домен, MX/NS/TXT через системный resolver или optional DNS dependency.
2. Adapter: `mosint`, `h8mail`, `pwnedOrNot`.
3. Restricted adapter: `holehe`, `email2phonenumber`, любые recovery/account-enumeration flows.

Причина restricted-слоя: email-to-account и email-to-phone могут раскрывать чувствительные персональные данные и часто зависят от password recovery поведения платформ.

### Phone OSINT

Связанные upstream-проекты:

- `sundowndev/phoneinfoga`
- `AzizKpln/Moriarty-Project`
- `megadose/ignorant`
- `TermuxHackz/X-osint`
- `martinvigo/email2phonenumber`

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

План:

1. Native: HTTP status, redirects, title, basic headers.
2. Adapter: `httpx`, `theHarvester`, `spiderfoot`, `amass`, `subfinder`.
3. Normalize domains, URLs, emails, subdomains into shared entity model.

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

