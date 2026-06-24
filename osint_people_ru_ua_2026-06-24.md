# OSINT по лицам и РФ/Украине из GitHub top-100

Срез построен на основе `top_100_osint_github_2026-06-24.*`: GitHub topic `osint`, неархивные репозитории, сортировка по stars.

Метод: для каждого репозитория использованы `description`, `topics` и README. Сырая regex-разметка была вручную ужесточена до уровней связи, чтобы не считать случайные бейджи Twitter или техническое слово `account` как OSINT по людям.

Ограничение: это каталог ссылок и evidence-сигналов, а не проверка качества, законности, безопасности или работоспособности инструментов. Инструменты для поиска людей, email, телефонов и соцсетей можно применять только при законном основании, согласии, журналистской/исследовательской необходимости или другой допустимой цели.

## Краткая сводка

- OSINT по лицам: 55 репозиториев/ресурсов из top-100.
- Из них direct_tool: 32, framework/platform/dataset: 8, resource_collection: 13, supporting_indirect: 2.
- РФ/Украина: 20 репозиториев/ресурсов из top-100.
- Из них direct_ru_ua: 6, ru_platform_or_domain: 11, weak_context: 3.
- Пересечение people + РФ/Украина: 15 репозиториев.

## OSINT по лицам

| Rank | Repository | Level | Focus | Stars | Description |
|---:|---|---|---|---:|---|
| 1 | [sherlock-project/sherlock](https://github.com/sherlock-project/sherlock) | direct_tool | username / social accounts | 85416 | Hunt down social media accounts by username across social networks |
| 4 | [soxoj/maigret](https://github.com/soxoj/maigret) | direct_tool | username dossier | 33636 | 🕵️‍♂️ Collect a dossier on a person by username from 3000+ sites |
| 5 | [jivoi/awesome-osint](https://github.com/jivoi/awesome-osint) | resource_collection | people / email / phone / social sections | 27030 | :scream: A curated list of amazingly awesome OSINT |
| 6 | [qeeqbox/social-analyzer](https://github.com/qeeqbox/social-analyzer) | direct_tool | social profile search | 23129 | API, CLI, and Web App for analyzing and finding a person's profile in 1000 social media \ websites |
| 9 | [mxrch/GHunt](https://github.com/mxrch/GHunt) | direct_tool | Google account / email OSINT | 19130 | 🕵️‍♂️ Offensive Google framework. |
| 10 | [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) | framework | person name / phone / email modules | 19060 | SpiderFoot automates OSINT for threat intelligence and mapping your attack surface. |
| 11 | [sundowndev/phoneinfoga](https://github.com/sundowndev/phoneinfoga) | direct_tool | phone number OSINT | 16722 | Information gathering framework for phone numbers |
| 12 | [laramies/theHarvester](https://github.com/laramies/theHarvester) | direct_tool | emails / names from public sources | 16614 | E-mails, subdomains and names Harvester - OSINT |
| 14 | [HunxByts/GhostTrack](https://github.com/HunxByts/GhostTrack) | direct_tool | phone / location lookup | 14268 | Useful tool to track location or mobile number |
| 16 | [Datalux/Osintgram](https://github.com/Datalux/Osintgram) | direct_tool | Instagram account OSINT | 13270 | Osintgram is a OSINT tool on Instagram. It offers an interactive shell to perform analysis on Instagram account of any users by its nickname |
| 17 | [s0md3v/Photon](https://github.com/s0md3v/Photon) | supporting_indirect | emails / social accounts from crawling | 12972 | Incredibly fast crawler designed for OSINT. |
| 18 | [instaloader/instaloader](https://github.com/instaloader/instaloader) | direct_tool | Instagram profiles/media metadata | 12626 | Download pictures (or videos) along with their captions and other metadata from Instagram. |
| 19 | [lockfale/OSINT-Framework](https://github.com/lockfale/OSINT-Framework) | resource_collection | general OSINT resources | 11532 | OSINT Framework |
| 20 | [megadose/holehe](https://github.com/megadose/holehe) | direct_tool | email to registered accounts | 11371 | holehe allows you to check if the mail is used on different sites like twitter, instagram and will retrieve information on sites with the forgotten password function. |
| 21 | [edoardottt/awesome-hacker-search-engines](https://github.com/edoardottt/awesome-hacker-search-engines) | resource_collection | people / email / phone search engines | 10806 | A curated list of awesome search engines useful during Penetration testing, Vulnerability assessments, Red/Blue Team operations, Bug Bounty and more |
| 24 | [blacklanternsecurity/bbot](https://github.com/blacklanternsecurity/bbot) | framework | username / email targets | 9966 | The recursive internet scanner for hackers. 🧡 |
| 28 | [jofpin/trape](https://github.com/jofpin/trape) | direct_tool | people tracking / social engineering | 8717 | People tracker on the Internet: OSINT analysis and research tool by Jose Pino |
| 30 | [cipher387/osint_stuff_tool_collection](https://github.com/cipher387/osint_stuff_tool_collection) | resource_collection | people / email / phone / social resources | 8283 | A collection of several hundred online tools for OSINT |
| 32 | [reconurge/flowsint](https://github.com/reconurge/flowsint) | platform | individual / phone enrichers | 6998 | A modern platform for visual, flexible, and extensible graph-based investigations. For cybersecurity analysts and investigators. |
| 33 | [p1ngul1n0/blackbird](https://github.com/p1ngul1n0/blackbird) | direct_tool | username / email accounts | 6561 | An OSINT tool to search for accounts by username and email in social networks. |
| 35 | [alpkeskin/mosint](https://github.com/alpkeskin/mosint) | direct_tool | email OSINT | 5897 | An automated e-mail OSINT tool |
| 39 | [khast3x/h8mail](https://github.com/khast3x/h8mail) | direct_tool | email / breach hunting | 5057 | Email OSINT & Password breach hunting tool, locally or using premium services. Supports chasing down related email |
| 40 | [may215/awesome-termux-hacking](https://github.com/may215/awesome-termux-hacking) | resource_collection | Termux people/social tools | 4633 | ⚡️An awesome list of the best Termux hacking tools |
| 44 | [megadose/toutatis](https://github.com/megadose/toutatis) | direct_tool | Instagram account extraction | 4027 | Toutatis is a tool that allows you to extract information from instagrams accounts such as e-mails, phone numbers and more |
| 45 | [giuliacassara/awesome-social-engineering](https://github.com/giuliacassara/awesome-social-engineering) | resource_collection | social engineering resources | 4026 | A curated list of awesome social engineering resources. |
| 47 | [snooppr/snoop](https://github.com/snooppr/snoop) | direct_tool | username search | 3952 | Snoop — инструмент разведки на основе открытых данных (OSINT world) |
| 50 | [jasonxtn/Argus](https://github.com/jasonxtn/Argus) | framework | email harvester / information toolkit | 3638 | The Ultimate Information Gathering Toolkit |
| 51 | [Lucksi/Mr.Holmes](https://github.com/Lucksi/Mr.Holmes) | direct_tool | username / geolocation / person OSINT | 3624 | A Complete Osint Tool :mag: |
| 53 | [Astrosp/Awesome-OSINT-List](https://github.com/Astrosp/Awesome-OSINT-List) | resource_collection | people / search / social OSINT resources | 3492 | 📡 Comprehensive collection of OSINT tools for cybersecurity professionals, researchers, and bug bounty hunters. Topics: information gathering, reverse search, red team, trust & s… |
| 54 | [ibnaleem/gosearch](https://github.com/ibnaleem/gosearch) | direct_tool | digital footprint / username | 3447 | 🔍 Search anyone's digital footprint across 300+ websites |
| 59 | [0x0be/yesitsme](https://github.com/0x0be/yesitsme) | direct_tool | Instagram by name/email/phone | 2848 | Simple OSINT script to find Instagram profiles by name and e-mail/phone |
| 61 | [ItIsMeCall911/Awesome-Telegram-OSINT](https://github.com/ItIsMeCall911/Awesome-Telegram-OSINT) | resource_collection | Telegram people/group resources | 2747 | 📚 A Curated List of Awesome Telegram OSINT Tools, Sites & Resources |
| 62 | [bhavsec/reconspider](https://github.com/bhavsec/reconspider) | framework | IP / email / website / organization OSINT | 2713 | 🔎 Most Advanced Open Source Intelligence (OSINT) Framework for scanning IP Address, Emails, Websites, Organizations. |
| 63 | [cipher387/Dorks-collections-list](https://github.com/cipher387/Dorks-collections-list) | resource_collection | LinkedIn / people dorks | 2685 | List of Github repositories and articles with list of dorks for different search engines |
| 65 | [martinvigo/email2phonenumber](https://github.com/martinvigo/email2phonenumber) | direct_tool | email to phone number | 2683 | A OSINT tool to obtain a target's phone number just by having his email address |
| 66 | [WebBreacher/WhatsMyName](https://github.com/WebBreacher/WhatsMyName) | dataset | username account dataset | 2614 | Community-maintained dataset of 700+ websites for finding accounts by username — powers OSINT and digital footprint tools. |
| 67 | [thewhiteh4t/pwnedOrNot](https://github.com/thewhiteh4t/pwnedOrNot) | direct_tool | compromised email/password lookup | 2582 | OSINT Tool for Finding Passwords of Compromised Email Addresses |
| 68 | [thewhiteh4t/nexfil](https://github.com/thewhiteh4t/nexfil) | direct_tool | profiles by username | 2568 | OSINT tool for finding profiles by username |
| 72 | [kpcyrd/sn0int](https://github.com/kpcyrd/sn0int) | framework | email harvesting / OSINT packages | 2463 | Semi-automatic OSINT framework and package manager |
| 73 | [TermuxHackz/X-osint](https://github.com/TermuxHackz/X-osint) | direct_tool | phone / email / name OSINT | 2401 | This is an Open source intelligent framework ie an osint tool which gathers valid information about a phone number, user's email address, perform VIN Osint, and reverse, perform s… |
| 74 | [kaifcodec/user-scanner](https://github.com/kaifcodec/user-scanner) | direct_tool | email and username OSINT | 2390 | 🕵️‍♂️ (2-in-1) Email & Username OSINT suite for deep data extraction. Analyzes 285+ scan vectors (100+ email / 185+ username) for security research, investigations, and digital f… |
| 75 | [alephdata/aleph](https://github.com/alephdata/aleph) | platform | people / companies in documents | 2384 | Search and browse documents and data; find the people and companies you look for. |
| 76 | [cipher387/API-s-for-OSINT](https://github.com/cipher387/API-s-for-OSINT) | resource_collection | phone / email / social APIs | 2345 | List of API's for gathering information about phone numbers, addresses, domains etc |
| 77 | [Alfredredbird/tookie-osint](https://github.com/Alfredredbird/tookie-osint) | direct_tool | social accounts from inputs | 2317 | Tookie is a advanced OSINT information gathering tool that finds social media accounts based on inputs. |
| 79 | [Owez/yark](https://github.com/Owez/yark) | direct_tool | YouTube OSINT/archive | 2174 | OSINT for YouTube made simple. |
| 82 | [Jieyab89/OSINT-Cheat-sheet](https://github.com/Jieyab89/OSINT-Cheat-sheet) | resource_collection | OSINT cheat sheet / SOCMINT | 2029 | OSINT cheat sheet, list OSINT tools, wiki, dataset, article, book , red team OSINT for hackers and OSINT tips and OSINT branch. This repository will grow every time will research,… |
| 83 | [AzizKpln/Moriarty-Project](https://github.com/AzizKpln/Moriarty-Project) | direct_tool | phone number information | 2000 | This tool gives information about the phone number that you entered. |
| 84 | [vaguileradiaz/tinfoleak](https://github.com/vaguileradiaz/tinfoleak) | direct_tool | Twitter intelligence | 1977 | The most complete open-source tool for Twitter intelligence analysis |
| 87 | [megadose/ignorant](https://github.com/megadose/ignorant) | direct_tool | phone to registered accounts | 1876 | ignorant allows you to check if a phone number is used on different sites like snapchat, instagram. |
| 89 | [osintambition/Social-Media-OSINT-Tools-Collection](https://github.com/osintambition/Social-Media-OSINT-Tools-Collection) | resource_collection | SOCMINT / social media | 1849 | A collection of most useful osint tools for SOCINT. |
| 90 | [The-Osint-Toolbox/Telegram-OSINT](https://github.com/The-Osint-Toolbox/Telegram-OSINT) | resource_collection | Telegram people/channel resources | 1848 | In-depth repository of Telegram OSINT resources covering, tools, techniques & tradecraft. |
| 91 | [ninoseki/mitaka](https://github.com/ninoseki/mitaka) | supporting_indirect | browser extension email search | 1810 | A browser extension for OSINT search |
| 94 | [iojw/socialscan](https://github.com/iojw/socialscan) | direct_tool | username / email usage | 1783 | Python library for accurately querying username and email usage on online platforms |
| 95 | [Yvesssn/DetectDee](https://github.com/Yvesssn/DetectDee) | direct_tool | username / email / phone social accounts | 1771 | DetectDee: Hunt down social media accounts by username, email or phone across social networks. |
| 97 | [initstring/linkedin2username](https://github.com/initstring/linkedin2username) | direct_tool | LinkedIn to username lists | 1746 | OSINT Tool: Generate username lists for companies on LinkedIn |

## РФ / Украина / русскоязычные платформы

| Rank | Repository | Level | Focus | Stars | Evidence note |
|---:|---|---|---|---:|---|
| 5 | [jivoi/awesome-osint](https://github.com/jivoi/awesome-osint) | direct_ru_ua | Ukraine/Russia resources and Russian platforms | 27030 | README содержит paste.in.ua, Yandex Russia и VKontakte sections. |
| 7 | [gildas-lormeau/SingleFile](https://github.com/gildas-lormeau/SingleFile) | weak_context | Yandex browser support | 21684 | Только слабый региональный сигнал: поддержка Yandex Browser. |
| 10 | [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) | ru_platform_or_domain | Yandex DNS module | 19060 | Источник/модуль Yandex DNS. |
| 20 | [megadose/holehe](https://github.com/megadose/holehe) | ru_platform_or_domain | mail.ru recovery check | 11371 | Поддержка mail.ru в списке сервисов проверки email. |
| 21 | [edoardottt/awesome-hacker-search-engines](https://github.com/edoardottt/awesome-hacker-search-engines) | ru_platform_or_domain | Geocam.ru / Yandex | 10806 | Содержит Geocam.ru и Yandex как OSINT/search resources. |
| 25 | [shmilylty/OneForAll](https://github.com/shmilylty/OneForAll) | ru_platform_or_domain | Yandex search module | 9875 | Использует Yandex как один из поисковых модулей для subdomain discovery. |
| 27 | [BigBodyCobain/Shadowbroker](https://github.com/BigBodyCobain/Shadowbroker) | direct_ru_ua | Ukraine frontline layer | 9378 | README упоминает Ukraine Frontline GeoJSON from DeepState Map. |
| 30 | [cipher387/osint_stuff_tool_collection](https://github.com/cipher387/osint_stuff_tool_collection) | direct_ru_ua | Russia/Ukraine transport and VK/Yandex resources | 8283 | Коллекция содержит Russia/Belarus/Ukraine train map, photo-map.ru/VK and Yandex resources. |
| 47 | [snooppr/snoop](https://github.com/snooppr/snoop) | direct_ru_ua | RU/UA country filters | 3952 | Русскоязычный инструмент; README содержит примеры поиска/исключения по UA/RU. |
| 53 | [Astrosp/Awesome-OSINT-List](https://github.com/Astrosp/Awesome-OSINT-List) | direct_ru_ua | Ukraine map / Yandex People | 3492 | Содержит Ukraine Interactive map и Yandex People Search. |
| 61 | [ItIsMeCall911/Awesome-Telegram-OSINT](https://github.com/ItIsMeCall911/Awesome-Telegram-OSINT) | ru_platform_or_domain | TGStat.ru / VK DB | 2747 | Telegram OSINT list с TGStat.ru и VK DB ссылками. |
| 63 | [cipher387/Dorks-collections-list](https://github.com/cipher387/Dorks-collections-list) | ru_platform_or_domain | Yandex dorks | 2685 | Есть раздел Yandex dorks. |
| 76 | [cipher387/API-s-for-OSINT](https://github.com/cipher387/API-s-for-OSINT) | ru_platform_or_domain | VK / Odnoklassniki APIs | 2345 | Содержит API Vkontakte и Odnoklassniki. |
| 77 | [Alfredredbird/tookie-osint](https://github.com/Alfredredbird/tookie-osint) | weak_context | Russian localization | 2317 | Слабый сигнал: README links include Russian translation. |
| 82 | [Jieyab89/OSINT-Cheat-sheet](https://github.com/Jieyab89/OSINT-Cheat-sheet) | direct_ru_ua | Russia invasion Ukraine article / Russian services | 2029 | Содержит Bellingcat материал по вторжению РФ в Украину, tvway.ru и Yandex Trends. |
| 85 | [OffcierCia/On-Chain-Investigations-Tools-List](https://github.com/OffcierCia/On-Chain-Investigations-Tools-List) | ru_platform_or_domain | shard.ru | 1905 | В on-chain tool list есть shard.ru. |
| 86 | [nitefood/asn](https://github.com/nitefood/asn) | weak_context | Russian transit example | 1901 | Слабый контекст: пример про Russian TRANSTELECOM transit. |
| 89 | [osintambition/Social-Media-OSINT-Tools-Collection](https://github.com/osintambition/Social-Media-OSINT-Tools-Collection) | ru_platform_or_domain | Tgstat RU | 1849 | SOCMINT collection содержит Tgstat RU. |
| 90 | [The-Osint-Toolbox/Telegram-OSINT](https://github.com/The-Osint-Toolbox/Telegram-OSINT) | ru_platform_or_domain | Yandex resource | 1848 | Telegram OSINT repo содержит Yandex resource. |
| 95 | [Yvesssn/DetectDee](https://github.com/Yvesssn/DetectDee) | ru_platform_or_domain | Russian services in account checks | 1771 | README evidence содержит nn.ru и yandexmusic. |

## Пересечение: люди + РФ/Украина

| Rank | Repository | People focus | RU/UA focus | Stars |
|---:|---|---|---|---:|
| 5 | [jivoi/awesome-osint](https://github.com/jivoi/awesome-osint) | people / email / phone / social sections | Ukraine/Russia resources and Russian platforms | 27030 |
| 10 | [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) | person name / phone / email modules | Yandex DNS module | 19060 |
| 20 | [megadose/holehe](https://github.com/megadose/holehe) | email to registered accounts | mail.ru recovery check | 11371 |
| 21 | [edoardottt/awesome-hacker-search-engines](https://github.com/edoardottt/awesome-hacker-search-engines) | people / email / phone search engines | Geocam.ru / Yandex | 10806 |
| 30 | [cipher387/osint_stuff_tool_collection](https://github.com/cipher387/osint_stuff_tool_collection) | people / email / phone / social resources | Russia/Ukraine transport and VK/Yandex resources | 8283 |
| 47 | [snooppr/snoop](https://github.com/snooppr/snoop) | username search | RU/UA country filters | 3952 |
| 53 | [Astrosp/Awesome-OSINT-List](https://github.com/Astrosp/Awesome-OSINT-List) | people / search / social OSINT resources | Ukraine map / Yandex People | 3492 |
| 61 | [ItIsMeCall911/Awesome-Telegram-OSINT](https://github.com/ItIsMeCall911/Awesome-Telegram-OSINT) | Telegram people/group resources | TGStat.ru / VK DB | 2747 |
| 63 | [cipher387/Dorks-collections-list](https://github.com/cipher387/Dorks-collections-list) | LinkedIn / people dorks | Yandex dorks | 2685 |
| 76 | [cipher387/API-s-for-OSINT](https://github.com/cipher387/API-s-for-OSINT) | phone / email / social APIs | VK / Odnoklassniki APIs | 2345 |
| 77 | [Alfredredbird/tookie-osint](https://github.com/Alfredredbird/tookie-osint) | social accounts from inputs | Russian localization | 2317 |
| 82 | [Jieyab89/OSINT-Cheat-sheet](https://github.com/Jieyab89/OSINT-Cheat-sheet) | OSINT cheat sheet / SOCMINT | Russia invasion Ukraine article / Russian services | 2029 |
| 89 | [osintambition/Social-Media-OSINT-Tools-Collection](https://github.com/osintambition/Social-Media-OSINT-Tools-Collection) | SOCMINT / social media | Tgstat RU | 1849 |
| 90 | [The-Osint-Toolbox/Telegram-OSINT](https://github.com/The-Osint-Toolbox/Telegram-OSINT) | Telegram people/channel resources | Yandex resource | 1848 |
| 95 | [Yvesssn/DetectDee](https://github.com/Yvesssn/DetectDee) | username / email / phone social accounts | Russian services in account checks | 1771 |

## Уровни связи

- `direct_tool`: сам проект прямо предназначен для поиска/обогащения данных по человеку, аккаунту, email, телефону или соцсети.
- `framework`, `platform`, `dataset`: не всегда person-first, но есть явные сущности человека, username, email, phone или documents/people enrichment.
- `resource_collection`: каталог ссылок/ресурсов, где есть person/SOCMINT/email/phone/social разделы.
- `supporting_indirect`: может помогать в person-OSINT, но не является специализированным инструментом по людям.
- `direct_ru_ua`: явная связь с Украиной/РФ как регионом, войной, картами, country filters или региональными ресурсами.
- `ru_platform_or_domain`: связь через VK, OK, Yandex, mail.ru, TGStat.ru, .ru-сервисы и похожие источники.
- `weak_context`: слабое совпадение, например локализация или пример в документации; оставлено отдельно, чтобы не смешивать с реальными региональными OSINT-ресурсами.
