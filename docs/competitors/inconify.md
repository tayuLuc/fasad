# inconify.ru — статус: мёртв, следов в архивах нет

Замер: 18.10.2026, ~18:30 МСК, all-curl (агентский браузер не использовался),
`-A "dsh-audit/1.0"` для архивов, браузерный UA для поисковиков.
Гипотеза родителя («тонкая обёртка над Presidio/spaCy/Natasha, мертва») — **подтверждена
по факту смерти; про «умел» подтвердить нечем** (см. §2).

## 1. Три стороны подтверждения смерти

1. **DNS (живой промер, этот сессия):**
   - `dig A / AAAA / MX / NS / SOA inconify.ru` → пусто по всем; `www` → пусто.
   - `nslookup` → `NXDOMAIN` (сервер 192.168.1.1, резолвер провайдера).
   - `curl https://inconify.ru` → `curl: (6) Could not resolve host` (rc 6, http 000).
2. **Реестр (.RU, ктоис регистратуры Tcinet):**
   `whois -h whois.tcinet.ru inconify.ru` → `No entries found for the selected
   source(s).` — домен **не зарегистрирован**, т.е. снят с делегирования и освобождён.
   Контроль формата на живом примере: `example.ru` → `state: REGISTERED, NOT
   DELEGATED, VERIFIED` — значит «No entries» = отсутствие записи, а не отказ сервера.
3. **Поиск/кэш:**
   - DDG `inconify.ru` → только iconify-замены (iconify.design и пр.), ни одного упоминания.
   - DDG `"inconify" анонимайзер` → единственный хит `x.com/Inconify`.
   - X @Inconify: страница отдаётся, `<title>` = «Incon (@Inconify) / X» — аккаунт
     существует, но это несёрфовый профиль (не опровергает смерть сервиса).
   - Bing `"inconify.ru"` (mkt=ru-RU) → органика не про домен (YouTube-мусор), 0 hits.
   - Google → капча-sorry, не промерено (не критично: двух движков + реестр хватает).
   - **Yandex** (lr=213, два UA, с куки) → 14 КБ страницы, вхождений `inconify` = 0;
     прямой запрос `yandex.ru/search` без JS отдал пустой/заглушечный ответ —
     засчитываю как «не подтвердил жизнь», не как «упоминаний нет» `[claim-ограничение]`.

## 2. Архивы: снапшотов НЕТ — контент извлечь невозможно

- Wayback availability API (`http://` и `https://`, оба хоста `inconify.ru` и
  `www.inconify.ru`) → `"archived_snapshots": {}`.
- Wayback CDX точечный (`url=inconify.ru&limit=50`) → `[]`.
- Wayback CDX по домену (`matchType=domain`) и wildcard-запросы → упираются в
  **`Internet Archive: Temporarily Offline`** (баннер IA на момент промера;
  availability API при этом отвечал нормально, см. оговорку ниже).
- Memento/timetravel API → пустой ответ.
- Common Crawl: `CC-MAIN-2024-51` и `CC-MAIN-2026-21` → `No Captures found for:
  *inconify.ru`; ряд других кроулов → 504 (сервер CC перегружен, не промерено).
- archive.today → соединение не установлено (нет файла ответа).

**Оговорка о честности замера:** IA на момент промера был частично деградирован
(баннер «Temporarily Offline» на CDX-эндпоинтах), поэтому «нулевой Wayback» на 18.10
нельзя возвести в абсолют — но availability API и CDX exact отвечали штатно и дали
пусто, а независимый CC (два кроула 2024 и 2026) тоже пуст. Вердикт «архивных слёдов
нет» держится на двух независимых индексах.
Стоит пере-проверить CDX через пару дней (IA чинят), но ожидания низкие.

**Дата смерти по снапшотам — НЕВОЗМОЖНО определить:** нет ни одного снапшота,
который зафиксировал бы живое состояние. Единственная датировка, которую даёт
реестр: смерть (или хотя бы снятие регистрации) — **до 2026-10-18T15:28:01Z**
(таймстемп `Last updated` в whois Tcinet, обновлён при отдаче ответа). Верхняя
граница момента жизни неизвестна — service may have been dead for years.
Из исходного чата: упоминался как живая обёртка — значит смерть между разговором
и 18.10.2026, но точный интервал восстановить нечем.

## 3. Что сервис «умел» — только по памяти чата, не по первичке

Первички нет (сайт, архивы, CC, Bing, DDG — молчат). Рабочая версия из исходного
чата, **не проверена, в наш spec как факт не вносить**:
- RU-веб-анонимайзер PII, форма: вставка текста → masked output (веб-вставка).
- Стек: обёртка над Presidio + spaCy + Natasha (Natasha — RU NER/ морфология,
  типично для имени/дата рождения/телефон RU-форм).
- Обещаний («99 %») и тарифа извлечь нечем — `[absent]`.
- Холдер-имя сервиса и его PII-типы в открытых кэшах не светились.

## 4. Уроки для нашего spec (что унести)

1. **Архивная гигиена конкурентной разведки:** фиксировать снапшоты живых
   конкурентов *заранее* (wayback save / local mirror), иначе смерть домена =
   полная потеря intel — кейс inconify это показал на практике.
2. **NXDOMAIN + whois «No entries» + нулевой Wayback/CC** — достаточная триада
   вердикта «мёртв, intel невосстановима»; не тратить агентский браузер.
3. Продуктивный сигнал слабый, но ненулевой: ни одного архивного следа при
   упоминании в чатах ⇒ сервис был микро-сайте без маркетинга/SEO — класс «тонких
   обёрток» на Presidio/Natasha не оставил следа. Наш дифференциатор (оффлайн Rust
   демон, Fail-Closed, чексуммы-валидаторы) — не конкурентная ниша, а могила ниши.
4. Очередь живых RU-аналогов того же класса (промерены 18.10: DNS+A+HTTPS 200):

## 5. Живые RU-аналоги (для следующей очереди разведки)

1. `redactum.ru` → 194.87.131.188, HTTPS 200.
2. `docnull.ru` → 72.56.98.165, HTTPS 200.
3. `cleardoc.ru` → 45.130.41.193, HTTPS 200.
4. `aisearch.ru/obezlichivanie` → 159.194.240.91, HTTPS 200 (страница обезличивания).
   (Все — по DDG-выдаче «обезличивание персональных данных онлайн сервис»; что
   именно умеют — не залезал, задача не позволяла.)

## 6. Сырые куски промеров

```text
$ dig +short A inconify.ru          → (пусто, rc=0)
$ nslookup inconify.ru              → ** server can't find inconify.ru: NXDOMAIN
$ curl -A dsh-audit/1.0 https://inconify.ru
  curl: (6) Could not resolve host: inconify.ru   [http_code=000]

$ whois -h whois.tcinet.ru inconify.ru
% TCI Whois Service. Terms of use:
No entries found for the selected source(s).
Last updated on 2026-10-18T15:28:01Z

$ whois -h whois.tcinet.ru example.ru          # контроль формата
domain:        EXAMPLE.RU
state:         REGISTERED, NOT DELEGATED, VERIFIED

$ curl -A dsh-audit/1.0 http://archive.org/wayback/available?url=inconify.ru
{"url": "inconify.ru", "archived_snapshots": {}}
$ ... url=www.inconify.ru
{"url": "www.inconify.ru", "archived_snapshots": {}}
$ curl https://web.archive.org/cdx/search/cdx?url=inconify.ru&limit=50&output=json
[]
$ curl https://web.archive.org/cdx/search/cdx?url=inconify.ru&matchType=domain...
<html>...<title>Internet Archive: Temporarily Offline</title>...

$ curl https://index.commoncrawl.org/CC-MAIN-2024-51-index?url=*inconify.ru&output=json
{"message": "No Captures found for: *inconify.ru"}
$ curl .../CC-MAIN-2026-21-index...
{"message": "No Captures found for: *inconify.ru"}

$ DDG "inconify.ru"          → выдачи только про iconify.design (не тот домен)
$ DDG "inconify" анонимайзер  → 1 хит: https://x.com/Inconify
$ Bing "inconify.ru" mkt=ru-RU → органика не про домен
$ Yandex text="inconify.ru" lr=213 → страница 14 КБ, grep -ci inconify = 0
$ curl x.com/Inconify (browser UA) → <title>Incon (@Inconify) / X</title>
```
