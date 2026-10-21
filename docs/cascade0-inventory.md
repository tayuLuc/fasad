# Инвентарь каскада 0: детерминированные обходы

Сводная первичка всех детекторных обходов каскада 0 в одном месте: реестр
атомов, границы каждого, честный список «не покрыто», где что проверяется и
почем. Маршрут сюда: [SPEC](SPEC.md) §2 и [daemon-scope](daemon-scope.md)
§ «Что каскад 0 находит и не находит» — те документы остаются нарративом и
контрактами; здесь справочник, и он не дублирует их прозу.

Все номера строк сняты grep'ом с head ветки (commit `5a5da42`); при ребейзе
переснимать, не доверять памяти (memory law: a cited primary can move).

## 1. Атом-реестр

Конвейер каскада 0 — `scan_with` (`crates/guard-daemon/src/cascade0.rs:285`):
нормализация → окна цифр → проход числительных → проход base64 → сортировка,
дедуп, `drop_contained` (`:328`). Входная точка `scan` (`:268`), потребитель —
`pipeline.rs:350`.

### 1.1 Нормализатор

`crates/guard-detectors/src/normalize.rs` — PRE-слой перед всеми остальными атомами.

- `normalize` — `normalize.rs:186`, тонкая обёртка над `OffsetMap::build` (`:284`),
  однопроходный O(n).
- Правила (`:167–175`): удаление кириллических комбайнинг-марок (U+0483…U+0487);
  удаление zero-width (U+200B…U+200D, U+FEFF — наше расширение сверх NFKC);
  fullwidth-цифры/латиница → ASCII, широкие `Zs` → U+0020.
- Рулинг: разрывы между цифрами НЕ схлопываются — толерантность к перемычкам
  обязанность оконного слоя каскада 0 (док модуля, «Склейки разрывов между
  цифрами НЕТ», `normalize.rs:33`).
- `OffsetMap` — карта координат норма→оригинал: `map_to_original` (`:392`),
  `map_span` (`:514`), `map_span_to_original` (`:492`), `compose` (`:440`),
  `map2` (`:480`), `original_for` (`:524`).
- Сознательно не реализовано — `rules_todo` (`:530–552`), семь пунктов, в т.ч.
  U+00AD SOFT HYPHEN (п.5) и регистронезависимость (п.7).

### 1.2 Оконный слой цифр (общий для всех атомов-обходов)

`validated_windows` (`cascade0.rs:388`) — три прогона: `digit_runs` (`:470`),
окна групп `num_runs` (`:570`), `iban_tokens` (`:616`). Рамки окна:
`MAX_WINDOW_GROUPS = 5` (`:505`), `MAX_GROUP_DIGITS = 6` (`:509`).
Разделители — общий перечень с валидатором:
`checksums::NUMBER_SEPARATORS` (`checksums.rs:1116`), читают его
`sep_len`/`strip_separators` (`cascade0.rs:512,528`). Изоляция прогона —
`isolated` (`:655`): прижатый к латинице/цифре прогон номером не считается.
Кредитация хита: `push_hits` (`:661`) / `push_span_hits` (`:680`).

### 1.3 Base64-обход (PR #94, закрыт)

`scan_base64` (`cascade0.rs:854`), кандидаты `b64_tokens` (`:729`), форма
`b64_shape_ok` (`:762`), декод `b64_decode` (`:806`, `Zeroizing`).
Константы: `B64_MIN_PAYLOAD_BYTES = 11` (`:706`), `B64_MIN_TOKEN_BYTES = 16`
(`:711`). Границы — в §2.2. Спан кредитзуется на исходный токен, источник
`base64_decode` (`guard-types/src/verdict.rs:102`), вес 1.0.

### 1.4 Числительные словами (issue #51 п.2, влит PR #118)

`crates/guard-daemon/src/numwords.rs`: `spelled_numbers` (`:243`), структура
`Spelled {range, digits}` (`:226`, `digits` в `Zeroizing`). Интеграция —
`scan_words` (`cascade0.rs:826`): собранные цифры едут в те же
`validated_windows`, спан возвращается на фразу словами; порог
`MIN_SPELLED_DIGITS = 9` (`cascade0.rs:218`). Источник остаётся
`checksum_rf`/`checksum_eu`, восьмой вариант `DetectionSource` не заводён.
Границы — в §2.1.

### 1.5 Чексуммы (реестр валидаторов)

Вызов по имени из схемы — `call_validator` (`cascade0.rs:223`); таблица длин
`DIGIT_SPECS` (`:149`), IBAN отдельно (`:203`). Схема по умолчанию —
`config/schema.default.json` (класс → валидатор). Позиция «в каскаде 0» для
банковских строк — «формат без класса»: валидатор живёт в коде, класса схемы
у него нет (`schema.default.json`, примечание: «объявить класс без измерения =
заводской номер на неповеренном приборе»).

| Класс | Функция | Валидатор (checksums.rs) | Формула (первичка dep-verify-algorithms.md) | Вес | Контракт-тест |
| --- | --- | --- | --- | --- | --- |
| ИНН-10 | `inn10` (`:126`) | mod 11, веса удвоением | §1 | 1.0 | `reference_vectors.rs:131` · §1: `checksums.rs:1318,1338` |
| ИНН-12 | `inn12` (`:140`) | mod 11 две ступени (cd11, cd12) | §2 | 1.0 | тот же TSV · §2: `:1365` |
| СНИЛС | `snils` (`:190`) | веса 9..1, mod 101, floor >001001998 | §3 | 1.0 | тот же TSV · §3: `:1393,1423` |
| ОГРН-13 | `ogrn13` (`:286`) | mod 11 + структурное вето п.7 165н (`ogrn_structure_ok` `:252`) | §4 | 1.0 | тот же TSV · `:1479,1547` |
| ОГРНИП-15 | `ogrnip15` (`:316`) | mod 13 + вето (С∈{3,4}, КК≠00) | §4 (SPEC-«mod11» опровергнут замером) | 1.0 | тот же TSV · `:1479,1547` |
| Карта (PAN) | `luhn` (`:375`) | Луна ISO 7812-1:2017, 12..19 цифр | §5 | 1.0 | тот же TSV · `:1650`; hint `mir_bin` (`:393`) — тип, не фильтр |
| IBAN | `iban` (`:1210`) | ISO 13616: реестр 89 стран (`IBAN_REGISTRY` `:440`) + mod-97 (`:1169`) | §7/§7a | 1.0 | тот же TSV |
| БИК | `bik_format` (`:1247`) | формат: 9 цифр с `04` (чексуммы нет, 383-П; SPEC-«спец 000/001/002» кодом НЕ реализован, вето на них нет — `checksums.rs:1239–1246`); ловушка `040106…` (форма ОКУД) — за словарным слоем | §7 | 1.0 | тот же TSV (семейство `bik`) |
| Счёт банка | `bank_account_format` (`:1279`) | формат: 20 цифр, префикс `ACCOUNT_PREFIXES` (`:1262`: 3010/3011/40/42; полная таблица 809-П не собрана) | §7/§7a | 1.0 | тот же TSV (семейство `account`) |
| Пара БИК↔счёт | `bik_account_cross` (`:1295`) | перекрёст БИК[1:3]==счёт[6:8]; в оконный сканер не смонтирован (атом B, `cascade0.rs:147–149`) | §7 | 1.0 | тот же TSV (семейство `bik_account`) · `:2203` `#[ignore]` (расхождение первички) |

Эталонные векторы — `data/golden/reference-vectors.tsv` (таблицы из
`dep-verify-algorithms.md` §1–§7; читают
`crates/guard-detectors/tests/reference_vectors.rs:131` (сверка) и `:195`
(покрытие семейств)). Ожидаемое NEVER вычисляется проверяемой функцией
(AGENTS §Дисциплина фактов п.3). Вектор весов — контракт
`crates/guard-types/tests/invariant_checksum_w.rs:233` (выпадение base64-декода
из ручки весов краснит тест).

### 1.6 Секреты (атом live, НЕ смонтирован в демон)

`crates/guard-detectors/src/secrets.rs` — трёхфазник SPEC §2: префикс-фильтр
`aho_corasick` по якорям `ANCHORS` (`:217`, 16 якорей) → валидация тела в окне
`WINDOW = 200` байт (`:162`, `validate_body` `:422`) → энтропия Шеннона
(`shannon_entropy` `:530`, 16-грамма `ENTROPY_WINDOW` `:165`, порог
`ENTROPY_THRESHOLD = 4.0` `:170`, `entropy_pass` `:485`). Confidence: формат
`0.95` (`:156`), entropy-only `0.60` (`:158`). API: `SecretScanner::new`
(`:370`), `scan` (`:381`), convenience `scan` (`:564`). Классы `SecretKind`
(`:91`): AWS `AKIA`, GitHub `ghp_/gho_/ghs_/ghu_/ghr_`, fine-grained
`github_pat_`, OpenAI `sk-/sk-proj-/sk-svcacct-`, Google `AIza`, Slack
`xoxb-/xoxp-`, GitLab `glpat-`, JWT `eyJ`, `HighEntropy`. Probability-of-Randomness
из SPEC §2 кодом нет — только энтропия Шеннона (первичка: `secrets.rs:34–35`).
Проверяется: `secrets.rs:577–819` (`format_vectors_hit_with_confidence_095`,
anti-FP-классы `word_skiff_and_skincare_not_format_openai`,
`eyj_midword_not_jwt`, `hex_strings_do_not_trigger_entropy`).
Монтаж: в `pipeline.rs` / каскаде 0 демона не вызывается — grep
`secrets::|SecretScanner` по `crates/guard-daemon/src` пустой; SPEC §10 п.3
(сборка детектора в демон) — атом впереди.

### 1.7 Автомат Ахо–Корасик маркеров (атом live, НЕ смонтирован в демон)

`crates/guard-detectors/src/dictionary.rs` — один `AhoCorasick` на весь список
маркеров (ОПФ, адресные, паспортные, суффиксы отчеств): `DictionaryMatcher::new`
(`:62`), `match_spans` (`:78`), convenience `match_spans` (`:177`). Списки слов
приходят из конфигурации (`config/schema.default.json`), не хардкод.
Ограничения по первичке: ASCII-case-insensitive (кириллица матчится
регистр-сохраняюще, `:10–17`); `WordBoundary::Ascii` (`:36`) — граница по
символу-соседу, кириллица слово продолжает. Проверяется: `dictionary.rs:256,281`
(word-boundary), `:222` (кириллический регистр — задокументированное
ограничение). Монтаж в демон — тот же атом SPEC §10 п.3, что у секретов.

## 2. Границы (per-атом)

### 2.1 numwords (`numwords.rs`, интеграция `cascade0.rs:826`)

1. Порог: 9 цифр — `MIN_SPELLED_DIGITS` (`cascade0.rs:218`), числами короче
   валидаторам нечем подтверждаться; он же guard года: «тысяча девятьсот
   семьдесят один» = 1971 спана не даёт. Связь константы с `DIGIT_SPECS`
   пинит `spelled_floor_is_the_shortest_digit_spec` (`cascade0.rs:1775`).
2. Токен = максимальная цепочка кириллицы (U+0400..U+04FF, ведущие байты
   `0xD0/0xD1` — `is_cyrillic_lead` `numwords.rs:473`); латиница и цифры слово
   ОБРЫВАЮТ, не склеиваются (`latin_and_digits_split_tokens_and_never_glue`
   `:673`: «инн12двести» = 200, под порогом).
3. Разделитель между словами — всё, что не кириллица (`skip_separators`
   `:454`): дефис, табуляция, перевод строки фразу не ломают
   («двести-тридцать-восемь» = 238, `case_and_separators` `:571`). Мягкий
   перенос U+00AD нормализатором НЕ убирается (`rules_todo` п.5) — в тексте с
   переносами на границе строк фраза рвётся на куски, и это следствие
   перечисления, а не кода слоя.
4. Покрытие: количественные 0..=999 триллионов (вложенный масштаб —
   `closing` `:369`, `scale_powers_are_ordered` `:683`), именительный +
   родительный падеж, женский род единиц, `ё` в обеих ипостасях
   (`yo_is_accepted_both_ways` `:583`).
5. Не покрыто (зафиксировано в доке модуля `:28–48`): порядковые
   (`ordinal_breaks_the_phrase` `:644`), знак, дроби/собирательные
   (`sign_and_fraction_are_not_covered` `:653`), даты словами, диктовка
   «цифра за цифрой» (`digits_never_concatenate_across_a_break` `:590`),
   ведущие нули (слов для них не бывает → БИК и 20-значный счёт словами
   недостижимы), падежи кроме двух, союз «и» между разрядами.
6. FP-контроль: спан только по подтверждению валидатора; задокументированный
   FP-класс — круглые количества: «пять миллиардов» = 5000000000 проходит
   ИНН-10 (`spelled_round_billion_is_the_documented_tradeoff`
   `cascade0.rs:1983`); обмен FN→FP работает в пользу нахождения.
7. LUHN-подтверждение словами: `spelled_card_pan_passes_luhn` (`:1830`),
   реестровые — `spelled_registry_numbers_fire` (`:1849`).
8. Потолок спана — КАКОЙ СЕЙЧАС по head: `MAX_ORIGINAL_BYTES = 128`
   (`crates/guard-vault/src/token.rs:53`, переснято grep'ом) — фраза словами
   длиннее 128 Б даёт `TooLong` → `503 span_too_long` (fail-closed); пинит
   `crates/guard-daemon/tests/vault_span_cap.rs` (`:138` отказ, `:182` маска
   ниже потолка). Решение по потолку — issue #120, слоем не реализуется.
9. Вложенность: числительные внутри base64-нагрузки не ищем (`scan_words`
   читает нормализованный текст; `words_inside_base64_are_not_scanned`
   `cascade0.rs:2003`).

### 2.2 base64 (`cascade0.rs:854`)

1. Кандидат: пробельная граница с обеих сторон (`b64_tokens:743–744` —
   `is_ascii_whitespace`; в норме все широкие Zs уже сведены к U+0020), длина
   кратна 4 и ≥ `B64_MIN_TOKEN_BYTES = 16` (`:711`), паддинг `=` только
   хвостом ≤ 2, алфавит в токене не смешан (`b64_shape_ok:762`; стандартный и
   url-safe принимаются по отдельности).
2. Декод: сначала standard, затем url-safe (`b64_decode:806`); полезная
   нагрузка ≥ `B64_MIN_PAYLOAD_BYTES = 11` байт — ИНН-10 с одной перемычкой;
   blob ровно из 10 цифр не проверяется — принятый FN
   (`base64_payload_floor_is_the_documented_tradeoff` `:1559`).
3. Окно: нагрузка проходит тот же слой, что текст — UTF-8-with-losses →
   `normalize::normalize` → `validated_windows`; фильтр «в нагрузке есть
   цифра» стоит ПОСЛЕ нормализации (полноширинные цифры, ревью #94 F-1;
   `base64_fullwidth_digits_match_the_text_path` `:1346`).
4. Вложенность ровно один уровень: кандидатов в нагрузке не ищем
   (`base64_nesting_is_exactly_one_level` `:1427`; рекурсия = неограниченный
   CPU на вражеском входе).
5. FP-контроль: спан только по подтверждению валидатора; случайные байты,
   JWT-сегменты (`a.b.c` не стоит на пробельной границе) и base64 текста без
   цифр спанов не дают (`base64_negative_registry` `:1471`). Маркер
   обратимости нашего vault (`[[F0#base64url]]`, `MARKER_PREFIX` `token.rs:96`)
   кандидатом не является — прижат к `#`, самого-маскирования токена прокси
   нет (`r7_vault_markers`, `tests/cascade0_bypass_review94.rs:454`).
6. Координаты = исходный токен: `span = map.map_span_to_original(токен)`
   (fail-closed на не-char-границе), декод наружу не отдаётся
   (`base64_span_sits_on_original_bytes` `:1448`).
7. `Zeroizing`: залочены декод и его строковая копия; третий буфер (копия
   нормализатора) не залочен — осознанный паритет с текстовым путём, чинится
   в нормализаторе (ревью #94 F-3).

### 2.3 Общий оконный слой (границы, общие для числовых атомов)

1. Прогон изолирован: прижатый к латинице/цифре номером не считается
   (`isolated:655`, `glued_digits_are_not_numbers` `:1166`); кириллица соседом
   не считается — «ИНН7785240858» без пробела типична.
2. Рамки окна: ≤5 групп, ≤6 цифр в группе (`:505,509`) — «1000000000
   2000000000» не склеивается в счёт (`window_frames_refuse_plain_number_pairs`
   `:1089`).
3. Разделители внутри номера: 6 позиций `NUMBER_SEPARATORS`
   (`checksums.rs:1116–1123`): пробел, U+002D, U+2010, U+2011, U+2012, U+FF0D.
   Точка и косая черта в наборе сознательно нет (даты/дроби, док перед
   `MAX_WINDOW_GROUPS`).
4. Перекрывающиеся классы — вектор, не победитель; из вложенных спанов одного
   класса остаётся самый широкий (`drop_contained:328`).

## 3. НЕ покрыто (открытые issues, промер gh live на этом head)

| Issue | Заголовок (gh) | Где болит (первичка) |
| --- | --- | --- |
| #51 п.1 (OPEN) | транслит RU→LAT / LAT→RU в препроцессинге | нормализатор транслита не знает: `normalize.rs` правил 1–4 (§1.1), Ушаков/Ushakov не сводятся; пункт принят к рассмотрению, не реализован |
| #101 (OPEN) | NUMBER_SEPARATORS: нет U+2013/U+2014/U+2212 | в перечне их нет по head (`checksums.rs:1116–1123`): номерок из Word/PDF с длинным тире не склеивается — FN-класс |
| #102 (OPEN) | MAX_WINDOW_GROUPS=5 → FP на перечислениях «1000 2000 3000 4000» | рамка `cascade0.rs:505` + LUHN ~10 % на 16 цифрах |
| #26 (OPEN) | чексумма-совпала ⇒ маркер не обязателен (FN-хвост golden) | хвост покрытия golden-v1, `docs/golden-report.md`; гейт recall меряет его родителю |
| #72 (OPEN) | опознавание владельца регистрозависимо (одна фамилия в двух регистрах) | не каскад 0, смежный слой vault/morph (`guard-vault/src/morph.rs`); в инвентаре как граница «что детерминированный путь не чинит» |
| #65 (OPEN) | PendingForms: ключение владельца поверхностью токена | движок `crates/guard-vault/src/morph.rs` (`MorphTable` `:360`); SPEC §3 ссылка «открытая задача #65» (`SPEC.md:156`) |
| #120 (OPEN) | vault-потолок 128 Б × словесные номера = вечный 503 | `token.rs:53`; контракт `vault_span_cap.rs`; слоем не решается (§2.1 п.8) |
| — (монтаж) | secrets/dictionary live в библиотеке, в демон не вызваны | §1.6/§1.7; атом SPEC §10 п.3 |
| — (диктовка) | «цифра за цифрой» не склеивается | numwords док `:40–42`, `digits_never_concatenate_across_a_break` |
| — (словами) | БИК и 20-значный счёт словами недостижимы (ведущие нули) | numwords док `:44–45` |

## 4. Контроль: где каждый атом проверяется

| Атом | Регресс | Golden-спаны | Прочее |
| --- | --- | --- | --- |
| Нормализатор | `normalize/tests.rs:43,89,149,174` (рваная кириллица, разрывы цифр, fullwidth, идемпотентность через карту) | — | property: `normalize/proptests.rs:353,358,364` (монотонность, round-trip, алфавиты) |
| Оконный слой цифр | юниты `cascade0.rs:925–1238` (`golden_values_are_found`, `formatted_numbers_are_found_with_full_span`, `nested_windows_collapse_to_the_widest`, `window_frames_refuse_plain_number_pairs`, `iban_ru_from_golden_is_found_with_source_eu`, `invalid_vectors_from_reference_table_are_not_hits`, `glued_digits_are_not_numbers`, `overlapping_classes_are_a_vector_not_a_winner`) | `crates/guard-daemon/tests/cascade0_golden.rs`: `:82` покрытие recall-сплита, `:115` форматированный номер, `:227` negative-split (приманки) | эталоны чексумм: `reference_vectors.rs:131,195`; контракт весов `invariant_checksum_w.rs:233` |
| base64 | юниты `cascade0.rs:1283–1659` (payload/span/nesting/алфавиты/флор/векторы) | `cascade0_golden.rs:276` (каждое золотое значение в base64), `:332` (приманки base64-доставки) | независимый review-набор `tests/cascade0_bypass_review94.rs` (`r1`–`r9`, `:61–454`); промер `REVIEW94|fill_100KiB` (`:83`) |
| numwords | юниты `numwords.rs:507–683` (task_vectors, роды, падежи, вложенный масштаб, разделители, рестарт) + `cascade0.rs:1775–2003` (порог, год, золотые словами, schema, coexist, FP-класс, base64-паритет) | золотые значения словами: `spelled_inn12_fires_with_the_phrase_as_span` `:1808`, `spelled_card_pan_passes_luhn` `:1830`, `spelled_registry_numbers_fire` `:1849` (значения взяты из `data/golden/golden-v1.jsonl`, не пересчитаны); контракт потолка `vault_span_cap.rs:138,182` | — |
| Секреты | юниты `secrets.rs:618–819` (форматные векторы 0.95, anti-FP, энтропия) | — | — |
| Dictionary | юниты `dictionary.rs:212–346` (регистр, границы, байтовые спаны) | — | — |
| Монтированность пути | `tests/cascade_parity.rs` (`cascade0::scan` vs `pipeline::analyze`), `tests/cascade_http.rs`, `tests/cascade_failclosed.rs` | — | — |
| Микромеры (горячий путь, `#[ignore]`, release, щадящий режим) | B64MICRO: `cargo test --release -p guard-daemon --lib base64_bypass_hot_path -- --ignored --test-threads=2 --nocapture` (`cascade0.rs:1694`) · WORDMICRO: `cargo test --release -p guard-daemon --lib words_hot_path -- --ignored --test-threads=2 --nocapture` (`:2030`) | — | — |

## 5. Цена (числа пересняты с head-доков; источником печати является код)

| Что | Число | Откуда (код печати → где задокументировано) |
| --- | --- | --- |
| numwords-слой, 10 КиБ русской прозы | `WORDMICRO|prose|bytes|10270|found|0|iters|500|min_us|91|median_us|109` (~9 % бюджета каскада 0) | печать `cascade0.rs:2056` → `daemon-scope.md:163` |
| base64-обход, горячий путь (100 кандидатов / 10 КиБ, release) | +124 мкс min | `cascade0.rs:1697` (ноги before/after) → `daemon-scope.md:96–97` |
| base64, плотный корпус `blobs|100` после влития слов | 264 мкс min (было 136 до) | те же ноги `cascade0.rs:1697` → `daemon-scope.md:165–166` |
| 100 КиБ base64-заливки без цифр | 26.6 мс debug (наш промер); 21.8 мс debug / 1.2 мс release (промер ревью #94) | печать `tests/cascade0_bypass_review94.rs:83` → `daemon-scope.md:93–95` |
| Тело = один base64-токен на потолке 1 МиБ | 29.2 мс release (в бюджете SPEC 80–300 мс) | `daemon-scope.md:95–97` (предел `config.rs:33` `DEFAULT_MAX_BODY_BYTES = 1_048_576`) |
| Потолок words-слоя (регресс-утверждение) | min < 2 мс на 10 КиБ | assert в `cascade0.rs:2034` |

Бюджет каскада 0 (<1 мс) — SPEC §2; метрика recall (гейт ≥98 %, N≥150,
Вилсон) измеряется родителем на харнесе, KNOWN-RED B1 остаётся `#[ignore]` —
`daemon-scope.md` § «Что каскад 0 находит и не находит» п.5.
