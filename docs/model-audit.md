# Model audit — шаг 2 spike (issue #6)

Прогон: 2026-10-19, macOS (arm64), rustc 1.97.1, ort 2.0.0-rc.14 (download-binaries,
статик libonnxruntime.a, CPU EP), spike = `crates/guard-onnx/examples/spike.rs`.
Профиль: **debug** — release-прогон проводился ×5 и падал SIGSEGV 139 в обеих конфигурациях (plain, env 26.0), [model-audit-weights.md §W2 п.1](model-audit-weights.md); гейт бюджета закрыт dev-числами с оговоркой профиля.
Веса: `~/.cache/fasad-models`, манифест `models/manifest.tsv`.

> **Разделение 22.10 (ротация >300 строк, vault-правило «split at ~300», репо-обычай
> `dep-verify-*`):** этот файл = модели, веса и RAM-промеры релизного контура
> (§1–§3, §8–§10). IO-контракты, дефекты харнесса, парити и recall каскада-2
> (бывшие §4–§6 → §W1–§W3) вынесены в
> [model-audit-weights.md](model-audit-weights.md); латентность, чанкинг и
> калибровка α (бывшие §11–§12 → §I1–§I2) — в
> [model-audit-inference.md](model-audit-inference.md). Ссылка «model-audit §N»
> при N ∈ {1, 2, 3, 8, 9, 10} ведёт сюда; §4/§5/§6 (любой, в т.ч. §5.6, §5.7,
> §5 п.N) — в спутник №2; §11/§12 — в спутник №1. Нумерация §8–§10 НЕ сдвинута:
> §7 в файле не было, внешние ссылки на §8/§9/§10 (CI, скрипты, release-доки)
> валидны без правок.
>
> **Карта шва.** Голые §-ссылки секций §8–§10 этого файла на §5.N/§5 п.N/§6 —
> промеры, уехавшие в [model-audit-weights.md](model-audit-weights.md)
> (§5.6 → §W2.6, §5.7 → §W2.7, §6 → §W3; §5 п.N → §W2 п.N. §5.1–§5.5 и
> §5.N.M п.K НЕ существовали: §5 нумеровал только п.1–п.4 + аддендумы §5.6/§5.7,
> «§5.1» в коде до #133 был опиской — владелец §W2 п.1, см. #136; §5.7 п.K →
> §W2.7 п.K. §Graph = §W2 п.2 — маркер секции HF-карточки Decide). Внутренние ссылки
> спутников на секции друг друга помечены файлом-владельцем.

## Оглавление (компас)

- §1 Модель A — веса · §2 Метрики прогона (сырые METRIC) · §3 Маппинг external data
- §8 Релизный путь ORT (dylib 1.31.0) · §9 Release RSS (каскад-0) · §10 RSS демона с каскадами 1–2 (+10.8 покрытие golden, +10.9 обрыв «№»)
- Спутник №2 [model-audit-weights.md](model-audit-weights.md): §W1 IO-контракты (бывш. §4) · §W2 Дефекты харнесса (бывш. §5: +W2.6 «position-limit 512», +W2.7 парити/recall) · §W3 CI-контракт (бывш. §6)
- §11 Чанкинг пути запроса и §12 α-калибровка — переехали в [model-audit-inference.md](model-audit-inference.md) §I1/§I2


## 1. Модель A — веса (промер shasum -a 256 = LFS-oid HF, rev из GET api/models)

| file | repo@rev | bytes | sha256 |
|---|---|---|---|
| model.optimized.fp16.onnx | lockR/rubert-base-pii-ner-onnx@ea7610b2 | 355 541 615 | 039aba6b…c70a501 |
| onnx/model_q4f16.onnx | onnx-community/GLiNER2.5-Decide-ONNX@18271032 | 341 889 | 93f3e0d4…6381684f6 |
| onnx/model_q4f16.onnx_data | (там же) | 523 127 808 | df2b05dc…e66210e8 |
| tokenizer.json (rubert) | lockR | 3 714 701 | f61eee9d…89dec1b9 |
| tokenizer.json (decide) | onnx-community | 8 333 952 | 3ad87d9f…df467bcc8 |

Скелет манифеста (issue-промер) содержал ошибку размера external data:
1 744 089 088 B — это `model.onnx_data` **fp32**; для q4f16 = 523 127 808 B (промерен
tree-API и файлом на диске). Исправлено в манифесте.

## 2. Метрики прогона (сырые METRIC-строки, dev-профиль, threads=4)

```text
METRIC|rss_mib_baseline|2.2
METRIC|env_init_ms|23.0
METRIC|rss_mib_after_env|7.5
IO|external_data_bytes|523127808
METRIC|rss_mib_before_load_arbiter|7.5
METRIC|rss_mib_after_load_arbiter|269.0
IO|in|arbiter|input_ids|Tensor<i64>(batch, sequence)
IO|in|arbiter|attention_mask|Tensor<i64>(batch, sequence)
IO|in|arbiter|marker_positions|Tensor<i64>(batch, markers)
IO|out|arbiter|logits|Tensor<f32>(batch, markers)
```

## 3. Ключевой вопрос §1.8: маппинг external data

Сессия арбитра (graph + external data 523 МБ) поднялась с RSS 7.5 → **269.0 MiB (первый прогон) / 250.3 MiB (второй прогон, воспроизводимость ±7%)**.
Вывод: q4f16 external data **НЕ маппится целиком в resident-RSS** — ORT лениво/
частично подгружает веса (промер private-RSS `task_vm_info.internal`, «Память»
как в мониторе активности). Бюджет SPEC §1 (≤1.8 ГБ):
355 МБ (lockR fp16, полный load ожидается в шаге 4) + ~0.3 ГБ арбитр-резидент
+ арены/токенизаторы/буферы ≈ **0.9–1.2 ГБ прогноз — вписывается**, окончательный
вердикт после промера lockR-сегмента (см. [model-audit-weights.md §W2](model-audit-weights.md):
инференс-прогон упал на GatherElements до lockR-мерки).

## 8. Релизный путь ORT: официальный dylib 1.31.0 (issue #11, шаг 4a)

1. Причина (промеры §W2 п.1): статик-pyke на macOS release = SIGSEGV (chained fixups ×
   deployment target 11.0, unresolved `___isPlatformVersionAtLeast` → jmp 0x0); орт-дока и
   §9 SPEC: релиз поставляет dylib — статик-режим остаётся только CI-линтовкой.
2. Версия: api-31 (орт rc.14) ⇒ минимум ORT **1.31.0**; graceful-эскалация
   подтверждена промерами rc.14 с 1.20.1/1.23.0/1.24.4/1.26.0: exit 101
   «requested API version [31] not available» без краша (sysrc /tmp/mg43-45).
3. Артефакты релиза v1.31.0 (github.com/microsoft/onnxruntime/releases/tag/v1.31.0,
   sha256 промерены загрузкой 19.10):
   - macOS arm64: `onnxruntime-osx-arm64-1.31.0.tgz`
     sha256 1031b36dd3bdaa8d976a6130d9cf2a05e9be320b93ae804f8427b91dc3432afc (36 549 009 B);
     dylib внутри: sha256 2a50a63e7f41f8d4d551d3ee47248df3864f6540109fce8ad520ca3b51af4b70.
   - Linux x64: `onnxruntime-linux-x64-1.31.0.tgz`
     sha256 cc5c72baf5ae5c8238a6841f0897227be2d02826b9cf98eaf02fdefaeeb03a57 (11 408 003 B).
   - Windows x64: nupkg `Microsoft.ML.OnnxRuntime.1.31.0` (рантайм-dll в runtimes/win-x64/native,
     доставка copy-dylibs в шаге 9; sha256 — отдельный промер, не заявляем).
   - Артефакты НЕ коммитятся в git (AGENTS §Не тащим веса); CI ort-прогонов нет ([§W3](model-audit-weights.md)).
4. Сборка: `ORT_PREFER_DYNAMIC_LINK=1 ORT_LIB_PATH=<dir>/lib cargo build --release
   --features ort-inference` — build.rs дописал rpath-ветку (macos|linux), just-рецепты
   `ort-dylib`/`spike-dylib`. Релизный прогон 19.10 (сырой /tmp/mg48-49.out):
   exit=1 (GatherElements-заглушка §W2 п.3 — до живых marker_positions шага 4b), env_init
   37.8–40.3 ms, rss_after_load_arbiter 379.4–387.4 MiB — бюджет-гейт release закрыт.

## 9. Release RSS (шаг 9, релизный контур, SPEC §10 п.9)

Замеры живые (21.10), метод печатается в каждой строке вывода
`scripts/measure-rss.sh`: контур каскада-0 = `ps -o rss` (KB→MiB) плюс macOS
`footprint phys_footprint` («Память» Activity Monitor); контур полного каскада
= in-process `task_info(TASK_VM_INFO).internal` из C-острова
`crates/guard-onnx/spike/rss_mach.c` (Linux-ветка — `/proc/self/status` VmRSS).

Хост: macOS arm64, rustc 1.99.1, профиль `release` (`lto="fat"`,
`codegen-units=1`, `panic="unwind"`, `strip="symbols"` — `[profile.release]`
в Cargo.toml). Замер при `FASAD_THREADS=2`, `CARGO_BUILD_JOBS=2` (рюлинг
оператора 21.10 «не грузить CPU ноута», прогоны по одному за раз). Настоящий
рычаг потоков демона — `FASAD_THREADS` (`crates/guard-daemon/src/config.rs:76`,
дефолт 8; граница монтажа — п.4: на `cascade-0-only` инертен, с #87 жив на пути
каскадов 1–2); харнеса — флаг `--threads` (`crates/guard-onnx/examples/spike.rs:158`
`unwrap_or(4)`). `OMP_NUM_THREADS` в методику НЕ входит: он инертен, вендорный
`libonnxruntime` osx-arm64 собран без OpenMP и переменную не читает (первичка
правки к рюлингу — `otool`/`strings` по dylib, ревью #73). Точки, инструменты
и семантика вердикта не менялись относительно §W2.6.

1. **Каскад-0 (публикуемый бинарь `target/release/fasad`, HTTP-прогон).**
   `just measure-rss` поднимает демон на `FASAD_PORT=0`, прогревает 3×
   `/v1/analyze` и 1× `/v1/anonymize` (контракт `vault.rs::AnonymizeRequest =
   {text, spans}`: спаны берутся из ответа analyze, голый `{"text":…}` = 400 —
   промер живым POST 21.10) и снимает две точки. Сырые строки прогона при
   `FASAD_THREADS=2` (INFO: `env=FASAD_THREADS=2`):
   `RSS|cascade0|idle|2.7|ps -o rss (KB->MiB, resident)`,
   `RSS|cascade0|idle|1.4|footprint phys_footprint (macOS, «Память» Activity Monitor)`,
   `RSS|cascade0|after_warm|3.4|ps -o rss (KB->MiB, resident)`,
   `RSS|cascade0|after_warm|1.6|footprint phys_footprint (macOS, …)`,
   вердикт `BUDGET|cascade0|ok|peak_mib=3.4|budget_mib=1843.2`.
   Числа не перепечатаны от руки: их печатает `just measure-rss --cascade0
   --doc-rows` — флаг генерирует markdown-блок и `BUDGET`-строку из артефакта
   того же прогона (рюлинг kernel 21.10: «число, вписанное в документ от руки,
   — claim; цифры документа генерируются из артефакта»). Повторный прогон тем же
   флагом 20.10 воспроизвёл блок дословно: idle 2.7/1.4, after_warm 3.4/1.6,
   `peak_mib=3.4`.
   Прогон на демоне с дефолтом `FASAD_THREADS=8` — три запуска 21.10 тем же
   флагом, строки печатает скрипт (`INFO|cascade0|pid=…|env=FASAD_THREADS=8`):
   `peak_mib=3.3`, `peak_mib=3.3`, `peak_mib=3.4` при idle 2.7/1.4 все три раза.
   Прежнее число `peak_mib=2.8` (и idle 2.2) было ОДИНОЧНЫМ неавторитетным
   прогоном и не воспроизводится: ревьюер #76 получил 3.4, мои повторы —
   3.3/3.3/3.4 (ревью #76, F4).
   Разброс `ps` против `footprint` ≈ 1.2 MiB — это разные метрики (resident
   против phys_footprint), обе строки остаются в выводе, метод не выбирается
   в пользу одной. Пик = 0.15 % бюджета SPEC §1 (1843.2 MiB): контур демона
   бюджет не задействует.
2. **Полный каскад 1–2 (харнес spike, релизный профиль, официальный dylib ORT
   1.31.0, `--arb-budget --arb --lockr`; веса из кэша `~/.cache/fasad-models`
   по models/manifest.md):**
   `RSS|full|peak_both_models|976.3|spike task_info …` (метод в самой строке),
   вердикт
   `BUDGET|full|ok|peak_mib=976.3|budget_mib=1843.2` (53 % бюджета) при
   `--threads 4` (дефолт харнеса), wall-clock 2m42s. Прогон `--threads 2`
   (рюлинг 21.10): `RSS|full|peak_both_models|889.1`,
   `BUDGET|full|ok|peak_mib=889.1<1843.2` (48 % бюджета), wall-clock 10m20s.
   Для бюджета держим КОНСЕРВАТИВНУЮ точку 976.3 = max из двух (та же
   семантика, что в §W2.6 п.5).
3. **Оговорка профиля (§W2 п.1, §W2.6 п.5) по этой точке снята.** Прежний
   бюджет-гейт был закрыт dev-числом `peak_max = 1434.6 MiB` (3 прогона 19.10,
   debug-профиль — заголовок §2 «dev-профиль», §W2 п.1 про SIGSEGV release на
   статике pyke). Релизный профиль на официальном dylib = 976.3 MiB, на
   458.3 MiB меньше (арифметика над двумя промеренными числами):
   dev-консервативность подтверждена в безопасную сторону. Причина разницы
   (lto/codegen-units против раздувания обобщений ort/tokenizers в debug)
   не промерена и не заявляется.
4. **Потоки: на каскаде 1–2 влияют, на каскаде-0 не влияют (промер 21.10,
   N=4).** Полный каскад `--threads 4` = 976.3 MiB против `--threads 2` =
   889.1 MiB ⇒ −87.2 MiB (−9 % пика; арифметика над промеренными числами, оба
   прогона полные: wall-clock 2m42s и 10m20s). Механизм (арена/пул на поток в
   ort/tokenizers) не промерен. Каскад-0: прогоны `just measure-rss` дают 3.3/3.3/3.4 MiB
   (`FASAD_THREADS=8`), 3.4 MiB (`=2`, повтор 21.10 на head `7862d74`), idle
   2.7 против after_warm 3.4. Это ПОВТОРЫ ОДНОЙ конфигурации, а не сравнение
   двух: на стадии `cascade-0-only` рычаг `FASAD_THREADS` инертен —
   `config.rs:423` разбирает его в `cfg.threads`, единственным потребителем
   поля в демоне оставался тест `config.rs:638`, а в сессию ORT потоки идут из
   `guard-onnx::arbitrate` (`intra_threads`, arbitrate.rs:261-276), куда демон
   на этой стадии не доходит (первичка grep по `crates/` на `bfb0014`, 21.10;
   рюлинг AGENTS §3 п.3; её номера `:403`/`:610` сняты с той базы, на этом
   дереве то же самое лежит на `:423`/`:638` — переснято grep'ом, класс #93).
   На смонтированном пути каскадов 1–2 (#87) рычаг живой: `cascades.rs:750`
   берёт `cfg.threads` в `Spec`, и он уходит в `LockrExtractor::load(…,
   threads)` и `DecideArbiter::load(…, threads)` (`cascades.rs:867,869`) — это
   меряет §10, не этот раздел. Значит «8 против 2 = 0.1 MiB» не аргумент:
   конфигурация сравнивалась сама с собой. Разброс 3.0..3.5 (промер
   ревьюера) и 2.7..3.4 по фазам (мой) = шум повторов, и потолком шума он не
   подаётся (ревью #76, D5). Вывод «для контура демона потоки не фактор»
   держится на устройстве контура (на каскаде-0 нет сессий ORT; §W2.6 п.5 про
   ленивость mapper’а), а не на этой паре чисел; сама пара становится
   осмысленной только с монтажом каскадов (#87). Прежняя пара «3.4 против 2.8»
   (п.1) строилась на одиночном прогоне и снята (ревью #76, F4): «−9 %» из неё было бы читательским обобщением с
   полного каскада на каскад-0. Следствие: число потоков — часть методики, оно
   печатается в INFO-строке; бюджет-вердикт считается по max из прогонов.
5. **Windows-контур не промерен.** `scripts/measure-rss.sh` на `MINGW*`/`MSYS*`
   падает с exit 2 и явной причиной (реализованы Darwin/Linux). PowerShell-метод
   (`Get-Process` `WorkingSet64`/`PrivateMemorySize64`) не реализован и не
   промерен; в CI шаг RAM-гейта на windows-2022 выключен условием
   `if: matrix.os != 'windows-2022'`. Числа для Windows = «не промерено»
   (docs/release.md §RAM).
6. **CI-coverage ветки.** Job `dist` матрицы прогоняет `just measure-rss
   --skip-build` на ubuntu-24.04 и macos-14 (Linux-ветка = `/proc/self/status`
   VmRSS, тот же контракт `RSS|…`-строк): это закрывает [§W3](model-audit-weights.md) («второй источник
   метрик с CI-матрицы, когда появится job») для каскада-0. Полный каскад в CI
   не гоняется и дальше (веса в CI не качаются, [§W3](model-audit-weights.md)), его промеры — рукаместо.

## 10. Release RSS демона с примонтированными каскадами 1–2 (шаг 9A/9B, issue #14A)

Соседняя §9 (#76) — релизный контур на каскаде 0; эта секция при rebase на неё
передвинута с §9 на §10, содержимое не менялось, кроме пункта 8 (стык первичек
по `FASAD_THREADS`) и переименования метрики стационара (§10.2).

1. Конфигурация: `cargo build --release -p guard-daemon --features
   ort-inference` (продуктовый путь — dynamic-link официальный dylib 1.31.0,
   §8; на чистой macOS эта команда без env-префикса не линкуется —
   `___isPlatformVersionAtLeast`, §W2 п.2; префикс `ORT_PREFER_DYNAMIC_LINK=1
   ORT_LIB_PATH=…` — п.4 ниже и §«Как включить монтаж каскадов 1–2» п.1 в
   `crates/guard-daemon/README.md`), `FASAD_THREADS=2` (рюлинг 21.10: ноут оператора; рычаг потоков
   инференса, `OMP_NUM_THREADS` на нашей сборке инертен),
   `FASAD_MODEL_DIR=~/.cache/fasad-models`, macOS arm64, один демон, один
   прогон за раз.
2. Метод: `scripts/measure-daemon-rss.sh` — опрос `ps -o rss=` с шагом 100 мс
   от `exec` демона до остановки (пик загрузки весов попадает в выборку),
   нагрузка N запросов `/v1/analyze` на текст со всеми классами (ФИО, паспорт,
   адрес, телефон, почта, ИНН, СНИЛС = каскады 0, 1 и 2 в одном запросе).
   Метрики: `rss_peak_mib` = максимум по всем сэмглам; стационар =
   `rss_steady_median_mib` = МЕДИАНА хвостовых 20 % сэмплов (минимум 5), то
   есть состояние после прогона, а не максимум per-request. Прежняя метрика
   называлась `rss_after_reqs_mib` и была максимумом снимков по запросам —
   пиком с именем «steady-state» (ревью #87); переименована, прогон переснят.
   `ps`-RSS = резидентные KiB вместе с общими страницами фреймворка, то есть
   консервативная верхняя оценка (то же семейство метрик, что `/proc/self/status`
   VmRSS на Linux). Сырые METRIC-строки прогонов — артефакт `/tmp/rss_9b_final.txt`.
3. Числа (сгенерированы из артефакта прогона на дереве `dbce8ca`, не набраны):
   - `METRIC|samples|72|rss_peak_mib|853.9` + `steady_samples|14|rss_steady_median_mib|398.8` (N=5);
   - `METRIC|samples|161|rss_peak_mib|936.2` + `steady_samples|32|rss_steady_median_mib|321.4` (N=20);
   - `METRIC|samples|338|rss_peak_mib|730.1` + `steady_samples|67|rss_steady_median_mib|366.2` (N=50).
   Вердикт гейта во всех трёх: `METRIC|budget|1843.2|verdict|ok`, и заголовки
   того же прогона: `stage_header|cascade-0+models|cascade2_header|ok`.
4. Против гейта SPEC §10 п.9 (≤1.8 GiB = 1843.2 MiB): консервативный пик
   936.2 MiB (максимум из трёх прогонов) = 50.8 % бюджета, запас 907.0 MiB.
   Стационар (медиана хвоста) = 321.4–398.8 MiB. Пик НЕ растёт с N (853.9 →
   936.2 → 730.1 при N=5/20/50), то есть это пик загрузки весов, а не
   накопление: прироста, который можно было бы читать утечкой, на этих трёх
   прогонах нет. Вывод прежней редакции («рост пика затухает: +369 за 15
   запросов, +48.5 за 30») снят — он построен на метрике, которая была пиком
   per-request, и на шуме шага опроса 100 мс.
5. Числа §W2 п.5 (харнес: 1330.9/1434.6/1434.4 MiB) с этими НЕ сравнимы и не
   пересчитываются: там `task_info` private-RSS + `vmmap footprint` на
   threads=4 в прогоне харнеса, здесь `ps`-RSS демона на threads=2. Единый
   метод съёма для пары «харнес/демон» — задача релизного контура (#76),
   здесь зафиксирован собственный метод промера вместе с цифрой.
6. Проводной контроль fail-closed старта тем же бинарём:
   `FASAD_MODEL_DIR=/tmp/fasad-empty-models` (пустой каталог) →
   `exit=2`, stderr `fasad: старт невозможен: модельный каскад не загружен: нет
   файла /tmp/fasad-empty-models/lockR/rubert-base-pii-ner-onnx/model.optimized.fp16.onnx
   (каталог весов …, раскладка — scripts/fetch-models.sh)`, сокет не поднят.
   Молчаливого `cascade-0-only` на названном `model_dir` нет ни на одной ветке.
7. Дефект доставки, найденный этим промером: release-бинарь демона умирал до
   `main` (`Abort trap: 6: Library not loaded: @rpath/libonnxruntime.1.dylib …
   Reason: no LC_RPATH's found`). Причина: rpath печатает `build.rs` крейта
   `guard-onnx` через `cargo:rustc-link-arg-examples`, а link-args не
   распространяются на цели чужих пакетов; dev-тесты яму не видят, потому что в
   dev `ort` унифицируется в `load-dynamic` и грузит dylib через `dlopen`,
   которому `DYLD_LIBRARY_PATH` достаточно. Лечится
   `crates/guard-daemon/build.rs` (`cargo:rustc-link-arg-bins=-Wl,-rpath,
   $ORT_LIB_PATH`, macOS/Linux); Windows-ветка — `copy-dylibs` (#76).
8. Стык первичек по `FASAD_THREADS` (оба факта верны, граница — монтаж). На
   стадии `cascade-0-only` рычаг инертен: `config.rs:423` разбирает его в
   `cfg.threads` (дефолт 8 = `DEFAULT_THREADS`, `config.rs:76`), единственным
   потребителем поля в демоне оставался тест `config.rs:638`, а потоки в сессию
   ORT идут из `guard-onnx::arbitrate` (`intra_threads`, параметр
   `arbitrate.rs:261`, `.with_intra_threads(…)` `arbitrate.rs:276`), куда демон
   на этой стадии не доходит (первичка #76 — grep по `crates/` на `bfb0014`; её
   номера `:67`/`:403`/`:610` сняты с той базы, на этом дереве то же самое лежит
   на `:76`/`:423`/`:638`, переснято grep'ом). На смонтированном пути (этот PR)
   рычаг живой: `cascades.rs:750` берёт `cfg.threads` в `Spec`, и он уходит в
   `LockrExtractor::load(…, threads)` и `DecideArbiter::load(…, threads)`
   (`cascades.rs:867,869`), то есть в обе модельные legs. Все числа этого раздела сняты при `FASAD_THREADS=2`;
   сравнения «2 против 8» по смонтированному пути в разделе нет — оно не мерялось.

### 10.8 Покрытие продукта на полном golden (тот же бинарь, тот же метод)

Мера харнеса (`docs/model-audit-weights.md` §W2.7, `docs/golden-report.md`) считает стадии по отдельности и на
всём датасете; продукту доступен только выход конвейера — набор спанов, который
уйдёт в маскирование. Прогон `product_coverage_on_the_whole_golden`
(`tests/cascade_parity.rs`, под `#[ignore]`: 98.4 с на threads=1, нужны веса):
взяты строки ≤200 символов — 185 из 204 (окно lockR = 256 токенов,
дальше продукт обязан отказать, #84). Тексты подаются как есть, без санитизации.

| класс | gold | overlap (мера `union`) | exact (байт-в-байт, гейт #77) |
|---|---|---|---|
| `person_name` | 42 | 42 (100.0 %) | 0 (0.0 %) |
| `phone` | 34 | 34 (100.0 %) | 26 (76.5 %) |
| `email` | 32 | 32 (100.0 %) | 0 (0.0 %) |
| `card_pan` | 31 | 27 (87.1 %) | 26 (83.9 %) |
| `address` | 29 | 29 (100.0 %) | 0 (0.0 %) |
| `iban` | 26 | 23 (88.5 %) | 23 (88.5 %) |
| `inn` | 26 | 26 (100.0 %) | 21 (80.8 %) |
| `snils` | 25 | 23 (92.0 %) | 23 (92.0 %) |
| `ogrn` | 24 | 21 (87.5 %) | 21 (87.5 %) |
| `ogrnip` | 23 | 21 (91.3 %) | 21 (91.3 %) |
| `passport` | 15 | 10 (66.7 %) | 0 (0.0 %) |
| `bik` | 2 | 0 (0.0 %) | 0 (0.0 %) |
| `bank_account` | 1 | 0 (0.0 %) | 0 (0.0 %) |
| **итого** | **310** | **288 (92.9 %)** | **161 (51.9 %)** |

1. Итог по мере пересечения (логика `union` из #80): 288 из 310 =
   92.9 %.
2. Итог по гейт-мере байт-в-байт (#77): 161 из 310 =
   51.9 %.
3. Разрыв между ними и есть #41: `person_name`/`email`/`address` накрыты целыми
   (100 % overlap) и при этом дают 0 exact — границы lockR не совпадают с
   разметкой байт в байт, а координат у Decide нет.
4. Лишних спанов (без пересечения с золотом): 51 при 534
   выпущенных — это цена порога 0.20 (FN фатален, FP дёшев, SPEC §3).
5. Числа сгенерированы из артефакта прогона (`/tmp/cover_product_9b.txt`, дерево
   `dbce8ca` после мержа #86, 98.4 с на threads=1, `FASAD_REQUIRE_MODELS=1`),
   не набраны.
6. Сдвиг против предыдущего прогона (261/117 = 84.2 %/37.7 %) — работа каскада 0
   из #86 (терпимость к разделителям + полная таблица IBAN): `iban` 5 → 23 exact,
   `snils` 9 → 23, `card_pan` 14 → 26. Модельные классы не сдвинулись ни на
   спан: `person_name` 42, `email` 32, `address` 29 overlap, 0 exact — то есть
   #86 модельный путь действительно не тронул, и приписывать эти проценты
   монтажу нельзя.
7. Строка `COVER|rows|185|of|204` — это окно lockR (256 токенов), а не фильтр по
   качеству: 19 строк продукту сегодня недоступны вообще (502 `Truncated`, #84).

### 10.9 Функциональный обрыв, найденный этим прогоном: «№»

Первый же прогон упал на строке `g0133` («Договор оказания услуг № 782/24 …») с
`502 cascade_unavailable: сбой инференса: decide: констрэкт разметки: 1 токенов
[UNK] в живом входе`. Хронология факта (промер `tokenizer.json` обоих весов в
этом раунде, правит неточность 4b-3C): у каскада 1 `№` ЕСТЬ в словаре (Spiber rubert, WordPiece 120138: `№` = id 248,
сплайс не ломается); у каскада 2 (Unigram 128000) ни один токен не содержит
`№`, а `[UNK]` = id 3 = ровно тот `UNK_ID`, который ветоит `check_splice`
(`arbitrate.rs:48,579`); запись 4b-3C «`№` = [507, UNK]» в
`recall_golden.rs:320` приписана Spiber, а 507 в словаре Decide = `▁` (в rubert
507 = `##́`) — то есть наблюдение сделано на Decide-токенизаторе. Харнес
подменяет `№` пробелом перед прогоном Decide (row-level мере координаты не
нужны, `unk_rows` в счётчике прогона), продукт подменить текст не может —
координаты спанов это байты оригинала. 16 строк из 185 (20 из 204, промер
`data/golden/golden-v1.jsonl`) содержат `№`, а пропуск зафиксирован один:
каскад 2 вызывается только в серой зоне.

Политика после правки (#87): `ArbError::Layout` = деградация каскада 2 (вердиктов
нет, серый спан остаётся на `p1 ≥ 0.22 > τ = 0.20` ⇒ спан не теряется, пропадает
только способность арбитра двигать оценку), остальные ветки `ArbError` = 502.
Отказывать такому входу 502 = не обслуживать весь класс договоров; это не
fail-closed, а отказ от работы. Полный прогон после правки: 185 строк, 1
пропуск Decide (та самая `g0133`), rc=0. Настоящее лечение — #88 (заведено по итогам этого прогона).

