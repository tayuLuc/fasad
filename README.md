# fasad

> Локальный AI-гард: стендэлон-демон (Rust, оффлайн, <2 ГБ), разметка текста по
> категориям конфиденциальности + обратимое маскирование + OpenAI-совместимый прокси.

- Спецификация для сборщика: [docs/SPEC.md](docs/SPEC.md)
- Правила workspace: [AGENTS.md](AGENTS.md)
- Источник фактуры и расхождения: [docs/source-note.md](docs/source-note.md)
- Лицензия: Apache-2.0 ([LICENSE](LICENSE))

## Статус

Шаг 1 SPEC §10: каркас workspace (`guard-types` + скелеты четырёх крейтов + CI).
Детекторы/ONNX/vault/роуты — шаги 3–8; метрик recall нет, golden-набор не собран
(§5 п.7, §11 п.7). CI-бейдж не вешаем до первого зелёна на main.

> `lint-actions` (MegaLinter/zizmor) красится на `unpinned-uses` в bootstrap-файлах
> (то же на main до PR) и на shellcheck SC2012 в `scripts/`; два unpinned-шага,
> добавленных шагом 1, запинены SHA в `ci.yml`. Разбор ответственности и очередь
> починки — `known-red-on-main.md`; матрица `ci` (fmt/clippy/test/deny, обе ОС) зелёная.

## Setup

Требуется Rust ≥ 1.85 (edition 2024, MSRV в `[workspace.package]`) и
[just](https://github.com/casey/just) — контракт команд:

```sh
brew install just cargo-deny        # macos; linux: cargo install just cargo-deny
cargo build --workspace             # или `just check` — полный гейт перед push
```

Тяжёлые зависимости (`ort` → бинарь onnxruntime) за feature-gate
`guard-onnx/ort-inference`, по умолчанию выключена: шаг 1 инференса не содержит,
`cargo check` остаётся офлайн-дешёвым.

## Commands

| task | command |
| --- | --- |
| lint | `just lint` (fmt --check + clippy `-D warnings -D clippy::unwrap_used`) |
| fix | `just fix` (fmt --fix + clippy --fix) |
| test | `just test` (`cargo test --workspace`) |
| deny | `just deny` (`cargo deny check`: advisories/bans/licenses) |
| check | `just check` (lint + test + deny — то же, что CI) |
| build | `cargo build --workspace` (релизные сборки — только CI, §16 п.5) |
| run | `cargo run -p guard-daemon` → http://127.0.0.1:8765/health (шаг 1: только /health) |

## Layout

`crates/guard-{types,detectors,onnx,vault,daemon}` · `ui/` · `docs/` — см. SPEC §6.
