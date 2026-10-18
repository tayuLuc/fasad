# fasad

> Локальный AI-гард: стендэлон-демон (Rust, оффлайн, <2 ГБ), разметка текста по
> категориям конфиденциальности + обратимое маскирование + OpenAI-совместимый прокси.

- Спецификация для сборщика: [docs/SPEC.md](docs/SPEC.md)
- Правила workspace: [AGENTS.md](AGENTS.md)
- Источник фактуры и расхождения: [docs/source-note.md](docs/source-note.md)

## Статус

Гипотеза на вторичном источнике (LLM-транскрипт). Перед кодом — верификация
первички: SPEC §11.

## Stack (заявлено)

Rust workspace \u00b7 axum \u00b7 ort (ONNX Runtime) \u00b7 GLiNER 2.5 (экстрактор + Decide-арбитр)
\u00b7 det-каскад: regex + aho-corasick + чексуммы РФ/ЕС + секрет-сканер \u00b7 petrovich/rsmorphy
\u00b7 zeroize + mlock \u00b7 rust-embed UI

## Setup

```sh
# TBD \u2014 до шага 1 SPEC §10
```

## Commands

| task | command |
| --- | --- |
| install | TBD |
| dev | TBD |
| test | TBD |
| build | TBD |

## Layout

`crates/guard-{types,detectors,onnx,vault,daemon}` \u00b7 `ui/` \u00b7 `docs/` \u2014 см. SPEC §6.
