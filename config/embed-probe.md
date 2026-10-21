# Канарейка сборки

Этот файл существует только для теста
`crates/guard-daemon/tests/ui_sandbox.rs::schema_asset_embeds_exactly_the_schema`.

Он лежит в `config/` рядом со `schema.default.json` и **не** назван в фильтре
`include` у `SchemaAsset` (`crates/guard-daemon/src/ui.rs`). Если в собранном
бинарнике найдётся имя `embed-probe.md` — фильтр `include` снят, и демон начал
шить в себя всю папку `config/` целиком: любой файл, который туда положат
(локальный overrides, служебный дамп, чужая схема), уедет в наружный артефакт.

Файл не читается никем в рантайме: демоном (`schema.rs` берёт
`schema.default.json` по имени), тестами, песочницей.
