# known-red: lint-actions (MegaLinter/zizmor) — унаследованное и внесённое

Замерено 18.10 на PR #2 (step1-impl) и на main-push 39160680009 (bootstrap):
`Lint (Actions YAML + shell)` падает на zizmor 1.25.0 + shellcheck (SC2012 в
`scripts/snapshot-competitors.sh`, красится и на main). Разделение ответственности
по первичному промеру (логи прогонов + таблица ревью PR #2 гейт 8):

| находка | на main | на head PR | кто внёс |
|---|---|---|---|
| `ci.yml` `actions/checkout@v4` (unpinned) | есть | есть | bootstrap |
| `ci.yml` `dtolnay/rust-toolchain@stable` | есть | есть | bootstrap |
| `ci.yml` `Swatinem/rust-cache@v2` | есть | есть | bootstrap |
| `ci.yml` `taiki-e/install-action` ×2 (`just`, `cargo-deny`) | — | внёс диф PR → **запинены SHA, снято** (промер: 15→13 error) | диф PR |
| `lint.yml` ×3 `unpinned-uses` + `artipacked` + `excessive-permissions` | есть | есть | bootstrap |

Итог: диф PR #2 добавил ровно 2 unpinned-находки и убрал их пином
`taiki-e/install-action@8cca0918… # v2` — промер head-run 39166168880: zizmor 15→13,
двух новых строк в отчёте нет; матрица ci на том же head зелёная (39166168873). остальная краснота — 6+ находок
bootstrap-файлов — не его ответственность и не его заслуга.

## Что остаётся отдельному PR

- Пининг bootstrap-действий: `actions/checkout@v4`, `dtolnay/rust-toolchain@stable`,
  `Swatinem/rust-cache@v2`, `oxsecurity/megalinter@v9` → `@vN # <sha>` (§5.5 п.5:
  checkout v4 — сознательный выбор версии, вопрос только SHA-якоря; gh-release v3
  и rust-cache 2.9.2 придут шагом 9).
- `permissions: contents: read` на job `build-test` в `ci.yml` (excessive-permissions).
- `artipacked`: `persist-credentials: false` на checkout в ci.yml.
- shellcheck SC2012 в `scripts/snapshot-competitors.sh:27` (ls → find или
  allow-info в конфиге MegaLinter).
