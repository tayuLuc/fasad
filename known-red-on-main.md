# known-red: lint-actions (MegaLinter/zizmor) красится с bootstrap main

Замерено 18.10 на PR #2 (step1-impl) и на main-push 39160680009 (bootstrap,
коммит 705a66e): `Lint (Actions YAML + shell)` падает на zizmor 1.25.0 —
15 error (PR-ран) / тот же профиль на main (6+ промптированных `unpinned-uses`
на `.github/workflows/ci.yml` + `lint.yml`, `artipacked`, `excessive-permissions`).

## Почему это не блок мержа шага 1

1. Матрица `ci` (fmt/clippy/test/deny на ubuntu-24.04/windows-2022) на step1-impl
   **зелёная**: run 39161454349 (3 м 40 с), jobs windows+ubuntu — success.
2. На bootstrap-main lint-actions падал до этого PR (run 39160680009 completed
   failure, 2026-10-18T19:51Z): краснота не внесена диффом PR, унаследована от
   workflow-файлов main.
3. Родительский рулинг: файлы bootstrap (lint.yml, ci.yml-пины) чинятся
   отдельным PR пинингом actions на SHA (unpinned-uses) + explicit permissions +
   persist-credentials (artipacked) — шаг 9 release.yml всё равно перепишет пины
   (`dep-verify-repos` §5: gh-release v3, rust-cache 2.9.2).

## Что чинить отдельным PR

- `actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`,
  `taiki-e/install-action@just|cargo-deny`, `oxsecurity/megalinter@v9` → пин на
  tag+SHA (`@v4 # abc1234` или полный SHA), согласно §5.5 п.5 (checkout v4 —
  сознательный выбор, вопрос только SHA-якоря, не версии).
- `permissions:` на job-уровне уже есть в lint.yml; ci.yml job build-test без
  explicit permissions → добавить `permissions: contents: read`.
