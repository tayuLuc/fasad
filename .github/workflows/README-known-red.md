# lint-actions: профиль красноты (canonical)

Владелец: docs/competitors/known-red-on-main.md (таблица ответственности).

- Замер main 1553e0b (промер run 39170794352): zizmor **7 находок, 0 high** — остаток
  artipacked (ci.yml checkout без persist-credentials:false) + excessive-permissions
  (job без блока permissions). Фикс: issue #8.
- 6× unpinned сняты ПР #7 (замер baseline 13 findings / 6 high на 340ff32).
- Методичка (урок ревью #7): артефакты MegaLinter сверять по workflow_run.head_sha —
  `?run_id=` возвращает чужой артефакт (ошибочный фол возможен).
- Обновлять при каждом ПР, трогающем .github/workflows/.

## Архив

- 19.10.2026: issue #8 закрыт PR #10 (merge 42565ba); lint-actions **success**
  на main (ран 39185874912) — первая полностью зелёная пара CI+lint.
  Мишени более нет: README остаётся как журнал метода (промер артефактов по
  `workflow_run.head_sha`).
