# models — манифест весов (указатели, не бинари)

Веса в git не коммитятся (закон source-capture: URL+commit+хэш, не blob).
Формат манифеста: `models/manifest.md`. Скачивание — `scripts/fetch-models.sh`
(сверка sha256 после загрузки, fail-closed).
