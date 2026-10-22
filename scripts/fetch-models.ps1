# scripts/fetch-models.ps1 — скачивание ONNX-весов по манифесту, нативная
# доставка для Windows (issue #190: `fetch-models.sh` в cmd/PowerShell не
# запускается в принципе; Git-Bash в issue назван альтернативой).
#
# Parity-контракт = шапка scripts/fetch-models.sh + разбор строк его цикла:
#   - источник истины — models/manifest.tsv (tab; 8 полей:
#     role repo revision file sha256 size_bytes source notes);
#   - URL = <HFHost>/<repo>/resolve/<revision>/<file>; скачиваем ВСЕГДА по
#     явному commit-шейа (без сети, как в --list);
#   - после загрузки пересчитываем sha256 (Get-FileHash) и сверяем с
#     манифестом; несовпадение/обрезок = exit 1 (Fail-Closed, AGENTS.md —
#     никогда fail-open);
#   - размер сверяется байт-в-байт (поле size_bytes, кромка 0 = пропуск,
#     как в .sh: `want_size -ne '0'`);
#   - кеш: $env:FASAD_MODEL_CACHE (дефолт $env:USERPROFILE\.cache\fasad-models),
#     раскладка $cache/<repo>/<file> — идентична .sh, её же читает каскадный
#     монтаж (cascades.rs); повторный запуск = пересчёт чексумм по кешу, БЕЗ СЕТИ;
#   - зеркало: -HFHost / $env:FASAD_HF_HOST;
#   - план без сети: -List.
#
# ЧЕМ МЫНЕЕ, ЧЕМ .sh (честный список, не скрытая деградация):
#   - `TBD` в sha256/revision не поддерживается: первое подтверждение и
#     перепись манифеста остаются за .sh (владелец манифеста — CI/разработчик,
#     релизный манифест бандла полностью подтверждён); скрипт требует
#     64-hex sha и явный sha-revision, иначе exit 1 (fail-closed);
#   - докачка оборванного .part нет: INT/обрыв сети = red + файл .part лежит,
#     следующий запуск перезаписывает его с нуля (curl --continue-at - в PS
#     паритета не имеет; HF-CDN рвёт 355 МБ — это штатный red, повтор запуска
#     = рабочее решение);
#   - HF API @auto-разрешение не вызывается никогда (см. выше).
#
# PowerShell 5.1-совместимо (Windows PowerShell 5.1 = дефолт win10/11,
# первичка issue): без `&&`, без тернарного `?:`, без `Join-Path -AdditionalChildPath`,
# без `Split-Path -LeafBase`; Invoke-WebRequest -UseBasicParsing (5.1 не имеет
# -SkipCertificateCheck — зеркало обязано быть рабочим TLS-хостом, как и в .sh).
# Кодировка файла: UTF-8 с BOM — Windows PowerShell 5.1 читает без-BOM UTF-8
# как ANSI и калечит кириллицу (7-bit-файл был бы порчей читаемости).
#
# Запуск из каталога бандла:  .\scripts\fetch-models.ps1
# Справка:                   .\scripts\fetch-models.ps1 -Help
# Кеш в другое место:         .\scripts\fetch-models.ps1 -Cache D:\models
# Зеркало HF:                 .\scripts\fetch-models.ps1 -HFHost https://hf-mirror.com

[CmdletBinding()]
param(
    [string]$Manifest,
    [string]$Cache,
    [string]$HFHost,
    [switch]$List,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
function Write-Fail([string]$Message) {
    # Пишем в console-стрим [Console]::Error, НЕ Write-Error: в родительском
    # PowerShell с $ErrorActionPreference='Stop' Write-Error бросает
    # terminating-исключение НА СТРОКЕ вызова и глотает `exit 1` (CI-провен
    # run 39829067427: red-вердикт печатался, rc дочернего процесса терялся;
    # mac-паритет pwsh 7.6.7 та же механика). [Console]::Error.WriteLine =
    # чистый stderr-поток: exit 1 доходит до $LASTEXITCODE любого родителя;
    # метод безобъектный (InvokeMethodOnNull в доке PS5.1 про [Console] не
    # касается вызова статического метода класса System).
    # Ключевое слово ASCII-канона «sha256» = маркер вердикта (CI-гейт ищет
    # его в захваченном хвосте: кириллица в stderr-потоке нативки декодируется
    # родителем в codepage-мусор, hex/ASCII-остаток живёт под любой кодовой
    # страницей; lowercase-форма = сигнатура вердикта, crash-стек её не
    # содержит в регистроточном совпадении).
    [Console]::Error.WriteLine('fetch-models: FAIL: sha256/size gate: ' + $Message)
    exit 1
}

function Write-Log([string]$Message) {
    Write-Output ("fetch-models: " + $Message)
}

function Get-Sha256Hex([string]$Path) {
    # Get-FileHash — штатный модуль PS 4.0+ (win10/11 из коробки).
    # Lowercase — канон манифеста (hex-поле 64 символа в нижнем регистре).
    (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
}

if ($Help) {
    @'
использование: .\scripts\fetch-models.ps1 [параметры]

  -Manifest PATH  путь к манифесту (default: <каталог-со-скриптом>\..\models\manifest.tsv)
  -Cache DIR      каталог кеша (default: $env:FASAD_MODEL_CACHE или %USERPROFILE%\.cache\fasad-models)
  -HFHost URL     зеркало Hugging Face (default: $env:FASAD_HF_HOST или https://huggingface.co)
  -List           показать план скачивания и выйти (без сети)
  -Help           эта справка

Env-алиасы (parity с .sh): FASAD_MODEL_CACHE, FASAD_MANIFEST, FASAD_HF_HOST.
Паритет .sh и честные отличия (TBD/.part) — в шапке этого файла.
'@
    exit 0
}

if (-not $Manifest) {
    if ($env:FASAD_MANIFEST) { $Manifest = $env:FASAD_MANIFEST }
    else {
        # Каллер мог запустить из любого cwd — манифест ищем рядом со скриптом
        # (тот же контракт, что `dirname $0` в .sh).
        $Manifest = Join-Path (Join-Path $PSScriptRoot '..') 'models\manifest.tsv'
    }
}
if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
    Write-Fail "манифест не найден: $Manifest"
}
# Абсолютизируем (в .sh — cd+pwd; здесь GetFullPath, без зависимости от cwd).
$Manifest = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Manifest).Path)

if (-not $Cache) {
    if ($env:FASAD_MODEL_CACHE) { $Cache = $env:FASAD_MODEL_CACHE }
    elseif ($env:USERPROFILE) { $Cache = Join-Path $env:USERPROFILE '.cache\fasad-models' }
    # Домашний каталог вне Windows (паритет .sh `$HOME`, промер pwsh-теста на
    # mac): $env:HOME. win-контракт (USERPROFILE) проверки ниже не трогает.
    elseif ($env:HOME) { $Cache = Join-Path $env:HOME '.cache/fasad-models' }
    else { Write-Fail "нет FASAD_MODEL_CACHE и нет USERPROFILE/HOME — кеш не определим (fail-closed)" }
}
$Cache = [System.IO.Path]::GetFullPath($Cache)

if (-not $HFHost) {
    if ($env:FASAD_HF_HOST) { $HFHost = $env:FASAD_HF_HOST } else { $HFHost = 'https://huggingface.co' }
}
$HFHost = $HFHost.TrimEnd('/')

New-Item -ItemType Directory -Force -Path $Cache | Out-Null

# $Progress понижен: индикатор Invoke-WebRequest на 355 МБ печатает гигабайты
# escape-последовательностей в перенаправленный вывод (win-CI лог).
$ProgressPreference = 'SilentlyContinue'

$processed = 0
$lines = Get-Content -LiteralPath $Manifest
foreach ($line in $lines) {
    $line = $line.TrimEnd([char]13)   # CR режем defensively (файл LF; .sh — то же)
    if ($line -eq '') { continue }
    if ($line.StartsWith('#')) { continue }

    $fields = $line -split "`t"
    if ($fields.Count -lt 7) {
        Write-Fail "строка манифеста короче 7 полей: $line"
    }
    $role = $fields[0]
    $repo = $fields[1]
    $revision = $fields[2]
    $file = $fields[3]
    $wantSha = $fields[4]
    $wantSize = $fields[5]
    $source = $fields[6]

    if ($source -eq 'skip') { continue }
    if ($source -ne 'hf') { Write-Fail "${role}: source='$source' (пока только hf; TBD-контур .sh здесь не поддерживается)" }

    # Fail-closed на формате манифеста (политика #178: мусор в полях = отказ,
    # не молчаливый ноль). TBD НЕ поддерживается: паритет-контур релизного
    # манифеста = 64-hex + явный sha-revision (шапка файла, «чем мынее»).
    if ($wantSha -notmatch '^[0-9a-f]{64}$') {
        Write-Fail "${role}: sha256='$wantSha' — не 64 hex (TBD-контур только в .sh)"
    }
    if ($revision -notmatch '^[0-9a-f]{40}$') {
        Write-Fail "${role}: revision='$revision' — не commit-шейа (TBD-контур только в .sh)"
    }

    $url = "$HFHost/$repo/resolve/$revision/$file"
    $dest = Join-Path $Cache (Join-Path ($repo -replace '/', [System.IO.Path]::DirectorySeparatorChar) ($file -replace '/', [System.IO.Path]::DirectorySeparatorChar))

    if ($List) {
        Write-Output ("{0,-18} {1,-46} rev={2} sha={3}" -f $role, "$repo/$file", $revision, $wantSha)
        $processed++
        continue
    }

    $destDir = Split-Path -Parent $dest
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null

    $fromCache = Test-Path -LiteralPath $dest -PathType Leaf
    if ($fromCache) {
        # Кеш валидируется пересчётом, а не доверием существованию файла (.sh — то же).
        Write-Log "$role`: кеш-хит $dest — пересчёт sha256"
    }
    else {
        $tmp = "$dest.part"
        Write-Log "$role`: GET $url"
        try {
            # -UseBasicParsing обязателен PS 5.1 (парсер Edge-движка на раннерах нет).
            Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing `
                -UserAgent 'fasad-fetch/1.0' `
                -MaximumRedirection 10 `
                -TimeoutSec 3600
        }
        catch {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
            Write-Fail "$role`: скачивание не удалось (fail-closed): $($_.Exception.Message)"
        }
        # Проверка ПОСЛЕ скачивания, ДО финального имени (нитка .sh-ревью #9):
        # неподтверждённый файл не попадает в кеш под конечным именем.
        $gotSize = (Get-Item -LiteralPath $tmp).Length
        if ($wantSize -ne '0' -and "$gotSize" -ne $wantSize) {
            Remove-Item -LiteralPath $tmp -Force
            Write-Fail "$role`: размер $gotSize ≠ манифест $wantSize — обрезан или подмена"
        }
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force }
        Move-Item -LiteralPath $tmp -Destination $dest -Force
    }

    $gotSize = (Get-Item -LiteralPath $dest).Length
    $gotSha = Get-Sha256Hex $dest

    if ($wantSize -ne '0' -and "$gotSize" -ne $wantSize) {
        # Размер не сошелся на Финальном имени = файл скачан этим прогоном
        # (кеш-хит проверяется тем же условием и обязан был совпасть — иначе
        # он краснеет здесь же, и удаление бьёт по НАШЕМУ файлу). Неподтверж-
        # денный файл не имеет права оставаться в кеше (паритет .sh: mv —
        # только после проверки; здесь mv раньше, поэтому сносим явно).
        if (-not $fromCache) { Remove-Item -LiteralPath $dest -Force }
        Write-Fail "$role`: размер $gotSize ≠ манифест $wantSize ($dest) — обрезан или подмена"
    }
    if ($wantSha -ne $gotSha) {
        if (-not $fromCache) { Remove-Item -LiteralPath $dest -Force }
        Write-Fail "$role`: sha256 рассинхронизация (манифест $wantSha, факт $gotSha, файл $dest)"
    }
    Write-Log "$role`: sha256 совпал ($gotSha)"
    $processed++
}

if ($List) {
    Write-Log "план: $processed файл(ов) (без сети)"
    exit 0
}
if ($processed -lt 1) {
    Write-Fail "манифест не содержит ни одной записи hf"
}
Write-Log "готово: $processed файл(ов) в $Cache"
exit 0
