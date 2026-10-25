"use strict";

/*
  Песочница демона (SPEC §10 п.8). Три функции: разбор с раскраской по
  уверенности, редактор классов схемы и порог, roundtrip anonymize ->
  deanonymize в session-режиме.

  Правила, за которые отвечают тесты (crates/guard-daemon/tests/ui_sandbox.rs
  и гейт net_audit):
    - ни одного внешнего адреса: все запросы относительные, на тот же origin;
    - ни одного inline-скрипта, inline-стиля и eval: политикой `CSP` это
      запрещено, живём на CSSOM и addEventListener;
    - текст в DOM попадает только через textContent: в разборе могут быть
      любые ПДн, и размечать их как HTML нельзя.
*/

const $ = (id) => document.getElementById(id);

/* --- сессия -------------------------------------------------------------

  Демон не выдаёт идентификаторов: `/v1/session` у него нет, сессию выбирает
  клиент (валидатор на входе — 1..64 байта из [A-Za-z0-9._-]). Берём 16 случайных
  байт, это ровно 32 hex-символа, то есть в допустимое множество попадает.
------------------------------------------------------------------------ */

function newSession() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

let session = newSession();
let spans = [];
let masked = "";
let classes = [];
// #225: метки последней подмены = items anonymize-ответа (replacement-forms:
// `[КЛАСС_н_nonce]` session / `[[F0#…]]` stateless; суррогаты operator=replace
// меток НЕ зовут и в список не попадают — фильтр по пустому replacement).
let lastLabels = [];

function showSession() {
  $("session").textContent = "сессия: " + session;
}

/* --- шаги конвейера (#201) ------------------------------------------------

  Кнопки 1→2→3 = конвейер, а не меню: очередь читается глазами (первичка
  #201: «неактивные кнопки молчат»). Неактивная = disabled + title с
  причиной; подсветка текущего шага — .active. pending-режим (#198)
  перекрывает всё: modelRefused = true, конвейер запрещён целиком (503
  model_refusal на сервере = тот же контракт, UI обязан показывать очередь
  честно, а не красным постфактум).
-------------------------------------------------------------------------- */

let modelRefused = false;

function setStepActive(n) {
  for (let i = 1; i <= 3; i += 1) {
    $("step" + i).classList.toggle("active", i === n);
  }
}

function refreshButtons() {
  /* #198: заголовок карточки весов говорит, что делать, ДО чтения баннера:
     при смонтированном контуре = «кнопка нужна», при pending = «кнопка
     = действие»; при полном смонтированном каталоге (loadWeights: stage
     cascade-0+models) карточка сворачивается в статус-ленту (кнопка
     скрыта, remount-кнопки НЕТ — каскады монтируются на старте, #192). */
  const an = $("btnAnalyze"), ao = $("btnAnon"), de = $("btnDean"), cp = $("btnCopy");
  // #225: «Скопировать с задачей» = активность как у «Скопировать
  // обезличенный» (есть masked) + честный title про список меток.
  const ct = $("btnCopyTask");
  ct.disabled = cp.disabled;
  ct.title = cp.disabled
    ? "сначала «Обезличить»"
    : uniqueLabels(lastLabels).length === 0
      ? "копирует задачу без списка меток (меток не найдено)"
      : "masked + задача + список меток (" + uniqueLabels(lastLabels).length + ")";
  an.disabled = modelRefused;
  an.title = modelRefused ? "нужны веса: «Скачать веса» выше, затем перезапуск" : "";
  ao.disabled = modelRefused || spans.length === 0;
  ao.title = modelRefused
    ? "нужны веса: «Скачать веса» выше, затем перезапуск"
    : spans.length === 0
      ? "сначала «Разобрать»"
      : "";
  de.disabled = modelRefused || masked === "";
  de.title = modelRefused
    ? "нужны веса: «Скачать веса» выше, затем перезапуск"
    : masked === ""
      ? "сначала «Обезличить»"
      : "";
  cp.disabled = masked === "";
  cp.title = masked === "" ? "сначала «Обезличить»" : "";
  // #202: «В чат» = следующий после обезличивания шаг ручного промера.
  const ch = $("btnChat");
  ch.disabled = modelRefused || masked === "";
  ch.title = modelRefused
    ? "нужны веса: «Скачать веса» выше, затем перезапуск"
    : masked === ""
      ? "сначала «Обезличить»"
      : "";
}

/* --- транспорт ---------------------------------------------------------- */

class ApiError extends Error {
  constructor(status, body) {
    const detail =
      body && typeof body === "object" && body.error
        ? String(body.error.code || "") + ": " + String(body.error.message || "")
        : typeof body === "string"
          ? body.slice(0, 200)
          : "";
    super("HTTP " + status + (detail ? " | " + detail : ""));
    this.status = status;
  }
}

async function api(path, body, method) {
  const headers = { "X-Session-ID": session };
  const verb = method || (body === undefined ? "GET" : "POST");
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (verb !== "GET") headers["X-Guard-Policy"] = $("policy").value;
  const res = await fetch(path, {
    method: verb,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const raw = await res.text();
  let data = null;
  try {
    data = raw === "" ? null : JSON.parse(raw);
  } catch (err) {
    data = raw;
  }
  if (!res.ok) throw new ApiError(res.status, data);
  return { data: data, headers: res.headers };
}

/* Служебные заголовки ответа — то, чем клиент сверяет ожидания с тем, что
   демон реально применил. Показываем только те, что пришли. */
const GUARD_HEADERS = [
  "X-Guard-Redacted-Count",
  "X-Guard-Max-Risk",
  "X-Guard-Latency-Ms",
  "X-Guard-Stage",
  "X-Guard-Cascade2",
  "X-Guard-Policy-Applied",
  "X-Guard-Score-Threshold",
  "X-Guard-Unresolved",
  "X-Guard-Malformed",
];

function headerLine(headers) {
  const parts = [];
  for (const name of GUARD_HEADERS) {
    const value = headers.get(name);
    if (value !== null) parts.push(name.replace("X-Guard-", "") + "=" + value);
  }
  return parts.length === 0 ? "" : " | " + parts.join(" ");
}

function status(text, kind) {
  const el = $("status");
  el.textContent = text;
  if (kind) el.dataset.kind = kind;
  else delete el.dataset.kind;
}

function fail(err) {
  spans = [];
  renderSpans([]);
  paint($("src").value, []);
  status(err instanceof ApiError ? err.message : "сетевой сбой: " + err, "err");
}

/* --- координаты ---------------------------------------------------------

  Демон отдаёт и символьные, и байтовые offsets; канон внутреннего контракта —
  байты (#56). JS индексирует строку в единицах UTF-16, поэтому перед раскраской
  байты переводятся в символы таблицей соответствия. Для кириллицы индексы
  совпадают, расходятся на эмодзи и прочим за пределами BMP — таблица закрывает
  и это.
------------------------------------------------------------------------ */

function byteToChar(text) {
  const enc = new TextEncoder();
  const map = new Map();
  let byte = 0;
  let char = 0;
  for (const ch of text) {
    map.set(byte, char);
    byte += enc.encode(ch).length;
    char += ch.length;
  }
  map.set(byte, char);
  return map;
}

/* --- раскраска ----------------------------------------------------------

  Альфа фона = уверенность спана (α=confidence, SPEC §10 п.8), цвет рамки =
  вердикт маршрутизации: keep_public -> пропуск, mask_* -> маска,
  block_request -> блок. Перекрывающиеся спаны (арбитр не гарантирует
  непересечения на входе) раскрашиваются по первому, вложенные пропускаются:
  вложенный <mark> внутри <mark> дал бы визуальный шум без новой информации.
------------------------------------------------------------------------ */

function verdictClass(verdict) {
  if (verdict === "keep_public") return "pass";
  if (verdict === "mask_surrogate" || verdict === "mask_capsule") return "mask";
  if (verdict === "block_request") return "block";
  return "";
}

function tooltip(span) {
  const bits = [
    span.entity_type,
    "S=" + Number(span.score).toFixed(2),
    span.verdict,
    "байты " + span.byte_start + "-" + span.byte_end,
  ];
  if (span.validator) bits.push(span.validator);
  if (span.source) bits.push(span.source);
  return bits.join(" | ");
}

function paint(text, list) {
  const host = $("painted");
  host.replaceChildren();
  if (list.length === 0) {
    host.textContent = text;
    return;
  }
  const map = byteToChar(text);
  const sorted = list.slice().sort(function (a, b) {
    return a.byte_start - b.byte_start || b.byte_end - a.byte_end;
  });
  let cursor = 0;
  for (const span of sorted) {
    if (span.byte_start < cursor) continue;
    if (!map.has(span.byte_start) || !map.has(span.byte_end)) continue;
    const alpha = 0.12 + 0.73 * Math.max(0, Math.min(1, Number(span.score)));
    host.append(document.createTextNode(text.slice(map.get(cursor), map.get(span.byte_start))));
    const mark = document.createElement("mark");
    mark.className = "span " + verdictClass(span.verdict);
    mark.style.backgroundColor = "rgba(106, 169, 232, " + alpha.toFixed(3) + ")";
    mark.title = tooltip(span);
    mark.textContent = text.slice(map.get(span.byte_start), map.get(span.byte_end));
    host.append(mark);
    cursor = span.byte_end;
  }
  host.append(document.createTextNode(text.slice(map.get(cursor))));
}

function renderSpans(list) {
  const rows = $("spanRows");
  rows.replaceChildren();
  for (const span of list) {
    const tr = document.createElement("tr");
    const cells = [
      span.entity_type,
      Number(span.score).toFixed(2),
      span.verdict,
      span.source,
      span.validator || "—",
    ];
    for (const value of cells) {
      const td = document.createElement("td");
      td.textContent = value === null || value === undefined ? "—" : String(value);
      tr.append(td);
    }
    rows.append(tr);
  }
}

/* --- запросы песочницы -------------------------------------------------- */

function enabledClasses() {
  return classes.filter(function (id) {
    const box = $("t_" + id);
    return box ? box.checked : true;
  });
}

async function analyze() {
  const text = $("src").value;
  const body = { text: text };
  const on = enabledClasses();
  if (on.length < classes.length) body.entities = on;
  const thr = thrValue();
  if (thr > 0) body.score_threshold = thr;
  try {
    const res = await api("/v1/analyze", body);
    spans = Array.isArray(res.data) ? res.data : [];
    paint(text, spans);
    renderSpans(spans);
    $("out").textContent = "";
    masked = "";
    $("outMasked").textContent = "";
    $("outBack").textContent = "";
    $("roundtrip").hidden = true;
    chatText = "";
    $("chatPaste").value = "";
    $("outChat").textContent = "";
    $("outChatRevealed").textContent = "";
    $("btnReveal").disabled = true;
    lastLabels = [];
    $("revealChecklist").hidden = true;
    setStepActive(2);
    refreshButtons();
    status("спанов: " + spans.length + headerLine(res.headers));
  } catch (err) {
    fail(err);
  }
}

async function anonymize() {
  if (spans.length === 0) {
    status("нет спанов: сначала «Разобрать»", "err");
    return;
  }
  try {
    /* spans уходят дословно как из /v1/analyze: лишних полей контракт не требует */
    const res = await api("/v1/anonymize", { text: $("src").value, spans: spans });
    masked = res.data.text;
    // #225: список меток = из items ответа (контур #203: класс+n из
    // replacement, НЕ regex по masked); дубли складываются в уникальные
    // (одна форма много вхождений = одна строка чек-листа).
    lastLabels = (Array.isArray(res.data.items) ? res.data.items : [])
      .map(function (it) { return it && it.replacement ? String(it.replacement) : ""; })
      .filter(function (r) { return r !== ""; });
    /* #201: обезличенный живёт в СВОЁМ окне; исходник в #out и развёрнутый
       в #outBack его не затирают — пара «что ушло / что вернулось». */
    $("outMasked").textContent = masked;
    $("outBack").textContent = "";
    $("roundtrip").hidden = true;
    setStepActive(3);
    refreshButtons();
    status(
      "подмен: " + res.data.items.length +
      " | меток: " + uniqueLabels(lastLabels).length +
      headerLine(res.headers),
    );
  } catch (err) {
    fail(err);
  }
}

async function deanonymize() {
  if (masked === "") {
    status("нечего разворачивать: сначала «Обезличить»", "err");
    return;
  }
  try {
    const res = await api("/v1/deanonymize", { text: masked });
    const same = res.data.text === $("src").value;
    $("outBack").textContent = res.data.text;
    const rt = $("roundtrip");
    rt.hidden = false;
    rt.textContent = "побайтово совпал с исходником: " + (same ? "ДА" : "НЕТ");
    rt.dataset.kind = same ? "" : "err";
    status(
      "развёрнуто: " +
        res.data.substituted +
        " | исходник совпал побайтово: " +
        (same ? "да" : "нет") +
        headerLine(res.headers),
    );
  } catch (err) {
    fail(err);
  }
}

async function resetSession() {
  try {
    const res = await api("/v1/sessions/" + session, undefined, "DELETE");
    const n = res.data && res.data.deleted !== undefined ? res.data.deleted : "?";
    session = newSession();
    showSession();
    spans = [];
    masked = "";
    lastLabels = [];
    $("revealChecklist").hidden = true;
    renderSpans([]);
    paint("", []);
    $("out").textContent = "";
    $("outMasked").textContent = "";
    $("outBack").textContent = "";
    $("roundtrip").hidden = true;
    chatText = "";
    $("chatPaste").value = "";
    $("outChat").textContent = "";
    $("outChatRevealed").textContent = "";
    $("btnReveal").disabled = true;
    setStepActive(1);
    refreshButtons();
    status("сессия сброшена, удалено записей: " + n + headerLine(res.headers));
  } catch (err) {
    fail(err);
  }
}

/* --- схема и здоровье ---------------------------------------------------

  Классы берутся из `/assets/schema.json` — это тот же файл, который демон
  вшивает в себя как схему по умолчанию (rust-embed, один источник байтов).
  Оверрайд `FASAD_SCHEMA` песочница не видит: список тогда шире, чем у демона,
  и лишний класс просто никогда не приходит в ответе.
------------------------------------------------------------------------ */

async function loadSchema() {
  try {
    const res = await api("/assets/schema.json");
    classes = (res.data.classes || []).map(function (c) {
      return c.id;
    });
    const host = $("types");
    host.replaceChildren();
    for (const id of classes) {
      const label = document.createElement("label");
      const box = document.createElement("input");
      box.type = "checkbox";
      box.id = "t_" + id;
      box.checked = true;
      label.append(box, document.createTextNode(id));
      host.append(label);
    }
    if (classes.length === 0) host.textContent = "в схеме нет классов";
  } catch (err) {
    $("types").textContent = "схема не загружена: " + err;
  }
  /* #201: стартовая очередь («Разобрать» активен, 2/3 зажаты причинами)
     ставится после загрузки схемы — refreshButtons опирается на span-состояние,
     которого на пустой странице нет; порядок вызовов в wiring ниже. */
  setStepActive(1);
  refreshButtons();
}

async function loadHealth() {
  try {
    const res = await api("/health");
    $("mode").textContent =
      "режим: " +
      (res.data.mode === "session" ? "session — сессия" : "stateless — без сессии") +
      " | этап " +
      res.data.stage +
      " | версия " +
      res.data.version;
    // #201-добавка: режим = env-конфиг (не запрос), UI объясняет токены и
    // путь смены; смена дефолта = продукт-решение оператора (#201), молча
    // не предлагем.
    $("modeHint").textContent =
      res.data.mode === "session"
        ? "метки читаемые ([ФИО#…]), «Развернуть» работает по X-Session-ID этой вкладки"
        : "метки = шифр-токены [[F0#…]], «Развернуть» = только в этой сессии; " +
          "читаемые метки: FASAD_VAULT_MODE=session при запуске (README бандла)";
    applyStage(res.data.stage);
  } catch (err) {
    $("mode").textContent = "демон не отвечает: " + err;
  }
}

/* #198: ожидающий старт (трей-бинарь без весов). stage = models-pending
   (строка-контракт cascades::STAGE_PENDING; cascade-0-only на релизном
   бинаре = ложь #185, её здесь быть не может). Баннер + запрет конвейера;
   карточка весов (выше по документу) = единственное живое действие. */
function applyStage(stage) {
  const pending = stage === "models-pending";
  $("pendingPane").hidden = !pending;
  // #220: тонкая строка-статус на вкладке «Работа» + дефолтный таб.
  $("weightsStrap").hidden = !pending;
  if (pending && !window.localStorage.getItem(LS_TAB)) {
    showTab("settings");
  }
  modelRefused = pending;
  $("step1t").textContent = pending ? "Разобрать (нужны веса)" : "Разобрать";
  $("step2t").textContent = pending ? "Обезличить (нужны веса)" : "Обезличить";
  $("step3t").textContent = pending ? "Развернуть (нужны веса)" : "Развернуть";
  refreshButtons();
}

/* --- карточка веса (#192): GET /v1/status + кнопка POST /v1/models/fetch ---
   Полл: setInterval 1 с ТОЛЬКО во время running; без загрузки = один GET на
   загрузку страницы. Прогресс = байты текущего файла; результат done =
   перечитать статус + подсказка перезапуска (каскады монтируются на старте,
   «Скачал — перезапусти демона», ТЗ #192). */

let weightsTimer = null;

function fmtBytes(n) {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return n + " Б";
  if (n < 1048576) return (n / 1024).toFixed(1) + " КБ";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " МБ";
  return (n / 1073741824).toFixed(2) + " ГБ";
}

async function loadWeights() {
  let d;
  try {
    d = (await api("/v1/status")).data;
  } catch (err) {
    $("weightsDirS").textContent = "статус недоступен: " + err;
    return;
  }
  const w = d.weights || {};
  $("weightsDirS").textContent =
    "путь: " + (w.dir || "(не определён)") + (w.default ? " (по умолчанию)" : "");
  const ul = $("weightsFilesS");
  ul.replaceChildren();
  for (const f of w.present || []) {
    const li = document.createElement("li");
    const mark = f.ok ? "✓" : f.present ? "✗" : "✗";
    li.textContent =
      mark + " " + f.path + " — " +
      (f.present ? fmtBytes(f.bytes) : "нет") +
      (f.present && f.expected_bytes && f.bytes !== f.expected_bytes
        ? " (ожидалось " + fmtBytes(f.expected_bytes) + ")"
        : "");
    li.className = f.ok ? "ok" : "bad";
    ul.append(li);
  }
  const m = d.model || {};
  $("weightsModelS").textContent =
    "lockR rev " + (m.lockr_revision || "—") +
    " · Decide rev " + (m.arbiter_revision || "—") +
    " · этап " + d.stage;
  renderFetch(d.fetch);
}

function renderFetch(fr) {
  const bar = $("fetchBarS");
  const msg = $("fetchMsgS");
  const btn = $("btnFetchS");
  const phase = $("fetchPhaseS");
  if (!fr) return;
  if (fr.state === "running") {
    btn.disabled = true;
    bar.hidden = false;
    const p = fr.progress || {};
    const done = Number(p.bytes_done || 0);
    const total = Number(p.bytes_total || 0);
    bar.value = total > 0 ? Math.min(100, Math.round((done * 100) / total)) : 0;
    phase.textContent =
      "файл " + (fr.index + 1) + "/" + fr.total + " · " + (p.phase || "") +
      " · " + fmtBytes(done) + (total ? " / " + fmtBytes(total) : "");
    msg.textContent = "скачивание весов (~879 МБ)…";
    msg.dataset.kind = "";
    startPoll();
    return;
  }
  stopPoll();
  btn.disabled = false;
  bar.hidden = true;
  phase.textContent = "";
  if (fr.state === "done") {
    msg.textContent = "веса скачаны: перезапусти демона, чтобы каскады 1–2 смонтировались";
    msg.dataset.kind = "";
    return;
  }
  if (fr.state === "failed") {
    msg.textContent = "загрузка не удалась [" + (fr.error || "?") + "] файл: " + (fr.file || "");
    msg.dataset.kind = "err";
    return;
  }
  msg.textContent = "";
}

function startPoll() {
  if (weightsTimer) return;
  weightsTimer = setInterval(loadWeights, 1000);
}

function stopPoll() {
  if (weightsTimer) {
    clearInterval(weightsTimer);
    weightsTimer = null;
  }
}

async function fetchWeights() {
  const msg = $("fetchMsgS");
  $("btnFetchS").disabled = true;
  try {
    await api("/v1/models/fetch", {}, "POST");
    msg.textContent = "загрузка начата…";
    msg.dataset.kind = "";
  } catch (err) {
    msg.textContent = "старт не принят: " + err;
    msg.dataset.kind = "err";
  }
  $("btnFetchS").disabled = false;
  loadWeights();
}

/* --- #220: табы «Работа»/«Настройки» + форма конфигурации --------------------

 DOM НЕ перерисовывается: переключение = hidden-класс (текст в textarea,
 результаты разбора, очередь кнопок живут). Активный таб = localStorage
 («перезапусти демона» из баннера = перезагрузка браузером, и человек
 возвращается туда, где сидел). Дефолт = Работа; при ожидающем старте
 (stage models-pending) = Настройки: там карточка весов с кнопкой докачки. */

const LS_TAB = "fasad.tab";

function showTab(name) {
  const work = name !== "settings";
  $("tabWorkPane").hidden = !work;
  $("tabSettingsPane").hidden = work;
  $("tabWork").classList.toggle("active", work);
  $("tabSettings").classList.toggle("active", !work);
  $("tabWork").setAttribute("aria-selected", work ? "true" : "false");
  $("tabSettings").setAttribute("aria-selected", work ? "false" : "true");
  try {
    window.localStorage.setItem(LS_TAB, work ? "work" : "settings");
  } catch (err) {
    /* storage = не ПДн и не обязательный (issue #202 п.6): приватный режим
       бросает на setItem — таб переключается, запоминание тихо теряется. */
  }
}

function initTabs() {
  let stored = "work";
  try {
    stored = window.localStorage.getItem(LS_TAB) || "work";
  } catch (err) {
    stored = "work";
  }
  showTab(stored);
  $("tabWork").addEventListener("click", function () { showTab("work"); });
  $("tabSettings").addEventListener("click", function () { showTab("settings"); });
  $("strapSettings").addEventListener("click", function () { showTab("settings"); });
}

/* --- форма конфигурации: GET /v1/config + POST /v1/config (#220) -----------

 Поля рисуются ОТВЕТОМ сервера (ключи/метки/флаги = белый список config.rs,
 первичка = TABLE `FILE_ALLOWED_KEYS`, а не копия списка в JS: расхождение
 «UI предлагает то, что сервер отвергает» лечится отсутствием второго списка).
 Тип поля = number там, где валидатор config.rs числовой (диапазоны —
 первичка валидаторов: тред/таймауты/байты = целые > 0, пороги = [0, 1]).
 Сохранение = POST по одному ключу; успех = баннер «требуется перезапуск»
 (hot-reload вне контура #219); отказ = текст 422/403 в статусной строке. */

const CFG_NUMERIC = {
  FASAD_PORT: { min: 1024, max: 65535, step: 1 }, // граница = port_strict_for_write (#224)
  FASAD_THREADS: { min: 1, max: 256, step: 1 },
  FASAD_TIMEOUT_MS: { min: 1, max: 3600000, step: 1 },
  FASAD_READ_TIMEOUT_MS: { min: 1, max: 3600000, step: 1 },
  FASAD_MAX_BODY_BYTES: { min: 1, max: 104857600, step: 1 },
  FASAD_GRAY_LO: { min: 0, max: 1, step: 0.01 },
  FASAD_GRAY_HI: { min: 0, max: 1, step: 0.01 },
  FASAD_TAU_LOW: { min: 0, max: 1, step: 0.01 },
  FASAD_TAU_HIGH: { min: 0, max: 1, step: 0.01 },
  FASAD_ARBITER_ALPHA: { min: 0, max: 1, step: 0.01 },
};

function settingsStatus(text, kind) {
  const el = $("settingsStatus");
  el.textContent = text;
  if (kind) el.dataset.kind = kind;
  else delete el.dataset.kind;
}

async function loadSettings() {
  let d;
  try {
    d = (await api("/v1/config")).data;
  } catch (err) {
    $("configRows").textContent = "конфиг недоступен: " + err;
    return;
  }
  $("settingsMeta").textContent =
    "версия " + (d.version || "—") + " · стадия " + (d.stage || "—") +
    " · режим " + (d.mode || "—") + " · потоков " + (d.threads || "—");
  const f = d.file || {};
  $("settingsFile").textContent =
    "файл конфигурации: " + (f.path || "—") + (f.exists ? " (существует)" : " (файла нет — значения по умолчанию)");
  $("settingsSecret").textContent =
    "ключ FASAD_VAULT_KEY: " + (d.vault_key || "нет") +
    " · бинд " + (d.bind || "—") + " (оба — только переменные окружения)";
  const host = $("configRows");
  host.replaceChildren();
  let pendingRestart = false;
  for (const row of d.entries || []) {
    host.append(configRow(row));
    // #224 MINOR: `restart_required` из GET читается (не только из ответа
    // POST): баннер обязан выживать на reload, «сохранено — не применилось»
    // не должно становиться невидимым после F5.
    if (row.source === "file" && row.restart_required) pendingRestart = true;
  }
  $("restartBanner").hidden = !pendingRestart && $("restartBanner").hidden;
}

function configRow(row) {
  const wrap = document.createElement("div");
  wrap.className = "cfgrow";
  wrap.dataset.key = row.key;
  const label = document.createElement("label");
  label.setAttribute("for", "cfg_" + row.key);
  label.textContent = row.label;
  const input = document.createElement("input");
  input.id = "cfg_" + row.key;
  input.dataset.key = row.key;
  const num = CFG_NUMERIC[row.key];
  input.type = num ? "number" : "text";
  if (num) {
    input.min = String(num.min);
    input.max = String(num.max);
    input.step = String(num.step);
  }
  // Эффективное значение = стартовое; пустое = «значения нет» (не «пустой
  // секрет»: секреты в таблице не ездит, первичка Config::view).
  input.value = row.value || "";
  input.disabled = !row.ui_editable;
  const meta = document.createElement("span");
  meta.className = "cfgmeta";
  meta.textContent = row.key + " · из: " + row.source + (row.ui_editable ? "" : " · только файл");
  const btn = document.createElement("button");
  btn.type = "button";
  btn.textContent = "Сохранить";
  btn.disabled = !row.ui_editable;
  btn.addEventListener("click", function () { saveConfig(row.key, input.value); });
  wrap.append(label, input, meta, btn);
  return wrap;
}

async function saveConfig(key, value) {
  settingsStatus("сохраняю " + key + "…", "");
  try {
    const res = await api("/v1/config", { key: key, value: value }, "POST");
    $("restartBanner").hidden = false;
    settingsStatus((res.data && res.data.message) || "сохранено", "");
    loadSettings();
  } catch (err) {
    // Текст отказа = текст валидатора демона (422 по инварианту порогов,
    // 403 по запрещённому ключу): браузерную валидацию числовых полей
    // задают min/max/step, серверную — единая точка config.rs.
    settingsStatus("отказ: " + (err instanceof ApiError ? err.message : err), "err");
  }
}

/* --- wiring ------------------------------------------------------------- */

/* #221: поле порога = number (нативные ↑/↓), output-дублирование убрано.
   Number("") = NaN, и `NaN > 0` ложно: пустое поле = «порог не поднят»
   (0.00 = дефолт запроса), контракт body.score_threshold не меняется. */
function thrValue() {
  const v = Number($("thr").value);
  return Number.isFinite(v) ? Math.min(1, Math.max(0, v)) : 0;
}
$("thr").addEventListener("input", function () {
  const v = Number($("thr").value);
  if (!Number.isFinite(v) || v < 0 || v > 1) {
    status("порог: пусто или вне [0, 1] — считаю 0.00 (дефолт)", "warn");
    return;
  }
  $("thr").value = v.toFixed(2);
});
$("btnAnalyze").addEventListener("click", analyze);
$("btnAnon").addEventListener("click", anonymize);
$("btnDean").addEventListener("click", deanonymize);
$("btnReset").addEventListener("click", resetSession);

$("btnFetchS").addEventListener("click", fetchWeights);
$("btnCopy").addEventListener("click", copyMasked);
$("btnCopyTask").addEventListener("click", copyMaskedTask);
$("btnDemo").addEventListener("click", setDemoText);
$("demoNoAuto").addEventListener("change", toggleDemoNoAuto);
$("btnChat").addEventListener("click", sendToChat);
$("btnReveal").addEventListener("click", function () { revealChatAnswer("stream"); });
// #203 §4: «Раскрыть вставленный» = ручной цикл без прокси (вставка из своего
// чата). Активность = non-empty вставка (pending-контур ловится 503-отказом
// деанона, текст ошибки = честный).
$("btnRevealPaste").addEventListener("click", function () { revealChatAnswer("paste"); });
$("chatPaste").addEventListener("input", function () {
  $("btnRevealPaste").disabled = $("chatPaste").value === "";
});

/* --- #225: шаблон промпта с задачей + список меток ------------------------

  Задача-обёртка = ФИКСИРОВАННАЯ константа (текст генерится не моделью,
  ПДн в шаблоне нет — промер node-зубом); подставляются masked-выход и
  СПИСОК НАЙДЕННЫХ меток из anonymize-ответа (items[].replacement,
  span-контур #203 — НЕ regex по masked). Формат скобки-метки = обе
  формы vault (session/`stateless`) — контур chatTokens ниже. */
const TASK_TEMPLATE_HEADER =
  "Прочитай служебное письмо. Данные обезличены гардом: метки вида [КЛАСС_н_XXXX] и [[F0#…]] — это замены ПДн, а не выдумка.\n" +
  "Задачи:\n" +
  "1) О чём речь — 3 пункта.\n" +
  "2) Заполни таблицу реквизитов (сторона А, сторона Б, договор, счёт, карта, телефон, e-mail): значения БУКВАЛЬНО из текста, метки сохраняй, не раскрывай и не придумывай.\n" +
  "3) Проверь арифметику: сумма договора/счёта/платежа, посчитай итог.\n" +
  "4) Перечисли все числа, которые выглядят как паспорт/карта, и скажи, какие данные отсутствуют.\n";

function uniqueLabels(list) {
  const seen = Object.create(null);
  const out = [];
  for (const label of list) {
    if (!seen[label]) {
      seen[label] = true;
      out.push(label);
    }
  }
  return out;
}

/* Полный текст «с задачей» = шапка + список меток (graceful: пуст =
   «меток не найдено») + masked. Тот же для кнопки и для прокси-запроса. */
function taskPrompt(text, labels) {
  const uniq = uniqueLabels(labels);
  const listLine = uniq.length === 0
    ? "Меток не найдено — скопируй с задачей после «Обезличить»."
    : "Метки в тексте (" + uniq.length + "): " + uniq.join(", ");
  return TASK_TEMPLATE_HEADER + listLine + "\n\n---\n" + text;
}

/* #225: копирование masked+задача (тот же Clipboard-контур #201, fallback
   textarea+execCommand). */
async function copyMaskedTask() {
  if (masked === "") return;
  const payload = taskPrompt(masked, lastLabels);
  try {
    await navigator.clipboard.writeText(payload);
    status("текст с задачей скопирован (меток: " + uniqueLabels(lastLabels).length + ")");
  } catch (err) {
    const ta = document.createElement("textarea");
    ta.value = payload;
    ta.setAttribute("readonly", "");
    ta.className = "clip-box";
    document.body.append(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (copyErr) {
      ok = false;
    }
    ta.remove();
    status(ok
      ? "текст с задачей скопирован (меток: " + uniqueLabels(lastLabels).length + ")"
      : "буфер недоступен: " + err + " — скопируй окно «Что ушло» вручную", ok ? "" : "err");
  }
}

/* #201 п.3: копирование обезличенного = главный практический выход.
   Clipboard API (self-origin; CSP без new permission-директив, write —
   transient activation из click = штатный путь), fallback — внедрённая
   textarea + execCommand (loopback http = secure context НЕ гарантирован,
   clipboard-контур требует HTTPS/localhost: localhost = ok по спецификации,
   127.0.0.1 = тоже secure context; fallback для древних движков).
   Текст в DOM идёт только value (никакого innerHTML — ПДн-контракт). */
async function copyMasked() {
  if (masked === "") return;
  try {
    await navigator.clipboard.writeText(masked);
    status("обезличенный текст скопирован в буфер");
  } catch (err) {
    const ta = document.createElement("textarea");
    ta.value = masked;
    ta.setAttribute("readonly", "");
    /* Класс, не inline-стиль: style-src запрещает инлайн (контракт CSP
       песочницы, см. шапку файла); .clip-box = off-screen в app.css. */
    ta.className = "clip-box";
    document.body.append(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (copyErr) {
      ok = false;
    }
    ta.remove();
    status(ok
      ? "обезличенный текст скопирован в буфер"
      : "буфер недоступен: " + err + " — скопируй окно «Что ушло» вручную", ok ? "" : "err");
  }
}

/* Стартовая очередь (#201): шаг 1 активен, 2/3 зажаты причинами;
   refreshButtons перекрашивает при каждом изменении состояния, loadHealth()
   переключает pending-режим (#198). Инит идёт ПОСЛЕ объявлений функций
   (function-декларации hoisted, констанные state — нет): порядок = контракт. */

/* --- демо-документ (#202) --------------------------------------------------

  Большой «хороший пример» (1.5-2.5 КБ, форма = деловое письмо по образцам
  вендорских PII-песочниц): 8 классов схемы + формы #200 (паспорт 4508
  455561, телефон +7 916) честными вхождениями, ФИО в склонениях +
  транслит-пара (Ушаков/Ushakov — витрина FN-класса, не врать: транслит
  каскад 0 не красит, и в этом цель примера: видно, ПОЧЕМУ часть не
  замазана; «4508 455561» закрыт каркасным вето #212, email-обрезки —
  форматным валидатором #222: адрес в письмах целиком); «невалидные»
  95/1110 в реквизитах — каркас + форма без чексуммы #234 (0.95, в
  разборе читается валидатором «frame_invalid»: документ с невалидным
  номером = реальные ПДн, маскировать есть чем). <= MAX_BODY_BYTES
  (1 MiB) — зуб
  ui_sandbox. localStorage-флаг = не ПДн (issue #202 п.6).
-------------------------------------------------------------------------- */

const DEMO_TEXT = [
  "Исх. № 412-ОД от 14.10.2026",
  "Генеральному директору ООО «Вектор-Инвест»",
  "Ушакову Петру Сергеевичу",
  "",
  "Уважаемый Пётр Сергеевич!",
  "",
  "Настоящим подтверждаем заключение договора № 77-Д/26 от 03.10.2026 между ООО «Вектор-Инвест» (ИНН 7707083893, КПП 770701001, ОГРН 1027739401110, юр. адрес: 107031, Москва, ул. Кузнецкий Мост, д. 18, стр. 2) и ООО «Ромашка» (ИНН 5027196012, КПП 502701001, адрес: 140006, г. Люберцы, ул. Победная, д. 3, кв. 15).",
  "",
  "Контактные лица сторон:",
  "со стороны ООО «Вектор-Инвест»: Ушакова Кира Саввична, паспорт 45 09 123456, выдан ОВД г. Москвы 12.05.2019, адрес регистрации: 123308, Москва, 3-й Силиконный проезд, д. 6, кв. 212, телефон +7 916 240-18-77, e-mail: ushakova@ektor-invest.example;",
  "со стороны ООО «Ромашка»: Соколов Денис Андреевич (транслит в реестре: Ushakov Petr Sergeevich, Sokolov Denis), СНИЛС 112-233-455 95, телефон +7 (903) 118-45-90, e-mail: d.sokolov@romashka.example.",
  "",
  "Оплата по договору № 77-Д/26: сумма договора 1 224 000 рублей, аванс 30 % = 367 200 рублей, остаток 856 800 рублей переводом на расчётный счёт получателя № 40702810900000012345 в ПАО «Банк-Запад» (БИК 044525225, к/с 30101810400000000225), карта получателя 2202 2036 5123 4567 expiry 12/28, CVC не указывается в переписке.",
  "Паспортные данные директора плательщика для реестра: 4508 455561, выдан 07.04.2015 (форма серии/номера подряд — каскад 0 её не находит, и это видно в разборе ниже: проверка границ детектора, не опечатка в примере).",
  "",
  "Просим подтвердить получение и направить подписанный экземпляр по адресу: 107031, Москва, ул. Кузнецкий Мост, д. 18, стр. 2, а также на e-mail: reestr@romashka.example; вопросы по реквизитам — +7 495 789-65-43 (доб. 21).",
  "Для сверки реестра запрашиваем обратный адрес: support@cloud.i-o.example (плюс-адрес сверки: support+reestr@cloud.i-o.example).",
  "",
  "С уважением,",
  "Соколов Денис Андреевич",
  "ООО «Ромашка», ИНН 5027196012",
  "т. +7 903 118-45-90, d.sokolov@romashka.example",
].join("\n");

function setDemoText() {
  $("src").value = DEMO_TEXT;
  status("демо-документ подставлен: «Разобрать» (шаг 1)");
}

function demoAutofillOnLoad() {
  // Флаг = localStorage (issue #202: session/флаг примера = не ПДн);
  // throw-safe: sandboxed-iframe без хранилища = молчаливый дефолт «показать».
  let stored = "0";
  try {
    stored = window.localStorage.getItem("fasad.demo.noauto") || "0";
  } catch (err) {
    stored = "0";
  }
  if (stored === "1") {
    $("demoNoAuto").checked = true;
    return false;
  }
  return true;
}

function toggleDemoNoAuto() {
  try {
    window.localStorage.setItem("fasad.demo.noauto", $("demoNoAuto").checked ? "1" : "0");
  } catch (err) {
    /* хранилища нет = флаг живёт до перезагрузки, не ПДн */
  }
}

/* --- чат-панель (#202) -----------------------------------------------------

  Ручная проверка оператора: обезличенный → upstream через гард (тот же
  allowlist-контур #68: X-Upstream-URL, пустой allowlist демона = 403
  proxy_not_configured — честный текст в статусе) → ответ ИИ с токенами
  (SSE-поток #68: читаем чанками, печатаем по мере прихода) → «Раскрыть
  ответ» = POST /v1/deanonymize(text=ответ): оригиналы в ответе ИИ.
  mode/session.json из ответа = буфер-детект; ответ-буфер живёт в памяти
  вкладки (chatText), не в DOM (ПДн-контракт: текст только в textContent).
-------------------------------------------------------------------------- */

const LS_UPSTREAM = "fasad.chat.upstream";
const LS_MODEL = "fasad.chat.model";

let chatText = "";

function chatStatus(text, kind) {
  const el = $("chatStatus");
  el.textContent = text;
  if (kind) el.dataset.kind = kind;
  else delete el.dataset.kind;
}

function loadChatPrefs() {
  try {
    const u = window.localStorage.getItem(LS_UPSTREAM);
    const m = window.localStorage.getItem(LS_MODEL);
    if (u) $("upstream").value = u;
    if (m) $("chatModel").value = m;
  } catch (err) {
    /* хранилища нет = чистые поля, это не ПДн */
  }
}

function saveChatPrefs() {
  try {
    window.localStorage.setItem(LS_UPSTREAM, $("upstream").value.trim());
    window.localStorage.setItem(LS_MODEL, $("chatModel").value.trim());
  } catch (err) {
    /* см. loadChatPrefs */
  }
}

function chatTokens(text) {
  // Токены vault-режима — ОБЕ формы, первичка vault.rs:
  //   stateless = `[[F0#base64url]]` (MARKER_PREFIX, token.rs:117),
  //   session   = `[КЛАСС_н_nonce]` — ПОДЧЕРКИВАНИЕ, не `#`
  //   (`[PERSON_NAME_1_9A31C2D4]`, шапка vault.rs:12/31); ревью #203 §4:
  //   шаблон с `#` в session-режиме молча считал ноль = счётчик «токенов
  //   раскрыто» врал нулём; тест-пара `chat_token_counter_counts_both_forms`.
  // Шаблон = `[КЛАСС_н_nonce]` (не список классов): `(?i)` обязателен —
  // id схемы малы (inn, person_name), а РЕАЛЬНЫЕ метки session-режима
  // ЗАГЛАВНЫЕ: `Grammar::LABEL` = алфавит `A-Z0-9_` (vault.rs:240,914),
  // класс в метке верхним регистром (промер #203: `[PERSON_NAME_1_SOHIKRAL]`
  // = 23 метки демо; строгий regex по schema-ids = 0 = счётчик врал).
  // `[Телефон:…]` (формат SPEC §3) не совпадает: двоеточие не `_\d+_`.
  var reSession = /\[[a-z][a-z0-9_]*_\d+_[^\]\n]*\]/gi;
  return (text.match(/\[\[[^\]\n]*\]\]/g) || []).length +
    (text.match(reSession) || []).length;
}
async function sendToChat() {
  const up = $("upstream").value.trim();
  if (up === "") {
    chatStatus("укажи адрес чата (X-Upstream-URL): демон пропускает только хосты из FASAD_UPSTREAM_ALLOWLIST", "err");
    return;
  }
  saveChatPrefs();
  const model = $("chatModel").value.trim() || "fasad-ui-demo";
  const body = {
    model: model,
    stream: true,
    messages: [
      // #225: задача = та же константа-обёртка, что у кнопки копирования
      // (прокси-путь = user-шаблон; system = короткая константа «метки не
      // трогай»: бюджет подмен #84 промерен на document-размер = к шаблону
      // добавляется ~полкилобайта константы, не подмен).
      { role: "system", content: "Ты обрабатываешь обезличенный документ. Метки вида [КЛАСС_н_XXXX] и [[F0#…]] не трогай, значения из текста не придумывай." },
      { role: "user", content: taskPrompt(masked, lastLabels) },
    ],
  };
  chatText = "";
  $("chatPaste").value = "";
  $("outChat").textContent = "";
  $("outChatRevealed").textContent = "";
  $("btnReveal").disabled = true;
  $("revealChecklist").hidden = true;
  chatStatus("отправка в чат… (ответ придёт по мере генерации)");
  const headers = {
    "Content-Type": "application/json",
    "Accept": "text/event-stream",
    "X-Guard-Policy": $("policy").value,
    "X-Upstream-URL": up,
    "X-Session-ID": session,
  };
  // #202: Authorization = ключ апстрима (поле password, в localStorage НЕ
  // пишется); carry_headers прокси (#68) переносит его апстриму.
  const key = $("chatKey").value.trim();
  if (key !== "") headers["Authorization"] = "Bearer " + key;
  try {
    const res = await fetch("/v1/chat/completions", { method: "POST", headers, body: JSON.stringify(body) });
    if (!res.ok) {
      const raw = await res.text();
      let code = "";
      try { code = JSON.parse(raw).error.code; } catch (err) { code = raw.slice(0, 80); }
      chatStatus("отказ гарда/апстрима: HTTP " + res.status + " | " + code + " — " +
        (code === "proxy_not_configured"
          ? "запусти демона с FASAD_UPSTREAM_ALLOWLIST=<хост> (README §Прокси)"
          : code === "allowlist_denied"
            ? "хоста нет в FASAD_UPSTREAM_ALLOWLIST демона"
            : code === "cascade_unavailable"
              ? "каскад не досчитал спанов (окно экстрактора #84): укороти текст или разбей на части — в песочнице это видно честно"
              : "проверь адрес и ключ чата (поле «ключ чата» = Bearer, переносится апстриму)"
        ), "err");
      return;
    }
    // SSE-поток #68: чанки `data: {...}` → дельта assistant.content.
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const r = await reader.read();
      if (r.done) break;
      buf += dec.decode(r.value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line.startsWith("data:")) continue;
        const payload = line.slice(5).trim();
        if (payload === "[DONE]") continue;
        try {
          const j = JSON.parse(payload);
          const delta = j.choices && j.choices[0] && j.choices[0].delta && j.choices[0].delta.content;
          if (typeof delta === "string") {
            chatText += delta;
            $("outChat").textContent = chatText;
          }
        } catch (err) {
          /* не-JSON-строка (keep-alive) = молчание, контракт SSE */
        }
      }
    }
    chatStatus("ответ получен: токенов в ответе: " + chatTokens(chatText) +
      " — «Раскрыть ответ» вернёт оригиналы");
    $("btnReveal").disabled = chatText === "";
  } catch (err) {
    chatStatus("сетевой сбой чата: " + err, "err");
  }
}

/* #225: чек-лист расшифровки «изменённого ответа». Формы метки = ОБЕ
   (контур chatTokens #203: stateless `[[F0#…]]` + session `[КЛАСС_н_…]`);
   «остаточные» = совпадения формы в ответе ДО deanonymize (ответ чата
   обязан нести ровно известные метки) и ПОСЛЕ (после > 0 = модель
   мутировала метку = она не развернулась = честное предупреждение). */
const LABEL_FORM = /\[\[[^\]\n]*\]\]|\[[a-z][a-z0-9_]*_\d+_[^\]\n]*\]/gi;

function labelForms(text) {
  return (text.match(LABEL_FORM) || []);
}

function renderRevealChecklist(before, after, substituted) {
  const el = $("revealChecklist");
  const uniq = uniqueLabels(lastLabels);
  const m = uniq.length;
  const seen = labelForms(before);
  // «вернулась» = метка сессии дошла до ответа чата (вхождением в before).
  const back = uniq.filter(function (label) { return seen.indexOf(label) >= 0; });
  const lost = uniq.filter(function (label) { return seen.indexOf(label) < 0; });
  const residual = labelForms(after).length;
  const lines = [];
  lines.push("раскрыто " + back.length + " из " + m +
    " (подмен деанона: " + substituted + ")");
  if (m > 0 && lost.length > 0) {
    lines.push("не вернулись (" + lost.length + "): " + lost.join(", "));
  }
  if (residual > 0) {
    lines.push("ОСТАТОЧНЫЕ МЕТКИ после раскрытия: " + residual +
      " — модель мутировала метки (форма цела, замена не распознана)");
  }
  el.textContent = lines.join(" | ");
  el.dataset.kind = (lost.length > 0 || residual > 0) ? "err" : "";
  el.hidden = false;
}

async function revealChatAnswer(source) {
  const text = source === "paste" ? $("chatPaste").value : chatText;
  if (text === "") {
    chatStatus(
      source === "paste" ? "вставь ответ из своего чата в поле выше" : "сначала «В чат через прокси»",
      "err",
    );
    return;
  }
  try {
    // session-режим = X-Session-ID подставляет api() (vault-сессия вкладки);
    // stateless = ключ в самом токене [[F0#…]] (деанон без сессии живёт).
    const res = await api("/v1/deanonymize", { text: text });
    const n = res.data.substituted;
    $("outChatRevealed").textContent = res.data.text;
    renderRevealChecklist(text, String(res.data.text || ""), n);
    chatStatus(
      "токенов в ответе: " + chatTokens(text) + " | токенов раскрыто: " + n +
      headerLine(res.headers) +
      (n > 0
        ? " — сверь окна: смысл цел, ПДн были только в токенах"
        : " — токенов в ответе не найдено"),
    );
  } catch (err) {
    chatStatus("раскрытие: " + (err instanceof ApiError ? err.message : err), "err");
  }
}
/* Дефолтный текст = демо-документ #202 при первом открытии (флаг
   localStorage «больше не показывать» = короткая заготовка). */
if (demoAutofillOnLoad()) {
  $("src").value = DEMO_TEXT;
}
loadChatPrefs();
showSession();
setStepActive(1);
refreshButtons();
initTabs();
loadHealth();
loadSchema();
loadWeights();
loadSettings();
