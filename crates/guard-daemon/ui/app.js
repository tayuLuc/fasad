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

function showSession() {
  $("session").textContent = "сессия: " + session;
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
  const thr = Number($("thr").value);
  if (thr > 0) body.score_threshold = thr;
  try {
    const res = await api("/v1/analyze", body);
    spans = Array.isArray(res.data) ? res.data : [];
    paint(text, spans);
    renderSpans(spans);
    $("out").textContent = "";
    masked = "";
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
    $("out").textContent = masked;
    status(
      "подмен: " + res.data.items.length + headerLine(res.headers),
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
    $("out").textContent = res.data.text;
    const same = res.data.text === $("src").value;
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
    renderSpans([]);
    paint("", []);
    $("out").textContent = "";
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
}

async function loadHealth() {
  try {
    const res = await api("/health");
    $("mode").textContent =
      "режим: " +
      res.data.mode +
      " | этап " +
      res.data.stage +
      " | версия " +
      res.data.version;
  } catch (err) {
    $("mode").textContent = "демон не отвечает: " + err;
  }
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
    $("weightsDir").textContent = "статус недоступен: " + err;
    return;
  }
  const w = d.weights || {};
  $("weightsDir").textContent =
    "путь: " + (w.dir || "(не определён)") + (w.default ? " (по умолчанию)" : "");
  const ul = $("weightsFiles");
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
  $("weightsModel").textContent =
    "lockR rev " + (m.lockr_revision || "—") +
    " · Decide rev " + (m.arbiter_revision || "—") +
    " · этап " + d.stage;
  renderFetch(d.fetch);
}

function renderFetch(fr) {
  const bar = $("fetchBar");
  const msg = $("fetchMsg");
  const btn = $("btnFetch");
  const phase = $("fetchPhase");
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
  const msg = $("fetchMsg");
  $("btnFetch").disabled = true;
  try {
    await api("/v1/models/fetch", {}, "POST");
    msg.textContent = "загрузка начата…";
    msg.dataset.kind = "";
  } catch (err) {
    msg.textContent = "старт не принят: " + err;
    msg.dataset.kind = "err";
  }
  $("btnFetch").disabled = false;
  loadWeights();
}

/* --- wiring ------------------------------------------------------------- */

$("thr").addEventListener("input", function () {
  $("thrOut").value = Number($("thr").value).toFixed(2);
});
$("btnAnalyze").addEventListener("click", analyze);
$("btnAnon").addEventListener("click", anonymize);
$("btnDean").addEventListener("click", deanonymize);
$("btnReset").addEventListener("click", resetSession);

$("btnFetch").addEventListener("click", fetchWeights);

$("src").value =
  "Иванова Мария Петровна, ИНН 7707083893, тел. +7 916 123-45-67, " +
  "ivanova@example.test, паспорт 4509 123456";
showSession();
$("thrOut").value = "0.00";
loadHealth();
loadSchema();
loadWeights();
