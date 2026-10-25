// JS-зуб #248: острова группировки/счётчика/сортировки/фильтра таблицы
// терминов из ui/app.js (тот же run_js_fixture-контур #203/#246: node
// argv[2] / osascript __APP_PATH__; CRLF-нормализация = win-провен #225).
// Мутация островов (сломать счётчик, порядок, фильтр) = красный.
var app;
if (typeof process !== "undefined" && process.argv) {
  app = require("fs").readFileSync(process.argv[2], "utf8");
} else {
  ObjC.import("Foundation");
  app = $.NSString.stringWithContentsOfFileEncodingError("__APP_PATH__", 4, null).js;
}
app = app.replace(/\r\n/g, "\n");

function utf8Len(str) {
  // JXA-остров #203-контура: JavaScriptCore в osascript НЕ несёт TextEncoder
  // (провен этого зуба). Движки сходятся на подсчёте: UTF-8-байты =
  // 1 (ASCII) / 2 (до U+7FF) / 3 (BMP) / 4 (суррогатные пары).
  var n = 0;
  for (var i = 0; i < str.length; i += 1) {
    var c = str.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c < 0xdc00 && i + 1 < str.length) { n += 4; i += 1; }
    else n += 3;
  }
  return n;
}
function utf8Bytes(str) {
  var out = new Uint8Array(utf8Len(str));
  var p = 0;
  for (var i = 0; i < str.length; i += 1) {
    var c = str.charCodeAt(i);
    if (c < 0x80) {
      out[p++] = c;
    } else if (c < 0x800) {
      out[p++] = 0xc0 | (c >> 6);
      out[p++] = 0x80 | (c & 0x3f);
    } else if (c >= 0xd800 && c < 0xdc00 && i + 1 < str.length) {
      var lo = str.charCodeAt(i + 1);
      i += 1;
      var cp = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
      out[p++] = 0xf0 | (cp >> 18);
      out[p++] = 0x80 | ((cp >> 12) & 0x3f);
      out[p++] = 0x80 | ((cp >> 6) & 0x3f);
      out[p++] = 0x80 | (cp & 0x3f);
    } else {
      out[p++] = 0xe0 | (c >> 12);
      out[p++] = 0x80 | ((c >> 6) & 0x3f);
      out[p++] = 0x80 | (c & 0x3f);
    }
  }
  return out;
}

function fnSlice(name) {
  var i = app.indexOf(name);
  if (i < 0) { throw new Error("fn not found: " + name); }
  var j = app.indexOf("\n}", i);
  if (j < 0) { throw new Error("fn end not found: " + name); }
  return app.slice(i, j + 2) + "\n";
}

var rankSrc = "var SOURCE_RANK = " +
  app.slice(app.indexOf("[", app.indexOf("const SOURCE_RANK = ["))).split("];")[0].trim() + "];\n";
var src =
  "function TextEncoder() {}\nTextEncoder.prototype.encode = function (s) { return utf8Bytes(s); };\n" +
  fnSlice("function byteToChar") +
  fnSlice("function spanTexts") +
  rankSrc +
  fnSlice("function sourceRankFn") +
  fnSlice("function groupRank") +
  fnSlice("function groupSpans") +
  fnSlice("function sortGroups") +
  fnSlice("function filterGroups");
var f = new Function("utf8Len", "utf8Bytes", src + " return { spanTexts: spanTexts, groupSpans: groupSpans, sortGroups: sortGroups, filterGroups: filterGroups, SOURCE_RANK: SOURCE_RANK };");
var M = f(utf8Len, utf8Bytes);

// Демо-документ острова: кириллица = 2 байта/символ UTF-8, эмодзи = 4 байта
// и 2 UTF-16-индекса — байтовые координаты демона переводит тот же
// byteToChar, что paint (один контур координат).
var text =
  "Ушаков Пётр 🐾\n" +
  "Соколов Денис Андреевич подписал\n" +
  "ИНН 7707083893, ИНН 2482014338\n" +
  "Соколов Денис Андреевич в реестре\n";
var b = utf8Bytes(text);
function byteOf(charIndex) {
  // UTF-8-байты префикса ДО кодовой точки charIndex (char-индекс ≠ байт:
  // кириллица = 2 байта; slice по char-индексу = off-by-N, зуб это ловит).
  // text.slice(0, k) для k внутри суррогатной пары = валидный префикс UTF-16.
  return utf8Len(text.slice(0, charIndex));
}
function indexOfN(needle, occurrence) {
  var from = 0;
  var s = -1;
  var n = occurrence || 1;
  for (var k = 0; k < n; k += 1) {
    s = text.indexOf(needle, from);
    if (s < 0) { throw new Error("term missing in fixture text: " + needle); }
    from = s + needle.length;
  }
  return s;
}

function mk(cls, term, score, source, occurrence) {
  var bs = byteOf(indexOfN(term, occurrence));
  return {
    entity_type: cls,
    score: score,
    source: source,
    verdict: "mask_surrogate",
    byte_start: bs,
    byte_end: bs + utf8Len(term),
  };
}

function groupsOf(list) {
  return M.groupSpans(list, M.spanTexts(text, list));
}

// case 1: срез текста = термин (эмодзи после = байты ≠ символы ≠ UTF-16)
var t1 = M.spanTexts(text, [mk("person_name", "Ушаков Пётр", 0.8, "gliner_extractor")]);
var case1 = t1.length === 1 && t1[0] === "Ушаков Пётр";

// case 2: повтор токена = один термин ×2 (vault-семантика: повтор = один токен)
var s2 = [
  mk("person_name", "Соколов Денис Андреевич", 0.8, "gliner_extractor", 1),
  mk("person_name", "Соколов Денис Андреевич", 0.9, "gliner_extractor", 2),
];
var g2 = groupsOf(s2);
var case2 = g2.length === 1 && g2[0].count === 2 && g2[0].spans.length === 2;

// case 3: сортировка детерминированные первыми (frame-0.95 поднимается выше
// модели) + стабильный порядок first-occurrence внутри одного ранга
var s3 = [
  mk("person_name", "Соколов Денис Андреевич", 0.8, "gliner_extractor", 1),
  mk("inn", "2482014338", 0.95, "frame_invalid_checksum"),
  mk("card", "Ушаков Пётр", 0.7, "gliner_decide_arbitrator"),
];
// s3b = тройка + второй model-термин («Ушаков Пётр», gliner_extractor,
// first-occurrence ПОЗЖЕ «Соколов»): инверсия rank/перестановка model-пары =
// красный (зуб-стабильность; арбитр рангом НИЖЕ экстрактора = он в конце).
var s3b = s3.concat([mk("person_name", "Ушаков Пётр", 0.85, "gliner_extractor")]);
var g3 = M.sortGroups(groupsOf(s3b));
var g3keys = g3.map(function (g) { return g.cls + "=" + g.text; });
// Пара одного ранга = [b, a] по first-occurrence: пропасть tie-break
// (`|| a.i − b.i`) = компаратор отдаёт 0 = развёрнутую пару перестановкой =
// красный (нативная стабильность V8/JSC тут не аргумент: зуб меряет НАШ
// tie-break, а не движок).
var g3stable = M.sortGroups([
  { cls: "b", text: "y", count: 1, spans: [{ source: "gliner_extractor" }] },
  { cls: "a", text: "z", count: 1, spans: [{ source: "gliner_extractor" }] },
]).map(function (g) { return g.cls; });
var case3 = g3keys.join("|") ===
  "inn=2482014338|person_name=Соколов Денис Андреевич|person_name=Ушаков Пётр|card=Ушаков Пётр" &&
  g3stable.join(",") === "b,a";

// case 4: фильтр = подстрока, регистронезависимо; пустой = всё; счётчик = len
var s4 = [
  mk("inn", "7707083893", 1, "checksum_rf"),
  mk("inn", "2482014338", 1, "checksum_rf"),
  mk("person_name", "Ушаков Пётр", 0.8, "gliner_extractor"),
];
var g4 = groupsOf(s4);
var f4 = [
  M.filterGroups(g4, "").length,
  M.filterGroups(g4, "2482").map(function (g) { return g.cls; }).join(","),
  M.filterGroups(g4, "ушаков").map(function (g) { return g.text; }).join(","),
  M.filterGroups(g4, "  7707083893  ").length,
  M.filterGroups(g4, "нет-такого").length,
];
var case4 = f4.join("|") === "3|inn|Ушаков Пётр|1|0";

// case 5: мусорные координаты = пустой термин (не срез по чужому тексту);
// мусорный источник = ранг последней группы, не «детерминированный»
var bad = [{ entity_type: "inn", score: 1, source: "checksum_rf", verdict: "mask_surrogate", byte_start: 9999, byte_end: 1 }];
var t5 = M.spanTexts(text, bad);
var g5 = M.sortGroups([
  { cls: "x", text: "1", count: 1, spans: [{ source: "wat_unknown" }] },
  { cls: "y", text: "2", count: 1, spans: [{ source: "gliner_extractor" }] },
]).map(function (g) { return g.cls; });
var case5 = t5[0] === "" && g5.join(",") === "y,x";

// case 6: SOURCE_RANK = контракт JSON-имён DetectionSource (verdict.rs,
// первичка 04fe306) — детерминированные шесть первыми, модельные два после
var case6 = M.SOURCE_RANK.join(",") ===
  "checksum_rf,checksum_eu,base64_decode,secret_entropy,aho_corasick_rule," +
  "frame_invalid_checksum,gliner_extractor,gliner_decide_arbitrator";

var out = JSON.stringify({
  case1_textSlice: case1,
  case2_repeatCount: case2,
  case3_detFirst: case3,
  case4_filter: case4,
  case5_graceful: case5,
  case6_sourceRank: case6,
  groups3: g3keys,
  counts3: g3.map(function (g) { return g.count; }),
});
if (typeof process !== "undefined" && process.argv) {
  console.log(out);
}
out;
