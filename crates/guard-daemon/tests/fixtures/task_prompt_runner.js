// JS-зуб #225: шаблон-промпта + labelForms из ui/app.js (тот же
// run_js_fixture-контур #203: node argv[2] / osascript __APP_PATH__).
// CRLF-контракт (win git checkout = \r\n; CI-провен #225): весь промер
// живёт на LF-нормализации. Маркеры = идентификаторы, константы режутся
// парсером до `;` вне строкового литерала (многострочная `+`-склейка).
var app;
if (typeof process !== "undefined" && process.argv) {
  app = require("fs").readFileSync(process.argv[2], "utf8");
} else {
  ObjC.import("Foundation");
  app = $.NSString.stringWithContentsOfFileEncodingError("__APP_PATH__", 4, null).js;
}
app = app.replace(/\r\n/g, "\n");
function sliceBetween(startMark, endMark) {
  var i = app.indexOf(startMark);
  var j = app.indexOf(endMark, i);
  if (i < 0 || j < 0) { throw new Error("mark not found: " + startMark); }
  return app.slice(i, j + endMark.length) + "\n";
}
function fnSlice(name) {
  var i = app.indexOf(name);
  if (i < 0) { throw new Error("fn not found: " + name); }
  var j = app.indexOf("\n}", i);
  if (j < 0) { throw new Error("fn end not found: " + name); }
  return app.slice(i, j + 2) + "\n";
}
function constSlice(name) {
  var i = app.indexOf(name);
  if (i < 0) { return ""; }
  var j = i;
  var quote = null;
  var esc = false;
  for (;;) {
    var c = app[j];
    if (c === undefined) { throw new Error("const end not found: " + name); }
    if (esc) {
      esc = false;
    } else if (c === "\\") {
      esc = quote !== null;
    } else if (quote === null && (c === '"' || c === "'")) {
      quote = c;
    } else if (c === quote) {
      quote = null;
    }
    if (c === ";" && quote === null && !esc) {
      j += 1;
      break;
    }
    j += 1;
  }
  return app.slice(i, j) + ";\n";
}
function requireConst(name) {
  var hit = constSlice(name);
  if (hit === "") { throw new Error("const not found: " + name); }
  return hit;
}
var src =
  requireConst("const TASK_TEMPLATE_HEADER =") +
  fnSlice("function uniqueLabels") +
  fnSlice("function taskPrompt") +
  requireConst("const LABEL_FORM =") +
  fnSlice("function labelForms");
var api = new Function(
  "return (function () {" + src +
  " return { taskPrompt: taskPrompt, labelForms: labelForms, uniqueLabels: uniqueLabels };" +
  " })();"
)();
var out = {};
// 1) список меток подставляется (уникальные, со счётчиком), пустой = graceful.
var labels = ["[PERSON_NAME_1_ABCD]", "[INN_2_X1]", "[PERSON_NAME_1_ABCD]"];
var p = api.taskPrompt("x", labels);
out.labelsCounted = p.indexOf("(2):") >= 0;
out.deduped = (p.match(/\[PERSON_NAME_1_ABCD\]/g) || []).length === 1;
out.graceful = api.taskPrompt("x", []).indexOf("не найдено") >= 0;
out.tailIsText = api.taskPrompt("abcdef", []).slice(-6) === "abcdef";
// 3a) константа-шаблон доехала в остров целиком (промер `len48` =
// 1800 = заголовок+список; короткая строка = обрезок = red).
out.headerAlive = api.taskPrompt("x", []).length > 300;
// 2) labelForms = ОБЕ формы метки; формат-подстановка/числа = НЕ формы.
out.forms = api.labelForms(
  "[[F0#abc-def]] [PERSON_NAME_1_ABCD] [" +
    String.fromCharCode(1058, 1077, 1083, 1077, 1092, 1086, 1085) +
    ":123] 4508 455561 1 224 000"
).length;
// 3) длина: 48-меточный промпт ≤ 2000 (константа + список, ПДн нет).
var many = [];
for (var i = 0; i < 48; i += 1) { many.push("[PERSON_NAME_" + i + "_ABCDEFGH]"); }
out.len48 = api.taskPrompt("x", many).length;
var s = JSON.stringify(out);
if (typeof process !== "undefined" && process.argv) {
  console.log(s);
}
s;
