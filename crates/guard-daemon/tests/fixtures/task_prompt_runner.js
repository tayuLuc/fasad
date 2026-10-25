// JS-зуб #225: шаблон-промпта + labelForms из ui/app.js (островной прогон,
// тот же run_js_fixture-контур #203: node argv[2] / osascript __APP_PATH__).
var app;
if (typeof process !== "undefined" && process.argv) {
  app = require("fs").readFileSync(process.argv[2], "utf8");
} else {
  ObjC.import("Foundation");
  app = $.NSString.stringWithContentsOfFileEncodingError("__APP_PATH__", 4, null).js;
}
function sliceBetween(startMark, endMark) {
  var i = app.indexOf(startMark);
  var j = app.indexOf(endMark, i);
  if (i < 0 || j < 0) { throw new Error("mark not found: " + startMark); }
  return app.slice(i, j + endMark.length);
}
// const TASK_TEMPLATE_HEADER = "..."; = до `;`, за ним перенос строки.
var src =
  sliceBetween("const TASK_TEMPLATE_HEADER =", ";\n") + "\n" +
  sliceBetween("function uniqueLabels", "\n}") + "\n" +
  sliceBetween("function taskPrompt", "\n}") + "\n" +
  sliceBetween("const LABEL_FORM =", ";\n") + "\n" +
  sliceBetween("function labelForms", "\n}") + "\n";
var api = new Function(
  "return (function () {" + src +
  " return { taskPrompt: taskPrompt, labelForms: labelForms, uniqueLabels: uniqueLabels };" +
  " })();"
)();
var out = {};
// 1) список меток подставляется (уникальные, со счётчиком), пустой = graceful.
var labels = ["[PERSON_NAME_1_ABCD]", "[INN_2_X1]", "[PERSON_NAME_1_ABCD]"];
var p = api.taskPrompt("ТЕКСТ", labels);
out.labelsCounted = p.indexOf("(2):") >= 0;
out.deduped = (p.match(/\[PERSON_NAME_1_ABCD\]/g) || []).length === 1;
out.graceful = api.taskPrompt("x", []).indexOf("не найдено") >= 0;
out.tailIsText = p.slice(-5) === "ТЕКСТ";
// 2) labelForms = ОБЕ формы метки; формат-подстановка/числа = НЕ формы.
out.forms = api.labelForms(
  "[[F0#abc-def]] [PERSON_NAME_1_ABCD] [" +
    String.fromCharCode(1058, 1077, 1083, 1077, 1092, 1086, 1085) +
    ":123] 4508 455561 1 224 000"
).length;
// 3) длина: шаблон+48 меток ≤ 2000 (константа, ПДн нет: промер ниже).
var many = [];
for (var i = 0; i < 48; i += 1) { many.push("[PERSON_NAME_" + i + "_ABCDEFGH]"); }
out.len48 = api.taskPrompt("x", many).length;
var s = JSON.stringify(out);
if (typeof process !== "undefined" && process.argv) {
  console.log(s);
}
s;
