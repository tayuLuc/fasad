// JS-зуб #246: остров maskDropped из ui/app.js (тот же run_js_fixture-контур
// #203: node argv[2] / osascript __APP_PATH__). CRLF-контракт (win git
// checkout = \r\n; CI-провен #225): промер живёт на LF-нормализации.
// Мутация островa (вычесть base, вернуть 0) = красный.
var app;
if (typeof process !== "undefined" && process.argv) {
  app = require("fs").readFileSync(process.argv[2], "utf8");
} else {
  ObjC.import("Foundation");
  app = $.NSString.stringWithContentsOfFileEncodingError("__APP_PATH__", 4, null).js;
}
app = app.replace(/\r\n/g, "\n");
function fnSlice(name) {
  var i = app.indexOf(name);
  if (i < 0) { throw new Error("fn not found: " + name); }
  var j = app.indexOf("\n}", i);
  if (j < 0) { throw new Error("fn end not found: " + name); }
  return app.slice(i, j + 2) + "\n";
}
var src = fnSlice("function maskDropped");
var f = new Function("baseLen", "shownLen", src + " return maskDropped(baseLen, shownLen);");
// (7 базовых, 6 при S=0.99) = 1 снятый каркасный 0.95-хит (#234; скрин
// оператора v0.1.5). (2,2) = порог ничего не снял. (0,0) = пустой текст.
// (5,6) = монотонность: порог не добавляет спанов, отрицательной разницы
// счётчик не показывает. NaN/мусор = 0 (graceful, статус-строка живая).
var out = JSON.stringify([f(7, 6), f(2, 2), f(0, 0), f(5, 6), f(NaN, 3), f("3", "1")]);
if (typeof process !== "undefined" && process.argv) {
  console.log(out);
}
out;
