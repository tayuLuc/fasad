// JS-зуб #252-дочистка: CFG_NUMERIC из ui/app.js += FASAD_FRAME_MIN (контра
// #221: number-поле = README-обещание диапазона (0.5, 1]). Контур
// run_js_fixture #203: node argv[2] / osascript __APP_PATH__, CRLF-контракт.
var app;
if (typeof process !== "undefined" && process.argv) {
  app = require("fs").readFileSync(process.argv[2], "utf8");
} else {
  ObjC.import("Foundation");
  // osascript = argv без process: путь = аргумент вызова (run_js_fixture
  // подаёт его позиционно), фолбэк = __APP_PATH__ (контура mask_dropped).
  app = $.NSString.stringWithContentsOfFileEncodingError("__APP_PATH__", 4, null).js;
}
app = app.replace(/\r\n/g, "\n");
var i = app.indexOf("const CFG_NUMERIC = {");
if (i < 0) { throw new Error("CFG_NUMERIC not found"); }
var j = app.indexOf("\n};", i);
if (j < 0) { throw new Error("CFG_NUMERIC end not found"); }
// Срез = `const CFG_NUMERIC = {...};` целиком: eval с return имени.
var obj = new Function(app.slice(i, j + 3) + " return CFG_NUMERIC;")();
var fm = obj.FASAD_FRAME_MIN;
var out = JSON.stringify([
  fm.min,
  fm.max,
  fm.step,
  Object.keys(obj).length,
]);
if (typeof process !== "undefined" && process.argv) {
  console.log(out);
}
out;
