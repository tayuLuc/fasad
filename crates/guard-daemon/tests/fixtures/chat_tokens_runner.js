// JS-зуб #203 §4 (нить e): счётчик chatTokens из ui/app.js на ОБЕИХ формах
// меток vault. Движок: node (argv = [script, app.js]) или osascript JXA
// (mac: argv в скрипт не пробрасывается = первичка JXA-провен; путь app.js
// подставляет ТЕСТ литералом __APP_PATH__ ниже). Фикстуры = литералы здесь:
// «Телефон» через fromCharCode (кириллица-литерал = hit скана языка, а
// формат-подстановка [Телефон:…] в счётчик попадать НЕ должна).
var app;
if (typeof process !== "undefined" && process.argv) {
  app = require("fs").readFileSync(process.argv[2], "utf8");
} else {
  ObjC.import("Foundation");
  app = $.NSString.stringWithContentsOfFileEncodingError("__APP_PATH__", 4, null).js;
}
var i = app.indexOf("function chatTokens");
var src = app.slice(i, app.indexOf("\n}", i) + 3);
var f = new Function("text", src + " return chatTokens(text);");
var stateless = "x [[F0#NoIMUf3sHWFZPhjj0Hk-uw]] y [[F0#abc-def_123]] z";
var tPhone = String.fromCharCode(1058, 1077, 1083, 1077, 1092, 1086, 1085);
// РЕАЛЬНАЯ форма session-метки = ЗАГЛАВНЫЙ класс (Grammar::LABEL алфавит
// A-Z0-9_, vault.rs:240/914): `[PERSON_NAME_1_SOHIKRAL]` (промер #203:
// живой anonymize 48/48 меток верхним регистром); фикстура была
// строчная [inn_2_ABCDEF01] = regex `(?i)` ловил её и без кириллического
// промера (2/2 зелёный при реальном нуле) — первичка, не plausibility.
var session =
  "A [PERSON_NAME_1_SOHIKRAL], B [INN_2_7QZ3X9], " +
  "C [PHONE_3_112233445566], [" + tPhone + ":12345678901]";
var out = JSON.stringify([f(stateless), f(session)]);
if (typeof process !== "undefined" && process.argv) {
  console.log(out);
}
out;
