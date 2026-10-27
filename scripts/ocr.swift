// ocr.swift — Vision OCR CLI для скан-контура fasad-file.py (#304 этап-3).
//
// Движок = Apple Vision (VNRecognizeTextRequest): оффлайн (air-gap-инвариант
// AGENTS: сети нет), ru+en, первичка #294: 0.44 с/стр, качество = рабочий
// промер на служебных сканах. Запуск: swiftc -O ocr.swift -o ocr;
// путь бинаря для обёртки = FASAD_OCR_BIN (mac-only: linux/windows =
// скан-зубы skip, #316-паттерн legs).
//
// Выход: строка на распознанную строку, табуляция-колонки:
//   "x;y;w;h\tmidX;midY\tтекст"
// bbox = normalized [0..1], origin BOTTOM-LEFT (первичка Vision-контракта
// #294; потребитель fasad-file пересчитывает в px top-left:
// y_px = (1 - y - h) * H). Середина = вторая колонка (R&D-формат #294,
// потребители парсят 1-ю и 3-ю).
//
// Fail-closed: файл не читается / Vision отказал = rc 2; пустой вывод =
// 0 строк = потребитель (fasad-file) трактует как отказ маскирования,
// НЕ как чистоту файла.

import AppKit
import Foundation
import Vision

let args = CommandLine.arguments
guard args.count >= 2 else {
    fputs("usage: ocr <image>\n", stderr)
    exit(2)
}
guard let img = NSImage(contentsOfFile: args[1]),
      let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil)
else {
    fputs("cannot load image\n", stderr)
    exit(2)
}
let req = VNRecognizeTextRequest()
req.recognitionLanguages = ["ru", "en"]
req.recognitionLevel = .accurate
req.usesLanguageCorrection = true
// #326 NIT-1 (belt air-gap, AGENTS «никаких сетевых вызовов»): Vision-запрос
// обязан быть on-device. Форма = рантайм-гейт + документированная первичка;
// буквальная форма ревью (пин свойства под availability-
// гейт) НЕ КОМПИЛИРУЕТСЯ на SDK26 — первички (Swift 6.4,
// macOS 26.6, этот атом; каждая убивает наивную форму):
// (1) символ usesOnDeviceRecognition = 0 совпадений в SDK26.5 Vision.tbd,
//     Headers (grep) и рантайм-бинаре /System/.../Vision (nm -gU, strings)
//     = УДАЛЁН из API ПОЛНОСТЬЮ (жил SDK13–15) = macOS 13+ Vision on-device
//     ALWAYS (сетевой путь вынут из API), пин на 13+ = мёртвый код;
// (2) property-доступ краснеет «has no member» ДАЖЕ под #available(macOS
//     13,*): тип-чек по SDK сборки (availability = рантайм; промен swiftc);
// (3) препроцессорного предиката SDK-версии в Swift НЕТ: #if swift() =
//     язык-версия (swiftc 6.4 дефолт = 5; матрица промерена), #if
//     compiler(>=5.7) на SDK26 = истина = блок доходит до type-check (2);
// (4) setter-обходы = ложная гарантия: KVC = NSUnknownKeyException
//     (read-back промер), ObjC-селектор setUsesOnDeviceRecognition: =
//     responds(to:)=false (промер) = сеты = no-op.
// Контра air-gap = die rc 2 на macOS < 13 (там сетевой fallback = реальный;
// молчащий серверный ход = fail-open; AGENTS: честный отказ, не ложь).
// 13+ = первичка (1). Меры: компилируемость = swiftc SDK26 (этот атом);
// сеть = 0 (grep URLSession/NSURL/socket = пусто).
if #unavailable(macOS 13) {
    fputs("Vision on-device only from macOS 13; on 12 network fallback"
        + " = air-gap violation = fail-closed\n", stderr)
    exit(2)
}

let handler = VNImageRequestHandler(cgImage: cg, options: [:])
do {
    try handler.perform([req])
} catch {
    fputs("vision failed: \(error)\n", stderr)
    exit(2)
}
for obs in (req.results ?? []) {
    guard let top = obs.topCandidates(1).first else { continue }
    let bb = obs.boundingBox // normalized, origin bottom-left
    print("\(bb.origin.x);\(bb.origin.y);\(bb.width);\(bb.height)\t"
        + "\(bb.midX);\(bb.midY)\t\(top.string)")
}
