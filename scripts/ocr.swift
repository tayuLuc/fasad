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
