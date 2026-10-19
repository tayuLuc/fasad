#![forbid(unsafe_code)]
//! Каскады 1–2: нейросетевая разметка и арбитраж (ONNX).
//!
//! Скелет шага 1 (SPEC §10 п.1); реализация — шаг 4. Инференс-слой за фичей
//! `ort-inference`: без неё крейт не тянет onnxruntime и `cargo check` обеих ОС
//! остаётся лёгким.
//!
//! Свой пре/postprocess поверх `ort` напрямую: обёртки `gline-rs`/`gliclass-rs`
//! зажаты на `ort =rc.9` + `tokenizers ^0.21` (SPEC §7, промер 18.10 подтвердил
//! конфликт) — они остаются только референсом кода декодирования.

/// Чанкер: 256–384 токена, overlap 32, length bucketing, B=1..4 на CPU.
///
/// TODO(шаг 4): вторая конфигурация окна для 512-моделей (448 токенов, stride 128,
/// SPEC §5.7 п.4). Батчить 4096 токенов одним куском нельзя — O(L²) + padding waste.
pub mod chunker {
    /// Заглушка конфигурации окна.
    #[derive(Debug, Clone, Copy)]
    pub struct Window {
        /// Максимум токенов в окно.
        pub max_tokens: usize,
        /// Перекрытие соседних окон.
        pub overlap: usize,
    }
}

/// Экстрактор (`GLiNER` 2.5 multi / ruBERT-pii-ner): спаны + вектор классов + confidence.
///
/// TODO(шаг 4): свой декодер boundary-голов; `τ_low` 0.20–0.25 (FN фатален);
/// кэш эмбеддингов схемы меток `E ∈ R^{C×D}` считается один раз на старте.
pub mod extractor {
    /// Заглушка порогов экстрактора (SPEC §2 каскад 1).
    #[derive(Debug, Clone, Copy)]
    pub struct Thresholds {
        /// Нижний порог извлечения.
        pub low: f64,
        /// Верхний порог уверенности (выше — без арбитра).
        pub high: f64,
    }
}

/// Арбитр серой зоны (`GLiNER` 2.5 Decide): yes/no/choice за 1 forward pass.
///
/// TODO(шаг 4): short-circuit — вызывать только для 0.22 ≤ p1 < 0.80 и
/// контекстно-зависимых классов; итог `S = α·p1 + (1−α)·p2`, α не калибрована.
pub mod arbitrator {
    /// Заглушка окна серой зоны (SPEC §2 каскад 2).
    #[derive(Debug, Clone, Copy)]
    pub struct GrayZone {
        /// Нижняя граница спорных скоров.
        pub lo: f64,
        /// Верхняя граница спорных скоров.
        pub hi: f64,
    }
}

/// Слияние пересекающихся спанов: interval tree, greedy leftmost-longest.
///
/// TODO(шаг 4): min(start)..max(end) c сохранением приоритета чексуммы (вето не
/// понижается); примитивы — `ByteSpan::intersection` / `ByteSpan::merge_hull`.
pub mod merger {
    /// Заглушка дерева интервалов.
    #[derive(Debug)]
    pub struct IntervalTree;
}

/// Загрузка графов с external data (ловушка 4× промерена, SPEC §5.6 п.5).
///
/// TODO(шаг 4): инициализация сессии по manifest из `models/` (URL+revision+sha256),
/// без сетевых вызовов в рантайме.
pub mod graph {
    /// Заглушка описания графа.
    #[derive(Debug, Default, Clone)]
    pub struct GraphRef;
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_types_are_constructible() {
        let _ = super::chunker::Window {
            max_tokens: 384,
            overlap: 32,
        };
        let _ = super::extractor::Thresholds {
            low: 0.25,
            high: 0.80,
        };
        let _ = super::arbitrator::GrayZone { lo: 0.22, hi: 0.80 };
        let _ = super::merger::IntervalTree;
        let _ = super::graph::GraphRef;
    }
}
