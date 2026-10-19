#![forbid(unsafe_code)]
//! Каскады 1–2: нейросетевая разметка и арбитраж (ONNX).
//!
//! Скелет шага 1 (SPEC §10 п.1); реализация шага 4 идёт атомами: **4b-1** —
//! [`chunker`] (окно+overlap) и length-bucketing плюс [`merger`]
//! (greedy leftmost-longest); декодер boundary-голов, кэш эмбеддингов схем и
//! загрузка графов — следующие атомы того же шага. Инференс-слой за фичей
//! `ort-inference`: без неё крейт не тянет onnxruntime и `cargo check` обеих ОС
//! остаётся лёгким.
//!
//! Свой пре/postprocess поверх `ort` напрямую: обёртки `gline-rs`/`gliclass-rs`
//! зажаты на `ort =rc.9` + `tokenizers ^0.21` (SPEC §7, промер 18.10 подтвердил
//! конфликт) — они остаются только референсом кода декодирования.

/// Живой Decide-арбитр (4b-2c): констрэкт разметки + инференция + softmax по
/// группам. За фичей `ort-inference`: тип держит сессию `ort::session::Session`,
/// поэтому чистая часть ([`softmax`], [`decide_probs`]) доступна только с ней —
/// контракт §7 (крейт без фичи не тянет onnxruntime, `cargo check` обеих ОС лёгкий).
#[cfg(feature = "ort-inference")]
pub mod arbitrate;
pub mod chunker;
pub mod decide;
pub mod merger;
#[cfg(test)]
mod proptests;

/// Экстрактор (`GLiNER` 2.5 multi / ruBERT-pii-ner): спаны + вектор классов + confidence.
///
/// TODO(шаг 4b-2): свой декодер boundary-голов; `τ_low` 0.20–0.25 (FN фатален);
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
/// TODO(шаг 4b-3): short-circuit — вызывать только для 0.22 ≤ p1 < 0.80 и
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

/// Загрузка графов с external data (ловушка 4× промерена, SPEC §5.6 п.5).
///
/// TODO(шаг 4b-2): инициализация сессии по manifest из `models/` (URL+revision+sha256),
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
        let _ = super::chunker::ChunkCfg::default();
        let _ = super::extractor::Thresholds {
            low: 0.25,
            high: 0.80,
        };
        let _ = super::arbitrator::GrayZone { lo: 0.22, hi: 0.80 };
        let _ = super::merger::Merger::new();
        let _ = super::graph::GraphRef;
    }
}
