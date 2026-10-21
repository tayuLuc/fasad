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
/// Живой каскад 1 (lockR-экстрактор, #14A): констрэкт входа + инференция +
/// B/I-декод в одном типе. Вынесен из `examples/recall_golden.rs`, чтобы
/// продуктовый путь (`guard-daemon`) и харнес мерили и гоняли ОДИН код
/// (инвариант 7b «меряем = гоняем»); харнес после выноса вызывает этот модуль.
#[cfg(feature = "ort-inference")]
pub mod extract;
pub mod decide;
pub mod merger;
#[cfg(test)]
mod proptests;
/// Двухпороговая маршрутизация скоров (7b, #60): дефолты τ, полосы
/// Pass/Mask/Block, AND по рабочим порогам (quant-policy §3 п.2a), вето
/// валидатора. Единственный источник чисел `τ_low`/`τ_high` — демон
/// реэкспортирует из `config.rs`; харнес `examples/recall_golden.rs` считает
/// гейты этим же кодом (инвариант «меряем = гоняем»).
pub mod routing;

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
        // Стаб `extractor::Thresholds` (TODO 4b-2 по τ) закрыт атомом 7b:
        // пороги живут в `routing` — конструкция дефолтов проверяется там же
        // (`defaults_are_the_measured_constants`), здесь — constructible-контракт.
        let _ = super::routing::RoutingCfg::default();
        let _ = super::arbitrator::GrayZone { lo: 0.22, hi: 0.80 };
        let _ = super::merger::Merger::new();
        let _ = super::graph::GraphRef;
    }
}
