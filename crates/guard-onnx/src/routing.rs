//! Двухпороговая маршрутизация скоров каскада 1–2 (issue #60, атом 7b).
//!
//! Вынесено 1-в-1 из измерительного харнеса `examples/recall_golden.rs`:
//! демон (шаги 7c/8) и промер ходят по ОДНОМУ коду — инвариант «меряем =
//! гоняем» (issue #60 п.4: «examples → тонкая обёртка над lib, промер-метрики
//! не меняются»). Всё, что здесь есть сверх гейта харнеса, — обёртка над ним
//! же: гейт `score >= thr` = [`Route::extracted`] при вырожденной паре
//! `τ_low = τ_high = thr` ([`RoutingCfg::single`]).
//!
//! # Семантика полос (SPEC §2 каскад 1, amendment `docs/quant-policy.md` §3 п.2a)
//!
//! | условие                     | маршрут                                        |
//! |---|---|
//! | `score < max(τ_low, floor)`  | [`Route::Pass`]  — не извлечено                |
//! | извлечено, но `score < τ_high` | [`Route::Mask`]  — обратимое маскирование (серая зона, арбитр/vault) |
//! | `score ≥ τ_low` И `score ≥ τ_high` | [`Route::Block`] — fail-closed, запрос наружу не уходит |
//!
//! **Block = AND по обоим порогам** (amendment §3 п.2a: HARD-гейт действует на
//! рабочих `τ ∈ {0.20, 0.25}`, т.е. класс засчитывается только когда прошёл
//! обе τ). Реализовано буквально, проверкой обоих гейтов, а не свёрткой
//! `score >= τ_high`: при рассогласованной паре (`τ_high < τ_low` — конфиг
//! демона такое отвергает, `Thresholds::is_sane` в `guard-daemon`, но либа
//! обязана вести себя предсказуемо) наивный `>= τ_high` выводил бы в Block
//! скоры, прошедшие только один гейт, — тест
//! `inverted_pair_and_semantics_holds`.
//!
//! # `floor` — преселект (контракт #56 п.2)
//!
//! Третье число конфига — порог преселекта вызывающего (поле `score_threshold`
//! запроса `/v1/analyze`, шаг 6): он вправе **только поднимать** планку
//! (`effective = τ_low.max(floor)`), понизить её ниже серверного `τ_low` клиент
//! не может — не вправе ослаблять политику сервера. Block от `floor` НЕ зависит:
//! поднятие порога клиентом не разблокирует то, что сервер обязан блокировать.
//!
//! # Fail-Closed
//!
//! Нечисленный (`NaN`/`±inf`) скор или вне `[0,1]`/нечисленный порог — дефект
//! детектора/конфига, а не «низкий скор»: маршрут [`Route::Block`]
//! (AGENTS «ошибка детектора = запрос наружу не уходит»; молчащий `Pass`
//! при NaN был бы fail-open).
//!
//! # Детерминированный валидатор
//!
//! Скор валидатора (чексумма) весит 1.0 и порогами НЕ понижается (AGENTS
//! «Инженерные инварианты»): [`RoutingCfg::route_span`] для
//! `validator = true` возвращает [`Route::Block`] до всяких порогов — тот же
//! контракт, что `|| hit.source.deterministic_weight().is_some()` в
//! `guard-daemon::pipeline::passes` (шаг 6), теперь в одном месте.

use std::vec::Vec;

/// Дефолт `τ_low` экстрактора: **0.20**, нижняя граница диапазона SPEC §2
/// (0.20–0.25, «FN фатален, FP дёшев»).
///
/// Это «дефолт по замеру шага 6» (#56 п.2), а не выбор по вкусу. Промер
/// `recall_golden` на golden-v1.1 (N=150 recall-строк, `--threads 8`,
/// замороженный порядок блока, HEAD 08c35c3, 20.10):
///
/// | τ | Decide overall | Wilson lower 95 % | Decide `snils` |
/// |---|----------------|---------------------|----------------|
/// | 0.20 | 94.74 | 91.50 | 51.72 |
/// | 0.25 | 92.98 | 89.41 | 37.93 |
///
/// Разница +1.76 п.п. overall и +13.79 п.п. на `snils` в пользу 0.20; обе τ
/// проходят HARD-гейт amendment'а (`docs/quant-policy.md` §3 п.2a), значит
/// выбор делает нижняя граница, а SPEC §2 прямо велит держать порог низко.
///
/// С 7b единственный источник числа — здесь; `guard-daemon` реэкспортирует
/// (`config.rs`), env-переопределение `FASAD_TAU_LOW` живёт в конфиг-слое.
pub const DEFAULT_TAU_LOW: f64 = 0.20;

/// Дефолт `τ_high`: выше — без арбитра (SPEC §2 каскад 1). С 7b единственный
/// источник — здесь; демон реэкспортирует, env `FASAD_TAU_HIGH`.
pub const DEFAULT_TAU_HIGH: f64 = 0.80;

/// Дефолт `floor`: преселект не поднят (серверный `τ_low` работает сам).
pub const DEFAULT_FLOOR: f64 = 0.0;

/// Маршрут спана по двухпороговой полосе. Словарь намеренно шире вердикта
/// (`guard_types::Verdict`) — маппинг `Mask → MaskSurrogate|MaskCapsule`,
/// `Block → BlockRequest`, `Pass → KeepPublic` делает потребитель (7c),
/// т.к. выбор капсулы/суррогата — политика vault, а не маршрутизация.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Ниже полосы извлечения: текст не трогаем.
    Pass,
    /// Извлечено, но не «высокая уверенность»: обратимое маскирование,
    /// в серой зоне — кандидат арбитру (SPEC §2 каскад 2).
    Mask,
    /// Прошёл AND обоих порогов (или вето валидатора, или fail-closed):
    /// наружу в открытом виде не уходит.
    Block,
}

impl Route {
    /// Извлечено ли вообще (Mask или Block) — ровно старый гейт харнеса
    /// `score >= thr` при `RoutingCfg::single(thr)`.
    #[must_use]
    pub const fn extracted(self) -> bool {
        !matches!(self, Self::Pass)
    }
}

/// Конфиг маршрутизации: две рабочие τ + порог преселекта вызывающего.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RoutingCfg {
    /// `τ_low`: нижняя граница извлечения.
    pub tau_low: f64,
    /// `τ_high`: граница Block (AND вместе с `tau_low`).
    pub tau_high: f64,
    /// Преселект вызывающего: может только поднимать `τ_low` (см. doc модуля).
    pub floor: f64,
}

impl Default for RoutingCfg {
    fn default() -> Self {
        Self {
            tau_low: DEFAULT_TAU_LOW,
            tau_high: DEFAULT_TAU_HIGH,
            floor: DEFAULT_FLOOR,
        }
    }
}

impl RoutingCfg {
    /// Вырожденная пара `τ_low = τ_high = thr` — режим одного порога, в котором
    /// харнес `recall_golden` мерил 94.74@0.20 / 92.98@0.25. Полоса Mask пуста,
    /// `route(score).extracted() == score >= thr` (включительно, как в харнесе
    /// до 7b: `if conf < thr { continue }` / `decs[ci] >= thr as f32`).
    #[must_use]
    pub const fn single(thr: f64) -> Self {
        Self {
            tau_low: thr,
            tau_high: thr,
            floor: DEFAULT_FLOOR,
        }
    }

    /// Конечность и принадлежность `[0, 1]` всех трёх порогов. Ложь = мусор в
    /// конфиге: [`Self::route`] на ней обязан вернуть [`Route::Block`]
    /// (fail-closed), а валидировать и отказывать на старте — слой конфига
    /// (`guard-daemon::config::Thresholds::is_sane`).
    #[must_use]
    pub fn is_sane(&self) -> bool {
        let in_unit = |v: f64| v.is_finite() && (0.0..=1.0).contains(&v);
        in_unit(self.tau_low) && in_unit(self.tau_high) && in_unit(self.floor)
    }

    /// Маршрут по чистому скору модели. Вето валидатора здесь не применяется —
    /// для спана с источником [`Self::route_span`].
    #[must_use]
    pub fn route(&self, score: f64) -> Route {
        if !score.is_finite() || !self.is_sane() {
            return Route::Block;
        }
        // AND по обоим гейтам (amendment §3 п.2a) — не свёртка `>= tau_high`:
        // при рассогласованной паре Block требует прохождения обоих порогов.
        if score >= self.tau_low && score >= self.tau_high {
            return Route::Block;
        }
        if score >= self.tau_low.max(self.floor) {
            return Route::Mask;
        }
        Route::Pass
    }

    /// Маршрут спана с учётом вето валидатора: `validator = true` — Block
    /// безусловно, порогами и floor не понижается (AGENTS «приоритет
    /// детерминированного валидатора = 1.0»).
    #[must_use]
    pub fn route_span<C>(&self, span: &ScoredSpan<C>) -> Route {
        if span.validator {
            return Route::Block;
        }
        self.route(span.score)
    }
}

/// Векторный вход: скор с классом и флагом детерминированного валидатора.
/// `C` — идентификатор класса у потребителя (`&'static str` в харнесе,
/// `ClassId` в демоне).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoredSpan<C> {
    /// Класс схемы.
    pub class: C,
    /// Итоговый скор каскада.
    pub score: f64,
    /// True для детерминированного валидатора (вес 1.0, AGENTS): порогами не понижается.
    pub validator: bool,
}

/// Маршрутизированный спан (выход [`route_spans`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RoutedSpan<C> {
    /// Тот же класс, что на входе.
    pub class: C,
    /// Запрошенный скор (для логов/отрисовки без второго прохода).
    pub score: f64,
    /// Маршрут.
    pub route: Route,
}

/// Маршрутизировать вектор скоров одним вызовом — форма входа из ТЗ 7b
/// («score-вектор спанов + конфиг»), профиль выхода = профиль харнеса
/// (класс → вердикт полосы).
#[must_use]
pub fn route_spans<C>(cfg: &RoutingCfg, spans: &[ScoredSpan<C>]) -> Vec<RoutedSpan<C>>
where
    C: Copy,
{
    spans
        .iter()
        .map(|s| RoutedSpan {
            class: s.class,
            score: s.score,
            route: cfg.route_span(s),
        })
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::float_cmp,
    reason = "сравниваются константы контракта (0.20/0.25/0.80) и их точные f32-образы, не результат вычислений"
)]
mod tests {
    use super::*;

    fn cfg(low: f64, high: f64, floor: f64) -> RoutingCfg {
        RoutingCfg {
            tau_low: low,
            tau_high: high,
            floor,
        }
    }

    #[test]
    fn defaults_are_the_measured_constants() {
        // Числа — носители контракта #56 п.2 / SPEC §2; сдвиг сюда = сдвиг
        // замера, поэтому проверяем литералами, а не «дефолт равен дефолту».
        assert_eq!(DEFAULT_TAU_LOW, 0.20);
        assert_eq!(DEFAULT_TAU_HIGH, 0.80);
        assert_eq!(DEFAULT_FLOOR, 0.0);
        assert_eq!(RoutingCfg::default(), cfg(0.20, 0.80, 0.0));
    }

    #[test]
    fn bands_default_cfg() {
        // SPEC §2: ниже τ_low → pass, между → mask, ≥ τ_high → block.
        let c = RoutingCfg::default();
        let table: [(f64, Route); 7] = [
            (0.0, Route::Pass),
            (0.199_9, Route::Pass),
            (0.20, Route::Mask), // граница включительно (гейт харнеса `>=`)
            (0.50, Route::Mask),
            (0.799_9, Route::Mask),
            (0.80, Route::Block), // включительно
            (1.00, Route::Block),
        ];
        for (score, want) in table {
            assert_eq!(c.route(score), want, "score={score}");
        }
    }

    #[test]
    fn working_pair_bands() {
        // Рабочая пара amendment'а {0.20, 0.25}: между порогами — Mask, НЕ Block.
        let c = cfg(0.20, 0.25, 0.0);
        assert_eq!(c.route(0.19), Route::Pass);
        assert_eq!(c.route(0.20), Route::Mask);
        assert_eq!(c.route(0.249_999_9), Route::Mask);
        assert_eq!(c.route(0.25), Route::Block);
        assert_eq!(c.route(1.0), Route::Block);
    }

    #[test]
    fn inverted_pair_and_semantics_holds() {
        // Кейс расхождения порогов из ТЗ 7b: пара (τ_low=0.25, τ_high=0.20).
        // Скор 0.22 прошёл только верхний гейт: AND (amendment §3 п.2a) ⇒
        // не Block; не прошёл τ_low ⇒ и не Mask. Наивная свёртка `>= τ_high`
        // здесь дала бы Block — тест фиксирует, что её нет.
        let c = cfg(0.25, 0.20, 0.0);
        assert_eq!(c.route(0.22), Route::Pass, "один порог не даёт Block");
        assert_eq!(c.route(0.20), Route::Pass);
        assert_eq!(c.route(0.25), Route::Block, "AND обоих пройден");
        // Вырождение пары не даёт Mask-зоны: полоса [τ_low, τ_high) пуста.
        assert_eq!(c.route(0.249_9), Route::Pass);
    }

    #[test]
    fn floor_raises_only_and_never_unblocks() {
        let c = cfg(0.20, 0.80, 0.30);
        assert_eq!(
            c.route(0.22),
            Route::Pass,
            "floor поднят — извлечение ниже него гаснет"
        );
        assert_eq!(c.route(0.30), Route::Mask);
        assert_eq!(c.route(0.85), Route::Block, "floor не разблокирует Block");
        // floor НИЖЕ τ_low не понижает серверную планку (#56 п.2).
        let low = cfg(0.20, 0.80, 0.10);
        assert_eq!(low.route(0.22), Route::Mask);
        assert_eq!(low.route(0.19), Route::Pass);
    }

    #[test]
    fn fail_closed_on_garbage() {
        let c = RoutingCfg::default();
        assert_eq!(
            c.route(f64::NAN),
            Route::Block,
            "NaN скора = дефект детектора"
        );
        assert_eq!(c.route(f64::INFINITY), Route::Block);
        assert_eq!(c.route(f64::NEG_INFINITY), Route::Block);
        // Мусор в порогах = Block всему (fail-closed), не тихий Pass.
        for bad in [
            cfg(f64::NAN, 0.8, 0.0),
            cfg(0.2, 2.0, 0.0),
            cfg(0.2, 0.8, -0.1),
        ] {
            assert_eq!(
                bad.route(0.0),
                Route::Block,
                "cfg {bad:?} не прошёл is_sane: всё Block"
            );
            assert!(!bad.is_sane());
        }
        assert!(c.is_sane());
    }

    #[test]
    fn validator_priority_not_downgraded() {
        // Вето валидатора (вес 1.0) не понижается ни порогами, ни floor,
        // ни мусорным полем score: cfg с floor выше обоих гейтов — модельный
        // скор гаснет в Pass, валидатор остаётся Block.
        let c = cfg(0.20, 0.80, 0.95);
        let v = ScoredSpan {
            class: "inn",
            score: 0.42,
            validator: true,
        };
        assert_eq!(c.route_span(&v), Route::Block);
        let m = ScoredSpan {
            class: "phone",
            score: 0.42,
            validator: false,
        };
        assert_eq!(
            c.route_span(&m),
            Route::Pass,
            "тот же скор без валидатора — под floor"
        );
    }

    #[test]
    fn route_spans_vector_table() {
        // Таблица «score-вектор спанов → профиль mask/block/pass по классам»
        // (форма входа/выхода из ТЗ 7b), конфиг — дефолты демона.
        let spans = [
            ScoredSpan {
                class: "email",
                score: 0.10,
                validator: false,
            },
            ScoredSpan {
                class: "person_name",
                score: 0.55,
                validator: false,
            },
            ScoredSpan {
                class: "card_pan",
                score: 0.95,
                validator: false,
            },
            ScoredSpan {
                class: "inn",
                score: 1.00,
                validator: true,
            },
            ScoredSpan {
                class: "snils",
                score: 0.20,
                validator: false,
            },
        ];
        let got: Vec<Route> = route_spans(&RoutingCfg::default(), &spans)
            .iter()
            .map(|r| r.route)
            .collect();
        assert_eq!(
            got,
            vec![
                Route::Pass,
                Route::Mask,
                Route::Block,
                Route::Block,
                Route::Mask,
            ]
        );
        // Порядок выхода = порядок входа, позиционно. Без этой строки таблица
        // осталась бы зелёной при перестановке: классы в таблице разные, но
        // проверялся только профиль маршрутов, а не то, к какому спану он
        // относится. На этом утверждении держится зип `route_spans` с хитами в
        // `guard-daemon::pipeline` (шаг 7c).
        let classes: Vec<&str> = route_spans(&RoutingCfg::default(), &spans)
            .iter()
            .map(|r| r.class)
            .collect();
        assert_eq!(
            classes,
            vec!["email", "person_name", "card_pan", "inn", "snils"],
            "route_spans переставил спаны"
        );
    }

    /// Инвариант, на котором держится зип маршрутов с хитами в `pipeline`:
    /// сколько на входе, столько на выходе, и i-й выход — i-й вход.
    #[test]
    fn route_spans_pairs_routes_with_input_order() {
        let spans: Vec<ScoredSpan<u16>> = (0_u16..40)
            .map(|i| ScoredSpan {
                class: i,
                // Скор чередуется через полосу, чтобы перестановка не могла
                // спрятаться за одинаковыми маршрутами.
                score: if i % 3 == 0 { 0.95 } else { 0.10 },
                validator: false,
            })
            .collect();
        let routed = route_spans(&RoutingCfg::default(), &spans);
        assert_eq!(routed.len(), spans.len(), "route_spans теряет спаны");
        for (i, r) in routed.iter().enumerate() {
            assert_eq!(r.class, spans[i].class, "порядок классов сломан на {i}");
            assert_eq!(r.score, spans[i].score, "скор уехал со своего спана");
            assert_eq!(
                r.route,
                RoutingCfg::default().route(spans[i].score),
                "маршрут спана {i} не совпадает с точечным route"
            );
        }
    }

    #[test]
    fn single_cfg_profile_matches_harness_gate() {
        // Режим харнеса: пара вырождена ⇒ Mask невозможен, extracted() == `>=`.
        let c = RoutingCfg::single(0.25);
        for s in [0.0, 0.249_999_9, 0.25, 0.5, 1.0] {
            assert_eq!(c.route(s).extracted(), s >= 0.25, "score={s}");
        }
        assert_eq!(c.route(0.30), Route::Block);
        assert_eq!(c.route(0.10), Route::Pass);
        // NaN: старый гейт харнеса (`conf < thr` ложно) span ОСТАВЛЯЛ;
        // fail-closed маршрутизатор Block'ует — поведенческий ноль-дрейф на
        // живых данных это не затрагивает (softmax конечен, иначе 0.0), см.
        // тест инвариантности в example.
        assert_eq!(c.route(f64::NAN), Route::Block);
    }
}
