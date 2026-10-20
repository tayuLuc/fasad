#![no_main]
//! Фазз-таргет потокового реврайтера (`guard_vault::rewriter`) — требование
//! issue #50, закрытие замечания Н4 ревью #54.
//!
//! Инварианты здесь — ровно те же два, что проверяются живым тестом
//! `crates/guard-vault/src/rewriter.rs::random_bytes_pass_verbatim_under_any_split`
//! и `substitution_never_grows_output` (промер 4000 + 2000 итераций, CI-зелёные).
//! Таргет добавляет к ним то, чего ГПСЧ-тест не даёт: свободу фаззера залезть в
//! приманки ложных открытий грамматики и в произвольные точки реза.
//!
//! Смысл инвариантов (почему именно они, а не «не паникуй»):
//!
//! 1. `Unknown`-резолвер ⇒ выдача побайтно равна входу. Реврайтер стоит на
//!    пути ответа: если он на нераспознанном маркере съест байт, мы получим
//!    молчаливое искажение ответа модели (отказоустойчивость сломается тихо), а
//!    если пропустит тело маркера — утечку `ПДн` в логах/метриках ниже по
//!    потоку. Оба направления ловятся этим равенством.
//! 2. Нарезка не меняет выдачу. Состояние автомата переживает границы чанков
//!    HTTP-стрима; расхождение «один проход vs произвольные срезы» = дыра в FSM
//!    (тот же класс, что поймал тест `f0_token_survives_random_and_broken_splits`).
//! 3. Подмена не раздувает выдачу: `Substitute(body)` короче маркера минимум на
//!    обрамление, значит длина выдачи не больше длины входа. Растущая выдача —
//!    признак автомата, путающего префикс с суффиксом.
//!
//! Корпус не заводится осознанно (#50 допускает таргет без сида): стартовая
//! точка — случайные байты, а грамматически живые маркеры фаззер находит сам по
//! приманкам из assert-сообщений и Coverage-фидбека.
use guard_vault::rewriter::{Grammar, Resolution, StreamRewriter};
use libfuzzer_sys::fuzz_target;

// Один срез `&[u8]`: `fuzz_target!` в libfuzzer-sys 0.4.13 принимает либо один
// `&[u8]`, либо тип с `#[derive(Arbitrary)]`; решено не тянуть derive-фичу.
// Первые до четырёх байтов входа — это байты реза, остальное — сам поток.
fuzz_target!(|input: &[u8]| {
    let (seed, payload) = input.split_at(input.len().min(4));
    let mut cuts = [0_u8; 4];
    cuts[..seed.len()].copy_from_slice(seed);
    let input = payload;
    for grammar in [Grammar::LABEL, Grammar::F0_INLINE] {
        // 1 + 2: нерезолвнутый маркер обязан пройти дословно при любом разрезе.
        let (whole, _) =
            StreamRewriter::new(grammar, |_: &[u8]| Resolution::Unknown).run_to_end(input);
        assert_eq!(whole, input, "Unknown-резолвер: реврайтер съел байты");

        let mut split = StreamRewriter::new(grammar, |_: &[u8]| Resolution::Unknown);
        let mut out = Vec::new();
        let mut rest = input;
        for c in cuts {
            if rest.is_empty() {
                break;
            }
            // `c % rest.len()` + 1: режем всегда на ненулевой префикс, пустых
            // push-вызовов у автомата нет по контракту.
            let n = 1 + usize::from(c) % rest.len();
            let (head, tail) = rest.split_at(n);
            let _ = split.push(head, &mut out);
            rest = tail;
        }
        if !rest.is_empty() {
            let _ = split.push(rest, &mut out);
        }
        let _ = split.finish(&mut out);
        assert_eq!(out, whole, "произвольная нарезка изменила выдачу");

        // 3: подмена тела его же байтами не раздувает выдачу и не паникует.
        let (sub, _) = StreamRewriter::new(grammar, |body: &[u8]| {
            if body.is_empty() {
                Resolution::Unknown
            } else {
                Resolution::Substitute(body.to_vec())
            }
        })
        .run_to_end(input);
        assert!(
            sub.len() <= input.len(),
            "подмена раздула выдачу: {} > {}",
            sub.len(),
            input.len()
        );
    }
});
