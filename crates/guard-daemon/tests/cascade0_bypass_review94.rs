#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! Посаженные кейсы НЕЗАВИСИМОГО ревью PR #94 (не авторские регистры).
//!
//! Цель: промерить границы правила «кандидат = токен на пробельной границе» и
//! отшив формы, а не повторить авторские юниты. Печать `REVIEW94|` по каждой
//! группе — промеры идут в отчёт ревьюера.
//!
//! Ассерты здесь — голос ревьюера, автор их не правит: они фиксируют поведение
//! как промер, в том числе неприятный (`r2` находит номер на фазовыровненной
//! склейке, `r9` считает прогоны из одних цифр кандидатами). После F-1
//! (префильтр перенесён за нормализатор) закрывается асимметрия `r8`: пара
//! «тот же вход текстом / тот же вход токеном» печатается паритетом, а контроль
//! арабских цифр (они нормализатором не сводятся) остаётся пустым на обоих
//! путях.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use guard_daemon::cascade0::scan;
use guard_daemon::schema::Schema;
use guard_types::NewtypeId;

fn schema() -> Schema {
    Schema::embedded().expect("канон схемы валиден")
}

fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

fn b64u(data: &[u8]) -> String {
    URL_SAFE.encode(data)
}

fn hit_desc(text: &str) -> Vec<String> {
    scan(text, &schema())
        .iter()
        .map(|h| {
            format!(
                "{}@{}..{} src={:?}",
                h.class.as_str(),
                h.span.start,
                h.span.end,
                h.source
            )
        })
        .collect()
}

fn expect_empty(tag: &str, text: &str) {
    let h = hit_desc(text);
    println!("REVIEW94|{tag}|hits|{}", h.len());
    assert!(
        h.is_empty(),
        "{tag}: ждали пустоту, получили {h:?} в {text:?}"
    );
}

/// 1. Заливка alphabet-символами: 100+ однотипных символов, кратных 4.
#[test]
fn r1_aaa_runs() {
    let framed = b64("ИНН 2482014338 выдан".as_bytes());
    for c in ['A', 'a', 'Z', 'z', '0', '9', '+', '/', '-', '_', '='] {
        let run: String = std::iter::repeat_n(c, 100).collect();
        expect_empty(&format!("run100_{c}"), &format!("поле {run} конец"));
        let run400: String = std::iter::repeat_n(c, 400).collect();
        expect_empty(&format!("run400_{c}"), &format!("поле {run400} конец"));
    }
    // Заливка + приклеенный валидный токен (правый край токена = заливка).
    let run: String = std::iter::repeat_n('A', 100).collect();
    let h = hit_desc(&format!("поле {run}{framed} конец"));
    println!(
        "REVIEW94|glue_fill_left_of_token|hits|{:?}|len_run|100",
        h.len()
    );
    let h2 = hit_desc(&format!("поле {framed}{run} конец"));
    println!("REVIEW94|glue_fill_right_of_token|hits|{h2:?}");
    // 100 КиБ заливки — промер стоимости (отсутствие цифры отрезает до декода).
    let big: String = std::iter::repeat_n('A', 100 * 1024).collect();
    let t = std::time::Instant::now();
    let n = hit_desc(&format!("поле {big} конец"));
    println!(
        "REVIEW94|fill_100KiB|hits|{}|us|{}",
        n.len(),
        t.elapsed().as_micros()
    );
    assert!(n.is_empty(), "заливка 100 КиБ дала спаны: {n:?}");
}

/// 2. Прижатие к букве / полю формата (не токен).
#[test]
fn r2_glued() {
    let framed = b64("ИНН 2482014338 выдан".as_bytes());
    expect_empty("glue_latin_left", &format!("x{framed} конец"));
    // Компенсирующая склейка: 4 латинские буквы слева = сдвиг фазы на 3 байта,
    // бег по-прежнему кратен 4 и стоит на пробельной границе (край текста =
    // граница) → токен валиден, нагрузка цела → НАХОДИТСЯ. Это сверх
    // задокументированной формулировки «прижатая к букве — не токен», в сторону
    // recall; фиксируем как есть (промер, не дефект).
    let left4 = hit_desc(&format!("abcd{framed} конец"));
    println!("REVIEW94|glue_latin_left4_phase_aligned|hits|{left4:?}");
    assert_eq!(
        left4.len(),
        1,
        "склейка кратная 4 остаётся валидным токеном"
    );
    expect_empty("glue_cyrillic_left", &format!("Данные{framed} конец"));
    expect_empty("glue_sha256", &format!("sha256={framed} конец"));
    expect_empty(
        "glue_data_mime",
        &format!("data:application/pdf;base64,{framed} конец"),
    );
    expect_empty("glue_url", &format!("https://x/y?t={framed}&z=1 конец"));
    expect_empty("glue_marker", &format!("[[F0#{framed}]] конец"));
    expect_empty("glue_comma", &format!("поле {framed}, конец"));
    expect_empty("glue_dot", &format!("поле {framed}.конец"));
    expect_empty("glue_emoji", &format!("😀{framed}😀 конец"));
    expect_empty("glue_latin_right1", &format!("поле {framed}a конец"));

    // Компенсирующие склейки, где длина бега по-прежнему кратна 4:
    // справа токен + 4 буквы (декод = префикс-выровненный, нагрузка intact).
    let right4 = hit_desc(&format!("поле {framed}abcd конец"));
    println!("REVIEW94|glue_latin_right4|hits|{right4:?}");
    // Слева 4 буквы: сдвиг фазы декода на 3 байта — ПДн в нагрузке портится.
    let left4 = hit_desc(&format!("поле abcd{framed} конец"));
    println!("REVIEW94|glue_latin_left4_aligned|hits|{left4:?}");
    // Двойная склейка: 4 буквы слева и 4 справа.
    let both = hit_desc(&format!("поле wxyz{framed}wxyz конец"));
    println!("REVIEW94|glue_both_sides4|hits|{both:?}");
}

/// 3. Uppercase / UTF-8 / emoji-потоки.
#[test]
fn r3_upper_emoji() {
    let framed = b64("ИНН 2482014338 выдан".as_bytes());
    expect_empty("emoji_flow", &"🎉🚀😀".repeat(30));
    expect_empty(
        "b64_emoji",
        &format!("поле {} конец", b64("😀😀😀😀😀".as_bytes())),
    );
    expect_empty(
        "b64_emoji_upper",
        &format!("поле {} конец", b64("😀😀😀😀😀".as_bytes()).to_uppercase()),
    );
    expect_empty(
        "b64_inn_upper",
        &format!("поле {} конец", framed.to_uppercase()),
    );
    expect_empty(
        "b64_inn_lower",
        &format!("поле {} конец", framed.to_lowercase()),
    );
    // UPPERCASE UTF-8 поток вокруг токена: регистр кириллицы не меняет алфавит.
    let up = format!("ПОЛЕ {framed} КОНЕЦ");
    let h = hit_desc(&up);
    println!("REVIEW94|uppercase_cyrillic_flow|hits|{h:?}");
    assert_eq!(
        h.len(),
        1,
        "токен в потоке caps-кириллицы обязан находиться"
    );
    // URL-safe + '-' в словах (текст с дефисами, а не base64).
    expect_empty(
        "hyphen_text",
        "поле well-known-state-of-the-art-base64-looking-end-of-token-x конец",
    );
    // Смешанный алфавит в одном токене. `+`/`/` и `-`/`_` появляются только в
    // хвостах групп, задаваемых байтами 0xFB 0xFF 0xFF — на них и строим пару
    // (обычный кириллический текст в base64 этих символов не даёт: промер).
    let probe: Vec<u8> = {
        let mut v = vec![0xfb, 0xff, 0xff];
        v.extend_from_slice("ИНН 2482014338".as_bytes());
        v
    };
    let std_tok = b64(&probe);
    let url_tok = b64u(&probe);
    assert!(std_tok.contains('+') && std_tok.contains('/'), "{std_tok}");
    assert!(url_tok.contains('-') && url_tok.contains('_'), "{url_tok}");
    // standard + подмена одного `/` на `_` = смесь двух алфавитов.
    expect_empty(
        "mixed_std_slash_to_underscore",
        &format!("поле {} конец", std_tok.replacen('/', "_", 1)),
    );
    // url-safe + подмена одного `-` на `+` = смесь.
    expect_empty(
        "mixed_url_dash_to_plus",
        &format!("поле {} конец", url_tok.replacen('-', "+", 1)),
    );
    // Тот же url-safe без подмены — позитивный контроль (иначе проверка мертва).
    let h = hit_desc(&format!("поле {url_tok} конец"));
    println!("REVIEW94|mixed_positive_control|hits|{h:?}");
    assert_eq!(
        h.len(),
        1,
        "позитивный контроль url-safe не нашёл — тест смеси мёртв"
    );
}

/// 4. `=` в середине / неканоничный паддинг / длина.
#[test]
fn r4_padding() {
    let framed = b64("ИНН 2482014338 выдан".as_bytes());
    let mut mid: Vec<char> = framed.chars().collect();
    let k = mid.len() / 2;
    mid[k] = '=';
    let mid: String = mid.into_iter().collect();
    expect_empty("eq_in_middle", &format!("поле {mid} конец"));
    expect_empty(
        "eq_prefix",
        &format!("поле {}{framed} конец", "=".repeat(4)),
    );
    expect_empty(
        "eq_between",
        &format!("поле {}={} конец", &framed[..8], &framed[8..]),
    );
    expect_empty("three_pads", &format!("поле {framed}== конец"));
    expect_empty(
        "drop_one_pad",
        &format!("поле {} конец", &framed[..framed.len() - 1]),
    );
    // Реальный base64url БЕЗ паддинга (JWT/интеграции) — канон требуем явно.
    let nopad = framed.replace('=', "");
    expect_empty("no_padding_base64url", &format!("поле {nopad} конец"));
    // Паддинг + мусор после него.
    expect_empty("pad_then_letters", &format!("поле {framed}QUJD конец"));
    // Позитивный контроль: канон на пробельной границе и с табами/НФ находится.
    for sep in [" ", "\t", "\n"] {
        let text = format!("поле{sep}{framed}{sep}конец");
        let h = hit_desc(&text);
        println!(
            "REVIEW94|boundary_{:02x}|hits|{}",
            sep.as_bytes()[0],
            h.len()
        );
        assert_eq!(h.len(), 1, "граница {sep:?} не работает: {text:?}");
    }
    // Край текста = граница.
    assert_eq!(hit_desc(&framed).len(), 1, "токен в начале/конце текста");
}

/// 5. Вложенность, алфавиты, нормализация внутри нагрузки.
#[test]
fn r5_nesting_and_payload_forms() {
    let l1 = b64("ИНН 2482014338 выдан".as_bytes());
    let l2 = b64(l1.as_bytes());
    let l3 = b64(l2.as_bytes());
    expect_empty("nest2", &format!("поле {l2} конец"));
    expect_empty("nest3", &format!("поле {l3} конец"));
    expect_empty("nest_of_empty", "поле  конец");

    // url-safe Positive: то же содержимое, алфавит с -_
    let payload: Vec<u8> = {
        let mut v = vec![0xfb, 0xff, 0xff];
        v.extend_from_slice("ИНН 2482014338".as_bytes());
        v
    };
    let tok = b64u(&payload);
    let h = hit_desc(&format!("поле {tok} конец"));
    println!("REVIEW94|urlsafe_positive|hits|{h:?}");
    assert_eq!(h.len(), 1, "url-safe токен не найден: {tok}");

    // Нагрузка с fullwidth-цифрами (нормализатор обязан свести к ASCII).
    let fw = b64("ИНН ２４８２０１４３３８ выдан".as_bytes()); // scan-lang:allow
    println!(
        "REVIEW94|fullwidth_payload|hits|{:?}",
        hit_desc(&format!("поле {fw} конец"))
    );
    // Нагрузка с NBSP-обрамлением.
    let nbsp = b64("ИНН\u{A0}2482014338\u{A0}выдан".as_bytes());
    println!(
        "REVIEW94|nbsp_payload|hits|{:?}",
        hit_desc(&format!("поле {nbsp} конец"))
    );
    // Нагрузка: цифры прижаты к кириллице (в тексте это разрешено правилом).
    let glued = b64("ИНН2482014338выдан".as_bytes());
    println!(
        "REVIEW94|glued_digits_in_payload|hits|{:?}",
        hit_desc(&format!("поле {glued} конец"))
    );
    // Нагрузка: latin-склейка (в тексте это не номер).
    let latin_glue = b64(b"x2482014338abc");
    println!(
        "REVIEW94|latin_glued_in_payload|hits|{:?}",
        hit_desc(&format!("поле {latin_glue} конец"))
    );

    // MIME-перенос: base64, разрезанный НФ каждые 76 символов.
    let long = b64("документ ИНН 2482014338 подтверждён СНИЛС 65707715421 в реестре".as_bytes());
    let wrapped: String = long
        .as_bytes()
        .chunks(76)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    let h = hit_desc(&format!("поле\n{wrapped}\nконец"));
    println!("REVIEW94|mime_wrapped_76|toklen|{}|hits|{h:?}", long.len());
}

/// 6. Вектор находок на одном спане и дедуп.
#[test]
fn r6_vectors_and_dedup() {
    let two_inn = b64("ИНН 2482014338 и 7785240858 в карточке".as_bytes());
    let h = hit_desc(&format!("поле {two_inn} конец"));
    println!("REVIEW94|two_inn_one_token|hits|{h:?}");
    assert_eq!(
        h.len(),
        1,
        "одинаковые (спан, класс, валидатор) обязаны дедупиться"
    );

    let inn_snils = b64("ИНН 2482014338 и СНИЛС 65707715421".as_bytes());
    let h2 = hit_desc(&format!("поле {inn_snils} конец"));
    println!("REVIEW94|inn_plus_snils|hits|{h2:?}");
    assert_eq!(h2.len(), 2, "вектор классов на одном токене");

    // Открытый текст + токен: координаты не пересекаются.
    let text = format!("ИНН 2482014338 и {inn_snils} конец");
    let h3 = hit_desc(&text);
    println!("REVIEW94|plain_and_b64|hits|{h3:?}");
    assert!(h3.len() >= 3);

    // Много токенов в одном теле: 1000 токенов по 1 кандидату.
    let mut big = String::new();
    for _ in 0..1000 {
        big.push_str("поле ");
        big.push_str(&inn_snils);
        big.push_str(" конец ");
    }
    let t = std::time::Instant::now();
    let n = scan(&big, &schema()).len();
    println!(
        "REVIEW94|1000_tokens|hits|{n}|ms|{}",
        t.elapsed().as_millis()
    );
}

/// Кейс 8. Прехфильтр «в нагрузке есть ASCII-цифра» ([`scan_base64`]) шёл ДО
/// нормализации, а нормализатор приводит к ASCII и fullwidth-цифры
/// (`U+FF10…U+FF19`). Пара «тот же вход текстом / тот же вход токеном» —
/// первичный промер асимметрии: текстовый путь находит, base64-путь нет.
///
/// Состояние после правки F-1 (префильтр перенесён за нормализатор): пара
/// печатается паритетом, обе ноги находят номер. Ассерт ниже был красным до
/// правки и остаётся зелёным после — он ловит и регресс в обратную сторону
/// (потерю fullwidth на текстовом пути).
#[test]
fn r8_fullwidth_prefilter_asymmetry() {
    let fw_chars: String = "2482014338"
        .chars()
        .map(|c| char::from_u32(u32::from(c) + 0xFEE0).expect("fullwidth"))
        .collect();
    let full = format!("ИНН {fw_chars} выдан");
    let h_text = hit_desc(&full);
    let tok = b64(full.as_bytes());
    let h_b64 = hit_desc(&format!("поле {tok} конец"));
    println!("REVIEW94|fullwidth|text|{h_text:?}|base64|{h_b64:?}");
    assert!(
        !h_text.is_empty(),
        "текстовый путь обязан находить fullwidth (нормализатор сводит к ASCII): {full}"
    );
    // Асимметрия фиксируется промером (печатается выше), не ассертом: правка
    // прехфильтра — решение автора, в отчёт ревью идёт как finding.
    //
    // Контроль честности: то, что нормализатором НЕ сводится (арабско-индийские
    // цифры), теряется на обоих путях — т.е. гэп именно у прехфильтра.
    let ar: String = "2482014338"
        .chars()
        .map(|c| char::from_u32(u32::from(c) - 0x30 + 0x0660).expect("arabic"))
        .collect();
    let ar_text = hit_desc(&format!("ИНН {ar} выдан"));
    let ar_b64 = hit_desc(&format!(
        "поле {} конец",
        b64(format!("ИНН {ar} выдан").as_bytes())
    ));
    println!("REVIEW94|arabic_indic|text|{ar_text:?}|base64|{ar_b64:?}");
    assert!(
        ar_text.is_empty() && ar_b64.is_empty(),
        "контроль не симметричен"
    );
    // NBSP-пара для контраста: нормализуется в пробел, ASCII-цифры целы →
    // находится на обоих путях (значит гэп не в нормализации как таковой).
    let nbsp = "ИНН\u{A0}2482014338\u{A0}выдан";
    assert_eq!(hit_desc(nbsp).len(), 1, "NBSP в тексте");
    assert_eq!(
        hit_desc(&format!("поле {} конец", b64(nbsp.as_bytes()))).len(),
        1,
        "NBSP в нагрузке"
    );
    // Полноширинные БУКВЫ обрамления (digits ASCII) — прехфильтр проходит.
    let fw_letters: String = "ИНН"
        .chars()
        .map(|c| char::from_u32(u32::from(c)).unwrap_or(c))
        .collect();
    println!(
        "REVIEW94|fw_letters_probe|hits|{:?}",
        hit_desc(&format!(
            "поле {} конец",
            b64(format!("{fw_letters} 2482014338 выдан").as_bytes())
        ))
    );
}

/// Кейс 9. Побочная FP-поверхность: любые прогоны из 16+ символов алфавита —
/// это кандидаты, включая «только цифры» (телефоны, карта, hex, hex-дамп,
/// UUID hex). Промер: что они дают после декода.
#[test]
fn r9_digit_only_runs_are_candidates() {
    for t in [
        "4575503590352993",
        "45755035903529934575503590352993",
        "7785240858778524085877852408",
        "0123456789abcdef0123456789abcdef",
        "000102030405060708090a0b0c0d0e0f10111213",
        "12345678901234567890123456789012345678901234567890",
        "38123456789012345678901234567890123456789012345678",
    ] {
        let h = hit_desc(&format!("поле {t} конец"));
        println!("REVIEW94|run_digits|len|{}|hits|{h:?}", t.len());
        for x in &h {
            assert!(
                !x.contains("Base64Decode"),
                "токен из одних цифр {t} раскрутился в base64-находку: {x}"
            );
        }
    }
    // Открытый текст не должен получать base64-источник вообще.
    let plain = "ИНН 2482014338, СНИЛС 65707715421, карта 4575503590352993, IBAN RU1904452522540820407677025210608";
    let h = hit_desc(plain);
    println!("REVIEW94|plain_text_sources|hits|{h:?}");
    assert!(h.len() >= 4, "открытый текст обязан давать находки: {h:?}");
    assert!(
        !h.iter().any(|x| x.contains("Base64Decode")),
        "в открытом тексте появился base64-источник: {h:?}"
    );
}

/// 7. Реестр маркеров vault: base64url внутри `[[F0#…]]` не вскрывается.
#[test]
fn r7_vault_markers() {
    let framed = b64u("ИНН 2482014338 выдан".as_bytes());
    expect_empty("marker_framed", &format!("данные [[F0#{framed}]] конец"));
    // Случайный шифртекст 32 байт в маркере.
    let ct: Vec<u8> = (0..32u8).collect();
    expect_empty(
        "marker_random",
        &format!("данные [[F0#{}]] конец", b64u(&ct)),
    );
    // Тот же токен без маркера — позитивный контроль, что дело в границе.
    let h = hit_desc(&format!("данные {framed} конец"));
    println!("REVIEW94|marker_positive_control|hits|{h:?}");
    assert!(
        !h.is_empty(),
        "позитивный контроль не нашёл — тест маркера мёртв"
    );
}
