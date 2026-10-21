//! Вшитая в бинарник песочница (SPEC §1 п.4, §10 п.8).
//!
//! Фронт — три статических файла из `crates/guard-daemon/ui/` (html, css, js, без
//! фреймворков) плюс копия рабочей схемы. `rust-embed` зашивает их в бинарник,
//! поэтому оффлайн-продукт не нуждается ни в каком внешнем хранилище статистики:
//! демоном отдаётся и страница, и данные.
//!
//! Два решения здесь первичны, и оба проверяются тестами
//! (`crates/guard-daemon/tests/ui_sandbox.rs`):
//!
//! 1. **Отдаётся ровно четыре имени.** Пути не пробрасываются в файловую систему
//!    вообще: в отладочной сборке `rust-embed` читает с диска, и маршрут вида
//!    `/assets/{path}` без белого списка был бы дырой «прочитай что угодно».
//!    Всё, чего нет в списке, — `404`, и проверка на `../` это же и есть.
//! 2. **`Content-Security-Policy` на каждом ответе статики.** `default-src 'none'`
//!    плюс явно разрешённые `'self'`: скрипты и стили только наши, коннект только
//!    на свой origin, форм и фреймов нет. Фронт написан под этот заголовок: ни
//!    одного inline-скрипта, inline-стиля, `eval` и внешнего адреса.

use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

/// Статика фронта: `crates/guard-daemon/ui/`.
#[derive(Embed)]
#[folder = "ui"]
pub struct Asset;

/// Имя, под которым песочница видит рабочую схему (`/assets/schema.json`).
pub const SCHEMA_FILE: &str = "schema.json";

/// Политика для статики. Разрешает ровно то, чем пользуется фронт, и больше
/// ничего: ни чужих origin, ни `inline`, ни `data:`.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
     connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; \
     object-src 'none'";

/// Маршруты песочницы. `GET /` — convenience для браузера, `GET /ui` — имя из
/// SPEC §8; оба отдают одну страницу.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/", axum::routing::get(index))
        .route("/ui", axum::routing::get(index))
        .route("/assets/{name}", axum::routing::get(asset))
}

async fn index() -> Response {
    serve::<Asset>("index.html")
}

async fn asset(axum::extract::Path(name): axum::extract::Path<String>) -> Response {
    match name.as_str() {
        "app.css" => serve::<Asset>("app.css"),
        "app.js" => serve::<Asset>("app.js"),
        SCHEMA_FILE => serve_schema(),
        _ => not_found(),
    }
}

/// Схема для песочницы — тот же массив байт, что демон вшил в себя как
/// [`crate::schema::DEFAULT_SCHEMA_JSON`], без второй вшивки папки `config/`.
///
/// Так расхождение «песочница показывает не ту схему, по которой работает
/// демон» невозможно физически: источник один. Побочный эффект важен не меньше:
/// `rust-embed` с `#[folder = "../../config"]` шил бы **всю** папку
/// конфигурации, а это каталог пользователя (локальные override-файлы), —
/// чужой файл уезжал бы в наружный артефакт. Здесь такой поверхности нет
/// вовсе; канарейка `config/embed-probe.md` проверяется на проводе
/// (`asset_names_outside_the_allow_list_are_refused`).
fn serve_schema() -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CONTENT_SECURITY_POLICY, CSP),
        ],
        crate::schema::DEFAULT_SCHEMA_JSON,
    )
        .into_response()
}

/// Ответ по одному имени из белого списка. Отсутствующий файл — `404` без
/// тела: в статике нет ничего, что стоило бы объяснять наружу.
fn serve<E: Embed>(name: &str) -> Response {
    let Some(file) = E::get(name) else {
        return not_found();
    };
    let body = file.data.into_owned();
    let mut resp = (
        [
            (header::CONTENT_TYPE, file.metadata.mimetype()),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response();
    resp.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    resp
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(CSP),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
    )
        .into_response()
}
