# justfile — контракт сборки fasad (паттерн copyosity `make fix/check`, SPEC §5.5.5).
#
# CI (`.github/workflows/ci.yml`) зовёт `just lint` — локально тот же набор, что
# краснит PR. `just check` — полный гейт перед push. Установка just: brew install
# just (или cargo install just).

_default:
    @just --list

# Прогнать всё, что блокирует merge: линты + тесты + аудит зависимостей.
check: lint test deny

# Авточинит всё, что чинится автоматически (fmt + clippy --fix).
fix:
    cargo fmt --all -- --fix
    cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged

# Только линтеры (fmt-проверка + clippy с deny-флагами CI).
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used

# Тесты всего workspace.
test:
    cargo test --workspace

# Аудит дерева зависимостей (bans/advisories/licenses) — deny.toml.
deny:
    cargo deny check
