# SPIKE(step2) — issue #6

`rss_mach.c` — C-остров для промера private-RSS (`task_info(TASK_VM_INFO)`) на
macOS. Workspace-контракт `unsafe_code = forbid` (Cargo.toml `[workspace.lints.rust]`)
нельзя инвертировать точечным `allow` (rustc E0453), поэтому FFI изолирован в C и
линкуется `build.rs` **только** в example `spike` (`cargo:rustc-link-arg-examples`).
На Linux RSS берётся из `/proc/self/status` (`VmRSS`) — чистый Rust, C не нужен;
на Windows spike RSS не меряет (CI-матрица spike не прогоняет вовсе — см. шапку
`examples/spike.rs`).

Ассерты в `.c` фиксируют layout `struct task_vm_info` (372 B, `internal` на 48) —
промер `cc` на MacOSX.sdk в заходе 19.10; при дрейфе ОС-заголовка сборка краснеет
(	fail-closed, AGENTS.md).
