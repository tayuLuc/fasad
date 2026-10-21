# SPIKE(step2) — issue #6

`rss_mach.c` — C-остров для промера private-RSS (`task_info(TASK_VM_INFO)`) на
macOS. Workspace `unsafe_code = deny` + `#![forbid(unsafe_code)]` в src-крейтах
(итог ревью #9): библиотеки остаются forbid-контрактными изнутри; example
(`spike.rs`) несёт точечный `#[allow(unsafe_code)]` на FFI-мосту (dylib+dlsym),
FFI-логика изолирована здесь, в C с layout-ассертами.
На Linux RSS берётся из `/proc/self/status` (`VmRSS`) — чистый Rust, C не нужен;
на Windows spike RSS не меряет (CI-матрица spike не прогоняет вовсе — см. шапку
`examples/spike.rs`).

Ассерты в `.c` фиксируют **потребляемое** поле `internal` (смещение 48, ширина 8)
— промер `cc` на MacOSX.sdk в заходе 19.10; полный размер `task_vm_info` не
пинится: он плавает по SDK (372 локальный, 356 на SDK CI-раннера macos-14 —
поймано ногой #31, run 39592065551), Apple дописывает поля в хвост, ABI-префикс
заморожен. При дрейфе потребляемого поля сборка краснеет (fail-closed, AGENTS.md).
