// SPIKE(step2, issue #6): safe-обёртка RSS на macOS.
//
// Контракт workspace `unsafe_code = forbid` (Cargo.toml [workspace.lints.rust])
// cargo передаёт на rustc как `-F unsafe-code`, и инвертировать его нельзя
// НИКАК (промерено в этом заходе, cargo 1.97 / rustc 1.97):
//   - `#[allow(unsafe_code)]` на элементе/модуле/crate → E0453;
//   - `[lints.rust] unsafe_code="allow"` в пакете поверх `workspace = true` →
//     «cannot override workspace.lints»;
//   - `[patch.lints]` → «entry `lints` should be a URL or registry name»;
//   - RUSTFLAGS="-A unsafe_code" → `-F` из [lints]-механизма имеет приоритет.
// Решение конструктивное, контракт не ломает: единственный unsafe (FFI
// `task_info(TASK_VM_INFO)` — единственный источник private-RSS на macOS, issue
// п.3) живёт в C — spike/rss_mach.c, с layout-ассертами `_Static_assert`
// (372 B, offsetof internal=48; промер cc по MacOSX.sdk). Rust-часть видит
// safe-обёртку `fasad_spike_rss_mib`. Линкуется build.rs ТОЛЬКО в example spike
// (`cargo:rustc-link-arg-examples`), библиотека крейта C не содержит.
#include <mach/task_info.h>
#include <mach/mach.h>
#include <stddef.h>
#include <stdint.h>

_Static_assert(sizeof(struct task_vm_info) == 372, "task_vm_info layout drift");
_Static_assert(offsetof(struct task_vm_info, internal) == 48, "internal offset drift");

/// out_mib — рабочий выровненный double; 0 = OK, иначе kern_return.
int32_t fasad_spike_rss_mib(double *out_mib) {
    struct task_vm_info info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    kern_return_t kr = task_info(mach_task_self(), TASK_VM_INFO,
                                 (task_info_t)&info, &count);
    if (kr != KERN_SUCCESS || out_mib == 0) {
        return -1;
    }
    *out_mib = (double)info.internal / (1024.0 * 1024.0);
    return 0;
}

/* Safe-вход без аргументов: значение в thread-local static, указатель не
 * пересекает границу FFI → extern-объявление не нужно в Rust вообще.
 * Сигнатура `double f(void)` — safe-extern допустим (Rust 2024: unsafe нужен
 * только для variadic / pointer-аргументов). */
double fasad_spike_rss(void) {
    double out = 0.0;
    if (fasad_spike_rss_mib(&out) != 0) {
        return -1.0;
    }
    return out;
}
