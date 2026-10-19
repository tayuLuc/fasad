/* Стаб clang-runtime helper'а ___isPlatformVersionAtLeast (issue #6 харнесс).
 * Орф-статик rc.14 (host_utils.mm/model.mm) ссылается на него; бэкпорт есть в
 * libSystem только при min>=12.3, cargo в release печатает min=11.0 (промеры
 * 19.10: env/deployment-target/platform_version-линк-аргументы НЕ помогают —
 * warning "passed two min versions", символ остаётся undefined). Отдельная TU:
 * clang компилирует её без API-зависимостей, ld кладёт стаб ПЕРЕД dead-strip
 * решает. Возвращает false: CoreML EP spike не использует (CPU EP). */
int ___isPlatformVersionAtLeast(int platform, int major, int minor, int patch) {
    (void)platform;
    (void)major;
    (void)minor;
    (void)patch;
    return 0;
}
