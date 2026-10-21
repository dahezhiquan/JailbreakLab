#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

typedef void (*ms_hook_function_t)(void *, void *, void **);
typedef void (*ms_hook_memory_t)(void *, const void *, size_t);

bool jailbreaklab_install_getpid_hook_for_testing(
    ms_hook_function_t hook,
    ms_hook_memory_t hook_memory,
    void *target
);

static void *observed_target = NULL;
static void *observed_replacement = NULL;

static void fake_ms_hook(void *target, void *replacement, void **original) {
    observed_target = target;
    observed_replacement = replacement;
    *original = target;
}

static void fake_ms_hook_memory(void *target, const void *code, size_t size) {
    memcpy(target, code, size);
}

int main(void) {
    uint32_t target[4] = {0};
    assert(!jailbreaklab_install_getpid_hook_for_testing(
        NULL, fake_ms_hook_memory, target
    ));
    assert(!jailbreaklab_install_getpid_hook_for_testing(
        fake_ms_hook, fake_ms_hook_memory, NULL
    ));
    assert(jailbreaklab_install_getpid_hook_for_testing(
        fake_ms_hook, fake_ms_hook_memory, target
    ));
    assert(observed_target == target);
    assert(observed_replacement != NULL);
    assert(target[0] == 0x58000050);
    assert(target[1] == 0xd61f0200);
    puts("MSHookFunction injection tests passed");
    return 0;
}
