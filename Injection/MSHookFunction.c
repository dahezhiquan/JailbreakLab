#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

typedef void (*ms_hook_function_t)(void *, void *, void **);
typedef void (*ms_hook_memory_t)(void *, const void *, size_t);
typedef pid_t (*getpid_function_t)(void);

static getpid_function_t original_getpid = NULL;
static pid_t fallback_pid = 0;

static pid_t jailbreaklab_getpid(void) {
    return original_getpid != NULL ? original_getpid() : fallback_pid;
}

#if !defined(JAILBREAKLAB_TESTING)
static ms_hook_function_t resolve_ms_hook_function(void) {
    ms_hook_function_t hook = (ms_hook_function_t)dlsym(
        RTLD_DEFAULT, "MSHookFunction"
    );
    if (hook != NULL) return hook;

    static const char *candidates[] = {
        "/var/jb/usr/lib/libsubstrate.dylib",
        "/usr/lib/libsubstrate.dylib",
        "/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
        "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate"
    };
    for (size_t index = 0; index < sizeof(candidates) / sizeof(candidates[0]); index++) {
        void *handle = dlopen(candidates[index], RTLD_NOW | RTLD_GLOBAL);
        if (handle == NULL) continue;
        hook = (ms_hook_function_t)dlsym(handle, "MSHookFunction");
        if (hook != NULL) return hook;
    }
    return NULL;
}
#endif

static bool has_expected_arm64_jump(const void *target) {
#if defined(__arm64__)
    uint32_t words[3] = {0};
    memcpy(words, target, sizeof(words));
    if (words[0] == 0x58000050 && words[1] == 0xd61f0200) return true;
    return (words[0] & 0x9f00001f) == 0x90000011 &&
        (words[1] & 0xff8003ff) == 0x91000231 &&
        words[2] == 0xd61f0220;
#else
    (void)target;
    return false;
#endif
}

static bool install_getpid_hook(
    ms_hook_function_t hook,
    ms_hook_memory_t hook_memory,
    void *target
) {
    if (hook == NULL || target == NULL) return false;
    getpid_function_t trampoline = NULL;
    hook(target, (void *)jailbreaklab_getpid, (void **)&trampoline);
    if (trampoline == NULL) return false;
    original_getpid = trampoline;

    if (has_expected_arm64_jump(target)) return true;
    if (hook_memory == NULL) return false;

    uintptr_t replacement = (uintptr_t)(void *)jailbreaklab_getpid;
#if __has_feature(ptrauth_calls)
    replacement = (uintptr_t)ptrauth_strip(
        (void *)replacement, ptrauth_key_function_pointer
    );
#endif
    uint32_t jump[4] = {
        0x58000050,
        0xd61f0200,
        (uint32_t)replacement,
        (uint32_t)(replacement >> 32)
    };
    hook_memory(target, jump, sizeof(jump));
#if defined(__arm64__)
    return has_expected_arm64_jump(target);
#else
    return true;
#endif
}

#if defined(JAILBREAKLAB_TESTING)
bool jailbreaklab_install_getpid_hook_for_testing(
    ms_hook_function_t hook,
    ms_hook_memory_t hook_memory,
    void *target
) {
    fallback_pid = 123;
    return install_getpid_hook(hook, hook_memory, target);
}
#else
__attribute__((constructor))
static void install_mshook_environment(void) {
    fallback_pid = getpid();
    ms_hook_function_t hook = resolve_ms_hook_function();
    ms_hook_memory_t hook_memory = (ms_hook_memory_t)dlsym(
        RTLD_DEFAULT, "MSHookMemory"
    );
    void *target = dlsym(RTLD_DEFAULT, "getpid");
    (void)install_getpid_hook(hook, hook_memory, target);
}
#endif
