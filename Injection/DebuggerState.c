#include <dlfcn.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <unistd.h>

typedef void (*ms_hook_function_t)(void *, void *, void **);
typedef int (*sysctl_function_t)(
    int *, unsigned int, void *, size_t *, void *, size_t
);

static sysctl_function_t original_sysctl = NULL;

static bool is_current_process_query(
    const int *name,
    unsigned int name_length,
    const void *old_value,
    const size_t *old_length,
    const void *new_value,
    size_t new_length,
    size_t supplied_length
) {
    return name != NULL && name_length == 4 &&
        name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID && name[3] == getpid() &&
        old_value != NULL && old_length != NULL &&
        new_value == NULL && new_length == 0 &&
        supplied_length >= sizeof(struct kinfo_proc) &&
        *old_length >= sizeof(struct kinfo_proc);
}

static int jailbreaklab_sysctl(
    int *name,
    unsigned int name_length,
    void *old_value,
    size_t *old_length,
    void *new_value,
    size_t new_length
) {
    if (original_sysctl == NULL) return -1;

    size_t supplied_length = old_length == NULL ? 0 : *old_length;
    int result = original_sysctl(
        name, name_length, old_value, old_length, new_value, new_length
    );
    if (result == 0 && is_current_process_query(
        name, name_length, old_value, old_length,
        new_value, new_length, supplied_length
    )) {
        struct kinfo_proc *process_info = old_value;
        process_info->kp_proc.p_flag |= P_TRACED;
    }
    return result;
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

static bool install_sysctl_hook(ms_hook_function_t hook, void *target) {
    if (hook == NULL || target == NULL) return false;
    sysctl_function_t trampoline = NULL;
    hook(target, (void *)jailbreaklab_sysctl, (void **)&trampoline);
    if (trampoline == NULL) return false;
    original_sysctl = trampoline;
    return true;
}

#if defined(JAILBREAKLAB_TESTING)
bool jailbreaklab_install_sysctl_hook_for_testing(
    ms_hook_function_t hook,
    void *target
) {
    original_sysctl = NULL;
    return install_sysctl_hook(hook, target);
}
#else
__attribute__((constructor))
static void install_debugger_state_environment(void) {
    ms_hook_function_t hook = resolve_ms_hook_function();
    void *target = dlsym(RTLD_DEFAULT, "sysctl");
    (void)install_sysctl_hook(hook, target);
}
#endif
