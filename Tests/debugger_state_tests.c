#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <unistd.h>

typedef void (*ms_hook_function_t)(void *, void *, void **);
typedef int (*sysctl_function_t)(
    int *, unsigned int, void *, size_t *, void *, size_t
);

bool jailbreaklab_install_sysctl_hook_for_testing(
    ms_hook_function_t hook,
    void *target
);

static void *observed_target = NULL;
static sysctl_function_t observed_replacement = NULL;

static int fake_sysctl(
    int *name,
    unsigned int name_length,
    void *old_value,
    size_t *old_length,
    void *new_value,
    size_t new_length
) {
    (void)name;
    (void)name_length;
    (void)new_value;
    (void)new_length;
    if (old_value != NULL && old_length != NULL &&
        *old_length >= sizeof(struct kinfo_proc)) {
        memset(old_value, 0, sizeof(struct kinfo_proc));
        *old_length = sizeof(struct kinfo_proc);
    }
    return 0;
}

static void fake_ms_hook(void *target, void *replacement, void **original) {
    observed_target = target;
    observed_replacement = (sysctl_function_t)replacement;
    *original = (void *)fake_sysctl;
}

static struct kinfo_proc run_query(
    int pid,
    unsigned int name_length,
    void *new_value,
    size_t new_length,
    size_t supplied_length
) {
    int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    struct kinfo_proc process_info;
    memset(&process_info, 0, sizeof(process_info));
    size_t length = supplied_length;
    assert(observed_replacement != NULL);
    assert(observed_replacement(
        name, name_length, &process_info, &length, new_value, new_length
    ) == 0);
    return process_info;
}

int main(void) {
    void *target = (void *)fake_sysctl;
    assert(!jailbreaklab_install_sysctl_hook_for_testing(NULL, target));
    assert(!jailbreaklab_install_sysctl_hook_for_testing(fake_ms_hook, NULL));
    assert(jailbreaklab_install_sysctl_hook_for_testing(fake_ms_hook, target));
    assert(observed_target == target);
    assert(observed_replacement != NULL);

    struct kinfo_proc process_info = run_query(
        getpid(), 4, NULL, 0, sizeof(struct kinfo_proc)
    );
    assert((process_info.kp_proc.p_flag & P_TRACED) != 0);

    process_info = run_query(
        getpid() + 1, 4, NULL, 0, sizeof(struct kinfo_proc)
    );
    assert((process_info.kp_proc.p_flag & P_TRACED) == 0);

    process_info = run_query(
        getpid(), 3, NULL, 0, sizeof(struct kinfo_proc)
    );
    assert((process_info.kp_proc.p_flag & P_TRACED) == 0);

    int write_value = 1;
    process_info = run_query(
        getpid(), 4, &write_value, sizeof(write_value), sizeof(struct kinfo_proc)
    );
    assert((process_info.kp_proc.p_flag & P_TRACED) == 0);

    process_info = run_query(
        getpid(), 4, NULL, 0, sizeof(struct kinfo_proc) - 1
    );
    assert((process_info.kp_proc.p_flag & P_TRACED) == 0);

    puts("debugger state injection tests passed");
    return 0;
}
