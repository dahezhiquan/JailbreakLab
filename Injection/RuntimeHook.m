#include <objc/runtime.h>

typedef id (*object_getter_imp_t)(id, SEL);

static object_getter_imp_t original_process_name = NULL;

static id jailbreaklab_process_name(id object, SEL selector) {
    return original_process_name != NULL
        ? original_process_name(object, selector)
        : nil;
}

__attribute__((constructor))
static void install_runtime_hook(void) {
    Class process_info_class = objc_getClass("NSProcessInfo");
    SEL process_name_selector = sel_registerName("processName");
    if (process_info_class == Nil || process_name_selector == NULL) return;

    Method method = class_getInstanceMethod(process_info_class, process_name_selector);
    if (method == NULL) return;

    IMP replacement = (IMP)jailbreaklab_process_name;
    IMP current = method_getImplementation(method);
    if (current == replacement) return;

    original_process_name = (object_getter_imp_t)method_setImplementation(
        method, replacement
    );
}
