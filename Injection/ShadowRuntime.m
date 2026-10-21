#include <objc/runtime.h>

static id shadow_internal_dictionary(id object, SEL selector) {
    (void)object;
    (void)selector;
    return nil;
}

__attribute__((constructor))
static void register_shadow_ruleset_if_enabled(void) {
    if (objc_getClass("ShadowRuleset") != Nil) return;

    Class base_class = objc_getClass("NSObject");
    if (base_class == Nil) return;

    Class shadow_class = objc_allocateClassPair(base_class, "ShadowRuleset", 0);
    if (shadow_class == Nil) return;
    if (!class_addMethod(
        shadow_class,
        sel_registerName("internalDictionary"),
        (IMP)shadow_internal_dictionary,
        "@@:"
    )) {
        objc_disposeClassPair(shadow_class);
        return;
    }
    objc_registerClassPair(shadow_class);
}
