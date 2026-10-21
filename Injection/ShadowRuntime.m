#include <fcntl.h>
#include <objc/runtime.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static const char *kMarkerPath =
    "/private/var/db/jailbreaklab/shadow-class-enabled-v1";
static const char *kMarkerContents =
    "JAILBREAKLAB_ARTIFACT_V1\n"
    "/private/var/db/jailbreaklab/shadow-class-enabled-v1\n";

static bool marker_is_enabled(void) {
    int descriptor = open(kMarkerPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) return false;

    size_t expected_length = strlen(kMarkerContents);
    char buffer[160] = {0};
    ssize_t count = read(descriptor, buffer, sizeof(buffer));
    close(descriptor);
    return count == (ssize_t)expected_length &&
        memcmp(buffer, kMarkerContents, expected_length) == 0;
}

static id shadow_internal_dictionary(id object, SEL selector) {
    (void)object;
    (void)selector;
    return nil;
}

__attribute__((constructor))
static void register_shadow_ruleset_if_enabled(void) {
    if (!marker_is_enabled() || objc_getClass("ShadowRuleset") != Nil) return;

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
