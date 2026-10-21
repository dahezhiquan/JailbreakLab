#import <Foundation/Foundation.h>

#include <assert.h>
#include <dlfcn.h>
#include <objc/runtime.h>
#include <string.h>

int main(int argument_count, const char *arguments[]) {
    assert(argument_count == 2);

    NSProcessInfo *process_info = [NSProcessInfo processInfo];
    NSString *original_name = [process_info processName];
    assert(original_name != nil);

    void *handle = dlopen(arguments[1], RTLD_NOW | RTLD_LOCAL);
    assert(handle != NULL);

    Method method = class_getInstanceMethod(
        objc_getClass("NSProcessInfo"), sel_registerName("processName")
    );
    assert(method != NULL);

    Dl_info info = {0};
    IMP implementation = method_getImplementation(method);
    assert(dladdr((const void *)implementation, &info) == 1);
    assert(info.dli_fname != NULL);
    assert(strstr(info.dli_fname, "JailbreakLabRuntimeHook.dylib") != NULL);
    assert([[process_info processName] isEqualToString:original_name]);

    puts("runtime hook tests passed");
    return 0;
}
