#ifndef HelperBridge_h
#define HelperBridge_h

#include <stdbool.h>

char *JBRunHelper(
    const char *operation,
    const char *root_mode,
    const char *groups,
    bool dry_run,
    int *exit_code
);

void JBFreeHelperOutput(char *output);

#endif
