#include "HelperBridge.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const size_t kMaximumOutputSize = 1024 * 1024;

static const char *find_helper(void) {
    static const char *candidates[] = {
        "/var/jb/usr/local/libexec/jailbreaklab-helper",
        "/usr/local/libexec/jailbreaklab-helper",
        NULL
    };

    for (size_t index = 0; candidates[index] != NULL; index++) {
        if (access(candidates[index], X_OK) == 0) {
            return candidates[index];
        }
    }
    return NULL;
}

char *JBRunHelper(
    const char *operation,
    const char *root_mode,
    const char *groups,
    const char *target_bundle_id,
    const char *target_bundle_name,
    const char *target_executable,
    bool dry_run,
    int *exit_code
) {
    if (exit_code == NULL || operation == NULL || root_mode == NULL || groups == NULL ||
        target_bundle_id == NULL || target_bundle_name == NULL || target_executable == NULL) {
        return NULL;
    }

    *exit_code = EINVAL;
    const char *helper = find_helper();
    if (helper == NULL) {
        *exit_code = ENOENT;
        return strdup("");
    }

    int output_pipe[2];
    if (pipe(output_pipe) != 0) {
        *exit_code = errno;
        return strdup("");
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, output_pipe[0]);
    posix_spawn_file_actions_addclose(&actions, output_pipe[1]);

    char *arguments[16] = {0};
    size_t argument_index = 0;
    arguments[argument_index++] = (char *)helper;
    arguments[argument_index++] = "--operation";
    arguments[argument_index++] = (char *)operation;
    arguments[argument_index++] = "--root-mode";
    arguments[argument_index++] = (char *)root_mode;
    arguments[argument_index++] = "--groups";
    arguments[argument_index++] = (char *)groups;
    if (target_bundle_id[0] != '\0') {
        arguments[argument_index++] = "--target-bundle-id";
        arguments[argument_index++] = (char *)target_bundle_id;
        arguments[argument_index++] = "--target-bundle-name";
        arguments[argument_index++] = (char *)target_bundle_name;
        arguments[argument_index++] = "--target-executable";
        arguments[argument_index++] = (char *)target_executable;
    }
    arguments[argument_index++] = dry_run ? "--dry-run" : "--live";
    arguments[argument_index] = NULL;
    char *sanitized_environment[] = {
        "PATH=/usr/bin:/bin",
        "LANG=C",
        NULL
    };

    pid_t process_id = 0;
    int spawn_result = posix_spawn(
        &process_id,
        helper,
        &actions,
        NULL,
        arguments,
        sanitized_environment
    );
    posix_spawn_file_actions_destroy(&actions);
    close(output_pipe[1]);

    if (spawn_result != 0) {
        close(output_pipe[0]);
        *exit_code = spawn_result;
        return strdup("");
    }

    size_t capacity = 4096;
    size_t length = 0;
    char *output = calloc(capacity, 1);
    if (output == NULL) {
        close(output_pipe[0]);
        kill(process_id, SIGTERM);
        waitpid(process_id, NULL, 0);
        *exit_code = ENOMEM;
        return NULL;
    }

    while (length < kMaximumOutputSize) {
        if (capacity - length < 2048) {
            size_t next_capacity = capacity * 2;
            if (next_capacity > kMaximumOutputSize + 1) {
                next_capacity = kMaximumOutputSize + 1;
            }
            char *resized = realloc(output, next_capacity);
            if (resized == NULL) {
                break;
            }
            output = resized;
            capacity = next_capacity;
        }

        ssize_t bytes_read = read(output_pipe[0], output + length, capacity - length - 1);
        if (bytes_read == 0) {
            break;
        }
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        length += (size_t)bytes_read;
        output[length] = '\0';
    }
    close(output_pipe[0]);

    int status = 0;
    if (waitpid(process_id, &status, 0) < 0) {
        *exit_code = errno;
    } else if (WIFEXITED(status)) {
        *exit_code = WEXITSTATUS(status);
    } else {
        *exit_code = ECANCELED;
    }
    return output;
}

void JBFreeHelperOutput(char *output) {
    free(output);
}
