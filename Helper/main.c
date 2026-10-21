#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))
#define MAX_PATH_LENGTH 1024
#define PROCESS_PATH_BUFFER_SIZE 4096

static const char *kFileSignature = "JAILBREAKLAB_ARTIFACT_V1\n";
static const char *kDirectoryMarker = ".jailbreaklab-owned-v1";
static const char *kRestrictedStateDirectory = "/private/var/db/jailbreaklab";
static const char *kRestrictedStateFile = "restricted-write-state-v2";
static const char *kSymlinkStateFile = "abnormal-symlink-state-v1";

#define RESTRICTED_TARGET_COUNT 3

typedef struct {
    char magic[32];
    uint32_t version;
    uint32_t rootless;
    uint32_t active_mask;
    uint32_t created_mask;
    uint32_t original_modes[RESTRICTED_TARGET_COUNT];
    uint64_t devices[RESTRICTED_TARGET_COUNT];
    uint64_t inodes[RESTRICTED_TARGET_COUNT];
} restricted_state_t;

static const char *kRestrictedTargets[RESTRICTED_TARGET_COUNT] = {
    "/root", "/private", "/jb"
};

#define SYMLINK_TARGET_COUNT 7

typedef struct {
    char magic[32];
    uint32_t version;
    uint32_t rootless;
    uint32_t active_mask;
    uint32_t missing_mask;
    uint64_t devices[SYMLINK_TARGET_COUNT];
    uint64_t inodes[SYMLINK_TARGET_COUNT];
} symlink_state_t;

static const char *kSymlinkTargets[SYMLINK_TARGET_COUNT] = {
    "/Applications",
    "/Library/Ringtones",
    "/Library/Wallpaper",
    "/usr/include",
    "/usr/libexec",
    "/usr/share",
    "/var/lib/undecimus/apt"
};

typedef enum {
    SYMLINK_OPERATION_FAILED,
    SYMLINK_OPERATION_CHANGED,
    SYMLINK_OPERATION_ALREADY
} symlink_operation_result_t;

typedef enum {
    KIND_FILE,
    KIND_DIRECTORY
} artifact_kind_t;

typedef struct {
    const char *path;
    const char *group;
    artifact_kind_t kind;
} artifact_t;

static const artifact_t kArtifacts[] = {
    {"/var/mobile/Library/Preferences/ABPattern", "jailbreak-markers", KIND_FILE},
    {"/usr/lib/ABDYLD.dylib", "injection-frameworks", KIND_FILE},
    {"/usr/lib/ABSubLoader.dylib", "injection-frameworks", KIND_FILE},
    {"/usr/sbin/frida-server", "injection-frameworks", KIND_FILE},
    {"/etc/apt/sources.list.d/electra.list", "package-managers", KIND_FILE},
    {"/etc/apt/sources.list.d/sileo.sources", "package-managers", KIND_FILE},
    {"/.bootstrapped_electra", "jailbreak-markers", KIND_FILE},
    {"/usr/lib/libjailbreak.dylib", "injection-frameworks", KIND_FILE},
    {"/jb/lzma", "jailbreak-markers", KIND_FILE},
    {"/.cydia_no_stash", "jailbreak-markers", KIND_FILE},
    {"/.installed_unc0ver", "jailbreak-markers", KIND_FILE},
    {"/jb/offsets.plist", "jailbreak-markers", KIND_FILE},
    {"/usr/share/jailbreak/injectme.plist", "jailbreak-markers", KIND_FILE},
    {"/etc/apt/undecimus/undecimus.list", "package-managers", KIND_FILE},
    {"/var/lib/dpkg/info/mobilesubstrate.md5sums", "package-managers", KIND_FILE},
    {"/Library/MobileSubstrate/MobileSubstrate.dylib", "injection-frameworks", KIND_FILE},
    {"/jb/jailbreakd.plist", "jailbreak-markers", KIND_FILE},
    {"/jb/amfid_payload.dylib", "injection-frameworks", KIND_FILE},
    {"/jb/libjailbreak.dylib", "injection-frameworks", KIND_FILE},
    {"/usr/libexec/cydia/firmware.sh", "package-managers", KIND_FILE},
    {"/var/lib/cydia", "package-managers", KIND_DIRECTORY},
    {"/etc/apt", "package-managers", KIND_DIRECTORY},
    {"/private/var/lib/apt", "package-managers", KIND_DIRECTORY},
    {"/var/log/apt", "package-managers", KIND_DIRECTORY},
    {"/Applications/Cydia.app", "package-managers", KIND_DIRECTORY},
    {"/private/var/stash", "jailbreak-markers", KIND_DIRECTORY},
    {"/private/var/lib/cydia", "package-managers", KIND_DIRECTORY},
    {"/private/var/cache/apt", "package-managers", KIND_DIRECTORY},
    {"/private/var/log/syslog", "jailbreak-markers", KIND_FILE},
    {"/private/var/tmp/cydia.log", "package-managers", KIND_FILE},
    {"/Applications/Icy.app", "package-managers", KIND_DIRECTORY},
    {"/Applications/MxTube.app", "jailbreak-markers", KIND_DIRECTORY},
    {"/Applications/RockApp.app", "jailbreak-markers", KIND_DIRECTORY},
    {"/Applications/blackra1n.app", "jailbreak-markers", KIND_DIRECTORY},
    {"/Applications/SBSettings.app", "jailbreak-markers", KIND_DIRECTORY},
    {"/Applications/FakeCarrier.app", "jailbreak-markers", KIND_DIRECTORY},
    {"/Applications/WinterBoard.app", "jailbreak-markers", KIND_DIRECTORY},
    {"/Applications/IntelliScreen.app", "jailbreak-markers", KIND_DIRECTORY},
    {"/private/var/mobile/Library/SBSettings/Themes", "jailbreak-markers", KIND_DIRECTORY},
    {"/Library/MobileSubstrate/CydiaSubstrate.dylib", "injection-frameworks", KIND_FILE},
    {"/System/Library/LaunchDaemons/com.ikey.bbot.plist", "jailbreak-markers", KIND_FILE},
    {"/Library/MobileSubstrate/DynamicLibraries/Veency.plist", "injection-frameworks", KIND_FILE},
    {"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist", "injection-frameworks", KIND_FILE},
    {"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist", "package-managers", KIND_FILE},
    {"/Applications/Sileo.app", "package-managers", KIND_DIRECTORY},
    {"/var/binpack", "package-managers", KIND_DIRECTORY},
    {"/Library/PreferenceBundles/LibertyPref.bundle", "bypass-tools", KIND_DIRECTORY},
    {"/Library/PreferenceBundles/ShadowPreferences.bundle", "bypass-tools", KIND_DIRECTORY},
    {"/Library/PreferenceBundles/ABypassPrefs.bundle", "bypass-tools", KIND_DIRECTORY},
    {"/Library/PreferenceBundles/FlyJBPrefs.bundle", "bypass-tools", KIND_DIRECTORY},
    {"/Library/PreferenceBundles/Cephei.bundle", "bypass-tools", KIND_DIRECTORY},
    {"/Library/PreferenceBundles/SubstitutePrefs.bundle", "injection-frameworks", KIND_DIRECTORY},
    {"/Library/PreferenceBundles/libhbangprefs.bundle", "injection-frameworks", KIND_DIRECTORY},
    {"/usr/lib/libhooker.dylib", "injection-frameworks", KIND_FILE},
    {"/usr/lib/libsubstitute.dylib", "injection-frameworks", KIND_FILE},
    {"/usr/lib/substrate", "injection-frameworks", KIND_DIRECTORY},
    {"/usr/lib/TweakInject", "injection-frameworks", KIND_DIRECTORY},
    {"/var/binpack/Applications/loader.app", "package-managers", KIND_DIRECTORY},
    {"/Applications/FlyJB.app", "bypass-tools", KIND_DIRECTORY},
    {"/Applications/Zebra.app", "package-managers", KIND_DIRECTORY},
    {"/Library/BawAppie/ABypass", "bypass-tools", KIND_DIRECTORY},
    {"/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.plist", "injection-frameworks", KIND_FILE},
    {"/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.plist", "injection-frameworks", KIND_FILE},
    {"/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib", "injection-frameworks", KIND_FILE},
    {"/Library/MobileSubstrate/DynamicLibraries", "injection-frameworks", KIND_DIRECTORY},
    {"/var/mobile/Library/Preferences/me.jjolano.shadow.plist", "bypass-tools", KIND_FILE},
    {"/bin/bash", "remote-shell", KIND_FILE},
    {"/usr/sbin/sshd", "remote-shell", KIND_FILE},
    {"/usr/libexec/ssh-keysign", "remote-shell", KIND_FILE},
    {"/bin/sh", "remote-shell", KIND_FILE},
    {"/etc/ssh/sshd_config", "remote-shell", KIND_FILE},
    {"/usr/libexec/sftp-server", "remote-shell", KIND_FILE},
    {"/usr/bin/ssh", "remote-shell", KIND_FILE}
};

typedef struct {
    const char *operation;
    const char *root_mode;
    const char *groups;
    bool dry_run;
} options_t;

static void json_escape(const char *source, char *destination, size_t capacity) {
    size_t output = 0;
    if (capacity == 0) return;

    for (size_t index = 0; source[index] != '\0' && output + 2 < capacity; index++) {
        unsigned char value = (unsigned char)source[index];
        if (value == '"' || value == '\\') {
            destination[output++] = '\\';
            destination[output++] = (char)value;
        } else if (value == '\n' || value == '\r' || value == '\t') {
            destination[output++] = '\\';
            destination[output++] = value == '\n' ? 'n' : (value == '\r' ? 'r' : 't');
        } else if (value >= 0x20) {
            destination[output++] = (char)value;
        }
    }
    destination[output] = '\0';
}

static void emit_result(
    const char *path,
    const char *effective_path,
    const char *status,
    const char *message
) {
    char escaped_path[MAX_PATH_LENGTH * 2];
    char escaped_effective[MAX_PATH_LENGTH * 2];
    char escaped_message[2048];
    json_escape(path, escaped_path, sizeof(escaped_path));
    json_escape(effective_path, escaped_effective, sizeof(escaped_effective));
    json_escape(message, escaped_message, sizeof(escaped_message));
    printf(
        "{\"path\":\"%s\",\"effectivePath\":\"%s\",\"status\":\"%s\",\"message\":\"%s\"}\n",
        escaped_path, escaped_effective, status, escaped_message
    );
}

static bool group_selected(const char *groups, const char *group) {
    size_t group_length = strlen(group);
    const char *cursor = groups;
    while (*cursor != '\0') {
        const char *separator = strchr(cursor, ',');
        size_t token_length = separator == NULL ? strlen(cursor) : (size_t)(separator - cursor);
        if (token_length == group_length && strncmp(cursor, group, group_length) == 0) {
            return true;
        }
        if (separator == NULL) break;
        cursor = separator + 1;
    }
    return false;
}

static bool valid_group_list(const char *groups) {
    static const char *valid_groups[] = {
        "jailbreak-markers",
        "package-managers",
        "injection-frameworks",
        "bypass-tools",
        "remote-shell"
    };
    if (groups == NULL || groups[0] == '\0') return false;

    const char *cursor = groups;
    while (*cursor != '\0') {
        const char *separator = strchr(cursor, ',');
        size_t token_length = separator == NULL ? strlen(cursor) : (size_t)(separator - cursor);
        bool found = false;
        for (size_t index = 0; index < ARRAY_COUNT(valid_groups); index++) {
            if (strlen(valid_groups[index]) == token_length &&
                strncmp(cursor, valid_groups[index], token_length) == 0) {
                found = true;
                break;
            }
        }
        if (!found) return false;
        if (separator == NULL) break;
        if (separator[1] == '\0') return false;
        cursor = separator + 1;
    }
    return true;
}

static bool is_rootless_available(void) {
    struct stat information;
    return stat("/var/jb", &information) == 0 && S_ISDIR(information.st_mode);
}

static bool remains_in_data_volume(const char *path) {
    return strncmp(path, "/var/", 5) == 0 ||
           strcmp(path, "/var") == 0 ||
           strncmp(path, "/private/var/", 13) == 0 ||
           strcmp(path, "/private/var") == 0;
}

static bool effective_path_for_layout(
    const char *original,
    bool use_rootless,
    char *output,
    size_t capacity
) {
    char mapped[MAX_PATH_LENGTH];
    int result;
    if (use_rootless && !remains_in_data_volume(original)) {
        char rootless_prefix[PATH_MAX];
        if (realpath("/var/jb", rootless_prefix) == NULL) return false;
        result = snprintf(mapped, sizeof(mapped), "%s%s", rootless_prefix, original);
    } else {
        result = snprintf(mapped, sizeof(mapped), "%s", original);
    }
    if (result <= 0 || (size_t)result >= sizeof(mapped)) return false;

    // /var is normally a symlink to /private/var. Canonicalizing this fixed
    // system alias lets the component walker keep rejecting all symlinks.
    if (strncmp(mapped, "/var/", 5) == 0) {
        result = snprintf(output, capacity, "/private%s", mapped);
    } else {
        result = snprintf(output, capacity, "%s", mapped);
    }
    return result > 0 && (size_t)result < capacity;
}

static bool effective_path_for(
    const char *original,
    const char *root_mode,
    char *output,
    size_t capacity
) {
    bool use_rootless = strcmp(root_mode, "rootless") == 0 ||
        (strcmp(root_mode, "auto") == 0 && is_rootless_available());
    return effective_path_for_layout(original, use_rootless, output, capacity);
}

static bool restricted_effective_path(
    const char *original,
    bool use_rootless,
    char *output,
    size_t capacity
) {
    if (strcmp(original, "/private") == 0) {
        int result = snprintf(output, capacity, "%s", original);
        return result > 0 && (size_t)result < capacity;
    }
    return effective_path_for_layout(original, use_rootless, output, capacity);
}

static int open_root(void) {
    return open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

static int create_owned_directory_component(int parent, const char *name);

static bool valid_absolute_path(const char *path) {
    if (path == NULL || path[0] != '/' || path[1] == '\0') return false;
    if (strlen(path) >= MAX_PATH_LENGTH) return false;
    if (strstr(path, "/../") != NULL || strstr(path, "//") != NULL) return false;
    size_t length = strlen(path);
    return length < 3 || strcmp(path + length - 3, "/..") != 0;
}

static int open_directory_component(int parent, const char *name) {
    int descriptor = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    return descriptor;
}

static int open_parent_directory(
    const char *path,
    char *leaf,
    size_t leaf_capacity,
    bool create_missing
) {
    if (!valid_absolute_path(path)) {
        errno = EINVAL;
        return -1;
    }

    char buffer[MAX_PATH_LENGTH];
    snprintf(buffer, sizeof(buffer), "%s", path + 1);
    char *save_pointer = NULL;
    char *component = strtok_r(buffer, "/", &save_pointer);
    int current = open_root();
    if (current < 0) return -1;

    while (component != NULL) {
        char *next = strtok_r(NULL, "/", &save_pointer);
        if (next == NULL) {
            if (snprintf(leaf, leaf_capacity, "%s", component) >= (int)leaf_capacity) {
                close(current);
                errno = ENAMETOOLONG;
                return -1;
            }
            return current;
        }

        int next_descriptor = open_directory_component(current, component);
        if (next_descriptor < 0 && errno == ENOENT && create_missing) {
            next_descriptor = create_owned_directory_component(current, component);
        }
        close(current);
        if (next_descriptor < 0) return -1;
        current = next_descriptor;
        component = next;
    }

    close(current);
    errno = EINVAL;
    return -1;
}

static bool write_all(int descriptor, const char *bytes, size_t length) {
    size_t written = 0;
    while (written < length) {
        ssize_t result = write(descriptor, bytes + written, length - written);
        if (result < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        written += (size_t)result;
    }
    return true;
}

static bool fd_has_exact_signature(int descriptor, const char *signature) {
    size_t length = strlen(signature);
    char *buffer = calloc(length + 2, 1);
    if (buffer == NULL) return false;
    if (lseek(descriptor, 0, SEEK_SET) < 0) {
        free(buffer);
        return false;
    }
    ssize_t count = read(descriptor, buffer, length + 1);
    bool matches = count == (ssize_t)length && memcmp(buffer, signature, length) == 0;
    free(buffer);
    return matches;
}

static int create_owned_directory_component(int parent, const char *name) {
    if (mkdirat(parent, name, 0755) != 0) return -1;

    int directory = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) {
        unlinkat(parent, name, AT_REMOVEDIR);
        return -1;
    }

    int marker = openat(
        directory, kDirectoryMarker,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600
    );
    bool succeeded = marker >= 0 &&
        write_all(marker, kFileSignature, strlen(kFileSignature)) &&
        fsync(marker) == 0;
    if (marker >= 0) close(marker);
    if (!succeeded) {
        int saved = errno;
        unlinkat(directory, kDirectoryMarker, 0);
        close(directory);
        unlinkat(parent, name, AT_REMOVEDIR);
        errno = saved;
        return -1;
    }
    return directory;
}

static bool directory_is_owned(int directory) {
    int marker = openat(directory, kDirectoryMarker, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    bool owned = marker >= 0 && fd_has_exact_signature(marker, kFileSignature);
    if (marker >= 0) close(marker);
    return owned;
}

static bool verify_directory_write(int directory) {
    const char *probe_name = ".jailbreaklab-write-probe";
    int probe = openat(
        directory, probe_name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600
    );
    if (probe < 0) return false;

    bool content_written = write_all(probe, kFileSignature, strlen(kFileSignature)) &&
        fsync(probe) == 0;
    int saved = errno;
    close(probe);
    bool removed = unlinkat(directory, probe_name, 0) == 0;
    if (!removed) saved = errno;
    errno = saved;
    return content_written && removed;
}

static bool verify_directory_write_as_caller(int directory) {
    pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        if (geteuid() == 0 && getuid() != 0) {
            if (setegid(getgid()) != 0 || seteuid(getuid()) != 0) _exit(1);
        }
        _exit(verify_directory_write(directory) ? 0 : 1);
    }

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool dry_run_can_create(const char *path, char *message, size_t capacity) {
    if (!valid_absolute_path(path)) {
        errno = EINVAL;
        snprintf(message, capacity, "invalid path");
        return false;
    }
    struct stat information;
    if (lstat(path, &information) == 0) {
        errno = EEXIST;
        snprintf(message, capacity, "existing object would not be modified");
        return false;
    }
    if (errno != ENOENT) {
        snprintf(message, capacity, "cannot inspect target: %s", strerror(errno));
        return false;
    }
    snprintf(message, capacity, "would create signed marker and missing parent directories");
    return true;
}

static bool create_marker_file(const char *path, bool dry_run, char *message, size_t capacity) {
    if (dry_run) return dry_run_can_create(path, message, capacity);

    char leaf[NAME_MAX + 1];
    int parent = open_parent_directory(path, leaf, sizeof(leaf), true);
    if (parent < 0) {
        snprintf(message, capacity, "cannot open parent: %s", strerror(errno));
        return false;
    }

    struct stat information;
    if (fstatat(parent, leaf, &information, AT_SYMLINK_NOFOLLOW) == 0) {
        char signature[MAX_PATH_LENGTH + 64];
        snprintf(signature, sizeof(signature), "%s%s\n", kFileSignature, path);
        int existing = openat(parent, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        bool owned = existing >= 0 && fd_has_exact_signature(existing, signature);
        if (existing >= 0) close(existing);
        close(parent);
        if (owned) {
            snprintf(message, capacity, "signed marker file already exists");
            return true;
        }
        snprintf(message, capacity, "existing object was not modified");
        errno = EEXIST;
        return false;
    }
    if (errno != ENOENT) {
        int saved = errno;
        close(parent);
        errno = saved;
        snprintf(message, capacity, "cannot inspect target: %s", strerror(errno));
        return false;
    }
    int descriptor = openat(
        parent, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644
    );
    if (descriptor < 0) {
        int saved = errno;
        close(parent);
        errno = saved;
        snprintf(message, capacity, "create failed: %s", strerror(errno));
        return false;
    }

    char contents[MAX_PATH_LENGTH + 64];
    int content_length = snprintf(contents, sizeof(contents), "%s%s\n", kFileSignature, path);
    bool succeeded = content_length > 0 &&
        (size_t)content_length < sizeof(contents) &&
        write_all(descriptor, contents, (size_t)content_length) &&
        fsync(descriptor) == 0;
    int saved = errno;
    close(descriptor);
    if (!succeeded) unlinkat(parent, leaf, 0);
    close(parent);
    errno = saved;
    if (succeeded) {
        snprintf(message, capacity, "signed marker file created");
    } else {
        snprintf(message, capacity, "write failed: %s", strerror(errno));
    }
    return succeeded;
}

static bool create_marker_directory(const char *path, bool dry_run, char *message, size_t capacity) {
    if (dry_run) return dry_run_can_create(path, message, capacity);

    char leaf[NAME_MAX + 1];
    int parent = open_parent_directory(path, leaf, sizeof(leaf), true);
    if (parent < 0) {
        snprintf(message, capacity, "cannot open parent: %s", strerror(errno));
        return false;
    }

    struct stat information;
    if (fstatat(parent, leaf, &information, AT_SYMLINK_NOFOLLOW) == 0) {
        int existing = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        bool owned = existing >= 0 && directory_is_owned(existing);
        if (existing >= 0) close(existing);
        close(parent);
        if (owned) {
            snprintf(message, capacity, "owned marker directory already exists");
            return true;
        }
        snprintf(message, capacity, "existing object was not modified");
        errno = EEXIST;
        return false;
    }
    if (errno != ENOENT) {
        int saved = errno;
        close(parent);
        errno = saved;
        snprintf(message, capacity, "cannot inspect target: %s", strerror(errno));
        return false;
    }
    if (mkdirat(parent, leaf, 0755) != 0) {
        int saved = errno;
        close(parent);
        errno = saved;
        snprintf(message, capacity, "mkdir failed: %s", strerror(errno));
        return false;
    }

    int directory = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) {
        unlinkat(parent, leaf, AT_REMOVEDIR);
        close(parent);
        snprintf(message, capacity, "cannot reopen marker directory");
        return false;
    }

    int marker = openat(
        directory, kDirectoryMarker,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600
    );
    bool succeeded = marker >= 0 &&
        write_all(marker, kFileSignature, strlen(kFileSignature)) &&
        fsync(marker) == 0;
    if (marker >= 0) close(marker);
    if (!succeeded) {
        unlinkat(directory, kDirectoryMarker, 0);
        close(directory);
        unlinkat(parent, leaf, AT_REMOVEDIR);
        close(parent);
        snprintf(message, capacity, "ownership marker creation failed");
        return false;
    }

    close(directory);
    close(parent);
    snprintf(message, capacity, "owned marker directory created");
    return true;
}

static bool remove_marker_file(const char *path, bool dry_run, char *message, size_t capacity) {
    char leaf[NAME_MAX + 1];
    int parent = open_parent_directory(path, leaf, sizeof(leaf), false);
    if (parent < 0) {
        if (errno == ENOENT) {
            snprintf(message, capacity, "target is absent");
        } else {
            snprintf(message, capacity, "cannot open parent: %s", strerror(errno));
        }
        return false;
    }
    int descriptor = openat(parent, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) {
        int saved = errno;
        close(parent);
        errno = saved;
        if (errno == ENOENT) {
            snprintf(message, capacity, "target is absent");
        } else {
            snprintf(message, capacity, "cannot open target: %s", strerror(errno));
        }
        return false;
    }

    char signature[MAX_PATH_LENGTH + 64];
    snprintf(signature, sizeof(signature), "%s%s\n", kFileSignature, path);
    bool owned = fd_has_exact_signature(descriptor, signature);
    close(descriptor);
    if (!owned) {
        close(parent);
        errno = EPERM;
        snprintf(message, capacity, "existing file is not owned by Jailbreak Lab");
        return false;
    }
    if (dry_run) {
        close(parent);
        snprintf(message, capacity, "would remove owned marker file");
        return true;
    }
    bool succeeded = unlinkat(parent, leaf, 0) == 0;
    int saved = errno;
    close(parent);
    errno = saved;
    if (succeeded) {
        snprintf(message, capacity, "owned marker file removed");
    } else {
        snprintf(message, capacity, "remove failed: %s", strerror(errno));
    }
    return succeeded;
}

static bool remove_marker_directory(const char *path, bool dry_run, char *message, size_t capacity) {
    char leaf[NAME_MAX + 1];
    int parent = open_parent_directory(path, leaf, sizeof(leaf), false);
    if (parent < 0) {
        if (errno == ENOENT) {
            snprintf(message, capacity, "target is absent");
        } else {
            snprintf(message, capacity, "cannot open parent: %s", strerror(errno));
        }
        return false;
    }
    int directory = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) {
        int saved = errno;
        close(parent);
        errno = saved;
        if (errno == ENOENT) {
            snprintf(message, capacity, "target is absent");
        } else {
            snprintf(message, capacity, "cannot open directory: %s", strerror(errno));
        }
        return false;
    }
    bool owned = directory_is_owned(directory);
    if (!owned) {
        close(directory);
        close(parent);
        errno = EPERM;
        snprintf(message, capacity, "existing directory is not owned by Jailbreak Lab");
        return false;
    }

    DIR *stream = fdopendir(dup(directory));
    bool empty_except_marker = stream != NULL;
    if (stream != NULL) {
        struct dirent *entry;
        while ((entry = readdir(stream)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
                strcmp(entry->d_name, kDirectoryMarker) == 0) {
                continue;
            }
            empty_except_marker = false;
            break;
        }
        closedir(stream);
    }
    if (!empty_except_marker) {
        close(directory);
        close(parent);
        errno = ENOTEMPTY;
        snprintf(message, capacity, "owned directory contains non-lab content");
        return false;
    }
    if (dry_run) {
        close(directory);
        close(parent);
        snprintf(message, capacity, "would remove owned marker directory");
        return true;
    }

    bool marker_removed = unlinkat(directory, kDirectoryMarker, 0) == 0;
    close(directory);
    bool directory_removed = marker_removed && unlinkat(parent, leaf, AT_REMOVEDIR) == 0;
    int saved = errno;
    close(parent);
    errno = saved;
    if (directory_removed) {
        snprintf(message, capacity, "owned marker directory removed");
    } else {
        snprintf(message, capacity, "remove failed: %s", strerror(errno));
    }
    return directory_removed;
}

static void prune_owned_ancestors(const char *path) {
    char current[MAX_PATH_LENGTH];
    if (snprintf(current, sizeof(current), "%s", path) >= (int)sizeof(current)) return;

    char *separator = strrchr(current, '/');
    if (separator == NULL || separator == current) return;
    *separator = '\0';

    while (current[0] == '/' && current[1] != '\0') {
        char leaf[NAME_MAX + 1];
        int parent = open_parent_directory(current, leaf, sizeof(leaf), false);
        if (parent < 0) return;

        int directory = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (directory < 0 || !directory_is_owned(directory)) {
            if (directory >= 0) close(directory);
            close(parent);
            return;
        }

        DIR *stream = fdopendir(dup(directory));
        bool empty_except_marker = stream != NULL;
        if (stream != NULL) {
            struct dirent *entry;
            while ((entry = readdir(stream)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
                    strcmp(entry->d_name, kDirectoryMarker) == 0) {
                    continue;
                }
                empty_except_marker = false;
                break;
            }
            closedir(stream);
        }
        if (!empty_except_marker || unlinkat(directory, kDirectoryMarker, 0) != 0) {
            close(directory);
            close(parent);
            return;
        }

        close(directory);
        bool removed = unlinkat(parent, leaf, AT_REMOVEDIR) == 0;
        close(parent);
        if (!removed) return;

        separator = strrchr(current, '/');
        if (separator == NULL || separator == current) return;
        *separator = '\0';
    }
}

static int open_restricted_state_directory(bool create) {
    char message[1024];
    if (create && !create_marker_directory(
        kRestrictedStateDirectory, false, message, sizeof(message)
    ) && errno != EEXIST) {
        return -1;
    }

    char leaf[NAME_MAX + 1];
    int parent = open_parent_directory(
        kRestrictedStateDirectory, leaf, sizeof(leaf), false
    );
    if (parent < 0) return -1;
    int directory = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int saved = errno;
    close(parent);
    errno = saved;
    if (directory >= 0 && !directory_is_owned(directory)) {
        close(directory);
        errno = EPERM;
        return -1;
    }
    return directory;
}

static bool load_restricted_state(restricted_state_t *state) {
    int directory = open_restricted_state_directory(false);
    if (directory < 0) return false;
    int descriptor = openat(
        directory, kRestrictedStateFile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC
    );
    int saved = errno;
    close(directory);
    errno = saved;
    if (descriptor < 0) return false;

    restricted_state_t candidate;
    ssize_t count = read(descriptor, &candidate, sizeof(candidate));
    char extra = 0;
    ssize_t extra_count = read(descriptor, &extra, 1);
    close(descriptor);
    static const char expected_magic[] = "JAILBREAKLAB_RESTRICTED_V2";
    if (count != (ssize_t)sizeof(candidate) || extra_count != 0 ||
        candidate.version != 2 ||
        memcmp(candidate.magic, expected_magic, sizeof(expected_magic)) != 0) {
        errno = EINVAL;
        return false;
    }
    *state = candidate;
    return true;
}

static bool save_restricted_state(const restricted_state_t *state) {
    int directory = open_restricted_state_directory(true);
    if (directory < 0) return false;
    int descriptor = openat(
        directory, kRestrictedStateFile,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600
    );
    int saved = errno;
    if (descriptor < 0) {
        close(directory);
        errno = saved;
        return false;
    }
    bool succeeded = write_all(descriptor, (const char *)state, sizeof(*state)) &&
        fsync(descriptor) == 0;
    saved = errno;
    close(descriptor);
    if (!succeeded) unlinkat(directory, kRestrictedStateFile, 0);
    close(directory);
    errno = saved;
    return succeeded;
}

static void remove_restricted_state(void) {
    int directory = open_restricted_state_directory(false);
    if (directory >= 0) {
        unlinkat(directory, kRestrictedStateFile, 0);
        close(directory);
    }
    char message[1024];
    remove_marker_directory(kRestrictedStateDirectory, false, message, sizeof(message));
    prune_owned_ancestors(kRestrictedStateDirectory);
}

static int open_restricted_target(const char *path, struct stat *information) {
    char leaf[NAME_MAX + 1];
    int parent = open_parent_directory(path, leaf, sizeof(leaf), false);
    if (parent < 0) return -1;
    int directory = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int saved = errno;
    close(parent);
    errno = saved;
    if (directory >= 0 && fstat(directory, information) != 0) {
        saved = errno;
        close(directory);
        errno = saved;
        return -1;
    }
    return directory;
}

static bool restricted_identity_matches(
    const restricted_state_t *state,
    size_t index,
    const struct stat *information
) {
    return state->devices[index] == (uint64_t)information->st_dev &&
        state->inodes[index] == (uint64_t)information->st_ino;
}

static void rollback_new_restricted_directories(const restricted_state_t *state) {
    for (size_t index = 0; index < RESTRICTED_TARGET_COUNT; index++) {
        if ((state->created_mask & (1U << index)) == 0) continue;
        char path[MAX_PATH_LENGTH];
        if (!restricted_effective_path(
            kRestrictedTargets[index], state->rootless != 0, path, sizeof(path)
        )) continue;
        char message[1024];
        remove_marker_directory(path, false, message, sizeof(message));
        prune_owned_ancestors(path);
    }
}

static bool prepare_restricted_state(bool use_rootless, restricted_state_t *state) {
    memset(state, 0, sizeof(*state));
    snprintf(state->magic, sizeof(state->magic), "JAILBREAKLAB_RESTRICTED_V2");
    state->version = 2;
    state->rootless = use_rootless ? 1 : 0;

    for (size_t index = 0; index < RESTRICTED_TARGET_COUNT; index++) {
        char path[MAX_PATH_LENGTH];
        if (!restricted_effective_path(
            kRestrictedTargets[index], use_rootless, path, sizeof(path)
        )) {
            emit_result(kRestrictedTargets[index], kRestrictedTargets[index], "failed", "path mapping failed");
            continue;
        }

        struct stat information;
        bool existed = lstat(path, &information) == 0;
        int inspection_error = errno;
        if (existed && !S_ISDIR(information.st_mode)) {
            emit_result(kRestrictedTargets[index], path, "failed", "target is not a directory");
            continue;
        }
        if (!existed) {
            char message[1024] = {0};
            if (inspection_error != ENOENT) {
                snprintf(message, sizeof(message), "cannot inspect target: %s", strerror(inspection_error));
                emit_result(kRestrictedTargets[index], path, "failed", message);
                continue;
            }
            if (!create_marker_directory(path, false, message, sizeof(message)) ||
                lstat(path, &information) != 0) {
                if (message[0] == '\0') {
                    snprintf(message, sizeof(message), "cannot inspect created directory: %s", strerror(errno));
                }
                emit_result(kRestrictedTargets[index], path, "failed", message);
                continue;
            }
            state->created_mask |= (1U << index);
        }

        state->active_mask |= (1U << index);
        state->original_modes[index] = (uint32_t)(information.st_mode & 07777);
        state->devices[index] = (uint64_t)information.st_dev;
        state->inodes[index] = (uint64_t)information.st_ino;
    }

    if (state->active_mask == 0) return false;
    if (!save_restricted_state(state)) {
        int saved = errno;
        rollback_new_restricted_directories(state);
        errno = saved;
        for (size_t index = 0; index < RESTRICTED_TARGET_COUNT; index++) {
            if ((state->active_mask & (1U << index)) != 0) {
                emit_result(
                    kRestrictedTargets[index], kRestrictedTargets[index],
                    "failed", "cannot save original directory permissions"
                );
            }
        }
        return false;
    }
    return true;
}

static void enable_restricted_directories(bool use_rootless, bool dry_run) {
    if (dry_run) {
        for (size_t index = 0; index < RESTRICTED_TARGET_COUNT; index++) {
            char path[MAX_PATH_LENGTH];
            if (!restricted_effective_path(
                kRestrictedTargets[index], use_rootless, path, sizeof(path)
            )) snprintf(path, sizeof(path), "%s", kRestrictedTargets[index]);
            emit_result(kRestrictedTargets[index], path, "planned", "would set mode 1777 and run write probe");
        }
        return;
    }

    restricted_state_t state;
    bool state_loaded = load_restricted_state(&state);
    if (!state_loaded && !prepare_restricted_state(use_rootless, &state)) return;

    for (size_t index = 0; index < RESTRICTED_TARGET_COUNT; index++) {
        if ((state.active_mask & (1U << index)) == 0) {
            if (!state_loaded) continue;
            char path[MAX_PATH_LENGTH];
            if (!restricted_effective_path(
                kRestrictedTargets[index], state.rootless != 0, path, sizeof(path)
            )) snprintf(path, sizeof(path), "%s", kRestrictedTargets[index]);
            emit_result(
                kRestrictedTargets[index], path, "failed",
                "target was unavailable when original permissions were recorded"
            );
            continue;
        }
        char path[MAX_PATH_LENGTH];
        if (!restricted_effective_path(
            kRestrictedTargets[index], state.rootless != 0, path, sizeof(path)
        )) continue;

        struct stat information;
        int directory = open_restricted_target(path, &information);
        if (directory < 0 || !restricted_identity_matches(&state, index, &information)) {
            if (directory >= 0) close(directory);
            emit_result(kRestrictedTargets[index], path, "protected", "directory identity changed; no permissions modified");
            continue;
        }
        if (fchmod(directory, 01777) != 0) {
            char message[1024];
            snprintf(message, sizeof(message), "permission change failed: %s", strerror(errno));
            close(directory);
            emit_result(kRestrictedTargets[index], path, "failed", message);
            continue;
        }
        if (!verify_directory_write_as_caller(directory)) {
            fchmod(directory, (mode_t)state.original_modes[index]);
            close(directory);
            emit_result(kRestrictedTargets[index], path, "failed", "write probe failed; original mode restored");
            continue;
        }
        close(directory);
        emit_result(kRestrictedTargets[index], path, "created", "mode 1777 set; caller-UID write probe succeeded");
    }
}

static void disable_restricted_directories(bool dry_run) {
    if (dry_run) {
        for (size_t index = 0; index < RESTRICTED_TARGET_COUNT; index++) {
            emit_result(
                kRestrictedTargets[index], kRestrictedTargets[index],
                "planned", "would restore recorded original permissions"
            );
        }
        return;
    }

    restricted_state_t state;
    if (!load_restricted_state(&state)) {
        int state_error = errno;
        for (size_t index = 0; index < RESTRICTED_TARGET_COUNT; index++) {
            emit_result(
                kRestrictedTargets[index], kRestrictedTargets[index],
                state_error == ENOENT ? "absent" : "protected",
                state_error == ENOENT
                    ? "no saved permission state"
                    : "saved permission state is unavailable or invalid"
            );
        }
        return;
    }

    bool fully_restored = true;
    for (size_t index = 0; index < RESTRICTED_TARGET_COUNT; index++) {
        if ((state.active_mask & (1U << index)) == 0) {
            char path[MAX_PATH_LENGTH];
            if (!restricted_effective_path(
                kRestrictedTargets[index], state.rootless != 0, path, sizeof(path)
            )) snprintf(path, sizeof(path), "%s", kRestrictedTargets[index]);
            emit_result(kRestrictedTargets[index], path, "absent", "no saved permission state");
            continue;
        }
        char path[MAX_PATH_LENGTH];
        if (!restricted_effective_path(
            kRestrictedTargets[index], state.rootless != 0, path, sizeof(path)
        )) {
            fully_restored = false;
            continue;
        }

        struct stat information;
        int directory = open_restricted_target(path, &information);
        if (directory < 0 && errno == ENOENT && (state.created_mask & (1U << index)) != 0) {
            emit_result(kRestrictedTargets[index], path, "absent", "tool-created directory is already absent");
            continue;
        }
        if (directory < 0 || !restricted_identity_matches(&state, index, &information)) {
            if (directory >= 0) close(directory);
            fully_restored = false;
            emit_result(kRestrictedTargets[index], path, "protected", "directory identity changed; original mode not applied");
            continue;
        }
        if (fchmod(directory, (mode_t)state.original_modes[index]) != 0) {
            char message[1024];
            snprintf(message, sizeof(message), "permission restore failed: %s", strerror(errno));
            close(directory);
            fully_restored = false;
            emit_result(kRestrictedTargets[index], path, "failed", message);
            continue;
        }
        close(directory);

        if ((state.created_mask & (1U << index)) != 0) {
            char message[1024];
            if (remove_marker_directory(path, false, message, sizeof(message))) {
                prune_owned_ancestors(path);
            } else if (errno != ENOTEMPTY && errno != ENOENT) {
                fully_restored = false;
                emit_result(kRestrictedTargets[index], path, "failed", message);
                continue;
            }
        }
        emit_result(kRestrictedTargets[index], path, "removed", "recorded original permissions restored");
    }

    if (fully_restored) remove_restricted_state();
}

static bool symlink_entry_names(
    size_t index,
    char *backup_name,
    size_t backup_capacity,
    char *created_name,
    size_t created_capacity
) {
    int backup_length = snprintf(
        backup_name, backup_capacity, ".jailbreaklab-symlink-original-%zu", index
    );
    int created_length = snprintf(
        created_name, created_capacity, ".jailbreaklab-symlink-target-%zu", index
    );
    return backup_length > 0 && (size_t)backup_length < backup_capacity &&
        created_length > 0 && (size_t)created_length < created_capacity;
}

static bool symlink_destination_matches(
    int parent,
    const char *leaf,
    const char *expected
) {
    char destination[NAME_MAX + 1];
    ssize_t length = readlinkat(parent, leaf, destination, sizeof(destination) - 1);
    if (length < 0) return false;
    destination[length] = '\0';
    return strcmp(destination, expected) == 0;
}

static bool directory_identity_matches_at(
    int parent,
    const char *name,
    uint64_t device,
    uint64_t inode
) {
    struct stat information;
    return fstatat(parent, name, &information, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISDIR(information.st_mode) &&
        device == (uint64_t)information.st_dev &&
        inode == (uint64_t)information.st_ino;
}

static bool owned_directory_is_empty_at(int parent, const char *name) {
    int directory = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) return false;
    if (!directory_is_owned(directory)) {
        close(directory);
        errno = EPERM;
        return false;
    }

    DIR *stream = fdopendir(dup(directory));
    if (stream == NULL) {
        int saved = errno;
        close(directory);
        errno = saved;
        return false;
    }
    bool empty_except_marker = true;
    struct dirent *entry;
    while ((entry = readdir(stream)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
            strcmp(entry->d_name, kDirectoryMarker) == 0) {
            continue;
        }
        empty_except_marker = false;
        break;
    }
    closedir(stream);
    close(directory);
    if (!empty_except_marker) errno = ENOTEMPTY;
    return empty_except_marker;
}

static bool remove_owned_directory_at(int parent, const char *name) {
    int directory = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) return errno == ENOENT;
    if (!directory_is_owned(directory)) {
        close(directory);
        errno = EPERM;
        return false;
    }
    if (unlinkat(directory, kDirectoryMarker, 0) != 0) {
        int saved = errno;
        close(directory);
        errno = saved;
        return false;
    }
    close(directory);
    return unlinkat(parent, name, AT_REMOVEDIR) == 0;
}

static symlink_operation_result_t enable_symlink_at(
    int parent,
    const char *leaf,
    size_t index,
    bool original_missing,
    uint64_t original_device,
    uint64_t original_inode,
    char *message,
    size_t capacity
) {
    char backup_name[NAME_MAX + 1];
    char created_name[NAME_MAX + 1];
    if (!symlink_entry_names(
        index, backup_name, sizeof(backup_name), created_name, sizeof(created_name)
    )) {
        errno = ENAMETOOLONG;
        snprintf(message, capacity, "internal entry name is too long");
        return SYMLINK_OPERATION_FAILED;
    }

    struct stat current;
    bool leaf_exists = fstatat(parent, leaf, &current, AT_SYMLINK_NOFOLLOW) == 0;
    int leaf_error = leaf_exists ? 0 : errno;

    if (!original_missing) {
        if (leaf_exists && S_ISLNK(current.st_mode) &&
            symlink_destination_matches(parent, leaf, backup_name) &&
            directory_identity_matches_at(
                parent, backup_name, original_device, original_inode
            )) {
            snprintf(message, capacity, "tool-owned abnormal symlink already exists");
            return SYMLINK_OPERATION_ALREADY;
        }

        bool original_at_leaf = leaf_exists && S_ISDIR(current.st_mode) &&
            original_device == (uint64_t)current.st_dev &&
            original_inode == (uint64_t)current.st_ino;
        bool original_at_backup = directory_identity_matches_at(
            parent, backup_name, original_device, original_inode
        );
        if (!original_at_leaf && !(leaf_error == ENOENT && original_at_backup)) {
            errno = EPERM;
            snprintf(message, capacity, "target or backup identity changed; no object modified");
            return SYMLINK_OPERATION_FAILED;
        }

        bool moved = false;
        if (original_at_leaf) {
            struct stat backup_information;
            if (fstatat(parent, backup_name, &backup_information, AT_SYMLINK_NOFOLLOW) == 0 ||
                errno != ENOENT) {
                errno = EEXIST;
                snprintf(message, capacity, "reserved backup entry already exists");
                return SYMLINK_OPERATION_FAILED;
            }
            if (renameat(parent, leaf, parent, backup_name) != 0) {
                snprintf(message, capacity, "cannot preserve original directory: %s", strerror(errno));
                return SYMLINK_OPERATION_FAILED;
            }
            moved = true;
        }
        if (symlinkat(backup_name, parent, leaf) != 0) {
            int saved = errno;
            if (moved) renameat(parent, backup_name, parent, leaf);
            errno = saved;
            snprintf(message, capacity, "symlink creation failed: %s", strerror(errno));
            return SYMLINK_OPERATION_FAILED;
        }
        snprintf(message, capacity, "original directory preserved behind abnormal symlink");
        return SYMLINK_OPERATION_CHANGED;
    }

    if (leaf_exists && S_ISLNK(current.st_mode) &&
        symlink_destination_matches(parent, leaf, created_name)) {
        int created = openat(
            parent, created_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        );
        bool owned = created >= 0 && directory_is_owned(created);
        if (created >= 0) close(created);
        if (owned) {
            snprintf(message, capacity, "tool-owned abnormal symlink already exists");
            return SYMLINK_OPERATION_ALREADY;
        }
    }
    if (leaf_exists || leaf_error != ENOENT) {
        errno = EPERM;
        snprintf(message, capacity, "target appeared or changed; no object modified");
        return SYMLINK_OPERATION_FAILED;
    }

    int created = openat(
        parent, created_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    );
    bool created_for_operation = false;
    if (created >= 0) {
        if (!directory_is_owned(created)) {
            close(created);
            errno = EPERM;
            snprintf(message, capacity, "reserved backing directory is not tool-owned");
            return SYMLINK_OPERATION_FAILED;
        }
        close(created);
    } else if (errno == ENOENT) {
        created = create_owned_directory_component(parent, created_name);
        if (created < 0) {
            snprintf(message, capacity, "cannot create symlink backing directory: %s", strerror(errno));
            return SYMLINK_OPERATION_FAILED;
        }
        close(created);
        created_for_operation = true;
    } else {
        snprintf(message, capacity, "cannot inspect symlink backing directory: %s", strerror(errno));
        return SYMLINK_OPERATION_FAILED;
    }

    if (symlinkat(created_name, parent, leaf) != 0) {
        int saved = errno;
        if (created_for_operation) remove_owned_directory_at(parent, created_name);
        errno = saved;
        snprintf(message, capacity, "symlink creation failed: %s", strerror(errno));
        return SYMLINK_OPERATION_FAILED;
    }
    snprintf(message, capacity, "abnormal symlink and tool-owned backing directory created");
    return SYMLINK_OPERATION_CHANGED;
}

static symlink_operation_result_t disable_symlink_at(
    int parent,
    const char *leaf,
    size_t index,
    bool original_missing,
    uint64_t original_device,
    uint64_t original_inode,
    char *message,
    size_t capacity
) {
    char backup_name[NAME_MAX + 1];
    char created_name[NAME_MAX + 1];
    if (!symlink_entry_names(
        index, backup_name, sizeof(backup_name), created_name, sizeof(created_name)
    )) {
        errno = ENAMETOOLONG;
        snprintf(message, capacity, "internal entry name is too long");
        return SYMLINK_OPERATION_FAILED;
    }

    struct stat current;
    bool leaf_exists = fstatat(parent, leaf, &current, AT_SYMLINK_NOFOLLOW) == 0;
    int leaf_error = leaf_exists ? 0 : errno;

    if (!original_missing) {
        struct stat backup_information;
        bool backup_exists = fstatat(
            parent, backup_name, &backup_information, AT_SYMLINK_NOFOLLOW
        ) == 0;
        int backup_error = errno;
        bool original_at_leaf = leaf_exists && S_ISDIR(current.st_mode) &&
            original_device == (uint64_t)current.st_dev &&
            original_inode == (uint64_t)current.st_ino;
        if (original_at_leaf && !backup_exists && backup_error == ENOENT) {
            snprintf(message, capacity, "original directory is already restored");
            return SYMLINK_OPERATION_ALREADY;
        }
        bool valid_backup = backup_exists && S_ISDIR(backup_information.st_mode) &&
            original_device == (uint64_t)backup_information.st_dev &&
            original_inode == (uint64_t)backup_information.st_ino;
        bool valid_leaf = (!leaf_exists && leaf_error == ENOENT) ||
            (leaf_exists && S_ISLNK(current.st_mode) &&
             symlink_destination_matches(parent, leaf, backup_name));
        if (!valid_backup || !valid_leaf) {
            errno = EPERM;
            snprintf(message, capacity, "symlink or backup identity changed; original not restored");
            return SYMLINK_OPERATION_FAILED;
        }
        if (leaf_exists && unlinkat(parent, leaf, 0) != 0) {
            snprintf(message, capacity, "cannot remove tool-owned symlink: %s", strerror(errno));
            return SYMLINK_OPERATION_FAILED;
        }
        if (renameat(parent, backup_name, parent, leaf) != 0) {
            snprintf(
                message, capacity,
                "cannot restore original directory; it remains in the reserved backup: %s",
                strerror(errno)
            );
            return SYMLINK_OPERATION_FAILED;
        }
        snprintf(message, capacity, "original directory restored");
        return SYMLINK_OPERATION_CHANGED;
    }

    bool valid_leaf = (!leaf_exists && leaf_error == ENOENT) ||
        (leaf_exists && S_ISLNK(current.st_mode) &&
         symlink_destination_matches(parent, leaf, created_name));
    if (!valid_leaf) {
        errno = EPERM;
        snprintf(message, capacity, "symlink identity changed; no object removed");
        return SYMLINK_OPERATION_FAILED;
    }

    struct stat created_information;
    bool backing_exists = fstatat(
        parent, created_name, &created_information, AT_SYMLINK_NOFOLLOW
    ) == 0;
    int backing_error = errno;
    if (backing_exists && (!S_ISDIR(created_information.st_mode) ||
        !owned_directory_is_empty_at(parent, created_name))) {
        snprintf(message, capacity, "tool-owned backing directory is not empty or changed");
        return SYMLINK_OPERATION_FAILED;
    }
    if (!backing_exists && backing_error != ENOENT) {
        snprintf(message, capacity, "cannot inspect symlink backing directory: %s", strerror(backing_error));
        return SYMLINK_OPERATION_FAILED;
    }
    if (leaf_exists && unlinkat(parent, leaf, 0) != 0) {
        snprintf(message, capacity, "cannot remove tool-owned symlink: %s", strerror(errno));
        return SYMLINK_OPERATION_FAILED;
    }
    if (backing_exists && !remove_owned_directory_at(parent, created_name)) {
        snprintf(message, capacity, "cannot remove tool-owned backing directory: %s", strerror(errno));
        return SYMLINK_OPERATION_FAILED;
    }
    snprintf(message, capacity, "tool-owned abnormal symlink removed");
    return leaf_exists || backing_exists
        ? SYMLINK_OPERATION_CHANGED
        : SYMLINK_OPERATION_ALREADY;
}

static bool load_symlink_state(symlink_state_t *state) {
    int directory = open_restricted_state_directory(false);
    if (directory < 0) return false;
    int descriptor = openat(
        directory, kSymlinkStateFile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC
    );
    int saved = errno;
    close(directory);
    errno = saved;
    if (descriptor < 0) return false;

    symlink_state_t candidate;
    ssize_t count = read(descriptor, &candidate, sizeof(candidate));
    char extra = 0;
    ssize_t extra_count = read(descriptor, &extra, 1);
    close(descriptor);
    static const char expected_magic[] = "JAILBREAKLAB_SYMLINK_V1";
    uint32_t valid_mask = (1U << SYMLINK_TARGET_COUNT) - 1U;
    if (count != (ssize_t)sizeof(candidate) || extra_count != 0 ||
        candidate.version != 1 || candidate.rootless > 1 ||
        (candidate.active_mask & ~valid_mask) != 0 ||
        (candidate.missing_mask & ~candidate.active_mask) != 0 ||
        memcmp(candidate.magic, expected_magic, sizeof(expected_magic)) != 0) {
        errno = EINVAL;
        return false;
    }
    *state = candidate;
    return true;
}

static bool save_symlink_state(const symlink_state_t *state) {
    int directory = open_restricted_state_directory(true);
    if (directory < 0) return false;
    int descriptor = openat(
        directory, kSymlinkStateFile,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600
    );
    int saved = errno;
    if (descriptor < 0) {
        close(directory);
        errno = saved;
        return false;
    }
    bool succeeded = write_all(descriptor, (const char *)state, sizeof(*state)) &&
        fsync(descriptor) == 0;
    saved = errno;
    close(descriptor);
    if (!succeeded) unlinkat(directory, kSymlinkStateFile, 0);
    close(directory);
    errno = saved;
    return succeeded;
}

static void remove_symlink_state(void) {
    int directory = open_restricted_state_directory(false);
    if (directory >= 0) {
        unlinkat(directory, kSymlinkStateFile, 0);
        close(directory);
    }
    char message[1024];
    remove_marker_directory(kRestrictedStateDirectory, false, message, sizeof(message));
    prune_owned_ancestors(kRestrictedStateDirectory);
}

static bool prepare_symlink_state(bool use_rootless, symlink_state_t *state) {
    memset(state, 0, sizeof(*state));
    snprintf(state->magic, sizeof(state->magic), "JAILBREAKLAB_SYMLINK_V1");
    state->version = 1;
    state->rootless = use_rootless ? 1 : 0;

    for (size_t index = 0; index < SYMLINK_TARGET_COUNT; index++) {
        char path[MAX_PATH_LENGTH];
        if (!effective_path_for_layout(
            kSymlinkTargets[index], use_rootless, path, sizeof(path)
        )) {
            emit_result(kSymlinkTargets[index], kSymlinkTargets[index], "failed", "path mapping failed");
            continue;
        }

        struct stat information;
        if (lstat(path, &information) == 0) {
            if (S_ISLNK(information.st_mode)) {
                emit_result(
                    kSymlinkTargets[index], path, "already_present",
                    "existing symlink already satisfies the environment and was not modified"
                );
                continue;
            }
            if (!S_ISDIR(information.st_mode)) {
                emit_result(kSymlinkTargets[index], path, "protected", "existing non-directory was not modified");
                continue;
            }
            state->devices[index] = (uint64_t)information.st_dev;
            state->inodes[index] = (uint64_t)information.st_ino;
        } else if (errno == ENOENT) {
            state->missing_mask |= (1U << index);
        } else {
            char message[1024];
            snprintf(message, sizeof(message), "cannot inspect target: %s", strerror(errno));
            emit_result(kSymlinkTargets[index], path, "failed", message);
            continue;
        }
        state->active_mask |= (1U << index);
    }

    if (state->active_mask == 0) return false;
    if (!save_symlink_state(state)) {
        for (size_t index = 0; index < SYMLINK_TARGET_COUNT; index++) {
            if ((state->active_mask & (1U << index)) != 0) {
                emit_result(
                    kSymlinkTargets[index], kSymlinkTargets[index],
                    "failed", "cannot save original directory state"
                );
            }
        }
        return false;
    }
    return true;
}

static void enable_abnormal_symlinks(bool use_rootless, bool dry_run) {
    if (dry_run) {
        for (size_t index = 0; index < SYMLINK_TARGET_COUNT; index++) {
            char path[MAX_PATH_LENGTH];
            if (!effective_path_for_layout(
                kSymlinkTargets[index], use_rootless, path, sizeof(path)
            )) snprintf(path, sizeof(path), "%s", kSymlinkTargets[index]);
            emit_result(
                kSymlinkTargets[index], path, "planned",
                "would preserve the directory and replace its path with a symlink"
            );
        }
        return;
    }

    symlink_state_t state;
    bool state_loaded = load_symlink_state(&state);
    if (!state_loaded && !prepare_symlink_state(use_rootless, &state)) return;

    for (size_t index = 0; index < SYMLINK_TARGET_COUNT; index++) {
        if ((state.active_mask & (1U << index)) == 0) {
            if (state_loaded) {
                char path[MAX_PATH_LENGTH];
                if (!effective_path_for_layout(
                    kSymlinkTargets[index], state.rootless != 0, path, sizeof(path)
                )) snprintf(path, sizeof(path), "%s", kSymlinkTargets[index]);
                struct stat information;
                bool is_existing_symlink = lstat(path, &information) == 0 &&
                    S_ISLNK(information.st_mode);
                emit_result(kSymlinkTargets[index], path,
                    is_existing_symlink ? "already_present" : "protected",
                    is_existing_symlink
                        ? "existing symlink already satisfies the environment and was not modified"
                        : "target was not eligible when original state was recorded"
                );
            }
            continue;
        }

        char path[MAX_PATH_LENGTH];
        if (!effective_path_for_layout(
            kSymlinkTargets[index], state.rootless != 0, path, sizeof(path)
        )) {
            emit_result(kSymlinkTargets[index], kSymlinkTargets[index], "failed", "path mapping failed");
            continue;
        }
        char leaf[NAME_MAX + 1];
        bool original_missing = (state.missing_mask & (1U << index)) != 0;
        int parent = open_parent_directory(path, leaf, sizeof(leaf), original_missing);
        if (parent < 0) {
            char message[1024];
            snprintf(message, sizeof(message), "cannot open parent directory: %s", strerror(errno));
            emit_result(kSymlinkTargets[index], path, "failed", message);
            continue;
        }
        char message[1024];
        symlink_operation_result_t result = enable_symlink_at(
            parent, leaf, index, original_missing,
            state.devices[index], state.inodes[index], message, sizeof(message)
        );
        close(parent);
        emit_result(
            kSymlinkTargets[index], path,
            result == SYMLINK_OPERATION_CHANGED
                ? "created"
                : (result == SYMLINK_OPERATION_ALREADY ? "already_present" : "protected"),
            message
        );
    }
}

static void disable_abnormal_symlinks(bool dry_run) {
    if (dry_run) {
        for (size_t index = 0; index < SYMLINK_TARGET_COUNT; index++) {
            emit_result(
                kSymlinkTargets[index], kSymlinkTargets[index],
                "planned", "would remove the tool-owned symlink and restore the original directory"
            );
        }
        return;
    }

    symlink_state_t state;
    if (!load_symlink_state(&state)) {
        int state_error = errno;
        for (size_t index = 0; index < SYMLINK_TARGET_COUNT; index++) {
            emit_result(
                kSymlinkTargets[index], kSymlinkTargets[index],
                state_error == ENOENT ? "absent" : "protected",
                state_error == ENOENT
                    ? "no saved symlink state"
                    : "saved symlink state is unavailable or invalid"
            );
        }
        return;
    }

    bool fully_restored = true;
    for (size_t index = 0; index < SYMLINK_TARGET_COUNT; index++) {
        if ((state.active_mask & (1U << index)) == 0) {
            emit_result(
                kSymlinkTargets[index], kSymlinkTargets[index],
                "absent", "no saved symlink state for target"
            );
            continue;
        }
        char path[MAX_PATH_LENGTH];
        if (!effective_path_for_layout(
            kSymlinkTargets[index], state.rootless != 0, path, sizeof(path)
        )) {
            fully_restored = false;
            emit_result(kSymlinkTargets[index], kSymlinkTargets[index], "failed", "path mapping failed");
            continue;
        }
        char leaf[NAME_MAX + 1];
        int parent = open_parent_directory(path, leaf, sizeof(leaf), false);
        if (parent < 0) {
            if (errno == ENOENT && (state.missing_mask & (1U << index)) != 0) {
                emit_result(
                    kSymlinkTargets[index], path, "absent",
                    "originally absent target and parent are already absent"
                );
                continue;
            }
            fully_restored = false;
            char message[1024];
            snprintf(message, sizeof(message), "cannot open parent directory: %s", strerror(errno));
            emit_result(kSymlinkTargets[index], path, "failed", message);
            continue;
        }
        char message[1024];
        symlink_operation_result_t result = disable_symlink_at(
            parent, leaf, index, (state.missing_mask & (1U << index)) != 0,
            state.devices[index], state.inodes[index], message, sizeof(message)
        );
        close(parent);
        if (result == SYMLINK_OPERATION_FAILED) fully_restored = false;
        emit_result(
            kSymlinkTargets[index], path,
            result == SYMLINK_OPERATION_FAILED
                ? "protected"
                : (result == SYMLINK_OPERATION_CHANGED ? "removed" : "absent"),
            message
        );
        if (result != SYMLINK_OPERATION_FAILED &&
            (state.missing_mask & (1U << index)) != 0) {
            prune_owned_ancestors(path);
        }
    }

    if (fully_restored) remove_symlink_state();
}

static void emit_root_filesystem_status(void) {
    struct statfs filesystem;
    if (statfs("/", &filesystem) != 0) {
        emit_result("/", "/", "failed", "cannot determine whether root filesystem is read-only");
        return;
    }
    emit_result(
        "/", "/", "already_present",
        (filesystem.f_flags & MNT_RDONLY) != 0
            ? "root filesystem is read-only"
            : "root filesystem is writable"
    );
}

static void probe_artifact(const artifact_t *artifact, const char *effective_path) {
    struct stat information;
    int result = lstat(effective_path, &information);
    if (result == 0) {
        emit_result(artifact->path, effective_path, "already_present", "visible through lstat");
    } else if (errno == ENOENT) {
        emit_result(artifact->path, effective_path, "absent", "not visible through lstat");
    } else {
        emit_result(artifact->path, effective_path, "failed", strerror(errno));
    }
}

static void apply_artifact(const artifact_t *artifact, const char *effective_path, bool dry_run) {
    char message[1024];
    bool succeeded = artifact->kind == KIND_FILE
        ? create_marker_file(effective_path, dry_run, message, sizeof(message))
        : create_marker_directory(effective_path, dry_run, message, sizeof(message));
    if (succeeded) {
        emit_result(artifact->path, effective_path, dry_run ? "planned" : "created", message);
    } else if (errno == EEXIST) {
        emit_result(artifact->path, effective_path, "protected", message);
    } else {
        emit_result(artifact->path, effective_path, "failed", message);
    }
}

static void cleanup_artifact(const artifact_t *artifact, const char *effective_path, bool dry_run) {
    char message[1024];
    bool succeeded = artifact->kind == KIND_FILE
        ? remove_marker_file(effective_path, dry_run, message, sizeof(message))
        : remove_marker_directory(effective_path, dry_run, message, sizeof(message));
    if (succeeded) {
        emit_result(artifact->path, effective_path, dry_run ? "planned" : "removed", message);
        if (!dry_run) prune_owned_ancestors(effective_path);
    } else if (errno == ENOENT) {
        emit_result(artifact->path, effective_path, "absent", message);
    } else if (errno == EPERM || errno == ENOTEMPTY) {
        emit_result(artifact->path, effective_path, "protected", message);
    } else {
        emit_result(artifact->path, effective_path, "failed", message);
    }
}

static bool parse_options(int argument_count, char **arguments, options_t *options) {
    memset(options, 0, sizeof(*options));
    for (int index = 1; index < argument_count; index++) {
        if (strcmp(arguments[index], "--operation") == 0 && index + 1 < argument_count) {
            options->operation = arguments[++index];
        } else if (strcmp(arguments[index], "--root-mode") == 0 && index + 1 < argument_count) {
            options->root_mode = arguments[++index];
        } else if (strcmp(arguments[index], "--groups") == 0 && index + 1 < argument_count) {
            options->groups = arguments[++index];
        } else if (strcmp(arguments[index], "--dry-run") == 0) {
            options->dry_run = true;
        } else if (strcmp(arguments[index], "--live") == 0) {
            options->dry_run = false;
        } else {
            return false;
        }
    }

    bool operation_valid = options->operation != NULL &&
        (strcmp(options->operation, "probe") == 0 ||
         strcmp(options->operation, "apply") == 0 ||
         strcmp(options->operation, "cleanup") == 0 ||
         strcmp(options->operation, "enable-write") == 0 ||
         strcmp(options->operation, "disable-write") == 0 ||
         strcmp(options->operation, "disable-write-remove") == 0 ||
         strcmp(options->operation, "enable-symlinks") == 0 ||
         strcmp(options->operation, "disable-symlinks") == 0);
    bool root_mode_valid = options->root_mode != NULL &&
        (strcmp(options->root_mode, "auto") == 0 ||
         strcmp(options->root_mode, "rootful") == 0 ||
         strcmp(options->root_mode, "rootless") == 0);
    return operation_valid && root_mode_valid && valid_group_list(options->groups);
}

static bool caller_is_expected_app(void) {
    typedef int (*process_path_function_t)(int, void *, uint32_t);
    process_path_function_t process_path =
        (process_path_function_t)dlsym(RTLD_DEFAULT, "proc_pidpath");
    if (process_path == NULL) return false;

    char executable_path[PROCESS_PATH_BUFFER_SIZE];
    memset(executable_path, 0, sizeof(executable_path));
    int length = process_path(getppid(), executable_path, (uint32_t)sizeof(executable_path));
    if (length <= 0) return false;

    static const char *allowed_paths[] = {
        "/Applications/JailbreakLab.app/JailbreakLab",
        "/.jailbreaklab-symlink-original-0/JailbreakLab.app/JailbreakLab",
        "/var/jb/Applications/JailbreakLab.app/JailbreakLab",
        "/var/jb/.jailbreaklab-symlink-original-0/JailbreakLab.app/JailbreakLab",
        "/private/var/jb/Applications/JailbreakLab.app/JailbreakLab",
        "/private/var/jb/.jailbreaklab-symlink-original-0/JailbreakLab.app/JailbreakLab"
    };
    for (size_t index = 0; index < ARRAY_COUNT(allowed_paths); index++) {
        if (strcmp(executable_path, allowed_paths[index]) == 0) return true;
    }

    char rootless_app[PATH_MAX];
    if (realpath("/var/jb/Applications/JailbreakLab.app/JailbreakLab", rootless_app) != NULL &&
        strcmp(executable_path, rootless_app) == 0) {
        return true;
    }
    if (realpath(
        "/var/jb/.jailbreaklab-symlink-original-0/JailbreakLab.app/JailbreakLab",
        rootless_app
    ) != NULL && strcmp(executable_path, rootless_app) == 0) {
        return true;
    }
    return false;
}

int main(int argument_count, char **arguments) {
    options_t options;
    if (!parse_options(argument_count, arguments, &options)) {
        fprintf(stderr, "invalid arguments\n");
        return 64;
    }
    if (geteuid() != 0 && !options.dry_run && strcmp(options.operation, "probe") != 0) {
        fprintf(stderr, "live filesystem operations require effective uid 0\n");
        return 77;
    }
    bool restore_operation = strcmp(options.operation, "disable-write") == 0 ||
        strcmp(options.operation, "disable-write-remove") == 0 ||
        strcmp(options.operation, "disable-symlinks") == 0;
    bool root_restore = restore_operation && getuid() == 0 && geteuid() == 0;
    if (!options.dry_run && strcmp(options.operation, "probe") != 0 &&
        !root_restore && !caller_is_expected_app()) {
        fprintf(stderr, "live filesystem operations require the Jailbreak Lab app as direct caller\n");
        return 77;
    }

    if (strcmp(options.operation, "enable-write") == 0 ||
        strcmp(options.operation, "disable-write") == 0 ||
        strcmp(options.operation, "disable-write-remove") == 0) {
        emit_root_filesystem_status();
        bool use_rootless = strcmp(options.root_mode, "rootless") == 0 ||
            (strcmp(options.root_mode, "auto") == 0 && is_rootless_available());
        if (strcmp(options.operation, "enable-write") == 0) {
            enable_restricted_directories(use_rootless, options.dry_run);
        } else {
            disable_restricted_directories(options.dry_run);
        }
        return 0;
    }

    if (strcmp(options.operation, "enable-symlinks") == 0 ||
        strcmp(options.operation, "disable-symlinks") == 0) {
        bool use_rootless = strcmp(options.root_mode, "rootless") == 0 ||
            (strcmp(options.root_mode, "auto") == 0 && is_rootless_available());
        if (strcmp(options.operation, "enable-symlinks") == 0) {
            enable_abnormal_symlinks(use_rootless, options.dry_run);
        } else {
            disable_abnormal_symlinks(options.dry_run);
        }
        return 0;
    }

    for (size_t index = 0; index < ARRAY_COUNT(kArtifacts); index++) {
        const artifact_t *artifact = &kArtifacts[index];
        if (!group_selected(options.groups, artifact->group)) continue;

        char effective_path[MAX_PATH_LENGTH];
        if (!effective_path_for(artifact->path, options.root_mode, effective_path, sizeof(effective_path))) {
            emit_result(artifact->path, artifact->path, "failed", "effective path is too long");
            continue;
        }

        if (strcmp(options.operation, "probe") == 0) {
            probe_artifact(artifact, effective_path);
        } else if (strcmp(options.operation, "apply") == 0) {
            apply_artifact(artifact, effective_path, options.dry_run);
        } else {
            cleanup_artifact(artifact, effective_path, options.dry_run);
        }
    }
    return 0;
}
