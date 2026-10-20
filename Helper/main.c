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
#include <sys/types.h>
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

static bool effective_path_for(
    const char *original,
    const char *root_mode,
    char *output,
    size_t capacity
) {
    bool use_rootless = strcmp(root_mode, "rootless") == 0 ||
        (strcmp(root_mode, "auto") == 0 && is_rootless_available());

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
         strcmp(options->operation, "cleanup") == 0);
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
        "/var/jb/Applications/JailbreakLab.app/JailbreakLab",
        "/private/var/jb/Applications/JailbreakLab.app/JailbreakLab"
    };
    for (size_t index = 0; index < ARRAY_COUNT(allowed_paths); index++) {
        if (strcmp(executable_path, allowed_paths[index]) == 0) return true;
    }

    char rootless_app[PATH_MAX];
    if (realpath("/var/jb/Applications/JailbreakLab.app/JailbreakLab", rootless_app) != NULL &&
        strcmp(executable_path, rootless_app) == 0) {
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
    if (!options.dry_run && strcmp(options.operation, "probe") != 0 && !caller_is_expected_app()) {
        fprintf(stderr, "live filesystem operations require the Jailbreak Lab app as direct caller\n");
        return 77;
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
