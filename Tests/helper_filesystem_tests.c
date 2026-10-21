#define main jailbreaklab_helper_main
#include "../Helper/main.c"
#undef main

#include <assert.h>

int main(void) {
    char temporary[] = "/tmp/jailbreaklab-tests.XXXXXX";
    char *root = mkdtemp(temporary);
    assert(root != NULL);
    char resolved_root[PATH_MAX];
    assert(realpath(root, resolved_root) != NULL);
    root = resolved_root;

    char marker_path[MAX_PATH_LENGTH];
    snprintf(marker_path, sizeof(marker_path), "%s/missing/parent/test.dylib", root);

    char message[1024];
    assert(create_marker_file(marker_path, false, false, message, sizeof(message)));
    assert(create_marker_file(marker_path, false, false, message, sizeof(message)));

    struct stat information;
    assert(lstat(marker_path, &information) == 0);
    assert(S_ISREG(information.st_mode));
    assert((information.st_mode & 0111) == 0);

    assert(remove_marker_file(marker_path, false, false, message, sizeof(message)));
    prune_owned_ancestors(marker_path);

    char missing_path[MAX_PATH_LENGTH];
    snprintf(missing_path, sizeof(missing_path), "%s/missing", root);
    assert(lstat(missing_path, &information) != 0 && errno == ENOENT);

    char existing_path[MAX_PATH_LENGTH];
    snprintf(existing_path, sizeof(existing_path), "%s/existing", root);
    int existing = open(existing_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(existing >= 0);
    assert(write_all(existing, "external", 8));
    close(existing);
    assert(!create_marker_file(existing_path, false, false, message, sizeof(message)));
    assert(errno == EEXIST);
    assert(!remove_marker_file(existing_path, false, false, message, sizeof(message)));
    assert(errno == EPERM);

    char real_directory[MAX_PATH_LENGTH];
    char linked_directory[MAX_PATH_LENGTH];
    char linked_target[MAX_PATH_LENGTH];
    snprintf(real_directory, sizeof(real_directory), "%s/real", root);
    snprintf(linked_directory, sizeof(linked_directory), "%s/link", root);
    snprintf(linked_target, sizeof(linked_target), "%s/link/marker", root);
    assert(mkdir(real_directory, 0700) == 0);
    assert(symlink(real_directory, linked_directory) == 0);
    assert(!create_marker_file(linked_target, false, false, message, sizeof(message)));

    char apt_contents[MAX_PATH_LENGTH + 64];
    assert(is_apt_source_path("/etc/apt/sources.list.d/electra.list"));
    assert(marker_file_contents(
        "/tmp/electra.list", true, apt_contents, sizeof(apt_contents)
    ));
    assert(strcmp(
        apt_contents,
        "# JAILBREAKLAB_ARTIFACT_V1\n# /tmp/electra.list\n"
    ) == 0);

    char apt_marker_path[MAX_PATH_LENGTH];
    snprintf(apt_marker_path, sizeof(apt_marker_path), "%s/electra.list", root);
    assert(create_marker_file(
        apt_marker_path, true, false, message, sizeof(message)
    ));
    int apt_marker = open(apt_marker_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(apt_marker >= 0);
    assert(fd_has_exact_signature(apt_marker, apt_contents) == false);
    close(apt_marker);
    char expected_apt_contents[MAX_PATH_LENGTH + 64];
    assert(marker_file_contents(
        apt_marker_path, true, expected_apt_contents, sizeof(expected_apt_contents)
    ));
    apt_marker = open(apt_marker_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(apt_marker >= 0);
    assert(fd_has_exact_signature(apt_marker, expected_apt_contents));
    close(apt_marker);
    assert(remove_marker_file(
        apt_marker_path, true, false, message, sizeof(message)
    ));

    assert(create_marker_file(
        apt_marker_path, false, false, message, sizeof(message)
    ));
    assert(create_marker_file(
        apt_marker_path, true, false, message, sizeof(message)
    ));
    apt_marker = open(apt_marker_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(apt_marker >= 0);
    assert(fd_has_exact_signature(apt_marker, expected_apt_contents));
    close(apt_marker);
    assert(remove_marker_file(
        apt_marker_path, true, false, message, sizeof(message)
    ));

    char shadow_filter_path[MAX_PATH_LENGTH];
    snprintf(shadow_filter_path, sizeof(shadow_filter_path), "%s/shadow-filter.plist", root);
    shadow_target_state_t shadow_target;
    initialize_shadow_target(
        &shadow_target, "com.example.detector", "Detector.app", "Detector"
    );
    assert(shadow_target_is_valid(&shadow_target));
    assert(!valid_shadow_target("invalid<&", "Detector.app", "Detector"));
    assert(!valid_shadow_target("com.example.detector", "../Detector.app", "Detector"));
    char shadow_filter_contents[SHADOW_FILTER_CAPACITY];
    assert(build_shadow_filter_contents(
        &shadow_target, shadow_filter_contents, sizeof(shadow_filter_contents)
    ));
    assert(strstr(shadow_filter_contents, "com.example.detector") != NULL);
    bool filter_changed = false;
    assert(update_shadow_filter(
        shadow_filter_path, NULL, &shadow_target, true,
        &filter_changed, message, sizeof(message)
    ));
    assert(filter_changed);
    assert(update_shadow_filter(
        shadow_filter_path, &shadow_target, &shadow_target, true,
        &filter_changed, message, sizeof(message)
    ));
    assert(!filter_changed);
    shadow_target_state_t alternate_shadow_target;
    initialize_shadow_target(
        &alternate_shadow_target,
        "com.example.alternate",
        "Alternate Detector.app",
        "Alternate Detector"
    );
    char alternate_filter_contents[SHADOW_FILTER_CAPACITY];
    assert(build_shadow_filter_contents(
        &alternate_shadow_target,
        alternate_filter_contents,
        sizeof(alternate_filter_contents)
    ));
    assert(update_shadow_filter(
        shadow_filter_path, &shadow_target, &alternate_shadow_target, true,
        &filter_changed, message, sizeof(message)
    ));
    assert(filter_changed);
    assert(update_shadow_filter(
        shadow_filter_path, &alternate_shadow_target, &shadow_target, true,
        &filter_changed, message, sizeof(message)
    ));
    assert(filter_changed);
    int shadow_filter = open(
        shadow_filter_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC
    );
    assert(shadow_filter >= 0);
    assert(fd_has_exact_signature(shadow_filter, shadow_filter_contents));
    close(shadow_filter);
    assert(update_shadow_filter(
        shadow_filter_path, &shadow_target, &shadow_target, false,
        &filter_changed, message, sizeof(message)
    ));
    assert(filter_changed);
    assert(update_shadow_filter(
        shadow_filter_path, &shadow_target, &shadow_target, false,
        &filter_changed, message, sizeof(message)
    ));
    assert(!filter_changed);

    shadow_filter = open(
        shadow_filter_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600
    );
    assert(shadow_filter >= 0);
    assert(write_all(
        shadow_filter,
        kLegacyShadowFilterContents,
        strlen(kLegacyShadowFilterContents)
    ));
    close(shadow_filter);
    assert(update_shadow_filter(
        shadow_filter_path, NULL, &shadow_target, true,
        &filter_changed, message, sizeof(message)
    ));
    assert(filter_changed);
    shadow_filter = open(
        shadow_filter_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC
    );
    assert(shadow_filter >= 0);
    assert(fd_has_exact_signature(shadow_filter, shadow_filter_contents));
    close(shadow_filter);
    assert(update_shadow_filter(
        shadow_filter_path, &shadow_target, &shadow_target, false,
        &filter_changed, message, sizeof(message)
    ));
    assert(filter_changed);

    shadow_filter = open(
        shadow_filter_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600
    );
    assert(shadow_filter >= 0);
    assert(write_all(shadow_filter, "external", 8));
    close(shadow_filter);
    assert(!update_shadow_filter(
        shadow_filter_path, NULL, &shadow_target, true,
        &filter_changed, message, sizeof(message)
    ));
    assert(errno == EPERM);
    assert(unlink(shadow_filter_path) == 0);

    char runtime_filter_path[MAX_PATH_LENGTH];
    snprintf(runtime_filter_path, sizeof(runtime_filter_path), "%s/runtime-filter.plist", root);
    assert(update_runtime_hook_filter(
        runtime_filter_path, NULL, &shadow_target, true,
        &filter_changed, message, sizeof(message)
    ));
    assert(filter_changed);
    assert(update_runtime_hook_filter(
        runtime_filter_path, &shadow_target, &shadow_target, true,
        &filter_changed, message, sizeof(message)
    ));
    assert(!filter_changed);
    assert(update_runtime_hook_filter(
        runtime_filter_path, &shadow_target, &shadow_target, false,
        &filter_changed, message, sizeof(message)
    ));
    assert(filter_changed);

    int runtime_filter = open(
        runtime_filter_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600
    );
    assert(runtime_filter >= 0);
    assert(write_all(
        runtime_filter,
        kLegacyShadowFilterContents,
        strlen(kLegacyShadowFilterContents)
    ));
    close(runtime_filter);
    assert(!update_runtime_hook_filter(
        runtime_filter_path, NULL, &shadow_target, true,
        &filter_changed, message, sizeof(message)
    ));
    assert(errno == EPERM);
    assert(unlink(runtime_filter_path) == 0);

    char shadow_state_path[MAX_PATH_LENGTH];
    snprintf(shadow_state_path, sizeof(shadow_state_path), "%s/shadow-state", root);
    int shadow_state = open(
        shadow_state_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600
    );
    assert(shadow_state >= 0);
    assert(write_all(
        shadow_state, (const char *)&shadow_target, sizeof(shadow_target)
    ));
    shadow_target_state_t loaded_shadow_target;
    assert(read_shadow_target_descriptor(shadow_state, &loaded_shadow_target));
    assert(strcmp(
        loaded_shadow_target.bundle_identifier, shadow_target.bundle_identifier
    ) == 0);
    close(shadow_state);
    assert(unlink(shadow_state_path) == 0);

    char runtime_state_path[MAX_PATH_LENGTH];
    snprintf(runtime_state_path, sizeof(runtime_state_path), "%s/runtime-state", root);
    assert(save_target_state(
        runtime_state_path, &shadow_target, message, sizeof(message)
    ));
    assert(save_target_state(
        runtime_state_path, &alternate_shadow_target, message, sizeof(message)
    ));
    assert(load_target_state(runtime_state_path, &loaded_shadow_target));
    assert(strcmp(
        loaded_shadow_target.bundle_identifier,
        alternate_shadow_target.bundle_identifier
    ) == 0);
    assert(remove_target_state(runtime_state_path, message, sizeof(message)));
    assert(remove_target_state(runtime_state_path, message, sizeof(message)));

    assert(unlink(linked_directory) == 0);
    assert(rmdir(real_directory) == 0);
    assert(unlink(existing_path) == 0);

    char restricted_path[MAX_PATH_LENGTH];
    snprintf(restricted_path, sizeof(restricted_path), "%s/restricted", root);
    assert(mkdir(restricted_path, 0700) == 0);
    int restricted = open(restricted_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(restricted >= 0);
    assert(fstat(restricted, &information) == 0);

    restricted_state_t state = {0};
    state.devices[0] = (uint64_t)information.st_dev;
    state.inodes[0] = (uint64_t)information.st_ino;
    assert(restricted_identity_matches(&state, 0, &information));
    state.inodes[0]++;
    assert(!restricted_identity_matches(&state, 0, &information));

    assert(fchmod(restricted, 01777) == 0);
    assert(verify_directory_write_as_caller(restricted));
    assert(fchmod(restricted, 0700) == 0);
    close(restricted);
    assert(stat(restricted_path, &information) == 0);
    assert((information.st_mode & 07777) == 0700);

    char private_path[MAX_PATH_LENGTH];
    assert(restricted_effective_path("/private", true, private_path, sizeof(private_path)));
    assert(strcmp(private_path, "/private") == 0);
    assert(path_is_within_directory(
        "/private/preboot/hash/procursus/usr/lib/TweakInject",
        "/private/preboot/hash/procursus"
    ));
    assert(!path_is_within_directory(
        "/private/preboot/hash/procursus-malicious/usr/lib/TweakInject",
        "/private/preboot/hash/procursus"
    ));
    assert(!path_is_within_directory(
        "/private/var/mobile/usr/lib/TweakInject",
        "/private/preboot/hash/procursus"
    ));
    assert(rmdir(restricted_path) == 0);

    int test_root = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(test_root >= 0);
    assert(mkdirat(test_root, "original", 0700) == 0);
    struct stat original_information;
    assert(fstatat(test_root, "original", &original_information, AT_SYMLINK_NOFOLLOW) == 0);
    symlink_operation_result_t link_result = enable_symlink_at(
        test_root, "original", 0, false,
        (uint64_t)original_information.st_dev,
        (uint64_t)original_information.st_ino,
        message, sizeof(message)
    );
    assert(link_result == SYMLINK_OPERATION_CHANGED);
    assert(fstatat(test_root, "original", &information, AT_SYMLINK_NOFOLLOW) == 0);
    assert(S_ISLNK(information.st_mode));
    link_result = enable_symlink_at(
        test_root, "original", 0, false,
        (uint64_t)original_information.st_dev,
        (uint64_t)original_information.st_ino,
        message, sizeof(message)
    );
    assert(link_result == SYMLINK_OPERATION_ALREADY);
    link_result = disable_symlink_at(
        test_root, "original", 0, false,
        (uint64_t)original_information.st_dev,
        (uint64_t)original_information.st_ino,
        message, sizeof(message)
    );
    assert(link_result == SYMLINK_OPERATION_CHANGED);
    assert(fstatat(test_root, "original", &information, AT_SYMLINK_NOFOLLOW) == 0);
    assert(S_ISDIR(information.st_mode));
    assert((uint64_t)information.st_ino == (uint64_t)original_information.st_ino);
    assert(unlinkat(test_root, "original", AT_REMOVEDIR) == 0);

    link_result = enable_symlink_at(
        test_root, "missing-link", 1, true, 0, 0, message, sizeof(message)
    );
    assert(link_result == SYMLINK_OPERATION_CHANGED);
    assert(fstatat(test_root, "missing-link", &information, AT_SYMLINK_NOFOLLOW) == 0);
    assert(S_ISLNK(information.st_mode));
    link_result = disable_symlink_at(
        test_root, "missing-link", 1, true, 0, 0, message, sizeof(message)
    );
    assert(link_result == SYMLINK_OPERATION_CHANGED);
    assert(fstatat(test_root, "missing-link", &information, AT_SYMLINK_NOFOLLOW) != 0);
    assert(errno == ENOENT);

    assert(symlinkat("external", test_root, "external-link") == 0);
    link_result = enable_symlink_at(
        test_root, "external-link", 2, true, 0, 0, message, sizeof(message)
    );
    assert(link_result == SYMLINK_OPERATION_FAILED);
    assert(symlink_destination_matches(test_root, "external-link", "external"));
    assert(unlinkat(test_root, "external-link", 0) == 0);
    close(test_root);

    assert(rmdir(root) == 0);
    puts("helper filesystem tests passed");
    return 0;
}
