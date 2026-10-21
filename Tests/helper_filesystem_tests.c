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
    assert(create_marker_file(marker_path, false, message, sizeof(message)));
    assert(create_marker_file(marker_path, false, message, sizeof(message)));

    struct stat information;
    assert(lstat(marker_path, &information) == 0);
    assert(S_ISREG(information.st_mode));
    assert((information.st_mode & 0111) == 0);

    assert(remove_marker_file(marker_path, false, message, sizeof(message)));
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
    assert(!create_marker_file(existing_path, false, message, sizeof(message)));
    assert(errno == EEXIST);
    assert(!remove_marker_file(existing_path, false, message, sizeof(message)));
    assert(errno == EPERM);

    char real_directory[MAX_PATH_LENGTH];
    char linked_directory[MAX_PATH_LENGTH];
    char linked_target[MAX_PATH_LENGTH];
    snprintf(real_directory, sizeof(real_directory), "%s/real", root);
    snprintf(linked_directory, sizeof(linked_directory), "%s/link", root);
    snprintf(linked_target, sizeof(linked_target), "%s/link/marker", root);
    assert(mkdir(real_directory, 0700) == 0);
    assert(symlink(real_directory, linked_directory) == 0);
    assert(!create_marker_file(linked_target, false, message, sizeof(message)));

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
