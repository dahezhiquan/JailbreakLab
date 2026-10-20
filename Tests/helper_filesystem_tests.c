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
    snprintf(restricted_path, sizeof(restricted_path), "%s/jb", root);
    configure_restricted_write(restricted_path, true, false, false);
    assert(stat(restricted_path, &information) == 0);
    assert((information.st_mode & 01777) == 01777);
    configure_restricted_write(restricted_path, false, false, false);
    assert(stat(restricted_path, &information) == 0);
    assert((information.st_mode & 0777) == 0755);
    configure_restricted_write(restricted_path, true, false, false);
    configure_restricted_write(restricted_path, false, true, false);
    assert(lstat(restricted_path, &information) != 0 && errno == ENOENT);

    assert(mkdir(restricted_path, 0700) == 0);
    assert(chmod(restricted_path, 0777) == 0);
    configure_restricted_write(restricted_path, true, false, false);
    assert(stat(restricted_path, &information) == 0);
    assert((information.st_mode & 0777) == 0777);
    char ownership_marker[MAX_PATH_LENGTH];
    snprintf(
        ownership_marker, sizeof(ownership_marker),
        "%s/%s", restricted_path, kDirectoryMarker
    );
    assert(lstat(ownership_marker, &information) != 0 && errno == ENOENT);
    configure_restricted_write(restricted_path, false, true, false);
    assert(stat(restricted_path, &information) == 0);
    assert(rmdir(restricted_path) == 0);

    assert(rmdir(root) == 0);
    puts("helper filesystem tests passed");
    return 0;
}
